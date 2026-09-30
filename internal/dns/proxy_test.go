package dns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gonnectdns "github.com/asciimoth/gonnect/dns"
)

func TestD01D04ProxyServesUDPAndTCPWithTruncationFallback(t *testing.T) {
	proxy, endpoint := newTestProxy(t, time.Second)
	provider := newTestProvider(func(request gonnectdns.Request, call int64) (*gonnectdns.Message, error) {
		address := netip.MustParseAddr("192.0.2.17")
		if request.Message.Questions[0].Type == gonnectdns.TypeAAAA {
			address = netip.MustParseAddr("2001:db8::17")
		}
		response := dnsResponse(request.Message, address)
		if call == 3 {
			response.Answers = nil
			response.Truncated = true
		}
		return response, nil
	})
	defer func() { _ = provider.Close() }()
	proxy.Attach(provider)

	for _, test := range []struct {
		scheme       string
		questionType uint16
	}{
		{scheme: "udp", questionType: gonnectdns.TypeA},
		{scheme: "tcp", questionType: gonnectdns.TypeAAAA},
	} {
		client := gonnectdns.NewClient((&net.Dialer{}).DialContext, nil, nil, test.scheme+"://"+endpoint)
		response, err := gonnectdns.Query(context.Background(), client, dnsQuery(test.questionType))
		_ = client.Close()
		if err != nil || len(response.Answers) != 1 || response.Answers[0].Type != test.questionType {
			t.Fatalf("%s query response = %#v, error = %v", test.scheme, response, err)
		}
	}

	// The provider truncates call three. The DNS client must repeat that query
	// over the proxy's TCP listener and receive call four's complete answer.
	client := gonnectdns.NewClient((&net.Dialer{}).DialContext, nil, nil, "udp://"+endpoint)
	response, err := gonnectdns.Query(context.Background(), client, dnsQuery(gonnectdns.TypeA))
	_ = client.Close()
	if err != nil || response.Truncated || len(response.Answers) != 1 {
		t.Fatalf("fallback response = %#v, error = %v", response, err)
	}
	if calls := provider.calls.Load(); calls != 4 {
		t.Fatalf("provider calls = %d, want UDP, TCP, truncated UDP, fallback TCP", calls)
	}
}

func TestProxyRejectsMalformedSVCBWithoutPanic(t *testing.T) {
	// This 30-byte response declares an SVCB parameter value of 65535 bytes
	// inside a seven-byte RDATA field. It is the GO-2026-5942 shape.
	packet := []byte{
		0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0,
		0, 0, 64, 0, 1, 0, 0, 0, 0, 0, 7,
		0, 1, 0, 0, 1, 0xff, 0xff,
	}
	if message, err := unpackDNS(packet); err == nil || message != nil {
		t.Fatalf("unpackDNS(malformed SVCB) = %#v, %v; want parse error", message, err)
	}
}

func FuzzProxyDNSPackets(f *testing.F) {
	valid, err := gonnectdns.Pack(dnsQuery(gonnectdns.TypeA))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{
		0, 1, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0,
		0, 0, 64, 0, 1, 0, 0, 0, 0, 0, 7,
		0, 1, 0, 0, 1, 0xff, 0xff,
	})
	f.Fuzz(func(t *testing.T, packet []byte) {
		message, parseErr := unpackDNS(packet)
		if parseErr == nil && message == nil {
			t.Fatal("successful parse returned a nil message")
		}
	})
}

func TestD05D08ProviderReplacementNilAndShutdown(t *testing.T) {
	proxy, endpoint := newTestProxy(t, 200*time.Millisecond)
	oldStarted := make(chan struct{})
	oldCanceled := make(chan struct{})
	old := newTestProvider(func(request gonnectdns.Request, _ int64) (*gonnectdns.Message, error) {
		closeOnce(oldStarted)
		<-request.Context.Done()
		closeOnce(oldCanceled)
		return nil, request.Context.Err()
	})
	defer func() { _ = old.Close() }()
	proxy.Attach(old)

	client := gonnectdns.NewClient((&net.Dialer{}).DialContext, nil, nil, "udp://"+endpoint)
	defer func() { _ = client.Close() }()
	queryDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := gonnectdns.Query(ctx, client, dnsQuery(gonnectdns.TypeA))
		queryDone <- err
	}()
	select {
	case <-oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old provider did not receive request")
	}

	replacement := newTestProvider(func(request gonnectdns.Request, _ int64) (*gonnectdns.Message, error) {
		return dnsResponse(request.Message, netip.MustParseAddr("198.51.100.9")), nil
	})
	defer func() { _ = replacement.Close() }()
	proxy.Attach(replacement)
	select {
	case <-oldCanceled:
	case <-time.After(time.Second):
		t.Fatal("provider replacement did not cancel the old request")
	}

	response, err := gonnectdns.Query(context.Background(), client, dnsQuery(gonnectdns.TypeA))
	if err != nil || len(response.Answers) != 1 {
		t.Fatalf("replacement response = %#v, error = %v", response, err)
	}
	if got := response.Answers[0].Data; !bytes.Equal(got, netip.MustParseAddr("198.51.100.9").AsSlice()) {
		t.Fatalf("replacement answer = %v", got)
	}

	proxy.Attach(nil)
	dropContext, cancelDrop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelDrop()
	if _, err := gonnectdns.Query(dropContext, client, dnsQuery(gonnectdns.TypeA)); err == nil ||
		(!errors.Is(err, context.DeadlineExceeded) && !isTimeout(err)) {
		t.Fatalf("nil-provider query error = %v, want a timeout", err)
	}
	if calls := replacement.calls.Load(); calls != 1 {
		t.Fatalf("replacement calls after nil provider = %d, want 1", calls)
	}

	blocking := newTestProvider(func(request gonnectdns.Request, _ int64) (*gonnectdns.Message, error) {
		<-request.Context.Done()
		return nil, request.Context.Err()
	})
	defer func() { _ = blocking.Close() }()
	proxy.Attach(blocking)
	go func() {
		_, _ = gonnectdns.Query(context.Background(), client, dnsQuery(gonnectdns.TypeA))
	}()
	deadline := time.Now().Add(time.Second)
	for blocking.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if blocking.calls.Load() == 0 {
		t.Fatal("blocking provider did not receive request")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- proxy.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Proxy.Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Proxy.Close() did not wait for and stop active requests")
	}
	select {
	case <-queryDone:
	case <-time.After(time.Second):
		t.Fatal("replaced query did not finish")
	}
}

func TestD07ConcurrentQueriesAndProviderSwaps(t *testing.T) {
	proxy, endpoint := newTestProxy(t, time.Second)
	first := newAnswerProvider(netip.MustParseAddr("192.0.2.1"))
	second := newAnswerProvider(netip.MustParseAddr("192.0.2.2"))
	defer func() { _ = first.Close() }()
	defer func() { _ = second.Close() }()
	proxy.Attach(first)

	const queryCount = 100
	var workers sync.WaitGroup
	workers.Add(queryCount)
	for index := 0; index < queryCount; index++ {
		go func() {
			defer workers.Done()
			client := gonnectdns.NewClient((&net.Dialer{}).DialContext, nil, nil, "udp://"+endpoint)
			defer func() { _ = client.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := gonnectdns.Query(ctx, client, dnsQuery(gonnectdns.TypeA))
			if err == nil && (response == nil || len(response.Answers) != 1) {
				t.Errorf("successful concurrent query response = %#v", response)
			}
		}()
		if index%2 == 0 {
			proxy.Attach(second)
		} else {
			proxy.Attach(first)
		}
	}
	workers.Wait()
}

func newTestProxy(t *testing.T, timeout time.Duration) (*Proxy, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	packet, err := net.ListenPacket("udp4", endpoint)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	proxy := NewProxy(packet, listener, timeout)
	t.Cleanup(func() {
		if err := proxy.Close(); err != nil {
			t.Errorf("Proxy.Close() error = %v", err)
		}
	})
	return proxy, endpoint
}

type testProvider struct {
	requests chan gonnectdns.Request
	handler  func(gonnectdns.Request, int64) (*gonnectdns.Message, error)
	stop     chan struct{}
	done     chan struct{}
	calls    atomic.Int64
	once     sync.Once
}

func newTestProvider(handler func(gonnectdns.Request, int64) (*gonnectdns.Message, error)) *testProvider {
	p := &testProvider{requests: make(chan gonnectdns.Request), handler: handler, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			select {
			case request := <-p.requests:
				go func() {
					response, err := p.handler(request, p.calls.Add(1))
					select {
					case request.Reply <- gonnectdns.Response{Message: response, Err: err}:
					case <-request.Context.Done():
					case <-p.stop:
					}
				}()
			case <-p.stop:
				return
			}
		}
	}()
	return p
}

func newAnswerProvider(address netip.Addr) *testProvider {
	return newTestProvider(func(request gonnectdns.Request, _ int64) (*gonnectdns.Message, error) {
		return dnsResponse(request.Message, address), nil
	})
}

func (p *testProvider) Requests() chan<- gonnectdns.Request { return p.requests }
func (p *testProvider) Close() error {
	p.once.Do(func() { close(p.stop) })
	<-p.done
	return nil
}

func dnsQuery(questionType uint16) *gonnectdns.Message {
	return &gonnectdns.Message{
		ID: gonnectdns.NextID(), RecursionDesired: true,
		Questions: []gonnectdns.Question{{Name: "step17.example.", Type: questionType, Class: gonnectdns.ClassIN}},
	}
}

func dnsResponse(request *gonnectdns.Message, address netip.Addr) *gonnectdns.Message {
	data := address.AsSlice()
	recordType := gonnectdns.TypeAAAA
	if address.Is4() {
		recordType = gonnectdns.TypeA
	}
	return &gonnectdns.Message{
		ID: request.ID, Response: true, RecursionAvailable: true,
		Questions: append([]gonnectdns.Question(nil), request.Questions...),
		Answers:   []gonnectdns.Resource{{Name: request.Questions[0].Name, Type: recordType, Class: gonnectdns.ClassIN, TTL: 30, Data: data}},
	}
}

func closeOnce(channel chan struct{}) {
	select {
	case <-channel:
	default:
		close(channel)
	}
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
