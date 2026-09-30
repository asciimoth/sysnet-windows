package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	gonnectdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

func TestD09D12UpstreamProviderRefreshesNumericUnderlayDNS(t *testing.T) {
	paths := &dnsPathSource{snapshot: underlay.Snapshot{
		IPv4: &underlay.Path{InterfaceLUID: 4},
		IPv6: &underlay.Path{InterfaceLUID: 6},
	}}
	configurator := &dnsStateReader{states: map[uint64]State{
		4: {AutomaticIPv4: true, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}},
		6: {Servers: []netip.Addr{netip.MustParseAddr("2001:db8::53")}},
	}}
	dialer := &dnsTestDialer{}
	provider, err := NewUpstreamProvider(paths, configurator, dialer.Dial, time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamProvider() error = %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	// The question type does not select the transport family. The first
	// configured numeric server is IPv4, but it can answer an AAAA question.
	query := &gonnectdns.Message{ID: 7, Questions: []gonnectdns.Question{{
		Name: "step19.example.", Type: gonnectdns.TypeAAAA, Class: gonnectdns.ClassIN,
	}}}
	if _, err := gonnectdns.Query(context.Background(), provider, query); err != nil {
		t.Fatalf("first query error = %v", err)
	}
	if got := dialer.lastAddress(); got != "192.0.2.53:53" {
		t.Fatalf("first upstream = %q, want 192.0.2.53:53", got)
	}

	configurator.set(4, State{Servers: []netip.Addr{netip.MustParseAddr("198.51.100.53")}})
	if _, err := gonnectdns.Query(context.Background(), provider, query); err != nil {
		t.Fatalf("refreshed query error = %v", err)
	}
	if got := dialer.lastAddress(); got != "198.51.100.53:53" {
		t.Fatalf("refreshed upstream = %q, want 198.51.100.53:53", got)
	}
}

func TestUpstreamProviderExcludesManagedProxyAndUsesTCPFallback(t *testing.T) {
	managed := netip.MustParseAddr("10.0.0.1")
	paths := &dnsPathSource{snapshot: underlay.Snapshot{IPv4: &underlay.Path{InterfaceLUID: 4}}}
	configurator := &dnsStateReader{states: map[uint64]State{4: {
		Servers: []netip.Addr{managed, netip.MustParseAddr("192.0.2.53")},
	}}}
	dialer := &dnsTestDialer{truncateUDP: true}
	provider, err := NewUpstreamProvider(paths, configurator, dialer.Dial, time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamProvider() error = %v", err)
	}
	provider.SetExcluded(managed)
	t.Cleanup(func() { _ = provider.Close() })
	query := &gonnectdns.Message{Questions: []gonnectdns.Question{{Name: "fallback.example.", Type: gonnectdns.TypeA, Class: gonnectdns.ClassIN}}}
	if _, err := gonnectdns.Query(context.Background(), provider, query); err != nil {
		t.Fatalf("query error = %v", err)
	}
	if got := dialer.callsCopy(); len(got) != 2 || got[0] != "udp 192.0.2.53:53" || got[1] != "tcp 192.0.2.53:53" {
		t.Fatalf("dial calls = %v, want bound UDP then TCP to non-proxy upstream", got)
	}

	configurator.set(4, State{Servers: []netip.Addr{managed}})
	_, err = gonnectdns.Query(context.Background(), provider, query)
	if !errors.Is(err, gonnectdns.ErrNoUpstream) {
		t.Fatalf("proxy-only upstream error = %v, want ErrNoUpstream", err)
	}
}

func TestUpstreamProviderCloseCancelsActiveRequest(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	configurator := &blockingDNSConfigurator{started: started, canceled: canceled}
	provider, err := NewUpstreamProvider(
		&dnsPathSource{snapshot: underlay.Snapshot{IPv4: &underlay.Path{InterfaceLUID: 4}}},
		configurator,
		func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial must not run")
		},
		time.Minute,
	)
	if err != nil {
		t.Fatalf("NewUpstreamProvider() error = %v", err)
	}
	queryDone := make(chan error, 1)
	go func() {
		_, queryErr := gonnectdns.Query(context.Background(), provider, &gonnectdns.Message{
			Questions: []gonnectdns.Question{{Name: "cancel.example.", Type: gonnectdns.TypeA, Class: gonnectdns.ClassIN}},
		})
		queryDone <- queryErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("active DNS configuration read did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- provider.Close() }()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active request")
	}
	select {
	case err := <-queryDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("query error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled query did not return")
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type blockingDNSConfigurator struct {
	started  chan struct{}
	canceled chan struct{}
}

func (c *blockingDNSConfigurator) Read(ctx context.Context, _ uint64) (State, error) {
	close(c.started)
	<-ctx.Done()
	close(c.canceled)
	return State{}, ctx.Err()
}

func (*blockingDNSConfigurator) Apply(context.Context, uint64, State) error { return nil }

type dnsPathSource struct{ snapshot underlay.Snapshot }

func (s *dnsPathSource) Snapshot() underlay.Snapshot { return s.snapshot }

type dnsStateReader struct {
	mu     sync.Mutex
	states map[uint64]State
}

func (r *dnsStateReader) Read(_ context.Context, luid uint64) (State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, found := r.states[luid]
	if !found {
		return State{}, errors.New("unknown interface")
	}
	return CloneState(state), nil
}

func (r *dnsStateReader) Apply(_ context.Context, luid uint64, state State) error {
	r.set(luid, state)
	return nil
}

func (r *dnsStateReader) set(luid uint64, state State) {
	r.mu.Lock()
	r.states[luid] = CloneState(state)
	r.mu.Unlock()
}

type dnsTestDialer struct {
	mu          sync.Mutex
	calls       []string
	truncateUDP bool
}

func (d *dnsTestDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+" "+address)
	d.mu.Unlock()
	client, server := net.Pipe()
	go serveDNSPipe(ctx, server, network == "tcp", d.truncateUDP && network == "udp")
	return client, nil
}

func (d *dnsTestDialer) lastAddress() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		return ""
	}
	return d.calls[len(d.calls)-1][4:]
}

func (d *dnsTestDialer) callsCopy() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func serveDNSPipe(ctx context.Context, connection net.Conn, tcp, truncated bool) {
	defer func() { _ = connection.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	var packet []byte
	if tcp {
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			return
		}
		packet = make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(connection, packet); err != nil {
			return
		}
	} else {
		packet = make([]byte, 64*1024)
		count, err := connection.Read(packet)
		if err != nil {
			return
		}
		packet = packet[:count]
	}
	request, err := gonnectdns.Unpack(packet)
	if err != nil {
		return
	}
	response := request.Copy()
	response.Response = true
	response.RecursionAvailable = true
	response.Truncated = truncated
	wire, err := gonnectdns.Pack(response)
	if err != nil {
		return
	}
	if tcp {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
		wire = append(size[:], wire...)
	}
	_, _ = connection.Write(wire)
}
