package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

func TestN01N08OutboundCoversAndTracksEverySocketEntryPoint(t *testing.T) {
	t.Parallel()
	base := &recordingNetwork{}
	resolver := &recordingResolver{}
	provider := dns.NewResolverProvider(resolver, time.Minute, nil)
	t.Cleanup(func() { _ = provider.Close() })
	registry := &testRegistry{}
	outbound, err := NewOutbound(base, provider, func() error { return nil }, registry.track)
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	ctx := context.Background()
	config := &gonnect.ListenConfig{Control: func(string, string, syscall.RawConn) error { return nil }}
	operations := []func() (io.Closer, error){
		func() (io.Closer, error) { return outbound.Dial(ctx, "tcp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.Listen(ctx, "tcp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.PacketDial(ctx, "udp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.ListenPacket(ctx, "udp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.DialTCP(ctx, "tcp4", "", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.ListenTCP(ctx, "tcp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.DialUDP(ctx, "udp4", "", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.ListenUDP(ctx, "udp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.ListenPacketConfig(ctx, config, "udp4", "192.0.2.1:1") },
		func() (io.Closer, error) { return outbound.ListenUDPConfig(ctx, config, "udp4", "192.0.2.1:1") },
	}
	for index, operation := range operations {
		resource, operationErr := operation()
		if operationErr != nil {
			t.Fatalf("operation %d: %v", index, operationErr)
		}
		if resource == nil {
			t.Fatalf("operation %d returned nil resource", index)
		}
		if operationErr = resource.Close(); operationErr != nil {
			t.Fatalf("close operation %d: %v", index, operationErr)
		}
	}
	if got := base.callCount(); got != len(operations) {
		t.Fatalf("base calls = %d, want %d", got, len(operations))
	}
	tracked, released := registry.counts()
	if tracked != len(operations) || released != len(operations) {
		t.Fatalf("registry counts = tracked %d, released %d", tracked, released)
	}
	for index, closer := range registry.closersSnapshot() {
		if _, ok := closer.(*trackedCloser); !ok {
			t.Fatalf("tracked resource %d has type %T, want shared trackedCloser", index, closer)
		}
	}
}

func TestN05N08OutboundTracksAcceptedConnections(t *testing.T) {
	t.Parallel()
	base := &recordingNetwork{}
	provider := dns.NewResolverProvider(&recordingResolver{}, time.Minute, nil)
	t.Cleanup(func() { _ = provider.Close() })
	registry := &testRegistry{}
	outbound, err := NewOutbound(base, provider, func() error { return nil }, registry.track)
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	listener, err := outbound.Listen(context.Background(), "tcp4", "192.0.2.1:1")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	tracked, _ := registry.counts()
	if tracked != 2 {
		t.Fatalf("tracked resources after accept = %d, want 2", tracked)
	}
	_ = accepted.Close()
	_ = listener.Close()

	tcpListener, err := outbound.ListenTCP(context.Background(), "tcp4", "192.0.2.1:1")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	acceptedTCP, err := tcpListener.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP: %v", err)
	}
	_ = acceptedTCP.Close()
	_ = tcpListener.Close()
}

func TestTrackedResourceAndCallerShareOneConcurrentClose(t *testing.T) {
	t.Parallel()
	raw := &blockingCloseConn{started: make(chan struct{}), unblock: make(chan struct{})}
	var registered io.Closer
	connection, err := trackConn(func(closer io.Closer) (func(), error) {
		registered = closer
		return func() {}, nil
	}, raw)
	if err != nil {
		t.Fatalf("trackConn() error = %v", err)
	}
	callerResult := make(chan error, 1)
	ownerResult := make(chan error, 1)
	go func() { callerResult <- connection.Close() }()
	<-raw.started
	go func() { ownerResult <- registered.Close() }()
	select {
	case err := <-ownerResult:
		t.Fatalf("owner Close() returned before the shared close completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(raw.unblock)
	if err := <-callerResult; err != nil {
		t.Fatalf("caller Close() error = %v", err)
	}
	if err := <-ownerResult; err != nil {
		t.Fatalf("owner Close() error = %v", err)
	}
	if raw.calls != 1 {
		t.Fatalf("raw Close() calls = %d, want 1", raw.calls)
	}
}

func TestN13N16EveryResolverMethodUsesOutDNS(t *testing.T) {
	t.Parallel()
	resolver := &recordingResolver{}
	provider := dns.NewResolverProvider(resolver, time.Minute, nil)
	t.Cleanup(func() { _ = provider.Close() })
	outbound, err := NewOutbound(&recordingNetwork{}, provider, func() error { return nil }, (&testRegistry{}).track)
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	ctx := context.Background()
	if _, err = outbound.LookupIP(ctx, "ip4", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupIPAddr(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupNetIP(ctx, "ip6", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupHost(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupAddr(ctx, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupCNAME(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupPort(ctx, "tcp", "443"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupTXT(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupMX(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = outbound.LookupNS(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = outbound.LookupSRV(ctx, "service", "tcp", "example.test"); err != nil {
		t.Fatal(err)
	}
	if resolver.callCount() < 10 {
		t.Fatalf("OutDNS resolver calls = %d, want at least 10", resolver.callCount())
	}
}

func TestOutResolverBuildsCanonicalReverseNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		address string
		want    string
	}{
		{address: "192.0.2.1", want: "1.2.0.192.in-addr.arpa."},
		{address: "2001:db8::1", want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
	}
	for _, test := range tests {
		got, err := reverseName(test.address)
		if err != nil || got != test.want {
			t.Fatalf("reverseName(%q) = %q, %v, want %q", test.address, got, err, test.want)
		}
	}
	if _, err := reverseName("::ffff:192.0.2.1"); err == nil {
		t.Fatal("mapped address reverse succeeded")
	}
}

func TestN29N32OutboundRejectsBypassAfterCloseAndUnsupportedOperations(t *testing.T) {
	t.Parallel()
	closed := false
	closedErr := errors.New("system is closing")
	provider := dns.NewResolverProvider(&recordingResolver{}, time.Minute, nil)
	t.Cleanup(func() { _ = provider.Close() })
	base := &recordingNetwork{}
	outbound, err := NewOutbound(base, provider, func() error {
		if closed {
			return closedErr
		}
		return nil
	}, (&testRegistry{}).track)
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	if outbound.IsNative() {
		t.Fatal("OutNet reports native")
	}
	if _, err = outbound.ListenMulticastUDP(context.Background(), "udp4", "224.0.0.1:1", gonnect.MulticastOptions{}); !errors.Is(err, gonnect.ErrUnsupported) {
		t.Fatalf("multicast error = %v, want unsupported", err)
	}
	closed = true
	if _, err = outbound.Dial(context.Background(), "tcp4", "192.0.2.1:1"); !errors.Is(err, closedErr) {
		t.Fatalf("closed dial error = %v", err)
	}
	if _, err = outbound.LookupHost(context.Background(), "example.test"); !errors.Is(err, closedErr) {
		t.Fatalf("closed lookup error = %v", err)
	}
	if got := base.callCount(); got != 0 {
		t.Fatalf("closed wrapper made %d base calls", got)
	}
}

func TestN09N12BoundNetworkRejectsAmbiguousMappedAndRawRequests(t *testing.T) {
	t.Parallel()
	binder, err := NewBinder(&fakePaths{snapshot: underlaySnapshotForTests()})
	if err != nil {
		t.Fatal(err)
	}
	network, err := NewBoundNetwork(binder, &fakePaths{snapshot: underlaySnapshotForTests()}, Families{IPv4: true, IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = network.ListenUDP(ctx, "udp", ":0"); !errors.Is(err, ErrAmbiguousSocketFamily) {
		t.Fatalf("ambiguous wildcard error = %v", err)
	}
	if _, err = network.DialUDP(ctx, "udp6", "", "[::ffff:192.0.2.1]:53"); err == nil {
		t.Fatal("mapped IPv4 address succeeded")
	}
	if _, err = network.Dial(ctx, "ip4:icmp", "192.0.2.1:0"); !errors.Is(err, ErrUnsupportedSocketNetwork) {
		t.Fatalf("raw error = %v", err)
	}
}

func TestBoundNetworkRejectsMulticastAtDialAndPacketWrite(t *testing.T) {
	t.Parallel()
	paths := &fakePaths{snapshot: underlaySnapshotForTests()}
	binder, err := NewBinder(paths)
	if err != nil {
		t.Fatal(err)
	}
	network, err := NewBoundNetwork(binder, paths, Families{IPv4: true, IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dials := []struct {
		name string
		run  func() error
	}{
		{name: "generic IPv4", run: func() error { _, err := network.Dial(ctx, "udp4", "239.1.2.3:1234"); return err }},
		{name: "packet IPv6", run: func() error { _, err := network.PacketDial(ctx, "udp6", "[ff0e::1234]:1234"); return err }},
		{name: "TCP IPv4", run: func() error { _, err := network.DialTCP(ctx, "tcp4", "", "239.1.2.3:1234"); return err }},
		{name: "UDP IPv6", run: func() error { _, err := network.DialUDP(ctx, "udp6", "", "[ff0e::1234]:1234"); return err }},
	}
	for _, test := range dials {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, gonnect.ErrUnsupported) || !errors.Is(err, ErrUnsupportedSocketNetwork) {
				t.Fatalf("multicast dial error = %v, want unsupported socket network", err)
			}
		})
	}

	connection := &policyUDPConn{UDPConn: &stubUDPConn{}}
	ipv4 := &net.UDPAddr{IP: net.IPv4(239, 1, 2, 3), Port: 1234}
	ipv6 := &net.UDPAddr{IP: net.ParseIP("ff0e::1234"), Port: 1234}
	writes := []struct {
		name string
		run  func() error
	}{
		{name: "WriteTo IPv4", run: func() error { _, err := connection.WriteTo(nil, ipv4); return err }},
		{name: "WriteToUDP IPv6", run: func() error { _, err := connection.WriteToUDP(nil, ipv6); return err }},
		{name: "WriteToUDPAddrPort IPv4", run: func() error {
			_, err := connection.WriteToUDPAddrPort(nil, netip.MustParseAddrPort("239.1.2.3:1234"))
			return err
		}},
		{name: "WriteMsgUDP IPv6", run: func() error { _, _, err := connection.WriteMsgUDP(nil, nil, ipv6); return err }},
		{name: "WriteMsgUDPAddrPort IPv6", run: func() error {
			_, _, err := connection.WriteMsgUDPAddrPort(nil, nil, netip.MustParseAddrPort("[ff0e::1234]:1234"))
			return err
		}},
	}
	for _, test := range writes {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, gonnect.ErrUnsupported) || !errors.Is(err, ErrUnsupportedSocketNetwork) {
				t.Fatalf("multicast write error = %v, want unsupported socket network", err)
			}
		})
	}
	if _, err := connection.WriteToUDPAddrPort([]byte("ok"), netip.MustParseAddrPort("192.0.2.1:1234")); err != nil {
		t.Fatalf("unicast write error = %v", err)
	}
}

func FuzzSocketEndpoint(f *testing.F) {
	f.Add("udp4", "192.0.2.1:53", false)
	f.Add("udp6", "[2001:db8::1]:53", false)
	f.Add("udp4", "239.1.2.3:53", false)
	f.Add("udp6", "[ff0e::1234]:53", false)
	f.Add("ip4:icmp", "192.0.2.1:0", false)
	f.Fuzz(func(t *testing.T, network, endpoint string, wildcard bool) {
		_, _, _, _ = socketEndpoint(network, endpoint, wildcard)
	})
}

func TestBoundNetworkRejectsDisabledFamilyBeforeSocketCreation(t *testing.T) {
	t.Parallel()
	paths := &fakePaths{snapshot: underlay.Snapshot{IPv4: pathPointer(underlay.Path{
		InterfaceIndex: 41,
		InterfaceName:  "test IPv4",
		Source:         netip.MustParseAddr("127.0.0.1"),
	})}}
	options := &fakeOptions{}
	network, err := NewBoundNetwork(&Binder{paths: paths, options: options}, paths, Families{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	config := &gonnect.ListenConfig{Control: func(string, string, syscall.RawConn) error {
		t.Fatal("disabled-family caller control ran")
		return nil
	}}
	operations := []struct {
		name string
		run  func() (io.Closer, error)
	}{
		{name: "generic dial", run: func() (io.Closer, error) { return network.Dial(ctx, "tcp4", "127.0.0.1:1") }},
		{name: "generic listen", run: func() (io.Closer, error) { return network.Listen(ctx, "tcp4", "127.0.0.1:0") }},
		{name: "packet dial", run: func() (io.Closer, error) { return network.PacketDial(ctx, "udp4", "127.0.0.1:1") }},
		{name: "packet listen", run: func() (io.Closer, error) { return network.ListenPacket(ctx, "udp4", "127.0.0.1:0") }},
		{name: "TCP dial", run: func() (io.Closer, error) { return network.DialTCP(ctx, "tcp4", "", "127.0.0.1:1") }},
		{name: "TCP listen", run: func() (io.Closer, error) { return network.ListenTCP(ctx, "tcp4", "127.0.0.1:0") }},
		{name: "UDP dial", run: func() (io.Closer, error) { return network.DialUDP(ctx, "udp4", "", "127.0.0.1:1") }},
		{name: "UDP listen", run: func() (io.Closer, error) { return network.ListenUDP(ctx, "udp4", "127.0.0.1:0") }},
		{name: "configured packet listen", run: func() (io.Closer, error) {
			return network.ListenPacketConfig(ctx, config, "udp4", "127.0.0.1:0")
		}},
		{name: "configured UDP listen", run: func() (io.Closer, error) {
			return network.ListenUDPConfig(ctx, config, "udp4", "127.0.0.1:0")
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			resource, operationErr := operation.run()
			if resource != nil && !reflect.ValueOf(resource).IsNil() {
				_ = resource.Close()
				t.Fatal("disabled-family operation created a socket")
			}
			if !errors.Is(operationErr, gonnect.ErrUnsupported) {
				t.Fatalf("error = %v, want unsupported", operationErr)
			}
		})
	}
	if calls := options.calls(); len(calls) != 0 {
		t.Fatalf("disabled-family operations accessed socket options: %v", calls)
	}
}

func underlaySnapshotForTests() underlay.Snapshot {
	return underlay.Snapshot{IPv4: pathPointer(testPath(4, 41)), IPv6: pathPointer(testPath(6, 61))}
}

type testRegistry struct {
	mu                sync.Mutex
	tracked, released int
	closers           []io.Closer
}

func (r *testRegistry) track(closer io.Closer) (func(), error) {
	r.mu.Lock()
	r.tracked++
	r.closers = append(r.closers, closer)
	r.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); r.released++; r.mu.Unlock() }) }, nil
}

func (r *testRegistry) closersSnapshot() []io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]io.Closer(nil), r.closers...)
}

func (r *testRegistry) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tracked, r.released
}

type recordingNetwork struct {
	gonnect.RejectNetwork
	mu    sync.Mutex
	calls int
}

func (n *recordingNetwork) called()        { n.mu.Lock(); n.calls++; n.mu.Unlock() }
func (n *recordingNetwork) callCount() int { n.mu.Lock(); defer n.mu.Unlock(); return n.calls }
func (n *recordingNetwork) Dial(context.Context, string, string) (net.Conn, error) {
	n.called()
	return &stubConn{}, nil
}
func (n *recordingNetwork) Listen(context.Context, string, string) (net.Listener, error) {
	n.called()
	return &stubListener{}, nil
}
func (n *recordingNetwork) PacketDial(context.Context, string, string) (gonnect.PacketConn, error) {
	n.called()
	return &stubPacketConn{}, nil
}
func (n *recordingNetwork) ListenPacket(context.Context, string, string) (gonnect.PacketConn, error) {
	n.called()
	return &stubPacketConn{}, nil
}
func (n *recordingNetwork) DialTCP(context.Context, string, string, string) (gonnect.TCPConn, error) {
	n.called()
	return &stubTCPConn{}, nil
}
func (n *recordingNetwork) ListenTCP(context.Context, string, string) (gonnect.TCPListener, error) {
	n.called()
	return &stubListener{}, nil
}
func (n *recordingNetwork) DialUDP(context.Context, string, string, string) (gonnect.UDPConn, error) {
	n.called()
	return &stubUDPConn{}, nil
}
func (n *recordingNetwork) ListenUDP(context.Context, string, string) (gonnect.UDPConn, error) {
	n.called()
	return &stubUDPConn{}, nil
}
func (n *recordingNetwork) ListenPacketConfig(context.Context, *gonnect.ListenConfig, string, string) (gonnect.PacketConn, error) {
	n.called()
	return &stubPacketConn{}, nil
}
func (n *recordingNetwork) ListenUDPConfig(context.Context, *gonnect.ListenConfig, string, string) (gonnect.UDPConn, error) {
	n.called()
	return &stubUDPConn{}, nil
}

type stubAddr string

func (a stubAddr) Network() string { return "stub" }
func (a stubAddr) String() string  { return string(a) }

type stubConn struct{}

func (*stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*stubConn) Close() error                     { return nil }
func (*stubConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (*stubConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (*stubConn) SetDeadline(time.Time) error      { return nil }
func (*stubConn) SetReadDeadline(time.Time) error  { return nil }
func (*stubConn) SetWriteDeadline(time.Time) error { return nil }

type blockingCloseConn struct {
	stubConn
	started chan struct{}
	unblock chan struct{}
	calls   int
}

func (c *blockingCloseConn) Close() error {
	c.calls++
	close(c.started)
	<-c.unblock
	return nil
}

type stubPacketConn struct{ stubConn }

func (*stubPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (*stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

type stubUDPConn struct{ stubPacketConn }

func (*stubUDPConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) { return 0, nil, io.EOF }
func (*stubUDPConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (*stubUDPConn) WriteToUDP(p []byte, _ *net.UDPAddr) (int, error) { return len(p), nil }
func (*stubUDPConn) WriteToUDPAddrPort(p []byte, _ netip.AddrPort) (int, error) {
	return len(p), nil
}
func (*stubUDPConn) ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error) {
	return 0, 0, 0, nil, io.EOF
}
func (*stubUDPConn) ReadMsgUDPAddrPort([]byte, []byte) (int, int, int, netip.AddrPort, error) {
	return 0, 0, 0, netip.AddrPort{}, io.EOF
}
func (*stubUDPConn) WriteMsgUDP(p, _ []byte, _ *net.UDPAddr) (int, int, error) {
	return len(p), 0, nil
}
func (*stubUDPConn) WriteMsgUDPAddrPort(p, _ []byte, _ netip.AddrPort) (int, int, error) {
	return len(p), 0, nil
}

type stubTCPConn struct{ stubConn }

func (*stubTCPConn) ReadFrom(io.Reader) (int64, error)            { return 0, nil }
func (*stubTCPConn) WriteTo(io.Writer) (int64, error)             { return 0, nil }
func (*stubTCPConn) SetKeepAlive(bool) error                      { return nil }
func (*stubTCPConn) SetKeepAliveConfig(net.KeepAliveConfig) error { return nil }
func (*stubTCPConn) SetKeepAlivePeriod(time.Duration) error       { return nil }
func (*stubTCPConn) SetLinger(int) error                          { return nil }
func (*stubTCPConn) SetNoDelay(bool) error                        { return nil }
func (*stubTCPConn) CloseRead() error                             { return nil }
func (*stubTCPConn) CloseWrite() error                            { return nil }

type stubListener struct{}

func (*stubListener) Accept() (net.Conn, error)           { return &stubConn{}, nil }
func (*stubListener) AcceptTCP() (gonnect.TCPConn, error) { return &stubTCPConn{}, nil }
func (*stubListener) Close() error                        { return nil }
func (*stubListener) Addr() net.Addr                      { return stubAddr("listener") }
func (*stubListener) SetDeadline(time.Time) error         { return nil }

type recordingResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *recordingResolver) called()        { r.mu.Lock(); r.calls++; r.mu.Unlock() }
func (r *recordingResolver) callCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }
func (r *recordingResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	r.called()
	return []net.IP{net.IPv4(192, 0, 2, 1), net.ParseIP("2001:db8::1")}, nil
}
func (r *recordingResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.called()
	return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 1)}}, nil
}
func (r *recordingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.called()
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (r *recordingResolver) LookupHost(context.Context, string) ([]string, error) {
	r.called()
	return []string{"192.0.2.1"}, nil
}
func (r *recordingResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.called()
	return []string{"example.test."}, nil
}
func (r *recordingResolver) LookupCNAME(context.Context, string) (string, error) {
	r.called()
	return "example.test.", nil
}
func (r *recordingResolver) LookupPort(context.Context, string, string) (int, error) {
	r.called()
	return 443, nil
}
func (r *recordingResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.called()
	return []string{"text"}, nil
}
func (r *recordingResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	r.called()
	return []*net.MX{{Host: "mail.example.test.", Pref: 10}}, nil
}
func (r *recordingResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	r.called()
	return []*net.NS{{Host: "ns.example.test."}}, nil
}
func (r *recordingResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	r.called()
	return "example.test.", []*net.SRV{{Target: "service.example.test.", Port: 443}}, nil
}
