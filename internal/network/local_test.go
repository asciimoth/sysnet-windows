package network

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

const (
	localChildModeEnv = "SYSNET_LOCAL_CHILD_MODE"
	localChildAddrEnv = "SYSNET_LOCAL_CHILD_ADDR"
)

func TestN25N28NativeLocalNetSecondProcessAndExternalProbe(t *testing.T) {
	if mode := os.Getenv(localChildModeEnv); mode != "" {
		runLocalProbeChild(t, mode, os.Getenv(localChildAddrEnv))
		return
	}
	native := gonnect.NativeConfig{}.Build()
	registry := &testRegistry{}
	local, err := NewLocal(native, native, Families{IPv4: true, IPv6: true}, func() error { return nil }, registry.track)
	if err != nil {
		t.Fatal(err)
	}

	tcpListener, err := local.ListenTCP(context.Background(), "tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcpListener.Close() }()
	if err = tcpListener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	assertLoopbackEndpoint(t, tcpListener.Addr())
	tcpCommand := localProbeCommand(t, "tcp", tcpListener.Addr().String())
	var tcpOutput bytes.Buffer
	tcpCommand.Stdout = &tcpOutput
	tcpCommand.Stderr = &tcpOutput
	if err = tcpCommand.Start(); err != nil {
		t.Fatal(err)
	}
	tcpConnection, err := tcpListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	assertLoopbackEndpoint(t, tcpConnection.RemoteAddr())
	buffer := make([]byte, len("tcp-child"))
	if _, err = io.ReadFull(tcpConnection, buffer); err != nil {
		t.Fatal(err)
	}
	if _, err = tcpConnection.Write(buffer); err != nil {
		t.Fatal(err)
	}
	_ = tcpConnection.Close()
	if waitErr := tcpCommand.Wait(); waitErr != nil {
		t.Fatalf("TCP child: %v\n%s", waitErr, tcpOutput.Bytes())
	}

	udpListener, err := local.ListenUDP(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpListener.Close() }()
	if err = udpListener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	assertLoopbackEndpoint(t, udpListener.LocalAddr())
	udpCommand := localProbeCommand(t, "udp", udpListener.LocalAddr().String())
	var udpOutput bytes.Buffer
	udpCommand.Stdout = &udpOutput
	udpCommand.Stderr = &udpOutput
	if err = udpCommand.Start(); err != nil {
		t.Fatal(err)
	}
	udpBuffer := make([]byte, len("udp-child"))
	length, peer, err := udpListener.ReadFromUDP(udpBuffer)
	if err != nil {
		t.Fatal(err)
	}
	assertLoopbackEndpoint(t, peer)
	if _, err = udpListener.WriteToUDP(udpBuffer[:length], peer); err != nil {
		t.Fatal(err)
	}
	if waitErr := udpCommand.Wait(); waitErr != nil {
		t.Fatalf("UDP child: %v\n%s", waitErr, udpOutput.Bytes())
	}

	if external := firstNonLoopbackIPv4(t); external != nil {
		_, port, splitErr := net.SplitHostPort(tcpListener.Addr().String())
		if splitErr != nil {
			t.Fatal(splitErr)
		}
		probe := localProbeCommand(t, "reject", net.JoinHostPort(external.String(), port))
		if output, probeErr := probe.CombinedOutput(); probeErr != nil {
			t.Fatalf("external probe: %v\n%s", probeErr, output)
		}
	}

	tracked, _ := registry.counts()
	if tracked < 3 {
		t.Fatalf("tracked resources = %d, want listeners and accepted TCP connection", tracked)
	}
}

func localProbeCommand(t *testing.T, mode, address string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestN25N28NativeLocalNetSecondProcessAndExternalProbe$")
	command.Env = append(os.Environ(), localChildModeEnv+"="+mode, localChildAddrEnv+"="+address)
	return command
}

func runLocalProbeChild(t *testing.T, mode, address string) {
	t.Helper()
	if mode == "reject" {
		connection, err := net.DialTimeout("tcp4", address, 500*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Fatalf("non-loopback probe reached loopback listener at %s", address)
		}
		return
	}
	connection, err := net.DialTimeout(mode+"4", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err = connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(mode + "-child")
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply = %q, want %q", reply, payload)
	}
}

func assertLoopbackEndpoint(t *testing.T, endpoint net.Addr) {
	t.Helper()
	host, _, err := net.SplitHostPort(endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || address.IsUnspecified() {
		t.Fatalf("endpoint = %q, want concrete loopback", endpoint)
	}
}

func firstNonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range addresses {
		prefix, parseErr := netip.ParsePrefix(raw.String())
		if parseErr != nil {
			continue
		}
		address := prefix.Addr()
		if address.Is4() && !address.IsLoopback() && !address.IsUnspecified() {
			return net.IP(address.AsSlice())
		}
	}
	return nil
}

func TestN25N28LocalNetNormalizesAndTracksEverySocketEntryPoint(t *testing.T) {
	t.Parallel()
	base := &localRecordingNetwork{}
	resolver := &localResolver{answers: map[string][]netip.Addr{
		"localhost":  {netip.MustParseAddr("127.0.0.1")},
		"localhost6": {netip.IPv6Loopback()},
	}}
	registry := &testRegistry{}
	local, err := NewLocal(base, resolver, Families{IPv4: true, IPv6: true}, func() error { return nil }, registry.track)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	ctx := context.Background()
	resources := []interface{ Close() error }{}
	add := func(resource interface{ Close() error }, operationErr error) {
		t.Helper()
		if operationErr != nil {
			t.Fatalf("local operation: %v", operationErr)
		}
		resources = append(resources, resource)
	}
	connection, operationErr := local.Dial(ctx, "tcp", "localhost:80")
	add(connection, operationErr)
	connection, operationErr = local.Dial(ctx, "udp", "localhost:53")
	add(connection, operationErr)
	listener, operationErr := local.Listen(ctx, "tcp", ":0")
	add(listener, operationErr)
	packet, operationErr := local.PacketDial(ctx, "udp", "localhost:53")
	add(packet, operationErr)
	packetListener, operationErr := local.ListenPacket(ctx, "udp6", "[::]:0")
	add(packetListener, operationErr)
	packetListener, operationErr = local.ListenPacketConfig(ctx, &gonnect.ListenConfig{}, "udp4", ":0")
	add(packetListener, operationErr)
	tcp, operationErr := local.DialTCP(ctx, "tcp4", "", "localhost:80")
	add(tcp, operationErr)
	tcp, operationErr = local.DialTCP(ctx, "tcp6", "", "localhost6:80")
	add(tcp, operationErr)
	tcpListener, operationErr := local.ListenTCP(ctx, "tcp6", "[::]:0")
	add(tcpListener, operationErr)
	udp, operationErr := local.DialUDP(ctx, "udp4", "", "localhost:53")
	add(udp, operationErr)
	udp, operationErr = local.ListenUDP(ctx, "udp6", "[::]:0")
	add(udp, operationErr)
	udpListener, operationErr := local.ListenUDPConfig(ctx, &gonnect.ListenConfig{}, "udp", ":0")
	add(udpListener, operationErr)

	for _, resource := range resources {
		if closeErr := resource.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	}
	calls := base.snapshot()
	if len(calls) != len(resources) {
		t.Fatalf("base calls = %d, want %d", len(calls), len(resources))
	}
	for _, call := range calls {
		for _, endpoint := range call.endpoints {
			if endpoint == "" {
				continue
			}
			host, _, splitErr := net.SplitHostPort(endpoint)
			if splitErr != nil {
				t.Fatalf("%s endpoint %q: %v", call.method, endpoint, splitErr)
			}
			address, parseErr := netip.ParseAddr(host)
			if parseErr != nil || !address.IsLoopback() || address.IsUnspecified() {
				t.Fatalf("%s endpoint = %q, want concrete loopback", call.method, endpoint)
			}
		}
	}
	tracked, released := registry.counts()
	if tracked != len(resources) || released != len(resources) {
		t.Fatalf("registry = tracked %d, released %d; want %d each", tracked, released, len(resources))
	}
}

func TestN25LocalNetTracksAcceptedPeerOrientedConnection(t *testing.T) {
	t.Parallel()
	base := &localRecordingNetwork{}
	registry := &testRegistry{}
	local, err := NewLocal(base, &localResolver{}, Families{IPv4: true}, func() error { return nil }, registry.track)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := local.Listen(context.Background(), "tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := connection.RemoteAddr().String(); got != "remote" {
		t.Fatalf("accepted RemoteAddr = %q, want peer address", got)
	}
	tracked, _ := registry.counts()
	if tracked != 2 {
		t.Fatalf("tracked resources = %d, want listener and accepted connection", tracked)
	}
	_ = connection.Close()
	_ = listener.Close()
}

func TestN26N28LocalNetRejectsNonlocalAndPoisonedResolutionBeforeSocketCreation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		resolver *localResolver
		call     func(*Local) error
	}{
		{
			name:     "nonlocal literal",
			resolver: &localResolver{},
			call: func(local *Local) error {
				_, err := local.Dial(context.Background(), "tcp4", "192.0.2.1:80")
				return err
			},
		},
		{
			name:     "nonlocal listener",
			resolver: &localResolver{},
			call: func(local *Local) error {
				_, err := local.ListenUDP(context.Background(), "udp4", "192.0.2.1:0")
				return err
			},
		},
		{
			name: "poisoned name",
			resolver: &localResolver{answers: map[string][]netip.Addr{
				"localhost": {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")},
			}},
			call: func(local *Local) error {
				_, err := local.Dial(context.Background(), "tcp", "localhost:80")
				return err
			},
		},
		{
			name:     "mapped address",
			resolver: &localResolver{},
			call: func(local *Local) error {
				_, err := local.Dial(context.Background(), "tcp6", "[::ffff:127.0.0.1]:80")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			base := &localRecordingNetwork{}
			local, err := NewLocal(base, test.resolver, Families{IPv4: true, IPv6: true}, func() error { return nil }, (&testRegistry{}).track)
			if err != nil {
				t.Fatal(err)
			}
			if err = test.call(local); !errors.Is(err, ErrNonLoopbackAddress) {
				t.Fatalf("operation error = %v, want ErrNonLoopbackAddress", err)
			}
			if calls := base.snapshot(); len(calls) != 0 {
				t.Fatalf("rejected operation made %d socket calls", len(calls))
			}
		})
	}
}

func TestN27LocalNetResolutionFamiliesInterfacesAndLifecycle(t *testing.T) {
	t.Parallel()
	closedErr := errors.New("system is closing")
	closed := false
	base := &localRecordingNetwork{}
	resolver := &localResolver{answers: map[string][]netip.Addr{
		"localhost": {netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()},
	}}
	local, err := NewLocal(base, resolver, Families{IPv4: true}, func() error {
		if closed {
			return closedErr
		}
		return nil
	}, (&testRegistry{}).track)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := local.LookupNetIP(context.Background(), "ip", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("IPv4-only lookup = %v", addresses)
	}
	interfaces, err := local.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Flags()&net.FlagLoopback == 0 {
		t.Fatalf("LocalNet interfaces = %v, want only loopback", interfaces)
	}
	interfaceAddresses, err := local.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaceAddresses) != 1 || !localInterfaceAddr(interfaceAddresses[0], true, false) {
		t.Fatalf("LocalNet interface addresses = %v, want IPv4 loopback only", interfaceAddresses)
	}
	closed = true
	if _, err = local.LookupHost(context.Background(), "localhost"); !errors.Is(err, closedErr) {
		t.Fatalf("lookup after close error = %v", err)
	}
	if _, err = local.Listen(context.Background(), "tcp4", ":0"); !errors.Is(err, closedErr) {
		t.Fatalf("listen after close error = %v", err)
	}
	if local.IsNative() {
		t.Fatal("LocalNet reports native")
	}
}

type localCall struct {
	method    string
	network   string
	endpoints []string
}

type localRecordingNetwork struct {
	gonnect.RejectNetwork
	mu    sync.Mutex
	calls []localCall
}

func (n *localRecordingNetwork) record(method, network string, endpoints ...string) {
	n.mu.Lock()
	n.calls = append(n.calls, localCall{method: method, network: network, endpoints: endpoints})
	n.mu.Unlock()
}

func (n *localRecordingNetwork) snapshot() []localCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]localCall(nil), n.calls...)
}

func (n *localRecordingNetwork) Dial(_ context.Context, network, address string) (net.Conn, error) {
	n.record("Dial", network, address)
	return &stubConn{}, nil
}

func (n *localRecordingNetwork) Listen(_ context.Context, network, address string) (net.Listener, error) {
	n.record("Listen", network, address)
	return &stubListener{}, nil
}

func (n *localRecordingNetwork) PacketDial(_ context.Context, network, address string) (gonnect.PacketConn, error) {
	n.record("PacketDial", network, address)
	return &stubPacketConn{}, nil
}

func (n *localRecordingNetwork) ListenPacketConfig(_ context.Context, _ *gonnect.ListenConfig, network, address string) (gonnect.PacketConn, error) {
	n.record("ListenPacketConfig", network, address)
	return &stubPacketConn{}, nil
}

func (n *localRecordingNetwork) DialTCP(_ context.Context, network, laddr, raddr string) (gonnect.TCPConn, error) {
	n.record("DialTCP", network, laddr, raddr)
	return &stubTCPConn{}, nil
}

func (n *localRecordingNetwork) ListenTCP(_ context.Context, network, laddr string) (gonnect.TCPListener, error) {
	n.record("ListenTCP", network, laddr)
	return &stubListener{}, nil
}

func (n *localRecordingNetwork) DialUDP(_ context.Context, network, laddr, raddr string) (gonnect.UDPConn, error) {
	n.record("DialUDP", network, laddr, raddr)
	return &stubUDPConn{}, nil
}

func (n *localRecordingNetwork) ListenUDPConfig(_ context.Context, _ *gonnect.ListenConfig, network, laddr string) (gonnect.UDPConn, error) {
	n.record("ListenUDPConfig", network, laddr)
	return &stubUDPConn{}, nil
}

func (*localRecordingNetwork) Interfaces() ([]gonnect.NetworkInterface, error) {
	return []gonnect.NetworkInterface{
		&gonnect.LiteralInterface{
			IDVal: "loopback", IndexVal: 1, NameVal: "loopback", FlagsVal: net.FlagLoopback | net.FlagUp,
			AddrsVal: []net.Addr{
				&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
				&net.IPNet{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
			},
		},
		&gonnect.LiteralInterface{
			IDVal: "ethernet", IndexVal: 2, NameVal: "ethernet", FlagsVal: net.FlagUp,
			AddrsVal: []net.Addr{&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)}},
		},
	}, nil
}

type localResolver struct {
	gonnect.RejectNetwork
	answers map[string][]netip.Addr
}

func (r *localResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	addresses := r.answers[host]
	if len(addresses) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if network == "ip4" && !address.Is4() || network == "ip6" && !address.Is6() {
			continue
		}
		result = append(result, address)
	}
	return result, nil
}
