package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
)

// Tracker registers a live socket or listener for owner-driven cleanup. The
// returned function transfers cleanup responsibility back to the caller after
// a successful Close.
type Tracker func(io.Closer) (release func(), err error)

// WorkCheck rejects a new operation after its owning System starts closing.
type WorkCheck func() error

// Outbound is a policy-enforcing gonnect network. It resolves all names through
// the supplied DNS interface and tracks every socket or listener returned to a
// caller. It is deliberately non-native: bypassing these methods would bypass
// binding, name resolution, and resource ownership.
type Outbound struct {
	network gonnect.Network
	check   WorkCheck
	track   Tracker
}

// NewOutbound constructs an outbound policy wrapper. base must already enforce
// the mandatory interface binding for every socket creation method.
func NewOutbound(base gonnect.Network, outDNS dns.Interface, check WorkCheck, track Tracker) (*Outbound, error) {
	if base == nil {
		return nil, errors.New("create outbound network with nil base network")
	}
	if outDNS == nil {
		return nil, errors.New("create outbound network with nil DNS interface")
	}
	if check == nil || track == nil {
		return nil, errors.New("create outbound network without lifecycle ownership")
	}
	resolver := &outResolver{Resolver: dns.NewResolver(outDNS)}
	return &Outbound{
		network: gonnect.NewNetworkWithResolver(base, resolver),
		check:   check,
		track:   track,
	}, nil
}

// outResolver corrects reverse lookup input for the DNS adapter. The selected
// gonnect adapter sends its LookupAddr argument as a PTR question name, so the
// network wrapper must convert the public IP-literal argument first.
type outResolver struct{ *dns.Resolver }

func (r *outResolver) LookupAddr(ctx context.Context, address string) ([]string, error) {
	reverse, err := reverseName(address)
	if err != nil {
		return nil, err
	}
	return r.Resolver.LookupAddr(ctx, reverse)
}

func reverseName(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return "", &net.DNSError{Err: "invalid address", Name: value}
	}
	if address.Is4() {
		bytes := address.As4()
		return strconv.Itoa(int(bytes[3])) + "." + strconv.Itoa(int(bytes[2])) + "." +
			strconv.Itoa(int(bytes[1])) + "." + strconv.Itoa(int(bytes[0])) + ".in-addr.arpa.", nil
	}
	bytes := address.As16()
	const hex = "0123456789abcdef"
	var result strings.Builder
	result.Grow(32*2 + len("ip6.arpa."))
	for index := len(bytes) - 1; index >= 0; index-- {
		result.WriteByte(hex[bytes[index]&0x0f])
		result.WriteByte('.')
		result.WriteByte(hex[bytes[index]>>4])
		result.WriteByte('.')
	}
	result.WriteString("ip6.arpa.")
	return result.String(), nil
}

var _ gonnect.Network = (*Outbound)(nil)

func (*Outbound) IsNative() bool { return false }

func (n *Outbound) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return trackConn(n.track, connection)
}

func (n *Outbound) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	listener, err := n.network.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return trackListener(n.check, n.track, listener)
}

func (n *Outbound) PacketDial(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.PacketDial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return trackPacketConn(n.track, connection)
}

func (n *Outbound) ListenPacket(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return trackPacketConn(n.track, connection)
}

func (n *Outbound) DialTCP(ctx context.Context, network, laddr, raddr string) (gonnect.TCPConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.DialTCP(ctx, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return trackTCPConn(n.track, connection)
}

func (n *Outbound) ListenTCP(ctx context.Context, network, laddr string) (gonnect.TCPListener, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	listener, err := n.network.ListenTCP(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return trackTCPListener(n.check, n.track, listener)
}

func (n *Outbound) DialUDP(ctx context.Context, network, laddr, raddr string) (gonnect.UDPConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.DialUDP(ctx, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return trackUDPConn(n.track, connection)
}

func (n *Outbound) ListenUDP(ctx context.Context, network, laddr string) (gonnect.UDPConn, error) {
	return n.ListenUDPConfig(ctx, nil, network, laddr)
}

func (n *Outbound) ListenPacketConfig(ctx context.Context, config *gonnect.ListenConfig, network, address string) (gonnect.PacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.ListenPacketConfig(ctx, config, network, address)
	if err != nil {
		return nil, err
	}
	return trackPacketConn(n.track, connection)
}

func (n *Outbound) ListenUDPConfig(ctx context.Context, config *gonnect.ListenConfig, network, laddr string) (gonnect.UDPConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	connection, err := n.network.ListenUDPConfig(ctx, config, network, laddr)
	if err != nil {
		return nil, err
	}
	return trackUDPConn(n.track, connection)
}

// ListenMulticastUDP is explicit because the initial bypass policy does not
// claim that Windows retains the selected unicast interface for multicast.
func (n *Outbound) ListenMulticastUDP(context.Context, string, string, gonnect.MulticastOptions) (gonnect.MulticastPacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("outbound multicast UDP is not supported"))
}

func (n *Outbound) Interfaces() ([]gonnect.NetworkInterface, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.Interfaces()
}

func (n *Outbound) InterfaceAddrs() ([]net.Addr, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.InterfaceAddrs()
}

func (n *Outbound) InterfaceMulticastAddrs() ([]net.Addr, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.InterfaceMulticastAddrs()
}

func (n *Outbound) InterfacesByIndex(index int) ([]gonnect.NetworkInterface, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.InterfacesByIndex(index)
}

func (n *Outbound) InterfacesByName(name string) ([]gonnect.NetworkInterface, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.InterfacesByName(name)
}

func (n *Outbound) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupIP(ctx, network, host)
}

func (n *Outbound) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupIPAddr(ctx, host)
}

func (n *Outbound) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupNetIP(ctx, network, host)
}

func (n *Outbound) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupHost(ctx, host)
}

func (n *Outbound) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupAddr(ctx, address)
}

func (n *Outbound) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err := n.check(); err != nil {
		return "", err
	}
	return n.network.LookupCNAME(ctx, host)
}

func (n *Outbound) LookupPort(ctx context.Context, network, service string) (int, error) {
	if err := n.check(); err != nil {
		return 0, err
	}
	return n.network.LookupPort(ctx, network, service)
}

func (n *Outbound) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupTXT(ctx, name)
}

func (n *Outbound) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupMX(ctx, name)
}

func (n *Outbound) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return n.network.LookupNS(ctx, name)
}

func (n *Outbound) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if err := n.check(); err != nil {
		return "", nil, err
	}
	return n.network.LookupSRV(ctx, service, proto, name)
}

type trackedCloser struct {
	once    sync.Once
	close   func() error
	release func()
	err     error
}

func (c *trackedCloser) Close() error {
	c.once.Do(func() {
		c.err = c.close()
		if c.err == nil {
			c.release()
		}
	})
	return c.err
}

type ownedConn struct {
	net.Conn
	*trackedCloser
}

func (c *ownedConn) Close() error { return c.trackedCloser.Close() }

type ownedPacketConn struct {
	gonnect.PacketConn
	*trackedCloser
}

func (c *ownedPacketConn) Close() error { return c.trackedCloser.Close() }

type ownedTCPConn struct {
	gonnect.TCPConn
	*trackedCloser
}

func (c *ownedTCPConn) Close() error { return c.trackedCloser.Close() }

type ownedUDPConn struct {
	gonnect.UDPConn
	*trackedCloser
}

func (c *ownedUDPConn) Close() error { return c.trackedCloser.Close() }

type ownedListener struct {
	net.Listener
	*trackedCloser
	check WorkCheck
	track Tracker
}

func (l *ownedListener) Close() error { return l.trackedCloser.Close() }

func (l *ownedListener) Accept() (net.Conn, error) {
	if err := l.check(); err != nil {
		return nil, err
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return trackConn(l.track, connection)
}

type ownedTCPListener struct {
	gonnect.TCPListener
	*trackedCloser
	check WorkCheck
	track Tracker
}

func (l *ownedTCPListener) Close() error { return l.trackedCloser.Close() }

func (l *ownedTCPListener) Accept() (net.Conn, error) {
	if err := l.check(); err != nil {
		return nil, err
	}
	connection, err := l.TCPListener.Accept()
	if err != nil {
		return nil, err
	}
	return trackConn(l.track, connection)
}

func (l *ownedTCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	if err := l.check(); err != nil {
		return nil, err
	}
	connection, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return trackTCPConn(l.track, connection)
}

func trackConn(track Tracker, connection net.Conn) (net.Conn, error) {
	closer := &trackedCloser{close: connection.Close}
	release, err := track(closer)
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	closer.release = release
	return &ownedConn{Conn: connection, trackedCloser: closer}, nil
}

func trackPacketConn(track Tracker, connection gonnect.PacketConn) (gonnect.PacketConn, error) {
	closer := &trackedCloser{close: connection.Close}
	release, err := track(closer)
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	closer.release = release
	return &ownedPacketConn{PacketConn: connection, trackedCloser: closer}, nil
}

func trackTCPConn(track Tracker, connection gonnect.TCPConn) (gonnect.TCPConn, error) {
	closer := &trackedCloser{close: connection.Close}
	release, err := track(closer)
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	closer.release = release
	return &ownedTCPConn{TCPConn: connection, trackedCloser: closer}, nil
}

func trackUDPConn(track Tracker, connection gonnect.UDPConn) (gonnect.UDPConn, error) {
	closer := &trackedCloser{close: connection.Close}
	release, err := track(closer)
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	closer.release = release
	return &ownedUDPConn{UDPConn: connection, trackedCloser: closer}, nil
}

func trackListener(check WorkCheck, track Tracker, listener net.Listener) (net.Listener, error) {
	closer := &trackedCloser{close: listener.Close}
	release, err := track(closer)
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	closer.release = release
	return &ownedListener{Listener: listener, trackedCloser: closer, check: check, track: track}, nil
}

func trackTCPListener(check WorkCheck, track Tracker, listener gonnect.TCPListener) (gonnect.TCPListener, error) {
	closer := &trackedCloser{close: listener.Close}
	release, err := track(closer)
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	closer.release = release
	return &ownedTCPListener{TCPListener: listener, trackedCloser: closer, check: check, track: track}, nil
}
