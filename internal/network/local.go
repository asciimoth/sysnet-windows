package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect"
)

var (
	// ErrNonLoopbackAddress reports an endpoint that would escape LocalNet.
	ErrNonLoopbackAddress = errors.New("address is outside loopback scope")
	// ErrLocalFamilyDisabled reports a loopback family disabled by SystemConfig.
	ErrLocalFamilyDisabled = errors.New("loopback address family is disabled")
)

// Local is a native-socket network confined to the IPv4 and IPv6 loopback
// scopes. It resolves a name before creating a socket and passes only a numeric
// loopback endpoint to base. All returned resources belong to the System.
//
// Local is separate from the private managed-DNS listener path. A DNS listener
// can later bind a TUN-owned non-loopback address without weakening this type's
// public loopback policy.
type Local struct {
	base     gonnect.Network
	resolver gonnect.Resolver
	check    WorkCheck
	track    Tracker
	allow4   bool
	allow6   bool
}

// NewLocal constructs a loopback-only network. base creates native sockets;
// resolver supplies host results which Local validates before socket creation.
func NewLocal(base gonnect.Network, resolver gonnect.Resolver, families Families, check WorkCheck, track Tracker) (*Local, error) {
	if base == nil || resolver == nil {
		return nil, errors.New("create local network without native network or resolver")
	}
	if check == nil || track == nil {
		return nil, errors.New("create local network without lifecycle ownership")
	}
	if !families.IPv4 && !families.IPv6 {
		return nil, errors.New("create local network without an enabled address family")
	}
	return &Local{
		base: base, resolver: resolver, check: check, track: track,
		allow4: families.IPv4, allow6: families.IPv6,
	}, nil
}

var _ gonnect.Network = (*Local)(nil)

// IsNative is false because direct native calls would bypass loopback
// validation and System resource ownership.
func (*Local) IsNative() bool { return false }

func (n *Local) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	transport, family, remote, err := n.remoteEndpoint(ctx, network, address, "")
	if err != nil {
		return nil, err
	}
	connection, err := n.base.Dial(ctx, familyNetworkName(transport, family), remote)
	if err != nil {
		return nil, err
	}
	return trackConn(n.track, connection)
}

func (n *Local) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	family, local, err := n.localEndpoint(ctx, network, address, "tcp", 0)
	if err != nil {
		return nil, err
	}
	listener, err := n.base.Listen(ctx, familyNetworkName("tcp", family), local)
	if err != nil {
		return nil, err
	}
	return trackListener(n.check, n.track, listener)
}

func (n *Local) PacketDial(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	_, family, remote, err := n.remoteEndpoint(ctx, network, address, "udp")
	if err != nil {
		return nil, err
	}
	connection, err := n.base.PacketDial(ctx, familyNetworkName("udp", family), remote)
	if err != nil {
		return nil, err
	}
	return trackPacketConn(n.track, connection)
}

func (n *Local) ListenPacket(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	return n.ListenPacketConfig(ctx, nil, network, address)
}

func (n *Local) DialTCP(ctx context.Context, network, laddr, raddr string) (gonnect.TCPConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	_, family, remote, err := n.remoteEndpoint(ctx, network, raddr, "tcp")
	if err != nil {
		return nil, err
	}
	_, local, err := n.localEndpoint(ctx, network, laddr, "tcp", family)
	if err != nil {
		return nil, err
	}
	connection, err := n.base.DialTCP(ctx, familyNetworkName("tcp", family), local, remote)
	if err != nil {
		return nil, err
	}
	return trackTCPConn(n.track, connection)
}

func (n *Local) ListenTCP(ctx context.Context, network, laddr string) (gonnect.TCPListener, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	family, local, err := n.localEndpoint(ctx, network, laddr, "tcp", 0)
	if err != nil {
		return nil, err
	}
	listener, err := n.base.ListenTCP(ctx, familyNetworkName("tcp", family), local)
	if err != nil {
		return nil, err
	}
	return trackTCPListener(n.check, n.track, listener)
}

func (n *Local) DialUDP(ctx context.Context, network, laddr, raddr string) (gonnect.UDPConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	_, family, remote, err := n.remoteEndpoint(ctx, network, raddr, "udp")
	if err != nil {
		return nil, err
	}
	_, local, err := n.localEndpoint(ctx, network, laddr, "udp", family)
	if err != nil {
		return nil, err
	}
	connection, err := n.base.DialUDP(ctx, familyNetworkName("udp", family), local, remote)
	if err != nil {
		return nil, err
	}
	return trackUDPConn(n.track, connection)
}

func (n *Local) ListenUDP(ctx context.Context, network, laddr string) (gonnect.UDPConn, error) {
	return n.ListenUDPConfig(ctx, nil, network, laddr)
}

func (n *Local) ListenPacketConfig(ctx context.Context, config *gonnect.ListenConfig, network, address string) (gonnect.PacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	family, local, err := n.localEndpoint(ctx, network, address, "udp", 0)
	if err != nil {
		return nil, err
	}
	connection, err := n.base.ListenPacketConfig(ctx, config, familyNetworkName("udp", family), local)
	if err != nil {
		return nil, err
	}
	return trackPacketConn(n.track, connection)
}

func (n *Local) ListenUDPConfig(ctx context.Context, config *gonnect.ListenConfig, network, laddr string) (gonnect.UDPConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	family, local, err := n.localEndpoint(ctx, network, laddr, "udp", 0)
	if err != nil {
		return nil, err
	}
	connection, err := n.base.ListenUDPConfig(ctx, config, familyNetworkName("udp", family), local)
	if err != nil {
		return nil, err
	}
	return trackUDPConn(n.track, connection)
}

func (n *Local) ListenMulticastUDP(context.Context, string, string, gonnect.MulticastOptions) (gonnect.MulticastPacketConn, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return nil, errors.Join(gonnect.ErrUnsupported, ErrUnsupportedSocketNetwork)
}

func (n *Local) remoteEndpoint(ctx context.Context, network, endpoint, wantTransport string) (string, Family, string, error) {
	transport, selected, err := socketNetwork(network)
	if err != nil {
		return "", 0, "", err
	}
	if wantTransport != "" && transport != wantTransport {
		return "", 0, "", net.UnknownNetworkError(network)
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, "", err
	}
	if host == "" {
		return "", 0, "", &net.AddrError{Err: "remote address is unspecified", Addr: endpoint}
	}
	addresses, err := n.lookupLoopback(ctx, selected, host)
	if err != nil {
		return "", 0, "", err
	}
	address := addresses[0]
	family := FamilyIPv6
	if address.Is4() {
		family = FamilyIPv4
	}
	return transport, family, net.JoinHostPort(address.String(), port), nil
}

// localEndpoint replaces every wildcard with a concrete loopback address. A
// preferred family is used for a typed dial so its source matches the remote.
func (n *Local) localEndpoint(ctx context.Context, network, endpoint, wantTransport string, preferred Family) (Family, string, error) {
	transport, selected, err := socketNetwork(network)
	if err != nil {
		return 0, "", err
	}
	if transport != wantTransport {
		return 0, "", net.UnknownNetworkError(network)
	}
	if preferred != 0 {
		if selected != 0 && selected != preferred {
			return 0, "", &net.AddrError{Err: "address family conflicts with remote endpoint", Addr: endpoint}
		}
		selected = preferred
	}
	if endpoint == "" {
		endpoint = ":0"
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, "", err
	}
	if host == "" {
		family, address, familyErr := n.defaultLoopback(selected)
		if familyErr != nil {
			return 0, "", familyErr
		}
		return family, net.JoinHostPort(address.String(), port), nil
	}
	if wildcard, parseErr := netip.ParseAddr(host); parseErr == nil && wildcard.IsUnspecified() {
		wildcardFamily := FamilyIPv6
		if wildcard.Is4() {
			wildcardFamily = FamilyIPv4
		}
		if selected != 0 && selected != wildcardFamily {
			return 0, "", &net.AddrError{Err: "address family conflicts with network", Addr: host}
		}
		family, address, familyErr := n.defaultLoopback(wildcardFamily)
		if familyErr != nil {
			return 0, "", familyErr
		}
		return family, net.JoinHostPort(address.String(), port), nil
	}
	addresses, err := n.lookupLoopback(ctx, selected, host)
	if err != nil {
		return 0, "", err
	}
	address := addresses[0]
	family := FamilyIPv6
	if address.Is4() {
		family = FamilyIPv4
	}
	return family, net.JoinHostPort(address.String(), port), nil
}

func (n *Local) defaultLoopback(selected Family) (Family, netip.Addr, error) {
	if selected == FamilyIPv4 || selected == 0 && n.allow4 {
		if !n.allow4 {
			return 0, netip.Addr{}, ErrLocalFamilyDisabled
		}
		return FamilyIPv4, netip.MustParseAddr("127.0.0.1"), nil
	}
	if selected == FamilyIPv6 || selected == 0 && n.allow6 {
		if !n.allow6 {
			return 0, netip.Addr{}, ErrLocalFamilyDisabled
		}
		return FamilyIPv6, netip.IPv6Loopback(), nil
	}
	return 0, netip.Addr{}, ErrLocalFamilyDisabled
}

func (n *Local) lookupLoopback(ctx context.Context, selected Family, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		return n.validateLoopbackResults(host, selected, []netip.Addr{literal})
	}
	lookupNetwork := "ip"
	switch selected {
	case FamilyIPv4:
		lookupNetwork = "ip4"
	case FamilyIPv6:
		lookupNetwork = "ip6"
	}
	addresses, err := n.resolver.LookupNetIP(ctx, lookupNetwork, host)
	if err != nil {
		return nil, err
	}
	return n.validateLoopbackResults(host, selected, addresses)
}

func (n *Local) validateLoopbackResults(host string, selected Family, addresses []netip.Addr) ([]netip.Addr, error) {
	if len(addresses) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() || address.Is4In6() || address.Zone() != "" || !address.IsLoopback() {
			return nil, errors.Join(ErrNonLoopbackAddress, &net.AddrError{Err: ErrNonLoopbackAddress.Error(), Addr: host})
		}
		family := FamilyIPv6
		allowed := n.allow6
		if address.Is4() {
			family = FamilyIPv4
			allowed = n.allow4
		}
		if selected != 0 && selected != family || !allowed {
			continue
		}
		result = append(result, address)
	}
	if len(result) == 0 {
		return nil, errors.Join(ErrLocalFamilyDisabled, &net.AddrError{Err: "no enabled address family", Addr: host})
	}
	return result, nil
}

func (n *Local) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	selected, err := resolverFamily(network)
	if err != nil {
		return nil, err
	}
	addresses, err := n.lookupLoopback(ctx, selected, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, net.IP(address.AsSlice()))
	}
	return result, nil
}

func (n *Local) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	addresses, err := n.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IPAddr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, net.IPAddr{IP: net.IP(address.AsSlice())})
	}
	return result, nil
}

func (n *Local) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	selected, err := resolverFamily(network)
	if err != nil {
		return nil, err
	}
	return n.lookupLoopback(ctx, selected, host)
}

func (n *Local) LookupHost(ctx context.Context, host string) ([]string, error) {
	addresses, err := n.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.String())
	}
	return result, nil
}

func (n *Local) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	validated, err := n.lookupLoopback(ctx, 0, address)
	if err != nil {
		return nil, err
	}
	return n.resolver.LookupAddr(ctx, validated[0].String())
}

func (n *Local) LookupCNAME(ctx context.Context, host string) (string, error) {
	if _, err := n.LookupNetIP(ctx, "ip", host); err != nil {
		return "", err
	}
	name, err := n.resolver.LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	if _, err = n.lookupLoopback(ctx, 0, strings.TrimSuffix(name, ".")); err != nil {
		return "", err
	}
	return name, nil
}

func (n *Local) LookupPort(ctx context.Context, network, service string) (int, error) {
	if err := n.check(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return gonnect.LookupPortOffline(network, service)
}

func (n *Local) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if _, err := n.LookupNetIP(ctx, "ip", name); err != nil {
		return nil, err
	}
	return n.resolver.LookupTXT(ctx, name)
}

func (n *Local) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if _, err := n.LookupNetIP(ctx, "ip", name); err != nil {
		return nil, err
	}
	return n.resolver.LookupMX(ctx, name)
}

func (n *Local) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	if _, err := n.LookupNetIP(ctx, "ip", name); err != nil {
		return nil, err
	}
	return n.resolver.LookupNS(ctx, name)
}

func (n *Local) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if _, err := n.LookupNetIP(ctx, "ip", name); err != nil {
		return "", nil, err
	}
	return n.resolver.LookupSRV(ctx, service, proto, name)
}

func resolverFamily(network string) (Family, error) {
	switch network {
	case "ip":
		return 0, nil
	case "ip4":
		return FamilyIPv4, nil
	case "ip6":
		return FamilyIPv6, nil
	default:
		return 0, net.UnknownNetworkError(network)
	}
}

func (n *Local) Interfaces() ([]gonnect.NetworkInterface, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	interfaces, err := n.base.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]gonnect.NetworkInterface, 0, 1)
	for _, iface := range interfaces {
		if iface.Flags()&net.FlagLoopback == 0 {
			continue
		}
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			return nil, addrErr
		}
		filtered := make([]net.Addr, 0, len(addresses))
		for _, address := range addresses {
			if localInterfaceAddr(address, n.allow4, n.allow6) {
				filtered = append(filtered, address)
			}
		}
		result = append(result, &gonnect.LiteralInterface{
			IDVal: iface.ID(), IndexVal: iface.Index(), NameVal: iface.Name(),
			MTUVal: iface.MTU(), HardwareAddrVal: iface.HardwareAddr(),
			FlagsVal: iface.Flags(), AddrsVal: filtered,
		})
	}
	return result, nil
}

func (n *Local) InterfaceAddrs() ([]net.Addr, error) {
	interfaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []net.Addr
	for _, iface := range interfaces {
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			return nil, addrErr
		}
		result = append(result, addresses...)
	}
	return result, nil
}

func (n *Local) InterfaceMulticastAddrs() ([]net.Addr, error) {
	if err := n.check(); err != nil {
		return nil, err
	}
	return []net.Addr{}, nil
}

func (n *Local) InterfacesByIndex(index int) ([]gonnect.NetworkInterface, error) {
	return n.interfaceBy(func(iface gonnect.NetworkInterface) bool { return iface.Index() == index }, strconv.Itoa(index))
}

func (n *Local) InterfacesByName(name string) ([]gonnect.NetworkInterface, error) {
	return n.interfaceBy(func(iface gonnect.NetworkInterface) bool { return iface.Name() == name }, name)
}

func (n *Local) interfaceBy(match func(gonnect.NetworkInterface) bool, query string) ([]gonnect.NetworkInterface, error) {
	interfaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if match(iface) {
			return []gonnect.NetworkInterface{iface}, nil
		}
	}
	return nil, &net.AddrError{Err: "loopback interface not found", Addr: query}
}

func localInterfaceAddr(address net.Addr, allow4, allow6 bool) bool {
	var ip net.IP
	switch value := address.(type) {
	case *net.IPNet:
		ip = value.IP
	case *net.IPAddr:
		ip = value.IP
	default:
		return false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	parsed = parsed.Unmap()
	return parsed.IsLoopback() && (parsed.Is4() && allow4 || parsed.Is6() && allow6)
}
