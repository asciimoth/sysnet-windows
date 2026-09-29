package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

var (
	// ErrUnsupportedSocketNetwork reports a raw, multicast, or otherwise
	// unsupported socket kind. The operation is never retried without policy.
	ErrUnsupportedSocketNetwork = errors.New("unsupported outbound socket network")
	// ErrAmbiguousSocketFamily reports that a wildcard endpoint did not select
	// IPv4 or IPv6. Callers can use an explicit *4 or *6 network in this case.
	ErrAmbiguousSocketFamily = errors.New("outbound socket family is ambiguous")
)

// BoundNetwork creates native sockets with Binder controls. It accepts only
// numeric endpoints; Outbound supplies its DNS-aware resolving layer.
type BoundNetwork struct {
	binder *Binder
	paths  PathSource
	allow4 bool
	allow6 bool
}

// Families selects the address families accepted by BoundNetwork.
type Families struct {
	IPv4 bool
	IPv6 bool
}

// NewBoundNetwork creates a native socket network for the selected underlays.
func NewBoundNetwork(binder *Binder, paths PathSource, families Families) (*BoundNetwork, error) {
	if binder == nil || paths == nil {
		return nil, errors.New("create bound network without socket policy")
	}
	return &BoundNetwork{binder: binder, paths: paths, allow4: families.IPv4, allow6: families.IPv6}, nil
}

var _ gonnect.Network = (*BoundNetwork)(nil)

// IsNative is false because direct native shortcuts would bypass Binder.
func (*BoundNetwork) IsNative() bool { return false }

func (n *BoundNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	transport, family, remote, err := socketEndpoint(network, address, false)
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	control, err := n.binder.Control("dial "+strings.ToUpper(transport), family, netip.Addr{}, nil)
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Control: control}
	return dialer.DialContext(ctx, familyNetworkName(transport, family), remote)
}

func (n *BoundNetwork) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	transport, family, local, localIP, err := listenEndpoint(network, address, "tcp")
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	control, err := n.binder.Control("listen "+strings.ToUpper(transport), family, localIP, nil)
	if err != nil {
		return nil, err
	}
	return (&net.ListenConfig{Control: control}).Listen(ctx, familyNetworkName(transport, family), local)
}

func (n *BoundNetwork) PacketDial(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	connection, err := n.DialUDP(ctx, network, "", address)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (n *BoundNetwork) ListenPacket(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
	return n.ListenPacketConfig(ctx, nil, network, address)
}

func (n *BoundNetwork) DialTCP(ctx context.Context, network, laddr, raddr string) (gonnect.TCPConn, error) {
	family, remote, err := typedRemoteEndpoint(network, raddr, "tcp")
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	local, localIP, err := typedLocalEndpoint(network, laddr, family, "tcp")
	if err != nil {
		return nil, err
	}
	control, err := n.binder.Control("dial TCP", family, localIP, nil)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Control: control, LocalAddr: local}
	connection, err := dialer.DialContext(ctx, familyNetworkName("tcp", family), remote)
	if err != nil {
		return nil, err
	}
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		return nil, fmt.Errorf("dial TCP returned %T: %w", connection, gonnect.ErrUnsupported)
	}
	return tcp, nil
}

func (n *BoundNetwork) ListenTCP(ctx context.Context, network, laddr string) (gonnect.TCPListener, error) {
	_, family, local, localIP, err := listenEndpoint(network, laddr, "tcp")
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	control, err := n.binder.Control("listen TCP", family, localIP, nil)
	if err != nil {
		return nil, err
	}
	listener, err := (&net.ListenConfig{Control: control}).Listen(ctx, familyNetworkName("tcp", family), local)
	if err != nil {
		return nil, err
	}
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("listen TCP returned %T: %w", listener, gonnect.ErrUnsupported)
	}
	return &gonnect.NetTCPListener{TCPListener: tcp}, nil
}

func (n *BoundNetwork) DialUDP(ctx context.Context, network, laddr, raddr string) (gonnect.UDPConn, error) {
	family, remote, err := typedRemoteEndpoint(network, raddr, "udp")
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	local, localIP, err := typedLocalEndpoint(network, laddr, family, "udp")
	if err != nil {
		return nil, err
	}
	control, err := n.binder.Control("dial UDP", family, localIP, nil)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Control: control, LocalAddr: local}
	connection, err := dialer.DialContext(ctx, familyNetworkName("udp", family), remote)
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, fmt.Errorf("dial UDP returned %T: %w", connection, gonnect.ErrUnsupported)
	}
	return udp, nil
}

func (n *BoundNetwork) ListenUDP(ctx context.Context, network, laddr string) (gonnect.UDPConn, error) {
	return n.ListenUDPConfig(ctx, nil, network, laddr)
}

func (n *BoundNetwork) ListenPacketConfig(ctx context.Context, config *gonnect.ListenConfig, network, address string) (gonnect.PacketConn, error) {
	connection, err := n.listenUDP(ctx, config, network, address)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (n *BoundNetwork) ListenUDPConfig(ctx context.Context, config *gonnect.ListenConfig, network, laddr string) (gonnect.UDPConn, error) {
	return n.listenUDP(ctx, config, network, laddr)
}

func (n *BoundNetwork) listenUDP(ctx context.Context, config *gonnect.ListenConfig, network, laddr string) (*net.UDPConn, error) {
	_, family, local, localIP, err := listenEndpoint(network, laddr, "udp")
	if err != nil {
		return nil, err
	}
	if err := n.requireFamily(family); err != nil {
		return nil, err
	}
	var caller ControlFunc
	if config != nil {
		caller = config.Control
	}
	control, err := n.binder.Control("listen UDP", family, localIP, caller)
	if err != nil {
		return nil, err
	}
	connection, err := (&net.ListenConfig{Control: control}).ListenPacket(ctx, familyNetworkName("udp", family), local)
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, fmt.Errorf("listen UDP returned %T: %w", connection, gonnect.ErrUnsupported)
	}
	return udp, nil
}

func (*BoundNetwork) ListenMulticastUDP(context.Context, string, string, gonnect.MulticastOptions) (gonnect.MulticastPacketConn, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, ErrUnsupportedSocketNetwork)
}

func (n *BoundNetwork) Interfaces() ([]gonnect.NetworkInterface, error) {
	snapshot := n.paths.Snapshot()
	byIndex := make(map[uint32]*gonnect.LiteralInterface, 2)
	paths := []*underlayPath{}
	if n.allow4 {
		paths = append(paths, literalPath(snapshot.IPv4))
	}
	if n.allow6 {
		paths = append(paths, literalPath(snapshot.IPv6))
	}
	for _, path := range paths {
		if path == nil {
			continue
		}
		iface := byIndex[path.index]
		if iface == nil {
			iface = &gonnect.LiteralInterface{
				IDVal:    "windows-underlay:" + strconv.FormatUint(uint64(path.index), 10),
				IndexVal: int(path.index), NameVal: path.name, FlagsVal: net.FlagUp,
			}
			byIndex[path.index] = iface
		}
		bits := 128
		if path.source.Is4() {
			bits = 32
		}
		iface.AddrsVal = append(iface.AddrsVal, &net.IPNet{IP: path.source.AsSlice(), Mask: net.CIDRMask(bits, bits)})
	}
	result := make([]gonnect.NetworkInterface, 0, len(byIndex))
	for _, iface := range byIndex {
		result = append(result, iface)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Index() < result[j].Index() })
	return result, nil
}

func (n *BoundNetwork) requireFamily(family Family) error {
	if family == FamilyIPv4 && n.allow4 || family == FamilyIPv6 && n.allow6 {
		return nil
	}
	return errors.Join(gonnect.ErrUnsupported, fmt.Errorf("IPv%d outbound sockets are disabled", family))
}

type underlayPath struct {
	index  uint32
	name   string
	source netip.Addr
}

func literalPath(path *underlay.Path) *underlayPath {
	if path == nil {
		return nil
	}
	return &underlayPath{index: path.InterfaceIndex, name: path.InterfaceName, source: path.Source}
}

func (n *BoundNetwork) InterfaceAddrs() ([]net.Addr, error) {
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

func (*BoundNetwork) InterfaceMulticastAddrs() ([]net.Addr, error) { return []net.Addr{}, nil }

func (n *BoundNetwork) InterfacesByIndex(index int) ([]gonnect.NetworkInterface, error) {
	interfaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Index() == index {
			return []gonnect.NetworkInterface{iface}, nil
		}
	}
	return nil, &net.AddrError{Err: "interface not found", Addr: strconv.Itoa(index)}
}

func (n *BoundNetwork) InterfacesByName(name string) ([]gonnect.NetworkInterface, error) {
	interfaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Name() == name {
			return []gonnect.NetworkInterface{iface}, nil
		}
	}
	return nil, &net.AddrError{Err: "interface not found", Addr: name}
}

func (*BoundNetwork) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupAddr(context.Context, string) ([]string, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupCNAME(context.Context, string) (string, error) {
	return "", errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupPort(context.Context, string, string) (int, error) {
	return 0, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}
func (*BoundNetwork) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, errors.Join(gonnect.ErrUnsupported, errors.New("bound network requires OutDNS resolution"))
}

func socketEndpoint(network, address string, wildcard bool) (string, Family, string, error) {
	transport, suffixFamily, err := socketNetwork(network)
	if err != nil {
		return "", 0, "", err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, "", err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", 0, "", &net.AddrError{Err: "non-numeric port", Addr: address}
	}
	family, _, err := endpointFamily(host, suffixFamily, wildcard)
	if err != nil {
		return "", 0, "", err
	}
	return transport, family, net.JoinHostPort(host, port), nil
}

func listenEndpoint(network, address, wantTransport string) (string, Family, string, netip.Addr, error) {
	transport, family, endpoint, err := socketEndpoint(network, address, true)
	if err != nil {
		return "", 0, "", netip.Addr{}, err
	}
	if transport != wantTransport {
		return "", 0, "", netip.Addr{}, net.UnknownNetworkError(network)
	}
	host, _, _ := net.SplitHostPort(endpoint)
	_, local, err := endpointFamily(host, family, true)
	return transport, family, endpoint, local, err
}

func typedRemoteEndpoint(network, address, transport string) (Family, string, error) {
	gotTransport, family, endpoint, err := socketEndpoint(network, address, false)
	if err != nil {
		return 0, "", err
	}
	if gotTransport != transport {
		return 0, "", net.UnknownNetworkError(network)
	}
	return family, endpoint, nil
}

func typedLocalEndpoint(network, address string, family Family, transport string) (net.Addr, netip.Addr, error) {
	if address == "" {
		return nil, netip.Addr{}, nil
	}
	gotTransport, gotFamily, endpoint, err := socketEndpoint(network, address, true)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if gotTransport != transport || gotFamily != family {
		return nil, netip.Addr{}, ErrLocalAddressConflict
	}
	host, portText, _ := net.SplitHostPort(endpoint)
	_, local, err := endpointFamily(host, family, true)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	port, _ := strconv.Atoi(portText)
	if transport == "tcp" {
		return &net.TCPAddr{IP: local.AsSlice(), Port: port}, local, nil
	}
	return &net.UDPAddr{IP: local.AsSlice(), Port: port}, local, nil
}

func socketNetwork(network string) (string, Family, error) {
	switch network {
	case "tcp":
		return "tcp", 0, nil
	case "tcp4":
		return "tcp", FamilyIPv4, nil
	case "tcp6":
		return "tcp", FamilyIPv6, nil
	case "udp":
		return "udp", 0, nil
	case "udp4":
		return "udp", FamilyIPv4, nil
	case "udp6":
		return "udp", FamilyIPv6, nil
	default:
		return "", 0, errors.Join(net.UnknownNetworkError(network), ErrUnsupportedSocketNetwork)
	}
}

func endpointFamily(host string, selected Family, wildcard bool) (Family, netip.Addr, error) {
	if host == "" {
		if selected == 0 {
			return 0, netip.Addr{}, ErrAmbiguousSocketFamily
		}
		if selected == FamilyIPv4 {
			return selected, netip.IPv4Unspecified(), nil
		}
		return selected, netip.IPv6Unspecified(), nil
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Is4In6() || address.Zone() != "" {
		return 0, netip.Addr{}, &net.AddrError{Err: "numeric, unmapped IP address required", Addr: host}
	}
	family := FamilyIPv6
	if address.Is4() {
		family = FamilyIPv4
	}
	if selected != 0 && selected != family {
		return 0, netip.Addr{}, &net.AddrError{Err: "address family conflicts with network", Addr: host}
	}
	if !wildcard && address.IsUnspecified() {
		return 0, netip.Addr{}, &net.AddrError{Err: "remote address is unspecified", Addr: host}
	}
	return family, address, nil
}

func familyNetworkName(transport string, family Family) string {
	if family == FamilyIPv4 {
		return transport + "4"
	}
	return transport + "6"
}
