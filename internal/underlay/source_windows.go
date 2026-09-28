//go:build windows

package underlay

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// NativeSource reads Windows NetIO tables and monitors all changes which can
// alter underlay selection.
type NativeSource struct{}

// ReadCandidates reads interface, IP-interface, unicast-address, and route
// tables once, then combines them without retaining native table memory.
func (NativeSource) ReadCandidates(ctx context.Context) ([]Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormalWithoutStatistics)
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	ipInterfaces, err := winipcfg.GetIPInterfaceTable(windows.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("enumerate IP interfaces: %w", err)
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("enumerate unicast addresses: %w", err)
	}
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("enumerate routes: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	interfaceByLUID := make(map[winipcfg.LUID]winipcfg.MibIfRow2, len(interfaces))
	for _, row := range interfaces {
		interfaceByLUID[row.InterfaceLUID] = row
	}
	candidates := make([]Candidate, 0, len(ipInterfaces))
	indexByKey := make(map[nativeCandidateKey]int, len(ipInterfaces))
	for _, row := range ipInterfaces {
		iface, ok := interfaceByLUID[row.InterfaceLUID]
		if !ok {
			return nil, fmt.Errorf("IP interface %d has no interface row", row.InterfaceIndex)
		}
		if iface.InterfaceIndex != row.InterfaceIndex {
			return nil, fmt.Errorf("interface LUID %d changed index from %d to %d during snapshot", row.InterfaceLUID, iface.InterfaceIndex, row.InterfaceIndex)
		}
		ipv6, ok := nativeIPv6(row.Family)
		if !ok {
			continue
		}
		key := nativeCandidateKey{luid: row.InterfaceLUID, ipv6: ipv6}
		indexByKey[key] = len(candidates)
		candidates = append(candidates, Candidate{
			Interface: Interface{
				LUID: uint64(row.InterfaceLUID), Index: row.InterfaceIndex,
				GUID: strings.ToLower(iface.InterfaceGUID.String()), Name: iface.Alias(),
			},
			IPv6: ipv6, Operational: iface.OperStatus == winipcfg.IfOperStatusUp && row.Connected,
			InterfaceMetric: row.Metric,
		})
	}
	for _, row := range addresses {
		address := row.Address.Addr()
		if address.Zone() != "" {
			address = address.WithZone("")
		}
		if !address.IsValid() {
			return nil, fmt.Errorf("interface %d has an invalid unicast address", row.InterfaceIndex)
		}
		index, ok := indexByKey[nativeCandidateKey{luid: row.InterfaceLUID, ipv6: address.Is6()}]
		if !ok {
			continue
		}
		if candidates[index].Index != row.InterfaceIndex {
			return nil, fmt.Errorf("unicast interface LUID %d changed index during snapshot", row.InterfaceLUID)
		}
		usable := !row.SkipAsSource && (row.DadState == winipcfg.DadStatePreferred || row.DadState == winipcfg.DadStateDeprecated)
		candidates[index].Addresses = append(candidates[index].Addresses, Address{Address: address.Unmap(), Usable: usable})
	}
	for _, row := range routes {
		destination := row.DestinationPrefix.Prefix()
		if !destination.IsValid() {
			return nil, fmt.Errorf("interface %d has an invalid route destination", row.InterfaceIndex)
		}
		address := destination.Addr()
		if address.Zone() != "" {
			destination = netip.PrefixFrom(address.WithZone(""), destination.Bits())
		}
		index, ok := indexByKey[nativeCandidateKey{luid: row.InterfaceLUID, ipv6: destination.Addr().Is6()}]
		if !ok {
			continue
		}
		if candidates[index].Index != row.InterfaceIndex {
			return nil, fmt.Errorf("route interface LUID %d changed index during snapshot", row.InterfaceLUID)
		}
		candidates[index].Routes = append(candidates[index].Routes, Route{
			Destination: destination.Masked(), Metric: row.Metric,
		})
	}
	return candidates, nil
}

// SubscribeChanges registers all three NetIO callbacks before returning.
func (NativeSource) SubscribeChanges(notify func()) (Subscription, error) {
	if notify == nil {
		return nil, errors.New("underlay change callback is nil")
	}
	callbacks := make([]winipcfg.ChangeCallback, 0, 3)
	iface, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) { notify() })
	if err != nil {
		return nil, fmt.Errorf("register interface change callback: %w", err)
	}
	callbacks = append(callbacks, iface)
	route, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) { notify() })
	if err != nil {
		return nil, errors.Join(fmt.Errorf("register route change callback: %w", err), unregisterCallbacks(callbacks))
	}
	callbacks = append(callbacks, route)
	address, err := winipcfg.RegisterUnicastAddressChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) { notify() })
	if err != nil {
		return nil, errors.Join(fmt.Errorf("register address change callback: %w", err), unregisterCallbacks(callbacks))
	}
	callbacks = append(callbacks, address)
	return &nativeSubscription{callbacks: callbacks}, nil
}

type nativeCandidateKey struct {
	luid winipcfg.LUID
	ipv6 bool
}

type nativeSubscription struct {
	mu        sync.Mutex
	callbacks []winipcfg.ChangeCallback
}

func (s *nativeSubscription) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := make([]winipcfg.ChangeCallback, 0, len(s.callbacks))
	var result error
	for index := len(s.callbacks) - 1; index >= 0; index-- {
		if err := s.callbacks[index].Unregister(); err != nil {
			result = errors.Join(result, err)
			remaining = append(remaining, s.callbacks[index])
		}
	}
	s.callbacks = remaining
	return result
}

func unregisterCallbacks(callbacks []winipcfg.ChangeCallback) error {
	var result error
	for index := len(callbacks) - 1; index >= 0; index-- {
		result = errors.Join(result, callbacks[index].Unregister())
	}
	return result
}

func nativeIPv6(family winipcfg.AddressFamily) (bool, bool) {
	switch family {
	case windows.AF_INET:
		return false, true
	case windows.AF_INET6:
		return true, true
	default:
		return false, false
	}
}

var _ Source = NativeSource{}
