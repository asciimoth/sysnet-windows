//go:build windows

package netio

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const addressPollInterval = 20 * time.Millisecond

// NativeStore implements exact NetIO row operations with winipcfg. It does not
// use the package flush helpers because an owned adapter can contain foreign
// sentinel rows which must survive every operation.
type NativeStore struct{}

// Snapshot reads the interface identity and complete address, route, and
// per-family property state for iface.
func (NativeStore) Snapshot(ctx context.Context, iface Interface) (State, error) {
	if err := contextError(ctx); err != nil {
		return State{}, err
	}
	luid := winipcfg.LUID(iface.LUID)
	identity, err := luid.Interface()
	if err != nil {
		return State{}, fmt.Errorf("read interface identity: %w", err)
	}
	state := State{Interface: Interface{LUID: uint64(identity.InterfaceLUID), Index: identity.InterfaceIndex}}

	addressRows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return State{}, fmt.Errorf("enumerate interface addresses: %w", err)
	}
	for index := range addressRows {
		row := &addressRows[index]
		if row.InterfaceLUID != luid {
			continue
		}
		address := withoutZone(row.Address.Addr())
		prefix := netip.PrefixFrom(address, int(row.OnLinkPrefixLength))
		if !prefix.IsValid() {
			return State{}, fmt.Errorf("interface address row %d has an invalid prefix", index)
		}
		state.Addresses = append(state.Addresses, Address{
			Prefix: prefix,
			Usable: row.DadState == winipcfg.DadStatePreferred || row.DadState == winipcfg.DadStateDeprecated,
		})
	}
	if err := contextError(ctx); err != nil {
		return State{}, err
	}

	routeRows, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return State{}, fmt.Errorf("enumerate interface routes: %w", err)
	}
	for index := range routeRows {
		row := &routeRows[index]
		if row.InterfaceLUID != luid {
			continue
		}
		destination := row.DestinationPrefix.Prefix()
		if !destination.IsValid() {
			return State{}, fmt.Errorf("interface route row %d has an invalid destination", index)
		}
		destination = netip.PrefixFrom(withoutZone(destination.Addr()), destination.Bits()).Masked()
		nextHop := withoutZone(row.NextHop.Addr())
		if !nextHop.IsValid() {
			return State{}, fmt.Errorf("interface route row %d has an invalid next hop", index)
		}
		state.Routes = append(state.Routes, Route{Destination: destination, NextHop: nextHop, Metric: row.Metric})
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		row, err := luid.IPInterface(nativeFamily(family))
		if err != nil {
			if family == FamilyIPv4 && err == windows.ERROR_NOT_FOUND {
				continue
			}
			return State{}, fmt.Errorf("read IPv%d interface properties: %w", family, err)
		}
		state.Properties = append(state.Properties, Properties{
			Family: family, MTU: row.NLMTU, Metric: row.Metric, AutomaticMetric: row.UseAutomaticMetric,
		})
	}
	if err := contextError(ctx); err != nil {
		return State{}, err
	}
	return state, nil
}

func (NativeStore) CreateAddress(ctx context.Context, iface Interface, prefix netip.Prefix) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := winipcfg.LUID(iface.LUID).AddIPAddress(prefix); err != nil {
		return fmt.Errorf("create unicast address %s: %w", prefix, err)
	}
	return contextError(ctx)
}

func (NativeStore) DeleteAddress(ctx context.Context, iface Interface, prefix netip.Prefix) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := winipcfg.LUID(iface.LUID).DeleteIPAddress(prefix); err != nil {
		return fmt.Errorf("delete unicast address %s: %w", prefix, err)
	}
	return contextError(ctx)
}

// WaitAddressUsable waits for duplicate-address detection to reach a usable
// state. A duplicate or invalid state fails immediately; a tentative row waits
// until ctx reaches its deadline.
func (NativeStore) WaitAddressUsable(ctx context.Context, iface Interface, address netip.Addr) error {
	ticker := time.NewTicker(addressPollInterval)
	defer ticker.Stop()
	for {
		row, err := winipcfg.LUID(iface.LUID).IPAddress(address)
		if err != nil {
			return fmt.Errorf("read address usability for %s: %w", address, err)
		}
		switch row.DadState {
		case winipcfg.DadStatePreferred, winipcfg.DadStateDeprecated:
			return nil
		case winipcfg.DadStateDuplicate, winipcfg.DadStateInvalid:
			return fmt.Errorf("address %s entered unusable DAD state %d", address, row.DadState)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for address %s usability: %w", address, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (NativeStore) CreateRoute(ctx context.Context, iface Interface, route Route) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := winipcfg.LUID(iface.LUID).AddRoute(route.Destination, route.NextHop, route.Metric); err != nil {
		return fmt.Errorf("create route %s via %s: %w", route.Destination, route.NextHop, err)
	}
	return contextError(ctx)
}

func (NativeStore) DeleteRoute(ctx context.Context, iface Interface, route Route) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := winipcfg.LUID(iface.LUID).DeleteRoute(route.Destination, route.NextHop); err != nil {
		return fmt.Errorf("delete route %s via %s: %w", route.Destination, route.NextHop, err)
	}
	return contextError(ctx)
}

func (NativeStore) SetProperties(ctx context.Context, iface Interface, properties Properties) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	row, err := winipcfg.LUID(iface.LUID).IPInterface(nativeFamily(properties.Family))
	if err != nil {
		return fmt.Errorf("read IPv%d interface properties before update: %w", properties.Family, err)
	}
	if row.InterfaceIndex != iface.Index {
		return fmt.Errorf("%w: IPv%d property row has index %d, want %d", ErrIdentityMismatch, properties.Family, row.InterfaceIndex, iface.Index)
	}
	row.NLMTU = properties.MTU
	row.Metric = properties.Metric
	row.UseAutomaticMetric = properties.AutomaticMetric
	if err := row.Set(); err != nil {
		return fmt.Errorf("set IPv%d interface properties: %w", properties.Family, err)
	}
	return contextError(ctx)
}

func nativeFamily(family Family) winipcfg.AddressFamily {
	if family == FamilyIPv4 {
		return windows.AF_INET
	}
	return windows.AF_INET6
}

func withoutZone(address netip.Addr) netip.Addr {
	if address.Zone() != "" {
		return address.WithZone("")
	}
	return address
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

var _ Store = NativeStore{}
