//go:build windows

package netio

import (
	"context"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// NativeReader reads complete Windows unicast-address and route tables. The
// NetIO table calls return immutable copies, so values in HostState do not keep
// native buffers alive.
type NativeReader struct{}

// ReadHostState implements Reader.
func (NativeReader) ReadHostState(ctx context.Context) (HostState, error) {
	if err := ctx.Err(); err != nil {
		return HostState{}, err
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return HostState{}, fmt.Errorf("enumerate unicast addresses: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return HostState{}, err
	}
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return HostState{}, fmt.Errorf("enumerate routes: %w", err)
	}

	state := HostState{
		Addresses:         make([]netip.Addr, 0, len(addresses)),
		InterfacePrefixes: make([]netip.Prefix, 0, len(addresses)),
		Routes:            make([]netip.Prefix, 0, len(routes)),
	}
	for index := range addresses {
		address := addresses[index].Address.Addr()
		if address.Zone() != "" {
			address = address.WithZone("")
		}
		if !address.IsValid() {
			return HostState{}, fmt.Errorf("unicast address %d has an invalid family", index)
		}
		prefix := netip.PrefixFrom(address, int(addresses[index].OnLinkPrefixLength))
		if !prefix.IsValid() {
			return HostState{}, fmt.Errorf("unicast address %d has an invalid prefix length", index)
		}
		// Only preferred and deprecated rows are usable source addresses. Every
		// row still contributes its interface prefix because tentative or
		// duplicate configuration must also prevent a conflicting allocation.
		if addresses[index].DadState == winipcfg.DadStatePreferred ||
			addresses[index].DadState == winipcfg.DadStateDeprecated {
			state.Addresses = append(state.Addresses, address)
		}
		state.InterfacePrefixes = append(state.InterfacePrefixes, prefix.Masked())
	}
	for index := range routes {
		prefix := routes[index].DestinationPrefix.Prefix()
		if prefix.Addr().Zone() != "" {
			prefix = netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits())
		}
		if !prefix.IsValid() {
			return HostState{}, fmt.Errorf("route %d has an invalid destination", index)
		}
		state.Routes = append(state.Routes, prefix.Masked())
	}
	if err := ctx.Err(); err != nil {
		return HostState{}, err
	}
	return state, nil
}

var _ Reader = NativeReader{}
