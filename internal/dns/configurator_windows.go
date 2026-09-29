//go:build windows

package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// NativeConfigurator reads effective server addresses and preserves whether
// Windows obtains them automatically. Static mode is detected from the
// interface NameServer values. An empty value means that DHCP or router
// discovery owns the effective list.
type NativeConfigurator struct{}

func (NativeConfigurator) Read(ctx context.Context, luid uint64) (State, error) {
	if err := contextError(ctx); err != nil {
		return State{}, err
	}
	nativeLUID := winipcfg.LUID(luid)
	guid, err := nativeLUID.GUID()
	if err != nil {
		return State{}, fmt.Errorf("read DNS interface GUID: %w", err)
	}
	servers, err := nativeLUID.DNS()
	if err != nil {
		return State{}, fmt.Errorf("read effective DNS servers: %w", err)
	}
	static4, err := registryNameServers("Tcpip", guid.String())
	if err != nil {
		return State{}, err
	}
	static6, err := registryNameServers("Tcpip6", guid.String())
	if err != nil {
		return State{}, err
	}
	state := State{AutomaticIPv4: static4 == "", AutomaticIPv6: static6 == "", Servers: servers}
	// GetAdaptersAddresses can lag SetInterfaceDnsSettings. Merge registry
	// values so immediate readback still contains every configured server.
	for _, value := range []string{static4, static6} {
		for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
			if address, parseErr := netip.ParseAddr(field); parseErr == nil {
				address = address.Unmap()
				if !slices.Contains(state.Servers, address) {
					state.Servers = append(state.Servers, address)
				}
			}
		}
	}
	return state, nil
}

func (NativeConfigurator) Apply(ctx context.Context, luid uint64, state State) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := ValidateState(state); err != nil {
		return err
	}
	configurator := NativeConfigurator{}
	prior, err := configurator.Read(ctx, luid)
	if err != nil {
		return fmt.Errorf("read DNS state before apply: %w", err)
	}
	if err := applyNativeState(ctx, luid, state); err != nil {
		// A family-specific API call can change state before a later call fails.
		// Use an uncanceled context for bounded caller-owned rollback at this OS
		// boundary. The outer journal performs another readback and retry.
		rollbackErr := applyNativeState(context.WithoutCancel(ctx), luid, prior)
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func applyNativeState(ctx context.Context, luid uint64, state State) error {
	var ipv4, ipv6 []netip.Addr
	for _, server := range state.Servers {
		if server.Is4() && !state.AutomaticIPv4 {
			ipv4 = append(ipv4, server)
		} else if server.Is6() && !state.AutomaticIPv6 {
			ipv6 = append(ipv6, server)
		}
	}
	nativeLUID := winipcfg.LUID(luid)
	if err := setNameServers(nativeLUID, windows.AF_INET, ipv4); err != nil {
		return fmt.Errorf("set IPv4 DNS servers: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := setNameServers(nativeLUID, windows.AF_INET6, ipv6); err != nil {
		return fmt.Errorf("set IPv6 DNS servers: %w", err)
	}
	return contextError(ctx)
}

// setNameServers changes only the per-family name-server field. LUID.SetDNS
// also sets the search-list flag, even when its domains argument is nil. That
// would clear an administrator-owned suffix search list. Version 1 settings do
// not select the NRPT, encrypted-DNS, LLMNR, registration, or profile fields,
// so Windows leaves those settings unchanged.
func setNameServers(luid winipcfg.LUID, family winipcfg.AddressFamily, servers []netip.Addr) error {
	values := make([]string, 0, len(servers))
	for _, server := range servers {
		if server.Is4() == (family == windows.AF_INET) {
			values = append(values, server.String())
		}
	}
	nameServers, err := windows.UTF16PtrFromString(strings.Join(values, ","))
	if err != nil {
		return err
	}
	guid, err := luid.GUID()
	if err != nil {
		return fmt.Errorf("read DNS interface GUID: %w", err)
	}
	settings := &winipcfg.DnsInterfaceSettings{
		Version:    winipcfg.DnsInterfaceSettingsVersion1,
		Flags:      winipcfg.DnsInterfaceSettingsFlagNameserver,
		NameServer: nameServers,
	}
	if family == windows.AF_INET6 {
		settings.Flags |= winipcfg.DnsInterfaceSettingsFlagIPv6
	}
	return winipcfg.SetInterfaceDnsSettings(*guid, settings)
}

func registryNameServers(service, guid string) (string, error) {
	path := `SYSTEM\CurrentControlSet\Services\` + service + `\Parameters\Interfaces\` + guid
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open DNS interface registry state: %w", err)
	}
	defer key.Close()
	value, _, err := key.GetStringValue("NameServer")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read DNS interface registry state: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
