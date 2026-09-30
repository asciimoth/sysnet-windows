package windows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	gonnectdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

func TestT19DefaultTunTransactionPublishesOnlyUsablePolicy(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)

	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:  []string{"10.90.0.1/24"},
		TunRoutes: []string{"10.91.0.0/16", "0.0.0.0/0"},
		MTU:       1400,
	})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	owned := device.(*defaultTun)
	if system.defaultTun != owned {
		t.Fatal("default TUN was not published")
	}
	want := netio.Config{
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.90.0.1/24")},
		Routes: []netio.Route{
			{Destination: netip.MustParsePrefix("10.91.0.0/16"), NextHop: netip.IPv4Unspecified(), Metric: regularTunRouteMetric},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHop: netip.IPv4Unspecified(), Metric: defaultTunRouteMetric},
		},
		Properties: []netio.Properties{{Family: netio.FamilyIPv4, MTU: 1400, Metric: defaultTunRouteMetric}},
	}
	if got := manager.config(owned.interfaceID()); !netIOConfigEqual(got, want) {
		t.Fatalf("default NetIO config = %+v, want %+v", got, want)
	}
	if manager.applyCalls != 3 {
		t.Fatalf("NetIO apply calls = %d, want staged properties, addresses, then defaults", manager.applyCalls)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("DefaultTun.Close() error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second DefaultTun.Close() error = %v", err)
	}
	if system.defaultTun != nil || !factory.created[0].closed || !netIOConfigEmpty(manager.config(owned.interfaceID())) {
		t.Fatal("default TUN close did not remove all published policy")
	}
}

func TestCapabilitiesForDefaultTunLifecycleAndOwnership(t *testing.T) {
	system := newDefaultTunTestSystem(t, &regularTunFactory{}, newRegularTunManager())
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.89.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	report, err := system.CapabilitiesForTun(device)
	if err != nil {
		t.Fatalf("CapabilitiesForTun(default) error = %v", err)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("default-TUN capabilities are invalid: %v", err)
	}
	if len(report.Operations) == 0 {
		t.Fatal("default-TUN capability report has no instance operations")
	}
	for _, operation := range report.Operations {
		if operation.Key.Target != sysnet.TargetDefaultTun || operation.Key.Operation == sysnet.OpCreate || operation.Key.Operation == sysnet.OpCreateNamed {
			t.Fatalf("non-instance default-TUN operation = %+v", operation.Key)
		}
	}

	other := newDefaultTunTestSystem(t, &regularTunFactory{}, newRegularTunManager())
	foreign, err := other.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.88.0.1/24"}})
	if err != nil {
		t.Fatalf("foreign BuildDefaultTun() error = %v", err)
	}
	if _, err := system.CapabilitiesForTun(foreign); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("CapabilitiesForTun(foreign default) error = %v, want ErrUnknownTun", err)
	}
	if err := other.Close(); err != nil {
		t.Fatalf("foreign System.Close() error = %v", err)
	}

	replacement, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.87.0.1/24"}})
	if err != nil {
		t.Fatalf("replacement BuildDefaultTun() error = %v", err)
	}
	if _, err := system.CapabilitiesForTun(device); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("CapabilitiesForTun(retired default) error = %v, want ErrUnknownTun", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatalf("replacement Close() error = %v", err)
	}
	if _, err := system.CapabilitiesForTun(replacement); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("CapabilitiesForTun(closed default) error = %v, want ErrUnknownTun", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("System.Close() error = %v", err)
	}
}

func TestDefaultTunEmptyOptionsAllocateOwnedAddress(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	config := manager.config(device.(*defaultTun).interfaceID())
	if len(config.Addresses) != 1 || !config.Addresses[0].Addr().Is4() {
		t.Fatalf("automatically allocated addresses = %v, want one IPv4 address", config.Addresses)
	}
	if !containsRoute(config.Routes, netip.MustParsePrefix("0.0.0.0/0")) {
		t.Fatalf("automatically configured routes = %v, want IPv4 default", config.Routes)
	}
}

func TestDefaultTunDualRoutesAllocateBothAddressFamilies(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunRoutes: []string{"0.0.0.0/0", "::/0"}})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	config := manager.config(device.(*defaultTun).interfaceID())
	if len(config.Addresses) != 2 || !config.Addresses[0].Addr().Is4() || !config.Addresses[1].Addr().Is6() {
		t.Fatalf("automatically allocated addresses = %v, want IPv4 and IPv6", config.Addresses)
	}
	if !containsRoute(config.Routes, netip.MustParsePrefix("0.0.0.0/0")) ||
		!containsRoute(config.Routes, netip.MustParsePrefix("::/0")) {
		t.Fatalf("automatically configured routes = %v, want dual defaults", config.Routes)
	}
}

func TestT20InvalidDefaultTunReplacementPreservesOldObject(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	old, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.92.0.1/24"}})
	if err != nil {
		t.Fatalf("first BuildDefaultTun() error = %v", err)
	}
	oldConfig := manager.config(old.(*defaultTun).interfaceID())

	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"not-a-prefix"}}); err == nil {
		t.Fatal("invalid replacement error = nil")
	}
	if system.defaultTun != old || old.(*defaultTun).closed.Load() {
		t.Fatal("invalid replacement retired the old default TUN")
	}
	if len(factory.created) != 1 || !netIOConfigEqual(manager.config(old.(*defaultTun).interfaceID()), oldConfig) {
		t.Fatal("invalid replacement changed native state")
	}
}

func TestT21FailureAfterDefaultTunRetirementPublishesNoObject(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	old, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.93.0.1/24"}})
	if err != nil {
		t.Fatalf("first BuildDefaultTun() error = %v", err)
	}
	// The replacement stages properties (call 4), retires the old NetIO state
	// (call 5), and then applies replacement addresses (call 6).
	manager.failApplyCall = manager.applyCalls + 3
	manager.failApplyErr = errInjectedRegularTun
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.94.0.1/24"}}); !errors.Is(err, errInjectedRegularTun) {
		t.Fatalf("replacement error = %v, want injected failure", err)
	}
	if system.defaultTun != nil {
		t.Fatal("failed post-retirement replacement published a default TUN")
	}
	if !old.(*defaultTun).closed.Load() || !factory.created[1].closed {
		t.Fatal("failed replacement did not retire old and clean new adapters")
	}
	for _, native := range factory.created {
		if got := manager.config(native.interfaceID()); !netIOConfigEmpty(got) {
			t.Fatalf("failed replacement leaked NetIO state: %+v", got)
		}
	}
}

func TestDefaultTunFailuresBeforeRetirementPreserveOldObject(t *testing.T) {
	tests := []struct {
		name string
		fail func(*regularTunFactory, *regularTunManager)
	}{
		{name: "adapter creation", fail: func(factory *regularTunFactory, _ *regularTunManager) {
			factory.createErr = errInjectedRegularTun
		}},
		{name: "property staging", fail: func(_ *regularTunFactory, manager *regularTunManager) {
			manager.failApplyCall = manager.applyCalls + 1
			manager.failApplyErr = errInjectedRegularTun
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newDefaultTunTestSystem(t, factory, manager)
			old, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.97.0.1/24"}})
			if err != nil {
				t.Fatalf("first BuildDefaultTun() error = %v", err)
			}
			oldConfig := manager.config(old.(*defaultTun).interfaceID())
			test.fail(factory, manager)
			if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.98.0.1/24"}}); !errors.Is(err, errInjectedRegularTun) {
				t.Fatalf("replacement error = %v, want injected failure", err)
			}
			if system.defaultTun != old || old.(*defaultTun).closed.Load() {
				t.Fatal("pre-retirement failure retired the old default TUN")
			}
			if !netIOConfigEqual(manager.config(old.(*defaultTun).interfaceID()), oldConfig) {
				t.Fatal("pre-retirement failure changed the old NetIO policy")
			}
		})
	}
}

func TestDefaultTunFinalRouteFailureCleansNewPolicy(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	old, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.99.0.1/24"}})
	if err != nil {
		t.Fatalf("first BuildDefaultTun() error = %v", err)
	}
	// Stage the replacement twice, retire the old route, address, and base
	// records, and then fail when the replacement default route is published.
	manager.failApplyCall = manager.applyCalls + 6
	manager.failApplyErr = errInjectedRegularTun
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.100.0.1/24"}}); !errors.Is(err, errInjectedRegularTun) {
		t.Fatalf("replacement error = %v, want injected failure", err)
	}
	if system.defaultTun != nil || !old.(*defaultTun).closed.Load() || !factory.created[1].closed {
		t.Fatal("final-route failure did not leave an explicit inactive state")
	}
}

func TestDefaultTunReplacementRetiresOldAfterNewStaging(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	old, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.95.0.1/24"}})
	if err != nil {
		t.Fatalf("first BuildDefaultTun() error = %v", err)
	}
	replacement, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.95.0.1/24"}})
	if err != nil {
		t.Fatalf("replacement BuildDefaultTun() error = %v", err)
	}
	if !old.(*defaultTun).closed.Load() || system.defaultTun != replacement {
		t.Fatal("replacement identity was not published correctly")
	}
	if err := old.Close(); err != nil {
		t.Fatalf("retired DefaultTun.Close() error = %v", err)
	}
	if replacement.(*defaultTun).closed.Load() {
		t.Fatal("closing retired object closed its replacement")
	}
}

func TestNamedDefaultTunReplacementRecordsEarlyRetirement(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	old, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{Name: "managed", TunAddrs: []string{"10.96.0.1/24"}})
	if err != nil {
		t.Fatalf("first BuildDefaultTun() error = %v", err)
	}
	factory.createErr = errInjectedRegularTun
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{Name: "managed", TunAddrs: []string{"10.96.0.1/24"}}); !errors.Is(err, errInjectedRegularTun) {
		t.Fatalf("named replacement error = %v, want injected failure", err)
	}
	if !old.(*defaultTun).closed.Load() || system.defaultTun != nil {
		t.Fatal("failed same-name replacement did not publish the retirement boundary")
	}
}

func TestD05D08DefaultTunProviderLifecycle(t *testing.T) {
	proxyFactory := &fakeDNSProxyFactory{}
	system := newDefaultTunTestSystemWithDNS(t, &regularTunFactory{}, newRegularTunManager(), proxyFactory)
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.101.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	provider := &inertDNSProvider{requests: make(chan gonnectdns.Request)}
	if err := device.SetDNS(provider); err != nil {
		t.Fatalf("SetDNS(provider) error = %v", err)
	}
	proxy := proxyFactory.proxies[0]
	proxy.mu.Lock()
	gotProvider := proxy.provider
	proxy.mu.Unlock()
	if gotProvider != provider {
		t.Fatal("SetDNS(provider) did not attach the provider")
	}
	if err := device.SetDNS(nil); err != nil {
		t.Fatalf("SetDNS(nil) error = %v", err)
	}
	proxy.mu.Lock()
	gotProvider = proxy.provider
	proxy.mu.Unlock()
	if gotProvider != nil {
		t.Fatal("SetDNS(nil) selected an implicit provider")
	}
	if err := device.Close(); err != nil {
		t.Fatalf("DefaultTun.Close() error = %v", err)
	}
	if !proxy.Closed() {
		t.Fatal("DefaultTun.Close() did not close its DNS proxy")
	}
	if err := device.SetDNS(provider); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("SetDNS() after Close error = %v, want ErrUnknownTun", err)
	}
}

func TestDNSProxyBindFailureCleansStagedDefaultTun(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	bindErr := errors.New("injected DNS bind failure")
	system := newDefaultTunTestSystemWithDNS(t, factory, manager, &fakeDNSProxyFactory{err: bindErr})
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.102.0.1/24"}}); !errors.Is(err, bindErr) {
		t.Fatalf("BuildDefaultTun() error = %v, want bind failure", err)
	}
	if system.defaultTun != nil || len(factory.created) != 1 || !factory.created[0].closed {
		t.Fatal("DNS bind failure left a published or open default TUN")
	}
	metadata := factory.created[0].Metadata()
	iface := netio.Interface{LUID: metadata.LUID, Index: metadata.Index, GUID: metadata.GUID}
	if config := manager.config(iface); !netIOConfigEmpty(config) {
		t.Fatalf("DNS bind failure left NetIO state: %+v", config)
	}
}

func TestDNSProxyBindsAfterAddressAndBeforeDefaultRoute(t *testing.T) {
	tunFactory := &regularTunFactory{}
	manager := newRegularTunManager()
	var observedAddress netip.Addr
	var observedConfig netio.Config
	proxyFactory := &fakeDNSProxyFactory{onCreate: func(address netip.Addr) {
		observedAddress = address
		metadata := tunFactory.created[0].Metadata()
		observedConfig = manager.config(netio.Interface{LUID: metadata.LUID, Index: metadata.Index, GUID: metadata.GUID})
	}}
	system := newDefaultTunTestSystemWithDNS(t, tunFactory, manager, proxyFactory)
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.103.0.1/24"}}); err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	if observedAddress != netip.MustParseAddr("10.103.0.1") {
		t.Fatalf("proxy address = %v, want effective DnsIP", observedAddress)
	}
	if len(observedConfig.Addresses) != 1 || observedConfig.Addresses[0].Addr() != observedAddress {
		t.Fatalf("config when proxy bound = %+v, want usable DNS address", observedConfig)
	}
	if containsRoute(observedConfig.Routes, netip.MustParsePrefix("0.0.0.0/0")) {
		t.Fatal("default route was published before the DNS proxy bound")
	}
}

func TestD13D16DNSConfigurationFailuresRollbackOwnedState(t *testing.T) {
	t.Run("missing API", func(t *testing.T) {
		factory := &regularTunFactory{}
		system := newDefaultTunTestSystemWithDNSConfigurator(t, factory, newRegularTunManager(), nil, &fakeDNSProxyFactory{})
		if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.104.0.1/24"}}); err == nil {
			t.Fatal("BuildDefaultTun() error = nil")
		}
		if len(factory.created) != 0 {
			t.Fatal("missing DNS API created an adapter")
		}
	})

	for _, test := range []struct {
		name       string
		configure  func(*fakeDNSConfigurator)
		wantClosed bool
	}{
		{name: "read denied", configure: func(configurator *fakeDNSConfigurator) {
			configurator.readErr = errors.New("access denied")
		}, wantClosed: true},
		{name: "partial apply", configure: func(configurator *fakeDNSConfigurator) {
			configurator.applyErr = errors.New("partial DNS write")
			configurator.writeOnErr = true
		}, wantClosed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory := &regularTunFactory{}
			configurator := newFakeDNSConfigurator()
			test.configure(configurator)
			proxyFactory := &fakeDNSProxyFactory{}
			system := newDefaultTunTestSystemWithDNSConfigurator(t, factory, newRegularTunManager(), configurator, proxyFactory)
			if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.105.0.1/24"}}); err == nil {
				t.Fatal("BuildDefaultTun() error = nil")
			}
			if system.defaultTun != nil || len(factory.created) != 1 || !factory.created[0].closed {
				t.Fatal("DNS configuration failure leaked the default TUN")
			}
			if len(proxyFactory.proxies) != 1 || proxyFactory.proxies[0].Closed() != test.wantClosed {
				t.Fatal("DNS configuration failure leaked the proxy")
			}
		})
	}
}

func TestD17D20DNSRestorationIsOwnershipAware(t *testing.T) {
	for _, prior := range []internaldns.State{
		{AutomaticIPv4: true, AutomaticIPv6: true, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}},
		{AutomaticIPv6: true, Servers: []netip.Addr{netip.MustParseAddr("198.51.100.53")}},
	} {
		name := "static"
		if prior.AutomaticIPv4 {
			name = "DHCP"
		}
		t.Run(name, func(t *testing.T) {
			factory := &regularTunFactory{}
			configurator := newFakeDNSConfigurator()
			// The test factory assigns its first adapter LUID 101.
			configurator.states[101] = internaldns.CloneState(prior)
			system := newDefaultTunTestSystemWithDNSConfigurator(t, factory, newRegularTunManager(), configurator, &fakeDNSProxyFactory{})
			device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.106.0.1/24"}})
			if err != nil {
				t.Fatalf("BuildDefaultTun() error = %v", err)
			}
			if err := device.Close(); err != nil {
				t.Fatalf("DefaultTun.Close() error = %v", err)
			}
			got, _ := configurator.Read(context.Background(), 101)
			if !internaldns.EqualState(got, prior) {
				t.Fatalf("restored DNS state = %+v, want %+v", got, prior)
			}
		})
	}

	t.Run("external edit", func(t *testing.T) {
		factory := &regularTunFactory{}
		configurator := newFakeDNSConfigurator()
		system := newDefaultTunTestSystemWithDNSConfigurator(t, factory, newRegularTunManager(), configurator, &fakeDNSProxyFactory{})
		device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.107.0.1/24"}})
		if err != nil {
			t.Fatalf("BuildDefaultTun() error = %v", err)
		}
		external := internaldns.State{AutomaticIPv6: true, Servers: []netip.Addr{netip.MustParseAddr("203.0.113.53")}}
		configurator.mu.Lock()
		configurator.states[101] = external
		configurator.mu.Unlock()
		if err := device.Close(); err != nil {
			t.Fatalf("DefaultTun.Close() error = %v", err)
		}
		got, _ := configurator.Read(context.Background(), 101)
		if !internaldns.EqualState(got, external) {
			t.Fatalf("external DNS state was overwritten: %+v", got)
		}
	})
}

func TestDNSConfigurationPreservesOtherFamilyState(t *testing.T) {
	factory := &regularTunFactory{}
	configurator := newFakeDNSConfigurator()
	prior := internaldns.State{
		AutomaticIPv4: true,
		Servers:       []netip.Addr{netip.MustParseAddr("2001:db8::53")},
	}
	configurator.states[101] = internaldns.CloneState(prior)
	system := newDefaultTunTestSystemWithDNSConfigurator(t, factory, newRegularTunManager(), configurator, &fakeDNSProxyFactory{})
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.108.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	wantApplied := internaldns.State{Servers: []netip.Addr{
		netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("10.108.0.1"),
	}}
	got, _ := configurator.Read(context.Background(), 101)
	if !internaldns.EqualState(got, wantApplied) {
		t.Fatalf("applied DNS state = %+v, want %+v", got, wantApplied)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("DefaultTun.Close() error = %v", err)
	}
	got, _ = configurator.Read(context.Background(), 101)
	if !internaldns.EqualState(got, prior) {
		t.Fatalf("restored DNS state = %+v, want %+v", got, prior)
	}
}

func TestD21D28DefaultTunReportsNonexclusiveDNSScope(t *testing.T) {
	system := newDefaultTunTestSystem(t, &regularTunFactory{}, newRegularTunManager())
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"10.109.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	want := []sysnet.Warning{sysnet.WarningDefaultTunDNSRouteNotExclusive}
	if got := system.DefaultTunWarnings(device); !slices.Equal(got, want) {
		t.Fatalf("DefaultTunWarnings(active) = %v, want %v", got, want)
	}
	// The result is a fresh stable-identifier slice. A caller cannot mutate the
	// warning reported by a later call.
	got := system.DefaultTunWarnings(device)
	got[0] = "caller-mutation"
	if next := system.DefaultTunWarnings(device); !slices.Equal(next, want) {
		t.Fatalf("DefaultTunWarnings(after mutation) = %v, want %v", next, want)
	}
	if got := system.DefaultTunWarnings(&defaultTun{}); got != nil {
		t.Fatalf("DefaultTunWarnings(foreign) = %v, want nil", got)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("DefaultTun.Close() error = %v", err)
	}
	if got := system.DefaultTunWarnings(device); got != nil {
		t.Fatalf("DefaultTunWarnings(closed) = %v, want nil", got)
	}
}

func TestM3DefaultTunResourceAccountingCycles(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newDefaultTunTestSystem(t, factory, manager)
	providers := make([]*inertDNSProvider, 2)
	for index := range providers {
		providers[index] = &inertDNSProvider{requests: make(chan gonnectdns.Request)}
	}

	const cycles = 16
	for cycle := range cycles {
		device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
			TunAddrs: []string{fmt.Sprintf("10.110.%d.1/24", cycle)},
		})
		if err != nil {
			t.Fatalf("cycle %d BuildDefaultTun() error = %v", cycle, err)
		}
		// Adapter, base interface settings, addresses/routes, DNS, and default
		// routes have separate ordered ownership records.
		if got := system.journal.Len(); got != 5 {
			t.Fatalf("cycle %d journal entries = %d, want 5", cycle, got)
		}
		if err := device.SetDNS(providers[cycle%len(providers)]); err != nil {
			t.Fatalf("cycle %d SetDNS(provider) error = %v", cycle, err)
		}
		if err := device.SetDNS(nil); err != nil {
			t.Fatalf("cycle %d SetDNS(nil) error = %v", cycle, err)
		}
		owned := device.(*defaultTun)
		if err := device.Close(); err != nil {
			t.Fatalf("cycle %d Close() error = %v", cycle, err)
		}
		if got := system.journal.Len(); got != 0 {
			t.Fatalf("cycle %d journal entries after Close() = %d, want 0", cycle, got)
		}
		if got := manager.config(owned.interfaceID()); !netIOConfigEmpty(got) {
			t.Fatalf("cycle %d retained NetIO state: %+v", cycle, got)
		}
		if !factory.created[cycle].closed {
			t.Fatalf("cycle %d retained an open adapter", cycle)
		}
	}
}

func containsRoute(routes []netio.Route, destination netip.Prefix) bool {
	for _, route := range routes {
		if route.Destination == destination {
			return true
		}
	}
	return false
}

func newDefaultTunTestSystem(t *testing.T, factory *regularTunFactory, manager netio.Manager) *System {
	return newDefaultTunTestSystemWithDNS(t, factory, manager, &fakeDNSProxyFactory{})
}

func newDefaultTunTestSystemWithDNS(t *testing.T, factory *regularTunFactory, manager netio.Manager, dnsFactory internaldns.ProxyFactory) *System {
	return newDefaultTunTestSystemWithDNSConfigurator(t, factory, manager, newFakeDNSConfigurator(), dnsFactory)
}

func newDefaultTunTestSystemWithDNSConfigurator(t *testing.T, factory *regularTunFactory, manager netio.Manager, configurator internaldns.Configurator, dnsFactory internaldns.ProxyFactory) *System {
	t.Helper()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		tunFactory:       factory,
		netIO:            manager,
		allocationReader: emptyHostReader{},
		underlay:         staticUnderlaySource{candidates: []underlay.Candidate{outNetCandidate(false), outNetCandidate(true)}},
		dnsConfigurator:  configurator,
		dnsProxyFactory:  dnsFactory,
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			netIO: available, underlay: available,
		}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close() error = %v", err)
		}
	})
	return system
}

type fakeDNSConfigurator struct {
	mu         sync.Mutex
	states     map[uint64]internaldns.State
	readErr    error
	applyErr   error
	writeOnErr bool
	applyHook  func(uint64, internaldns.State)
}

func newFakeDNSConfigurator() *fakeDNSConfigurator {
	return &fakeDNSConfigurator{states: make(map[uint64]internaldns.State)}
}

func (f *fakeDNSConfigurator) Read(_ context.Context, luid uint64) (internaldns.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return internaldns.State{}, f.readErr
	}
	state, found := f.states[luid]
	if !found {
		state = internaldns.State{AutomaticIPv4: true, AutomaticIPv6: true}
	}
	return internaldns.CloneState(state), nil
}

func (f *fakeDNSConfigurator) Apply(_ context.Context, luid uint64, state internaldns.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyHook != nil {
		f.applyHook(luid, state)
	}
	applyErr := f.applyErr
	if applyErr != nil && !f.writeOnErr {
		return applyErr
	}
	f.states[luid] = internaldns.CloneState(state)
	if f.writeOnErr {
		f.applyErr = nil
	}
	return applyErr
}

type inertDNSProvider struct{ requests chan gonnectdns.Request }

func (p *inertDNSProvider) Requests() chan<- gonnectdns.Request { return p.requests }
func (*inertDNSProvider) Close() error                          { return nil }

type fakeDNSProxyFactory struct {
	mu       sync.Mutex
	proxies  []*fakeDNSProxy
	err      error
	onCreate func(netip.Addr)
}

func (f *fakeDNSProxyFactory) Create(address netip.Addr, _ time.Duration) (internaldns.ManagedProxy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.onCreate != nil {
		f.onCreate(address)
	}
	proxy := &fakeDNSProxy{}
	f.proxies = append(f.proxies, proxy)
	return proxy, nil
}

type fakeDNSProxy struct {
	mu       sync.Mutex
	provider gonnectdns.Interface
	closed   bool
}

func (p *fakeDNSProxy) Attach(provider gonnectdns.Interface) {
	p.mu.Lock()
	p.provider = provider
	p.mu.Unlock()
}

func (p *fakeDNSProxy) Close() error {
	p.mu.Lock()
	p.closed = true
	p.provider = nil
	p.mu.Unlock()
	return nil
}

func (p *fakeDNSProxy) Closed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}
