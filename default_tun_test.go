package windows

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
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
	manager.failApplyCall = manager.applyCalls + 4
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

func containsRoute(routes []netio.Route, destination netip.Prefix) bool {
	for _, route := range routes {
		if route.Destination == destination {
			return true
		}
	}
	return false
}

func newDefaultTunTestSystem(t *testing.T, factory *regularTunFactory, manager netio.Manager) *System {
	t.Helper()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		tunFactory:       factory,
		netIO:            manager,
		allocationReader: emptyHostReader{},
		underlay:         staticUnderlaySource{candidates: []underlay.Candidate{outNetCandidate(false), outNetCandidate(true)}},
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
