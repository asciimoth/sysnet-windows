package windows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

var errInjectedRegularTun = errors.New("injected regular TUN failure")

func TestRegularTunUnderlayOwnershipUsesStableAndCurrentIdentity(t *testing.T) {
	t.Parallel()
	system := &System{underlayOwned: make(map[*regularTun]underlay.Interface)}
	device := &regularTun{metadata: internaltun.Metadata{
		LUID: 41, Index: 42, GUID: "{aaaaaaaa-0000-0000-0000-000000000000}",
	}}
	system.registerOwnedUnderlay(device)
	if !system.ownsUnderlayInterface(underlay.Interface{LUID: 41, Index: 42}) {
		t.Fatal("current LUID and index were not recognized as owned")
	}
	if !system.ownsUnderlayInterface(underlay.Interface{
		LUID: 99, Index: 100, GUID: "{AAAAAAAA-0000-0000-0000-000000000000}",
	}) {
		t.Fatal("stable GUID was not recognized as owned after index recreation")
	}
	system.unregisterOwnedUnderlay(device)
	if system.ownsUnderlayInterface(underlay.Interface{LUID: 41, Index: 42}) {
		t.Fatal("closed adapter remained owned")
	}
}

func TestRegularTunLifecycleAndTransactions(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close() error = %v", err)
		}
	})

	device, err := system.BuildTun(sysnet.TunOpts{
		Name:      "private",
		TunAddrs:  []string{"10.19.0.1/24"},
		TunRoutes: []string{"10.20.0.0/16"},
		MTU:       1400,
	})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	if len(factory.configs) != 1 {
		t.Fatalf("factory calls = %d, want 1", len(factory.configs))
	}
	if got := factory.configs[0]; got.Name != "private" || got.NamePrefix != internaltun.DefaultNamePrefix || got.MTU != 1400 {
		t.Fatalf("factory config = %+v", got)
	}
	if got, want := mustGetAddrs(t, system, device), []string{"10.19.0.1/24"}; !slices.Equal(got, want) {
		t.Fatalf("GetTunAddrs() = %v, want %v", got, want)
	}
	if got, want := mustGetRoutes(t, system, device), []string{"10.20.0.0/16"}; !slices.Equal(got, want) {
		t.Fatalf("GetTunRoutes() = %v, want %v", got, want)
	}

	if err := system.AddTunAddr(device, "2001:db8:19::1/64"); err != nil {
		t.Fatalf("AddTunAddr() error = %v", err)
	}
	if err := system.SetTunRoutes(device, []string{"0.0.0.0/0", "2001:db8:20::/64"}); err != nil {
		t.Fatalf("SetTunRoutes() error = %v", err)
	}
	if err := system.SetTunMTU(device, 1300); err != nil {
		t.Fatalf("SetTunMTU() error = %v", err)
	}
	if got, want := mustGetAddrs(t, system, device), []string{"10.19.0.1/24", "2001:db8:19::1/64"}; !sameStrings(got, want) {
		t.Fatalf("GetTunAddrs() = %v, want %v", got, want)
	}
	if got, want := mustGetRoutes(t, system, device), []string{"0.0.0.0/0", "2001:db8:20::/64"}; !sameStrings(got, want) {
		t.Fatalf("GetTunRoutes() = %v, want %v", got, want)
	}
	if mtu, err := device.MTU(); err != nil || mtu != 1300 {
		t.Fatalf("Tun.MTU() = %d, %v; want 1300, nil", mtu, err)
	}
	perTun, err := system.CapabilitiesForTun(device)
	if err != nil {
		t.Fatalf("CapabilitiesForTun() error = %v", err)
	}
	if perTun.InstanceRevision < 4 || len(perTun.Operations) == 0 {
		t.Fatalf("per-TUN capabilities = %+v", perTun)
	}
	if err := perTun.Validate(); err != nil {
		t.Fatalf("per-TUN capabilities are invalid: %v", err)
	}

	if err := device.Close(); err != nil {
		t.Fatalf("Tun.Close() error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Tun.Close() error = %v", err)
	}
	if !factory.created[0].closed {
		t.Fatal("native TUN was not closed")
	}
	if got := manager.config(factory.created[0].interfaceID()); !netIOConfigEmpty(got) {
		t.Fatalf("NetIO state after close = %+v, want empty", got)
	}
	if _, err := system.GetTunAddrs(device); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("GetTunAddrs() after close error = %v, want ErrUnknownTun", err)
	}
	if _, err := device.Write(nil, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write() after close error = %v, want os.ErrClosed", err)
	}
}

func TestRegularTunCloseRetriesAfterTransientBusyRejection(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.212.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	if err := system.beginApply(); err != nil {
		t.Fatalf("beginApply() error = %v", err)
	}
	if err := device.Close(); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("Close() while busy error = %v, want unavailable", err)
	}
	if factory.created[0].closed || system.journal.Len() != 2 {
		t.Fatalf("busy Close() changed ownership: closed=%t journal=%d", factory.created[0].closed, system.journal.Len())
	}
	if err := system.finishApply(true, false); err != nil {
		t.Fatalf("finishApply() error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if !factory.created[0].closed || system.journal.Len() != 0 {
		t.Fatalf("Close() retry cleanup: closed=%t journal=%d", factory.created[0].closed, system.journal.Len())
	}
}

func TestRegularTunConcurrentCloseRetriesSerializeCleanup(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.213.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	if err := system.beginApply(); err != nil {
		t.Fatalf("beginApply() error = %v", err)
	}
	if err := device.Close(); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("Close() while busy error = %v, want unavailable", err)
	}
	if err := system.finishApply(true, false); err != nil {
		t.Fatalf("finishApply() error = %v", err)
	}

	results := make(chan error, 16)
	for range 16 {
		go func() { results <- device.Close() }()
	}
	for range 16 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Close() error = %v", err)
		}
	}
	if got := factory.created[0].closeCalls.Load(); got != 1 {
		t.Fatalf("native Close() calls = %d, want 1", got)
	}
	if system.journal.Len() != 0 {
		t.Fatalf("journal length = %d, want 0", system.journal.Len())
	}
}

func TestRegularTunConcurrentCloseWaitsForActiveCleanup(t *testing.T) {
	factory := &regularTunFactory{}
	manager := &blockingCloseManager{
		Manager: newRegularTunManager(),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.214.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	first := make(chan error, 1)
	go func() { first <- device.Close() }()
	<-manager.started
	second := make(chan error, 1)
	go func() { second <- device.Close() }()
	select {
	case err := <-second:
		close(manager.release)
		t.Fatalf("second Close() returned before active cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(manager.release)
	if err := <-first; err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got := factory.created[0].closeCalls.Load(); got != 1 {
		t.Fatalf("native Close() calls = %d, want 1", got)
	}
}

func TestRegularTunCloseRetainsTerminalVerifiedError(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.215.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	manager.failApplyCall = 2
	manager.failApplyAfterMutation = true
	manager.failApplyErr = errInjectedRegularTun
	for attempt := range 2 {
		if err := device.Close(); !errors.Is(err, errInjectedRegularTun) {
			t.Fatalf("Close() attempt %d error = %v, want injected error", attempt+1, err)
		}
	}
	if !factory.created[0].closed {
		t.Fatal("verified inverse error did not close native TUN")
	}
	if got := factory.created[0].closeCalls.Load(); got != 1 {
		t.Fatalf("native Close() calls = %d, want 1", got)
	}
}

func TestRegularTunAcceptsPreexistingDesiredInterfaceProperties(t *testing.T) {
	t.Parallel()
	iface := netio.Interface{
		LUID: 101, Index: 11, GUID: "{00000000-0000-0000-0000-000000000001}",
	}
	store := &preexistingPropertyStore{state: netio.State{
		Interface: iface,
		Properties: []netio.Properties{
			{Family: netio.FamilyIPv4, MTU: defaultTunMTU, Metric: regularTunRouteMetric},
			{Family: netio.FamilyIPv6, MTU: defaultTunMTU, Metric: regularTunRouteMetric},
		},
	}}
	manager, err := netio.NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	system := newRegularTunTestSystem(t, &regularTunFactory{}, manager)
	t.Cleanup(func() { _ = system.Close() })

	device, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	if _, err := system.GetTunAddrs(device); err != nil {
		t.Fatalf("GetTunAddrs() error = %v", err)
	}
	owned, err := manager.Read(context.Background(), iface)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !netIOConfigEmpty(owned) {
		t.Fatalf("owned NetIO configuration = %+v, want empty", owned)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if store.setCalls != 0 {
		t.Fatalf("SetProperties() calls = %d, want no mutation of preexisting values", store.setCalls)
	}
}

func TestT16T18RegularTunRejectsForeignClosedAndReusedIdentity(t *testing.T) {
	firstFactory := &regularTunFactory{}
	firstManager := newRegularTunManager()
	first := newRegularTunTestSystem(t, firstFactory, firstManager)
	t.Cleanup(func() { _ = first.Close() })
	second := newRegularTunTestSystem(t, &regularTunFactory{}, newRegularTunManager())
	t.Cleanup(func() { _ = second.Close() })

	device, err := first.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.21.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	mutations := firstManager.applyCalls
	if err := second.SetTunAddrs(device, []string{"10.22.0.1/24"}); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("foreign SetTunAddrs() error = %v, want ErrUnknownTun", err)
	}
	if firstManager.applyCalls != mutations {
		t.Fatal("foreign TUN validation changed NetIO state")
	}

	closedDevice, err := first.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("second BuildTun() error = %v", err)
	}
	if err := closedDevice.Close(); err != nil {
		t.Fatalf("second Tun.Close() error = %v", err)
	}
	if err := first.SetTunMTU(closedDevice, 1400); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("closed SetTunMTU() error = %v, want ErrUnknownTun", err)
	}

	mutations = firstManager.applyCalls
	owned := device.(*regularTun)
	firstManager.replaceIdentity(owned.interfaceID(), netio.Interface{
		LUID: owned.metadata.LUID, Index: owned.metadata.Index, GUID: "{ffffffff-ffff-ffff-ffff-ffffffffffff}",
	})
	if _, err := first.GetTunRoutes(device); !errors.Is(err, sysnet.ErrUnknownTun) {
		t.Fatalf("reused identity GetTunRoutes() error = %v, want ErrUnknownTun", err)
	}
	if firstManager.applyCalls != mutations {
		t.Fatal("reused identity check changed NetIO state")
	}
}

func TestT22T24RegularTunExternalChangeHasVisibleFailedState(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)

	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.23.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	manager.damage = netio.ErrResourceConflict
	if _, err := system.GetTunAddrs(device); !errors.Is(err, netio.ErrResourceConflict) || !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("GetTunAddrs() error = %v, want visible recovery failure", err)
	}
	if _, err := system.GetTunAddrs(device); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("second GetTunAddrs() error = %v, want retained failed state", err)
	}
	system.mu.RLock()
	state := system.state
	system.mu.RUnlock()
	if state != lifecycleRecoveryRequired {
		t.Fatalf("System state = %s, want recovery-required", state)
	}
	manager.damage = nil
	if err := system.Close(); err != nil {
		t.Fatalf("System.Close() recovery error = %v", err)
	}
}

func TestRegularTunPublicOperationsHonorLifecycleBeforeNativeRead(t *testing.T) {
	operations := []struct {
		name string
		call func(*System, gtun.Tun) error
	}{
		{name: "capabilities", call: func(system *System, device gtun.Tun) error {
			_, err := system.CapabilitiesForTun(device)
			return err
		}},
		{name: "set MTU", call: func(system *System, device gtun.Tun) error {
			return system.SetTunMTU(device, 1400)
		}},
		{name: "set addresses", call: func(system *System, device gtun.Tun) error {
			return system.SetTunAddrs(device, []string{"10.90.0.1/24"})
		}},
		{name: "add address", call: func(system *System, device gtun.Tun) error {
			return system.AddTunAddr(device, "10.90.0.2/24")
		}},
		{name: "get addresses", call: func(system *System, device gtun.Tun) error {
			_, err := system.GetTunAddrs(device)
			return err
		}},
		{name: "set routes", call: func(system *System, device gtun.Tun) error {
			return system.SetTunRoutes(device, []string{"10.91.0.0/24"})
		}},
		{name: "add route", call: func(system *System, device gtun.Tun) error {
			return system.AddTunRoute(device, "10.92.0.0/24")
		}},
		{name: "get routes", call: func(system *System, device gtun.Tun) error {
			_, err := system.GetTunRoutes(device)
			return err
		}},
		{name: "set name", call: func(system *System, device gtun.Tun) error {
			return system.SetTunName(device, "renamed")
		}},
	}
	for _, state := range []lifecycleState{lifecycleApplying, lifecycleRecoveryRequired, lifecycleClosing} {
		t.Run(state.String(), func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newRegularTunTestSystem(t, factory, manager)
			device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.89.0.1/24"}})
			if err != nil {
				t.Fatalf("BuildTun() error = %v", err)
			}
			system.mu.Lock()
			if err := system.transitionLocked(state); err != nil {
				system.mu.Unlock()
				t.Fatalf("transition to %s: %v", state, err)
			}
			system.rebuildCapabilitiesLocked()
			system.mu.Unlock()
			manager.mu.Lock()
			readsBefore := manager.readCalls
			appliesBefore := manager.applyCalls
			manager.mu.Unlock()

			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.call(system, device); !errors.Is(err, sysnet.ErrUnavailable) {
						t.Fatalf("error = %v, want unavailable", err)
					}
				})
			}
			manager.mu.Lock()
			if manager.readCalls != readsBefore || manager.applyCalls != appliesBefore {
				t.Errorf("rejected operations changed native calls: reads %d->%d, applies %d->%d",
					readsBefore, manager.readCalls, appliesBefore, manager.applyCalls)
			}
			manager.mu.Unlock()
			if err := system.Close(); err != nil {
				t.Fatalf("System.Close() error = %v", err)
			}
		})
	}
}

func TestRegularTunValidationRejectsBeforeNativeRead(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.93.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	manager.mu.Lock()
	readsBefore := manager.readCalls
	appliesBefore := manager.applyCalls
	manager.mu.Unlock()

	operations := []struct {
		name string
		call func() error
	}{
		{name: "MTU", call: func() error { return system.SetTunMTU(device, maxTunMTU+1) }},
		{name: "set addresses", call: func() error { return system.SetTunAddrs(device, []string{"invalid"}) }},
		{name: "add address", call: func() error { return system.AddTunAddr(device, "invalid") }},
		{name: "set routes", call: func() error { return system.SetTunRoutes(device, []string{"invalid"}) }},
		{name: "add route", call: func() error { return system.AddTunRoute(device, "invalid") }},
		{name: "rename", call: func() error { return system.SetTunName(device, "renamed") }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.call(); err == nil {
				t.Fatal("error = nil, want rejection")
			}
		})
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.readCalls != readsBefore || manager.applyCalls != appliesBefore {
		t.Fatalf("rejections changed native calls: reads %d->%d, applies %d->%d",
			readsBefore, manager.readCalls, appliesBefore, manager.applyCalls)
	}
}

func TestRegularTunOperationsHonorRefreshedDependencyBeforeNativeRead(t *testing.T) {
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	unavailable := unavailableCapability(sysnet.ReasonPermissionDenied)
	probe := &sequenceCapabilityProbe{facts: []capabilityProbeFacts{
		{netIO: available, split: available},
		{netIO: available, split: available},
		{netIO: unavailable, split: available},
	}}
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system, err := newSystem(SystemConfig{}, systemDependencies{
		tunFactory: factory, netIO: manager, allocationReader: emptyHostReader{},
		capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.94.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	manager.mu.Lock()
	readsBefore := manager.readCalls
	appliesBefore := manager.applyCalls
	manager.mu.Unlock()

	operations := []struct {
		name string
		call func() error
	}{
		{name: "capabilities", call: func() error {
			_, err := system.CapabilitiesForTun(device)
			return err
		}},
		{name: "set MTU", call: func() error { return system.SetTunMTU(device, 1400) }},
		{name: "set addresses", call: func() error {
			return system.SetTunAddrs(device, []string{"10.95.0.1/24"})
		}},
		{name: "get addresses", call: func() error {
			_, err := system.GetTunAddrs(device)
			return err
		}},
		{name: "set routes", call: func() error {
			return system.SetTunRoutes(device, []string{"10.96.0.0/24"})
		}},
		{name: "get routes", call: func() error {
			_, err := system.GetTunRoutes(device)
			return err
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.call(); !errors.Is(err, sysnet.ErrUnavailable) {
				t.Fatalf("error = %v, want unavailable", err)
			}
		})
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.readCalls != readsBefore || manager.applyCalls != appliesBefore {
		t.Fatalf("rejections changed native calls: reads %d->%d, applies %d->%d",
			readsBefore, manager.readCalls, appliesBefore, manager.applyCalls)
	}
}

func TestT28T30RegularTunBuildFailureRollsBack(t *testing.T) {
	t.Run("factory failure", func(t *testing.T) {
		factory := &regularTunFactory{createErr: errInjectedRegularTun}
		manager := newRegularTunManager()
		system := newRegularTunTestSystem(t, factory, manager)
		t.Cleanup(func() { _ = system.Close() })
		if _, err := system.BuildTun(sysnet.TunOpts{}); !errors.Is(err, errInjectedRegularTun) {
			t.Fatalf("BuildTun() error = %v, want injected error", err)
		}
		if len(factory.created) != 0 || manager.applyCalls != 0 {
			t.Fatalf("failure changed resources: devices=%d applies=%d", len(factory.created), manager.applyCalls)
		}
	})

	t.Run("NetIO apply failure closes adapter", func(t *testing.T) {
		factory := &regularTunFactory{}
		manager := newRegularTunManager()
		manager.failNextApply = errInjectedRegularTun
		system := newRegularTunTestSystem(t, factory, manager)
		t.Cleanup(func() { _ = system.Close() })
		if _, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.24.0.1/24"}}); !errors.Is(err, errInjectedRegularTun) {
			t.Fatalf("BuildTun() error = %v, want injected error", err)
		}
		if len(factory.created) != 1 || !factory.created[0].closed {
			t.Fatalf("created TUN cleanup = %+v", factory.created)
		}
		if got := manager.config(factory.created[0].interfaceID()); !netIOConfigEmpty(got) {
			t.Fatalf("NetIO state after rollback = %+v, want empty", got)
		}
	})

	t.Run("address conflict after adapter creation", func(t *testing.T) {
		factory := &regularTunFactory{}
		manager := newRegularTunManager()
		address := netip.MustParsePrefix("10.24.1.1/24")
		reader := &regularTunHostReader{states: []netio.HostState{
			{},
			{Addresses: []netip.Addr{address.Addr()}},
		}}
		available := sysnet.Capability{State: sysnet.CapabilityAvailable}
		system, err := newSystem(SystemConfig{}, systemDependencies{
			tunFactory: factory, netIO: manager, allocationReader: reader,
			capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
				netIO: available, split: available,
			}},
		})
		if err != nil {
			t.Fatalf("newSystem() error = %v", err)
		}
		t.Cleanup(func() { _ = system.Close() })
		if _, err := system.BuildTun(sysnet.TunOpts{
			TunAddrs: []string{address.String()},
		}); !errors.Is(err, internalallocator.ErrReservationConflict) {
			t.Fatalf("BuildTun() error = %v, want reservation conflict", err)
		}
		if len(factory.created) != 1 || !factory.created[0].closed || manager.applyCalls != 1 ||
			!netIOConfigEmpty(manager.config(factory.created[0].interfaceID())) {
			t.Fatalf("conflict cleanup: devices=%+v applies=%d", factory.created, manager.applyCalls)
		}
	})

	t.Run("configured prefix overlap prevents adapter creation", func(t *testing.T) {
		factory := &regularTunFactory{}
		manager := newRegularTunManager()
		available := sysnet.Capability{State: sysnet.CapabilityAvailable}
		system, err := newSystem(SystemConfig{}, systemDependencies{
			tunFactory: factory, netIO: manager,
			allocationReader: &regularTunHostReader{states: []netio.HostState{{
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.80.20.0/24")},
			}}},
			capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
				netIO: available, split: available,
			}},
		})
		if err != nil {
			t.Fatalf("newSystem() error = %v", err)
		}
		t.Cleanup(func() { _ = system.Close() })
		if _, err := system.BuildTun(sysnet.TunOpts{
			TunAddrs: []string{"10.80.1.1/16"},
		}); !errors.Is(err, internalallocator.ErrReservationConflict) {
			t.Fatalf("BuildTun() error = %v, want reservation conflict", err)
		}
		if len(factory.created) != 0 || manager.applyCalls != 0 {
			t.Fatalf("overlap changed resources: devices=%d applies=%d", len(factory.created), manager.applyCalls)
		}
	})

	t.Run("rollback failure joins errors and requires recovery", func(t *testing.T) {
		factory := &regularTunFactory{}
		manager := newRegularTunManager()
		applyErr := errors.New("apply after mutation")
		rollbackErr := errors.New("rollback failed")
		manager.mutateThenFail = applyErr
		manager.failEmpty = rollbackErr
		system := newRegularTunTestSystem(t, factory, manager)
		err := func() error {
			_, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.25.0.1/24"}})
			return err
		}()
		if !errors.Is(err, applyErr) || !errors.Is(err, rollbackErr) {
			t.Fatalf("BuildTun() error = %v, want joined apply and rollback errors", err)
		}
		if factory.created[0].closed {
			t.Fatal("adapter closed while NetIO rollback remained unverified")
		}
		if system.state != lifecycleRecoveryRequired {
			t.Fatalf("System state = %s, want recovery-required", system.state)
		}
		manager.failEmpty = nil
		if closeErr := system.Close(); closeErr != nil {
			t.Fatalf("recovery Close() error = %v", closeErr)
		}
		if !factory.created[0].closed || !netIOConfigEmpty(manager.config(factory.created[0].interfaceID())) {
			t.Fatal("recovery close did not remove NetIO state before closing the adapter")
		}
	})
}

func TestRegularTunSetterFailurePreservesVerifiedState(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.26.0.1/24"}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	manager.failNextApply = errInjectedRegularTun
	if err := system.SetTunAddrs(device, []string{"10.27.0.1/24"}); !errors.Is(err, errInjectedRegularTun) {
		t.Fatalf("SetTunAddrs() error = %v, want injected error", err)
	}
	if got, want := mustGetAddrs(t, system, device), []string{"10.26.0.1/24"}; !slices.Equal(got, want) {
		t.Fatalf("addresses after failed setter = %v, want %v", got, want)
	}
	native := factory.created[0]
	native.updateErr = errInjectedRegularTun
	if err := system.SetTunMTU(device, 1300); !errors.Is(err, errInjectedRegularTun) {
		t.Fatalf("SetTunMTU() error = %v, want injected report error", err)
	}
	native.updateErr = nil
	if mtu, err := device.MTU(); err != nil || mtu != defaultTunMTU {
		t.Fatalf("MTU after failed setter = %d, %v; want %d, nil", mtu, err, defaultTunMTU)
	}
	config := manager.config(native.interfaceID())
	for _, properties := range config.Properties {
		if properties.MTU != defaultTunMTU {
			t.Fatalf("native MTU after failed setter = %d, want %d", properties.MTU, defaultTunMTU)
		}
	}
}

func TestRegularTunSetMTUUsesEnabledFamilyFloor(t *testing.T) {
	tests := []struct {
		name   string
		config SystemConfig
		raw    int
		want   int
	}{
		{name: "dual family IPv4 minimum", raw: minIPv4MTU, want: defaultTunMTU},
		{name: "dual family below IPv6 minimum", raw: minIPv6MTU - 1, want: defaultTunMTU},
		{name: "dual family IPv6 minimum", raw: minIPv6MTU, want: minIPv6MTU},
		{name: "IPv4 only minimum", config: SystemConfig{Features: FeatureConfig{DisableIPv6: true}}, raw: minIPv4MTU, want: minIPv4MTU},
		{name: "IPv4 only below minimum", config: SystemConfig{Features: FeatureConfig{DisableIPv6: true}}, raw: minIPv4MTU - 1, want: defaultTunMTU},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newRegularTunTestSystemWithConfig(t, test.config, factory, minimumMTUManager{Manager: manager})
			t.Cleanup(func() { _ = system.Close() })
			device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.26.1.1/24"}})
			if err != nil {
				t.Fatalf("BuildTun() error = %v", err)
			}
			if err := system.SetTunMTU(device, test.raw); err != nil {
				t.Fatalf("SetTunMTU(%d) error = %v", test.raw, err)
			}
			if got, err := device.MTU(); err != nil || got != test.want {
				t.Fatalf("MTU() = %d, %v; want %d, nil", got, err, test.want)
			}
		})
	}
}

func TestRegularTunIPv4MTUDoesNotBlockEnabledIPv6Mutations(t *testing.T) {
	tests := []struct {
		name       string
		operation  sysnet.Operation
		mutate     func(*System, gtun.Tun) error
		wantFamily sysnet.AddressFamily
	}{
		{
			name: "set addresses", operation: sysnet.OpSetAddresses, wantFamily: sysnet.FamilyIPv6,
			mutate: func(system *System, device gtun.Tun) error {
				return system.SetTunAddrs(device, []string{"fd26::1/64"})
			},
		},
		{
			name: "add address", operation: sysnet.OpAddAddress, wantFamily: sysnet.FamilyDual,
			mutate: func(system *System, device gtun.Tun) error {
				return system.AddTunAddr(device, "fd26::1/64")
			},
		},
		{
			name: "set routes", operation: sysnet.OpSetRoutes, wantFamily: sysnet.FamilyDual,
			mutate: func(system *System, device gtun.Tun) error {
				return system.SetTunRoutes(device, []string{"fd26:1::/64"})
			},
		},
		{
			name: "add route", operation: sysnet.OpAddRoute, wantFamily: sysnet.FamilyDual,
			mutate: func(system *System, device gtun.Tun) error {
				return system.AddTunRoute(device, "fd26:1::/64")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newRegularTunTestSystem(t, factory, minimumMTUManager{Manager: manager})
			t.Cleanup(func() { _ = system.Close() })
			device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.26.1.1/24"}})
			if err != nil {
				t.Fatalf("BuildTun() error = %v", err)
			}
			if err := system.SetTunMTU(device, minIPv4MTU); err != nil {
				t.Fatalf("SetTunMTU() error = %v", err)
			}
			if got, err := device.MTU(); err != nil || got != defaultTunMTU {
				t.Fatalf("MTU() = %d, %v; want %d, nil", got, err, defaultTunMTU)
			}
			capabilities, err := system.CapabilitiesForTun(device)
			if err != nil {
				t.Fatalf("CapabilitiesForTun() error = %v", err)
			}
			capability := capabilities.Operation(sysnet.OperationKey{
				Target: sysnet.TargetTun, Operation: test.operation, Family: test.wantFamily,
			})
			if capability.State != sysnet.CapabilityAvailable {
				t.Fatalf("%s capability = %v, want available", test.operation, capability.State)
			}
			if err := test.mutate(system, device); err != nil {
				t.Fatalf("mutation error = %v", err)
			}
			config := manager.config(factory.created[0].interfaceID())
			for _, properties := range config.Properties {
				if properties.Family == netio.FamilyIPv6 && properties.MTU < minIPv6MTU {
					t.Fatalf("IPv6 MTU = %d, want at least %d", properties.MTU, minIPv6MTU)
				}
			}
		})
	}
}

func TestRegularTunVerifiedNetIOErrorsRemainRetryable(t *testing.T) {
	tests := []struct {
		name      string
		netIOErr  error
		operation func(*System, gtun.Tun) error
		verifyOld func(*testing.T, *System, gtun.Tun)
	}{
		{
			name: "address readback", netIOErr: netio.ErrReadback,
			operation: func(system *System, device gtun.Tun) error {
				return system.SetTunAddrs(device, []string{"10.27.1.1/24"})
			},
			verifyOld: func(t *testing.T, system *System, device gtun.Tun) {
				t.Helper()
				if got, want := mustGetAddrs(t, system, device), []string{"10.26.1.1/24"}; !slices.Equal(got, want) {
					t.Fatalf("addresses after verified rollback = %v, want %v", got, want)
				}
			},
		},
		{
			name: "route conflict", netIOErr: netio.ErrResourceConflict,
			operation: func(system *System, device gtun.Tun) error {
				return system.SetTunRoutes(device, []string{"10.29.0.0/16"})
			},
			verifyOld: func(t *testing.T, system *System, device gtun.Tun) {
				t.Helper()
				if got, want := mustGetRoutes(t, system, device), []string{"10.28.0.0/16"}; !slices.Equal(got, want) {
					t.Fatalf("routes after verified rollback = %v, want %v", got, want)
				}
			},
		},
		{
			name: "MTU readback", netIOErr: netio.ErrReadback,
			operation: func(system *System, device gtun.Tun) error {
				return system.SetTunMTU(device, 1300)
			},
			verifyOld: func(t *testing.T, _ *System, device gtun.Tun) {
				t.Helper()
				if got, err := device.MTU(); err != nil || got != defaultTunMTU {
					t.Fatalf("MTU after verified rollback = %d, %v; want %d, nil", got, err, defaultTunMTU)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newRegularTunTestSystem(t, factory, manager)
			t.Cleanup(func() { _ = system.Close() })
			device, err := system.BuildTun(sysnet.TunOpts{
				TunAddrs: []string{"10.26.1.1/24"}, TunRoutes: []string{"10.28.0.0/16"},
			})
			if err != nil {
				t.Fatalf("BuildTun() error = %v", err)
			}

			manager.failNextApply = errors.Join(errInjectedRegularTun, test.netIOErr)
			err = test.operation(system, device)
			if !errors.Is(err, errInjectedRegularTun) || netio.RequiresRecovery(err) {
				t.Fatalf("first operation error = %v, want verified non-recovery failure", err)
			}
			test.verifyOld(t, system, device)
			if system.state != lifecycleActive {
				t.Fatalf("System state = %s, want active", system.state)
			}
			if err := test.operation(system, device); err != nil {
				t.Fatalf("retry operation error = %v", err)
			}
		})
	}
}

func TestRegularTunNetIOErrorRequiresVerifiedPreviousState(t *testing.T) {
	tests := []struct {
		name      string
		afterFail func(*regularTunManager, netio.Interface)
		wantCause error
	}{
		{
			name: "changed state",
			afterFail: func(manager *regularTunManager, iface netio.Interface) {
				changed := manager.states[iface]
				changed.Addresses = []netip.Prefix{netip.MustParsePrefix("10.31.1.1/24")}
				manager.states[iface] = changed
			},
		},
		{
			name: "read failure",
			afterFail: func(manager *regularTunManager, _ netio.Interface) {
				manager.damage = errInjectedRegularTun
			},
			wantCause: errInjectedRegularTun,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newRegularTunTestSystem(t, factory, manager)
			device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.30.1.1/24"}})
			if err != nil {
				t.Fatalf("BuildTun() error = %v", err)
			}
			manager.failNextApply = netio.ErrReadback
			manager.afterNextApplyFailure = test.afterFail
			err = system.SetTunAddrs(device, []string{"10.31.1.1/24"})
			if !errors.Is(err, sysnet.ErrUnavailable) || !errors.Is(err, netio.ErrReadback) {
				t.Fatalf("SetTunAddrs() error = %v, want unavailable readback failure", err)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("SetTunAddrs() error = %v, want cause %v", err, test.wantCause)
			}
			if system.state != lifecycleRecoveryRequired {
				t.Fatalf("System state = %s, want recovery-required", system.state)
			}
			manager.damage = nil
			if err := system.Close(); err != nil {
				t.Fatalf("System.Close() error = %v", err)
			}
		})
	}
}

func TestRegularTunMTURestoreErrorUsesVerifiedState(t *testing.T) {
	t.Run("restored state remains usable", func(t *testing.T) {
		factory := &regularTunFactory{}
		manager := newRegularTunManager()
		system := newRegularTunTestSystem(t, factory, manager)
		t.Cleanup(func() { _ = system.Close() })
		device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.32.1.1/24"}})
		if err != nil {
			t.Fatalf("BuildTun() error = %v", err)
		}
		factory.created[0].updateErr = errInjectedRegularTun
		manager.failApplyCall = manager.applyCalls + 2
		manager.failApplyErr = netio.ErrReadback
		manager.failApplyAfterMutation = true
		err = system.SetTunMTU(device, 1300)
		if !errors.Is(err, errInjectedRegularTun) || !errors.Is(err, netio.ErrReadback) {
			t.Fatalf("SetTunMTU() error = %v, want report and rollback errors", err)
		}
		if system.state != lifecycleActive {
			t.Fatalf("System state = %s, want active", system.state)
		}
		if got, mtuErr := device.MTU(); mtuErr != nil || got != defaultTunMTU {
			t.Fatalf("MTU after restore = %d, %v; want %d, nil", got, mtuErr, defaultTunMTU)
		}
		factory.created[0].updateErr = nil
		if err := system.SetTunMTU(device, 1300); err != nil {
			t.Fatalf("retry SetTunMTU() error = %v", err)
		}
	})

	for _, rollbackErr := range []error{errInjectedRegularTun, netio.ErrReadback} {
		name := "plain error"
		if errors.Is(rollbackErr, netio.ErrReadback) {
			name = "readback error"
		}
		t.Run("unrestored state with "+name, func(t *testing.T) {
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newRegularTunTestSystem(t, factory, manager)
			device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"10.33.1.1/24"}})
			if err != nil {
				t.Fatalf("BuildTun() error = %v", err)
			}
			factory.created[0].updateErr = errInjectedRegularTun
			manager.failApplyCall = manager.applyCalls + 2
			manager.failApplyErr = rollbackErr
			err = system.SetTunMTU(device, 1300)
			if !errors.Is(err, sysnet.ErrUnavailable) || !errors.Is(err, rollbackErr) {
				t.Fatalf("SetTunMTU() error = %v, want unavailable rollback failure", err)
			}
			if system.state != lifecycleRecoveryRequired {
				t.Fatalf("System state = %s, want recovery-required", system.state)
			}
			manager.failApplyCall = 0
			manager.failApplyErr = nil
			factory.created[0].updateErr = nil
			if err := system.Close(); err != nil {
				t.Fatalf("System.Close() error = %v", err)
			}
		})
	}
}

func TestRegularTunPrefixExpansionRejectsNewHostOverlap(t *testing.T) {
	t.Parallel()
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	oldPrefix := netip.MustParsePrefix("10.81.1.1/24")
	foreignPrefix := netip.MustParsePrefix("10.81.2.0/24")
	reader := &regularTunHostReader{states: []netio.HostState{
		{},
		{},
		{
			Addresses:         []netip.Addr{oldPrefix.Addr()},
			InterfacePrefixes: []netip.Prefix{oldPrefix.Masked(), foreignPrefix},
		},
	}}
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		tunFactory: factory, netIO: manager, allocationReader: reader,
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			netIO: available, split: available,
		}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{oldPrefix.String()}})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	applyCalls := manager.applyCalls
	if err := system.SetTunAddrs(device, []string{"10.81.1.1/16"}); !errors.Is(err, internalallocator.ErrReservationConflict) {
		t.Fatalf("SetTunAddrs() error = %v, want ErrReservationConflict", err)
	}
	if manager.applyCalls != applyCalls {
		t.Fatalf("rejected prefix expansion made %d NetIO applies, want %d", manager.applyCalls, applyCalls)
	}
	if got := mustGetAddrs(t, system, device); !slices.Equal(got, []string{oldPrefix.String()}) {
		t.Fatalf("GetTunAddrs() after rejection = %v, want [%s]", got, oldPrefix)
	}
}

func TestRegularTunRejectsDuplicateAddressBeforeAdapterCreation(t *testing.T) {
	t.Parallel()
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	t.Cleanup(func() { _ = system.Close() })

	_, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{
		"10.82.1.1/24",
		"10.82.1.1/16",
	}})
	if !errors.Is(err, sysnet.ErrInvalidOptions) {
		t.Fatalf("BuildTun() error = %v, want ErrInvalidOptions", err)
	}
	if len(factory.created) != 0 || manager.applyCalls != 0 {
		t.Fatalf("invalid addresses changed resources: devices=%d applies=%d", len(factory.created), manager.applyCalls)
	}
}

func TestRegularTunCreateUseCloseLoop(t *testing.T) {
	factory := &regularTunFactory{}
	manager := newRegularTunManager()
	system := newRegularTunTestSystem(t, factory, manager)
	for iteration := range 25 {
		address := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 40, byte(iteration), 1}), 24).String()
		device, err := system.BuildTun(sysnet.TunOpts{TunAddrs: []string{address}})
		if err != nil {
			t.Fatalf("iteration %d: BuildTun() error = %v", iteration, err)
		}
		if _, err := system.GetTunAddrs(device); err != nil {
			t.Fatalf("iteration %d: GetTunAddrs() error = %v", iteration, err)
		}
		if err := device.Close(); err != nil {
			t.Fatalf("iteration %d: Close() error = %v", iteration, err)
		}
		if got := system.journal.Len(); got != 0 {
			t.Fatalf("iteration %d: journal entries after Close() = %d, want 0", iteration, got)
		}
	}
	for _, native := range factory.created {
		if !native.closed || !netIOConfigEmpty(manager.config(native.interfaceID())) {
			t.Fatalf("loop leaked native or NetIO state for %+v", native.metadata)
		}
	}
	if err := system.Close(); err != nil {
		t.Fatalf("System.Close() error = %v", err)
	}
}

func newRegularTunTestSystem(t *testing.T, factory *regularTunFactory, manager netio.Manager) *System {
	return newRegularTunTestSystemWithConfig(t, SystemConfig{}, factory, manager)
}

func newRegularTunTestSystemWithConfig(
	t *testing.T,
	config SystemConfig,
	factory *regularTunFactory,
	manager netio.Manager,
) *System {
	t.Helper()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(config, systemDependencies{
		tunFactory:       factory,
		netIO:            manager,
		allocationReader: emptyHostReader{},
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			netIO: available, split: available,
		}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	return system
}

func mustGetAddrs(t *testing.T, system *System, device gtun.Tun) []string {
	t.Helper()
	result, err := system.GetTunAddrs(device)
	if err != nil {
		t.Fatalf("GetTunAddrs() error = %v", err)
	}
	return result
}

func mustGetRoutes(t *testing.T, system *System, device gtun.Tun) []string {
	t.Helper()
	result, err := system.GetTunRoutes(device)
	if err != nil {
		t.Fatalf("GetTunRoutes() error = %v", err)
	}
	return result
}

func sameStrings(left, right []string) bool {
	return len(left) == len(right) && slices.ContainsFunc(left, func(value string) bool {
		return slices.Contains(right, value)
	})
}

type staticCapabilityProbe struct {
	facts capabilityProbeFacts
}

func (p staticCapabilityProbe) Probe(context.Context) capabilityProbeFacts { return p.facts }

type regularTunFactory struct {
	mu        sync.Mutex
	configs   []internaltun.Config
	created   []*fakeManagedTun
	createErr error
}

func (f *regularTunFactory) Create(_ context.Context, config internaltun.Config) (internaltun.ManagedTun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs = append(f.configs, config)
	if f.createErr != nil {
		return nil, f.createErr
	}
	id := uint64(len(f.created) + 1)
	device := &fakeManagedTun{
		metadata: internaltun.Metadata{
			GUID:  "{00000000-0000-0000-0000-" + twelveDigits(id) + "}",
			LUID:  100 + id,
			Index: uint32(10 + id),
		},
		name:   config.Name,
		mtu:    config.MTU,
		events: make(chan gtun.Event),
	}
	f.created = append(f.created, device)
	return device, nil
}

func twelveDigits(value uint64) string {
	const digits = "000000000000"
	text := []byte(digits)
	for index := len(text) - 1; value != 0 && index >= 0; index-- {
		text[index] = byte('0' + value%10)
		value /= 10
	}
	return string(text)
}

type fakeManagedTun struct {
	metadata   internaltun.Metadata
	name       string
	mtu        int
	events     chan gtun.Event
	closed     bool
	updateErr  error
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func (t *fakeManagedTun) interfaceID() netio.Interface {
	return netio.Interface{LUID: t.metadata.LUID, Index: t.metadata.Index, GUID: t.metadata.GUID}
}
func (*fakeManagedTun) File() *os.File { return nil }
func (*fakeManagedTun) IsNative() bool { return true }
func (t *fakeManagedTun) Read([][]byte, []int, int) (int, error) {
	if t.closed {
		return 0, os.ErrClosed
	}
	return 0, nil
}
func (t *fakeManagedTun) Write(bufs [][]byte, _ int) (int, error) {
	if t.closed {
		return 0, os.ErrClosed
	}
	return len(bufs), nil
}
func (*fakeManagedTun) MWO() int                         { return 0 }
func (*fakeManagedTun) MRO() int                         { return 0 }
func (t *fakeManagedTun) MTU() (int, error)              { return t.mtu, nil }
func (t *fakeManagedTun) Name() (string, error)          { return t.name, nil }
func (t *fakeManagedTun) Events() <-chan gtun.Event      { return t.events }
func (*fakeManagedTun) BatchSize() int                   { return 1 }
func (t *fakeManagedTun) Metadata() internaltun.Metadata { return t.metadata }
func (t *fakeManagedTun) UpdateReportedMTU(mtu int) error {
	if t.closed {
		return os.ErrClosed
	}
	if t.updateErr != nil {
		return t.updateErr
	}
	t.mtu = mtu
	return nil
}
func (t *fakeManagedTun) Close() error {
	t.closeCalls.Add(1)
	t.closeOnce.Do(func() {
		t.closed = true
		close(t.events)
	})
	return nil
}

type blockingCloseManager struct {
	netio.Manager
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type minimumMTUManager struct{ netio.Manager }

func (m minimumMTUManager) Apply(ctx context.Context, iface netio.Interface, config netio.Config) error {
	for _, properties := range config.Properties {
		minimum := uint32(minIPv4MTU)
		if properties.Family == netio.FamilyIPv6 {
			minimum = minIPv6MTU
		}
		if properties.MTU < minimum {
			return fmt.Errorf("%w: IPv%d MTU %d is below %d", netio.ErrInvalidConfig,
				properties.Family, properties.MTU, minimum)
		}
	}
	return m.Manager.Apply(ctx, iface, config)
}

func (m *blockingCloseManager) Apply(ctx context.Context, iface netio.Interface, config netio.Config) error {
	if netIOConfigEmpty(config) {
		m.once.Do(func() { close(m.started) })
		select {
		case <-m.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.Manager.Apply(ctx, iface, config)
}

type regularTunManager struct {
	mu                     sync.Mutex
	states                 map[netio.Interface]netio.Config
	identities             map[uint64]netio.Interface
	applyCalls             int
	readCalls              int
	failNextApply          error
	afterNextApplyFailure  func(*regularTunManager, netio.Interface)
	failApplyCall          int
	failApplyErr           error
	failApplyAfterMutation bool
	mutateThenFail         error
	failEmpty              error
	damage                 error
}

type regularTunHostReader struct {
	mu     sync.Mutex
	states []netio.HostState
	calls  int
}

type preexistingPropertyStore struct {
	state    netio.State
	setCalls int
}

func (s *preexistingPropertyStore) Snapshot(context.Context, netio.Interface) (netio.State, error) {
	return s.state, nil
}

func (*preexistingPropertyStore) CreateAddress(context.Context, netio.Interface, netip.Prefix) error {
	return errors.New("unexpected CreateAddress call")
}

func (*preexistingPropertyStore) DeleteAddress(context.Context, netio.Interface, netip.Prefix) error {
	return errors.New("unexpected DeleteAddress call")
}

func (*preexistingPropertyStore) WaitAddressUsable(context.Context, netio.Interface, netip.Addr) error {
	return errors.New("unexpected WaitAddressUsable call")
}

func (*preexistingPropertyStore) CreateRoute(context.Context, netio.Interface, netio.Route) error {
	return errors.New("unexpected CreateRoute call")
}

func (*preexistingPropertyStore) DeleteRoute(context.Context, netio.Interface, netio.Route) error {
	return errors.New("unexpected DeleteRoute call")
}

func (s *preexistingPropertyStore) SetProperties(context.Context, netio.Interface, netio.Properties) error {
	s.setCalls++
	return errors.New("unexpected SetProperties call")
}

func (r *regularTunHostReader) ReadHostState(context.Context) (netio.HostState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := min(r.calls, len(r.states)-1)
	r.calls++
	return r.states[index], nil
}

func newRegularTunManager() *regularTunManager {
	return &regularTunManager{
		states:     make(map[netio.Interface]netio.Config),
		identities: make(map[uint64]netio.Interface),
	}
}

func (m *regularTunManager) Apply(_ context.Context, iface netio.Interface, config netio.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyCalls++
	if current, exists := m.identities[iface.LUID]; exists && current != iface {
		return netio.ErrIdentityMismatch
	}
	m.identities[iface.LUID] = iface
	if m.failNextApply != nil {
		err := m.failNextApply
		m.failNextApply = nil
		if m.afterNextApplyFailure != nil {
			after := m.afterNextApplyFailure
			m.afterNextApplyFailure = nil
			after(m, iface)
		}
		return err
	}
	if m.failApplyCall == m.applyCalls {
		if m.failApplyAfterMutation {
			m.states[iface] = cloneNetIOConfig(config)
		}
		return m.failApplyErr
	}
	if netIOConfigEmpty(config) && m.failEmpty != nil {
		return m.failEmpty
	}
	m.states[iface] = cloneNetIOConfig(config)
	if m.mutateThenFail != nil {
		err := m.mutateThenFail
		m.mutateThenFail = nil
		return err
	}
	return nil
}

func (m *regularTunManager) Read(_ context.Context, iface netio.Interface) (netio.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readCalls++
	if current, exists := m.identities[iface.LUID]; exists && current != iface {
		return netio.Config{}, netio.ErrIdentityMismatch
	}
	if m.damage != nil {
		return netio.Config{}, m.damage
	}
	return cloneNetIOConfig(m.states[iface]), nil
}

func (m *regularTunManager) Verify(_ context.Context, iface netio.Interface, want netio.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readCalls++
	if current, exists := m.identities[iface.LUID]; exists && current != iface {
		return netio.ErrIdentityMismatch
	}
	if m.damage != nil {
		return m.damage
	}
	if !netIOConfigEqual(m.states[iface], want) {
		return netio.ErrReadback
	}
	return nil
}

func (m *regularTunManager) config(iface netio.Interface) netio.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneNetIOConfig(m.states[iface])
}

func (m *regularTunManager) replaceIdentity(old, replacement netio.Interface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identities[old.LUID] = replacement
}

var (
	_ internaltun.Factory    = (*regularTunFactory)(nil)
	_ internaltun.ManagedTun = (*fakeManagedTun)(nil)
	_ netio.Manager          = (*regularTunManager)(nil)
)
