package windows

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
)

var errInjectedRegularTun = errors.New("injected regular TUN failure")

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

func newRegularTunTestSystem(t *testing.T, factory *regularTunFactory, manager *regularTunManager) *System {
	t.Helper()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
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
	metadata  internaltun.Metadata
	name      string
	mtu       int
	events    chan gtun.Event
	closed    bool
	updateErr error
	closeOnce sync.Once
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
	t.closeOnce.Do(func() {
		t.closed = true
		close(t.events)
	})
	return nil
}

type regularTunManager struct {
	mu             sync.Mutex
	states         map[netio.Interface]netio.Config
	identities     map[uint64]netio.Interface
	applyCalls     int
	failNextApply  error
	mutateThenFail error
	failEmpty      error
	damage         error
}

type regularTunHostReader struct {
	mu     sync.Mutex
	states []netio.HostState
	calls  int
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
		return err
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
	if current, exists := m.identities[iface.LUID]; exists && current != iface {
		return netio.Config{}, netio.ErrIdentityMismatch
	}
	if m.damage != nil {
		return netio.Config{}, m.damage
	}
	return cloneNetIOConfig(m.states[iface]), nil
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
