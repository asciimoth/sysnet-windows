package windows

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/split"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
	"github.com/asciimoth/sysnet-windows/internal/wfp"
)

func TestR09R16R33R36DefaultTunBootstrapsExclusions(t *testing.T) {
	controller := &defaultSplitController{state: split.StateStarted}
	native := &defaultSplitNative{controller: controller}
	system := newDefaultTunTestSystem(t, &regularTunFactory{}, newRegularTunManager())
	system.dependencies.splitDependencies = split.Dependencies{
		Verifier: defaultSplitVerifier{},
		Opener:   native,
		WFP:      defaultSplitWFPFactory{manager: native},
		Snapshot: defaultSplitSnapshotter{snapshot: split.ProcessSnapshot{
			Processes: []split.Process{{PID: 100, ParentPID: 4}, {PID: 101, ParentPID: 100, ImagePath: `\Device\Volume1\child.exe`}},
			Warnings:  []split.ProcessWarning{{PID: 100, Operation: "OpenProcess"}},
		}},
		Resolver:       defaultSplitResolver{},
		CleanupTimeout: system.config.operationTimeout,
	}
	// The test installs its fake optional dependency after the common fixture
	// constructor. Restore the unresolved state that the native constructor has.
	system.probeFacts.split = sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun}}
	system.rebuildCapabilitiesLocked()

	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.99.0.1/24"},
		Exclude:  []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\Program Files\Excluded App\app.exe`}},
	})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	owned := device.(*defaultTun)
	if owned.splitPolicy == nil || owned.splitPolicy.AppliedGeneration() != owned.id {
		t.Fatalf("applied split generation = %d, want %d", owned.splitPolicy.AppliedGeneration(), owned.id)
	}
	if got, want := owned.splitPolicy.Warnings(), []split.ProcessWarning{{PID: 100, Operation: "OpenProcess"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot warnings = %+v, want %+v", got, want)
	}

	controller.mu.Lock()
	gotProcesses := append([]split.Process(nil), controller.processes...)
	gotAddresses := controller.addresses
	gotPaths := append([]string(nil), controller.paths...)
	controller.mu.Unlock()
	if want := (split.Addresses{TunnelIPv4: netip.MustParseAddr("10.99.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.10")}); gotAddresses != want {
		t.Fatalf("split addresses = %+v, want %+v", gotAddresses, want)
	}
	if len(gotProcesses) != 2 || gotProcesses[0].ImagePath != "" {
		t.Fatalf("registered partial process snapshot = %+v", gotProcesses)
	}
	if want := []string{`\Device\Volume1\Program Files\Excluded App\app.exe`}; !reflect.DeepEqual(gotPaths, want) {
		t.Fatalf("excluded device paths = %v, want %v", gotPaths, want)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("DefaultTun.Close() error = %v", err)
	}
	controller.mu.Lock()
	resetCalls := controller.resetCalls
	controller.mu.Unlock()
	if resetCalls != 1 || native.deleteCalls != 1 {
		t.Fatalf("cleanup reset calls = %d, WFP delete calls = %d, want 1 and 1", resetCalls, native.deleteCalls)
	}
}

func TestDefaultTunRejectsMissingSplitBootstrapBeforeMutation(t *testing.T) {
	factory := &regularTunFactory{}
	system := newDefaultTunTestSystem(t, factory, newRegularTunManager())
	_, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.99.0.1/24"},
		Exclude:  []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\missing.exe`}},
	})
	if err == nil {
		t.Fatal("BuildDefaultTun() error = nil")
	}
	if len(factory.created) != 0 {
		t.Fatalf("created adapters = %d, want zero", len(factory.created))
	}
}

func TestM6SplitBootstrapFailurePointsCleanEveryOwnedResource(t *testing.T) {
	injected := errors.New("injected split bootstrap failure")
	tests := []struct {
		name          string
		configure     func(*defaultSplitController)
		wantBuild     bool
		wantResetCall int
	}{
		{name: "before initialize", configure: func(controller *defaultSplitController) {
			controller.initializeErr = injected
		}, wantResetCall: 0},
		{name: "after initialize", configure: func(controller *defaultSplitController) {
			controller.initializeErr = injected
			controller.initializeAfterMutation = true
		}, wantResetCall: 1},
		{name: "before process registration", configure: func(controller *defaultSplitController) {
			controller.registerErr = injected
		}, wantResetCall: 1},
		{name: "after process registration", configure: func(controller *defaultSplitController) {
			controller.registerErr = injected
			controller.registerAfterMutation = true
		}, wantResetCall: 1},
		{name: "before address mutation", configure: func(controller *defaultSplitController) {
			controller.addressErr = injected
		}, wantResetCall: 1},
		{name: "after address mutation", configure: func(controller *defaultSplitController) {
			controller.addressErr = injected
			controller.addressAfterMutation = true
		}, wantBuild: true, wantResetCall: 1},
		{name: "before exclusion mutation", configure: func(controller *defaultSplitController) {
			controller.exclusionErr = injected
		}, wantResetCall: 1},
		{name: "after exclusion mutation", configure: func(controller *defaultSplitController) {
			controller.exclusionErr = injected
			controller.exclusionAfterMutation = true
		}, wantBuild: true, wantResetCall: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &defaultSplitController{state: split.StateStarted}
			test.configure(controller)
			native := &defaultSplitNative{controller: controller}
			factory := &regularTunFactory{}
			manager := newRegularTunManager()
			system := newDefaultTunTestSystem(t, factory, manager)
			system.dependencies.splitDependencies = split.Dependencies{
				Verifier: defaultSplitVerifier{}, Opener: native,
				WFP: defaultSplitWFPFactory{manager: native},
				Snapshot: defaultSplitSnapshotter{snapshot: split.ProcessSnapshot{
					Processes: []split.Process{{PID: 4}},
				}},
				Resolver: defaultSplitResolver{}, CleanupTimeout: time.Second,
			}
			system.probeFacts.split = sysnet.Capability{
				State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
			}
			system.rebuildCapabilitiesLocked()

			device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
				TunAddrs: []string{"10.98.0.1/24"},
				Exclude:  []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\excluded.exe`}},
			})
			if test.wantBuild {
				if err != nil || device == nil {
					t.Fatalf("BuildDefaultTun() = %v, %v; committed mutation must reconcile as success", device, err)
				}
				if err := device.Close(); err != nil {
					t.Fatalf("DefaultTun.Close() error = %v", err)
				}
			} else if device != nil || !errors.Is(err, injected) {
				t.Fatalf("BuildDefaultTun() = %v, %v; want nil and injected failure", device, err)
			}
			if native.deleteCalls != 1 {
				t.Fatalf("WFP delete calls = %d, want 1", native.deleteCalls)
			}
			if controller.resetCalls != test.wantResetCall {
				t.Fatalf("driver reset calls = %d, want %d", controller.resetCalls, test.wantResetCall)
			}
			if system.journal.Len() != 0 {
				t.Fatalf("journal entries = %d after verified cleanup, want 0", system.journal.Len())
			}
			if len(factory.created) != 1 || !factory.created[0].closed {
				t.Fatalf("adapter cleanup = %+v, want one closed adapter", factory.created)
			}
			if got := manager.config(factory.created[0].interfaceID()); !netIOConfigEmpty(got) {
				t.Fatalf("retained NetIO state = %+v", got)
			}
			system.mu.RLock()
			state := system.state
			system.mu.RUnlock()
			if state != lifecycleReady {
				t.Fatalf("System state = %s, want ready after verified cleanup", state)
			}
		})
	}
}

func TestR37R44DefaultTunPreservesSplitJournalButCleansOrdinaryState(t *testing.T) {
	resetErr := errors.New("split reset failed")
	controller := &defaultSplitController{state: split.StateStarted}
	native := &defaultSplitNative{controller: controller}
	system := newDefaultTunTestSystem(t, &regularTunFactory{}, newRegularTunManager())
	system.dependencies.splitDependencies = split.Dependencies{
		Verifier: defaultSplitVerifier{}, Opener: native,
		WFP:      defaultSplitWFPFactory{manager: native},
		Snapshot: defaultSplitSnapshotter{snapshot: split.ProcessSnapshot{Processes: []split.Process{{PID: 4}}}},
		Resolver: defaultSplitResolver{}, CleanupTimeout: time.Second,
	}
	system.probeFacts.split = sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun}}
	system.rebuildCapabilitiesLocked()

	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.99.0.1/24"},
		Exclude:  []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\excluded.exe`}},
	})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	owned := device.(*defaultTun)
	controller.mu.Lock()
	controller.resetErr = resetErr
	controller.resetState = split.StateEngaged
	controller.mu.Unlock()

	err = device.Close()
	if !errors.Is(err, resetErr) || !errors.Is(err, split.ErrRecoveryRequired) {
		t.Fatalf("DefaultTun.Close() error = %v, want reset and recovery errors", err)
	}
	if got := system.journal.Len(); got != 1 {
		t.Fatalf("journal entries after failed split cleanup = %d, want 1", got)
	}
	if owned.dnsProxy == nil || !owned.dnsProxy.Closed() || !owned.closed.Load() {
		t.Fatalf("ordinary cleanup: DNS closed=%t adapter closed=%t", owned.dnsProxy != nil && owned.dnsProxy.Closed(), owned.closed.Load())
	}
	if system.defaultTun != nil || system.activeSplitTun.Load() != nil {
		t.Fatal("closed default TUN remained published during split recovery")
	}
	if native.deleteCalls != 0 {
		t.Fatalf("WFP delete calls = %d before reset confirmation, want 0", native.deleteCalls)
	}
	system.mu.RLock()
	state := system.state
	system.mu.RUnlock()
	if state != lifecycleRecoveryRequired {
		t.Fatalf("System state = %s, want recovery-required", state)
	}

	controller.mu.Lock()
	controller.resetErr = nil
	controller.resetState = split.StateStarted
	controller.mu.Unlock()
	if err := system.Close(); err != nil {
		t.Fatalf("System.Close() recovery error = %v", err)
	}
	if got := system.journal.Len(); got != 0 || native.deleteCalls != 1 {
		t.Fatalf("recovery journal=%d WFP deletes=%d, want 0 and 1", got, native.deleteCalls)
	}
}

func TestDefaultTunReconcilesSplitAddressesAndDriverErrorsAsNewGenerations(t *testing.T) {
	source := &mutableUnderlaySource{candidates: []underlay.Candidate{outNetCandidate(false)}}
	controller := &defaultSplitController{state: split.StateStarted, events: make(chan split.Event, 2)}
	native := &defaultSplitNative{controller: controller}
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{OperationTimeout: time.Second}, systemDependencies{
		tunFactory: &regularTunFactory{}, netIO: newRegularTunManager(), allocationReader: emptyHostReader{},
		underlay: source, dnsConfigurator: newFakeDNSConfigurator(), dnsProxyFactory: &fakeDNSProxyFactory{},
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{netIO: available, underlay: available}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close() error = %v", err)
		}
	})
	system.dependencies.splitDependencies = split.Dependencies{
		Verifier: defaultSplitVerifier{}, Opener: native,
		WFP:      defaultSplitWFPFactory{manager: native},
		Snapshot: defaultSplitSnapshotter{snapshot: split.ProcessSnapshot{Processes: []split.Process{{PID: 4}}}},
		Resolver: defaultSplitResolver{}, CleanupTimeout: time.Second,
	}
	system.probeFacts.split = sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun}}
	system.rebuildCapabilitiesLocked()

	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.99.0.1/24"},
		Exclude:  []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\excluded.exe`}},
	})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	owned := device.(*defaultTun)
	initialGeneration := owned.splitPolicy.AppliedGeneration()

	candidate := outNetCandidate(false)
	candidate.Addresses = []underlay.Address{{Address: netip.MustParseAddr("198.51.100.20"), Usable: true}}
	source.set([]underlay.Candidate{candidate})
	if err := system.underlayMonitor.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	waitForSplitGeneration(t, owned.splitPolicy, initialGeneration+1)
	if got := owned.splitPolicy.AppliedAddresses().InternetIPv4; got != netip.MustParseAddr("198.51.100.20") {
		t.Fatalf("reconciled Internet IPv4 = %s", got)
	}

	beforeError := owned.splitPolicy.AppliedGeneration()
	controller.events <- split.Event{ID: split.EventErrorStopSplitting, PID: 99, NTStatus: 0xc0000001}
	waitForSplitGeneration(t, owned.splitPolicy, beforeError+1)
	controller.mu.Lock()
	gotPaths := append([]string(nil), controller.paths...)
	controller.mu.Unlock()
	if want := []string{`\Device\Volume1\Program Files\Excluded App\app.exe`}; !reflect.DeepEqual(gotPaths, want) {
		t.Fatalf("error readback changed exclusions: %v, want %v", gotPaths, want)
	}
}

func waitForSplitGeneration(t *testing.T, policy *split.Policy, minimum uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if policy.AppliedGeneration() >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("split generation = %d, want at least %d", policy.AppliedGeneration(), minimum)
}

type defaultSplitVerifier struct{}

func (defaultSplitVerifier) Verify(context.Context) (split.Deployment, error) {
	return split.Deployment{
		ServiceName: "split", BinaryPath: `C:\driver.sys`, Signer: "trusted", SHA256: "digest",
		Version: "1.3.0.0", ABI: "1.3.0.0",
	}, nil
}

type defaultSplitNative struct {
	controller  split.Controller
	deleteCalls int
}

func (n *defaultSplitNative) Open() (split.Controller, error) { return n.controller, nil }
func (n *defaultSplitNative) CreateSplitResources(context.Context) (wfp.Resources, error) {
	return wfp.Resources{
		Provider: wfp.Object{Kind: wfp.KindProvider, Key: "10000000-0000-0000-0000-000000000001"},
		Baseline: wfp.Object{Kind: wfp.KindBaselineSublayer, Key: "10000000-0000-0000-0000-000000000002"},
		DNS:      wfp.Object{Kind: wfp.KindDNSSublayer, Key: "10000000-0000-0000-0000-000000000003"},
	}, nil
}
func (n *defaultSplitNative) DeleteSplitResources(context.Context, wfp.Resources) error {
	n.deleteCalls++
	return nil
}
func (*defaultSplitNative) VerifySplitResources(context.Context, wfp.Resources) error { return nil }
func (*defaultSplitNative) VerifySplitResourcesAbsent(context.Context, wfp.Resources) error {
	return nil
}
func (*defaultSplitNative) Close() error { return nil }

// Open satisfies both split.Opener and wfp.Factory through different Go method
// signatures, which cannot coexist. The adapter below supplies the WFP side.
type defaultSplitWFPFactory struct{ manager *defaultSplitNative }

func (f defaultSplitWFPFactory) Open(context.Context) (wfp.Manager, error) { return f.manager, nil }

type defaultSplitSnapshotter struct{ snapshot split.ProcessSnapshot }

func (s defaultSplitSnapshotter) Snapshot(context.Context) (split.ProcessSnapshot, error) {
	return s.snapshot, nil
}

type defaultSplitResolver struct{}

func (defaultSplitResolver) Resolve(_ context.Context, path string) (string, error) {
	return `\Device\Volume1\Program Files\Excluded App\app.exe`, nil
}

type defaultSplitController struct {
	mu                      sync.Mutex
	state                   split.State
	resetState              split.State
	resetErr                error
	initializeErr           error
	initializeAfterMutation bool
	registerErr             error
	registerAfterMutation   bool
	addressErr              error
	addressAfterMutation    bool
	exclusionErr            error
	exclusionAfterMutation  bool
	processes               []split.Process
	addresses               split.Addresses
	paths                   []string
	events                  chan split.Event
	resetCalls              int
}

func (c *defaultSplitController) State(context.Context) (split.State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, nil
}
func (c *defaultSplitController) Initialize(context.Context, split.Sublayers) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initializeErr != nil && !c.initializeAfterMutation {
		return c.initializeErr
	}
	c.state = split.StateInitialized
	return c.initializeErr
}
func (c *defaultSplitController) RegisterProcesses(_ context.Context, processes []split.Process) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.registerErr != nil && !c.registerAfterMutation {
		return c.registerErr
	}
	c.processes = append([]split.Process(nil), processes...)
	c.state = split.StateReady
	return c.registerErr
}
func (c *defaultSplitController) SetAddresses(_ context.Context, addresses split.Addresses) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.addressErr != nil && !c.addressAfterMutation {
		return c.addressErr
	}
	c.addresses = addresses
	return c.addressErr
}
func (c *defaultSplitController) Addresses(context.Context) (split.Addresses, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addresses, nil
}
func (c *defaultSplitController) SetExcludedDevicePaths(_ context.Context, paths []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exclusionErr != nil && !c.exclusionAfterMutation {
		return c.exclusionErr
	}
	c.paths = append([]string(nil), paths...)
	c.state = split.StateEngaged
	return c.exclusionErr
}
func (c *defaultSplitController) ExcludedDevicePaths(context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.paths...), nil
}
func (c *defaultSplitController) ReadEvent(ctx context.Context) (split.Event, error) {
	if c.events == nil {
		<-ctx.Done()
		return split.Event{}, ctx.Err()
	}
	select {
	case event := <-c.events:
		return event, nil
	case <-ctx.Done():
		return split.Event{}, ctx.Err()
	}
}
func (c *defaultSplitController) Reset(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetCalls++
	if c.resetState != split.StateNone {
		c.state = c.resetState
	} else if c.resetErr == nil {
		c.state = split.StateStarted
	}
	return c.resetErr
}
func (*defaultSplitController) Close() error { return nil }
