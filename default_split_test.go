package windows

import (
	"context"
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
func (*defaultSplitNative) Close() error                                              { return nil }

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
	mu         sync.Mutex
	state      split.State
	processes  []split.Process
	addresses  split.Addresses
	paths      []string
	events     chan split.Event
	resetCalls int
}

func (c *defaultSplitController) State(context.Context) (split.State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, nil
}
func (c *defaultSplitController) Initialize(context.Context, split.Sublayers) error {
	c.mu.Lock()
	c.state = split.StateInitialized
	c.mu.Unlock()
	return nil
}
func (c *defaultSplitController) RegisterProcesses(_ context.Context, processes []split.Process) error {
	c.mu.Lock()
	c.processes = append([]split.Process(nil), processes...)
	c.state = split.StateReady
	c.mu.Unlock()
	return nil
}
func (c *defaultSplitController) SetAddresses(_ context.Context, addresses split.Addresses) error {
	c.mu.Lock()
	c.addresses = addresses
	c.mu.Unlock()
	return nil
}
func (c *defaultSplitController) Addresses(context.Context) (split.Addresses, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addresses, nil
}
func (c *defaultSplitController) SetExcludedDevicePaths(_ context.Context, paths []string) error {
	c.mu.Lock()
	c.paths = append([]string(nil), paths...)
	c.state = split.StateEngaged
	c.mu.Unlock()
	return nil
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
	c.resetCalls++
	c.state = split.StateStarted
	c.mu.Unlock()
	return nil
}
func (*defaultSplitController) Close() error { return nil }
