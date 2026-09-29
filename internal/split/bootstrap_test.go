package split

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/sysnet-windows/internal/wfp"
)

func TestBootstrapOrdersCompilationInitializeSnapshotAndPolicy(t *testing.T) {
	t.Parallel()
	log := &eventLog{}
	controller := newBootstrapController(log)
	session := bootstrapSession(controller)
	warning := errors.New("access denied")
	dependencies := Dependencies{
		Resolver: &fakeResolver{log: log, values: map[string]string{
			`C:\One.exe`: `\Device\Volume1\One.exe`,
			`c:\one.exe`: `\device\volume1\one.exe`,
		}},
		Snapshot: fakeSnapshotter{log: log, snapshot: ProcessSnapshot{
			Processes: []Process{{PID: 10, ParentPID: 4}, {PID: 11, ParentPID: 10, ImagePath: `\Device\Volume1\Child.exe`}},
			Warnings:  []ProcessWarning{{PID: 10, Operation: "OpenProcess", Err: warning}},
		}},
	}
	eventSeen := make(chan Event, 1)
	policy, err := Bootstrap(context.Background(), session, dependencies, BootstrapConfig{
		Generation: 7,
		Addresses: Addresses{
			TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.2"),
		},
		Paths:   []string{`C:\One.exe`, `c:\one.exe`},
		OnEvent: func(event Event) { eventSeen <- event },
	})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	controller.events <- Event{PID: 12, Raw: []byte{1}}
	select {
	case event := <-eventSeen:
		if event.PID != 12 {
			t.Fatalf("event PID = %d, want 12", event.PID)
		}
	case <-time.After(time.Second):
		t.Fatal("event reader did not deliver event")
	}
	policy.StopEvents()

	wantOrder := []string{
		"resolve:C:\\One.exe", "resolve:c:\\one.exe", "initialize", "snapshot", "register",
		"get-addresses", "get-exclusions", "addresses", "get-addresses",
		"exclusions", "get-exclusions", "get-addresses", "get-exclusions",
		"read-event", "read-event", "read-event-stop",
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("operation order = %v, want %v", got, wantOrder)
	}
	if got, want := controller.paths, []string{`\Device\Volume1\One.exe`}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	if got := policy.AppliedGeneration(); got != 7 {
		t.Fatalf("generation = %d, want 7", got)
	}
	warnings := policy.Warnings()
	if len(warnings) != 1 || !errors.Is(warnings[0].Err, warning) {
		t.Fatalf("warnings = %+v", warnings)
	}
	warnings[0].Operation = "changed"
	if policy.Warnings()[0].Operation != "OpenProcess" {
		t.Fatal("Warnings() aliases policy storage")
	}
}

func TestBootstrapPreservesPartialProcessesAndBirthsDuringSnapshot(t *testing.T) {
	t.Parallel()
	log := &eventLog{}
	controller := newBootstrapController(log)
	snapshotter := fakeSnapshotter{
		log:        log,
		onSnapshot: func() { controller.birthsBuffered = true },
		snapshot:   ProcessSnapshot{Processes: []Process{{PID: 40, ParentPID: 4}, {PID: 41, ImagePath: ""}}},
	}
	policy, err := Bootstrap(context.Background(), bootstrapSession(controller), Dependencies{
		Resolver: fakeResolver{}, Snapshot: snapshotter,
	}, BootstrapConfig{
		Generation: 1,
		Addresses:  Addresses{TunnelIPv6: netip.MustParseAddr("2001:db8::1"), InternetIPv6: netip.MustParseAddr("2001:db8::2")},
	})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	policy.StopEvents()
	if !controller.birthsBuffered {
		t.Fatal("snapshot ran before Initialize enabled birth buffering")
	}
	if got := controller.processes; !reflect.DeepEqual(got, snapshotter.snapshot.Processes) {
		t.Fatalf("registered processes = %+v, want %+v", got, snapshotter.snapshot.Processes)
	}
}

func TestBootstrapRejectsIncompleteAddressGenerationBeforeMutation(t *testing.T) {
	t.Parallel()
	tests := []Addresses{
		{},
		{TunnelIPv4: netip.MustParseAddr("10.0.0.1")},
		{TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("2001:db8::1")},
		{TunnelIPv6: netip.MustParseAddr("fe80::1%4"), InternetIPv6: netip.MustParseAddr("2001:db8::1")},
	}
	for _, addresses := range tests {
		controller := newBootstrapController(&eventLog{})
		_, err := Bootstrap(context.Background(), bootstrapSession(controller), Dependencies{
			Resolver: fakeResolver{}, Snapshot: fakeSnapshotter{},
		}, BootstrapConfig{Generation: 1, Addresses: addresses})
		if err == nil {
			t.Fatalf("Bootstrap(%+v) succeeded", addresses)
		}
		if controller.initializeCalls != 0 {
			t.Fatalf("Initialize calls = %d after invalid addresses", controller.initializeCalls)
		}
	}
}

func TestBootstrapResolvesCompleteSetBeforeInitialize(t *testing.T) {
	t.Parallel()
	resolveErr := errors.New("path disappeared")
	controller := newBootstrapController(&eventLog{})
	_, err := Bootstrap(context.Background(), bootstrapSession(controller), Dependencies{
		Resolver: &fakeResolver{values: map[string]string{`C:\ok.exe`: `\Device\ok.exe`}, errPath: `C:\bad.exe`, err: resolveErr},
		Snapshot: fakeSnapshotter{},
	}, BootstrapConfig{
		Generation: 1,
		Addresses:  Addresses{TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1")},
		Paths:      []string{`C:\ok.exe`, `C:\bad.exe`},
	})
	if !errors.Is(err, resolveErr) {
		t.Fatalf("Bootstrap() error = %v, want resolver cause", err)
	}
	if controller.initializeCalls != 0 {
		t.Fatalf("Initialize calls = %d, want zero", controller.initializeCalls)
	}
}

func TestPolicyUpdateReplacesCompleteExclusionSetAndAddressGeneration(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	policy := newTestPolicy(t, controller, Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}, []string{`C:\old.exe`})

	paths := []string{`C:\new.exe`, `C:\other.exe`}
	wantAddresses := Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.2"), InternetIPv4: netip.MustParseAddr("198.51.100.2"),
	}
	if err := policy.Update(context.Background(), BootstrapConfig{
		Generation: 2, Addresses: wantAddresses, Paths: paths,
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	paths[0] = `C:\mutated.exe`
	gotAddresses, gotPaths := controller.snapshot()
	if gotAddresses != wantAddresses {
		t.Fatalf("addresses = %+v, want %+v", gotAddresses, wantAddresses)
	}
	if want := []string{`C:\new.exe`, `C:\other.exe`}; !equalPaths(gotPaths, want) {
		t.Fatalf("paths = %v, want complete replacement %v", gotPaths, want)
	}
	if got := policy.AppliedGeneration(); got != 2 {
		t.Fatalf("generation = %d, want 2", got)
	}
}

func TestPolicyReconcilesCommittedCancelledAddressMutationWithFreshReadback(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	policy := newTestPolicy(t, controller, Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}, []string{`C:\app.exe`})
	want := Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("198.51.100.9"),
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	controller.addressMutation = func(_ context.Context, addresses Addresses) error {
		controller.storeAddresses(addresses)
		cancelRequest()
		return context.Canceled
	}
	controller.requireFreshAddressRead = true
	if err := policy.ReconcileAddresses(requestCtx, 2, want); err != nil {
		t.Fatalf("ReconcileAddresses() error = %v", err)
	}
	if !controller.sawFreshAddressRead {
		t.Fatal("address mutation did not use a fresh bounded readback context")
	}
	if got := policy.AppliedGeneration(); got != 2 {
		t.Fatalf("generation = %d, want 2", got)
	}
}

func TestPolicyReconcilesCommittedTimedOutExclusionReplacement(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	addresses := Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}
	policy := newTestPolicy(t, controller, addresses, []string{`C:\old.exe`})
	controller.pathMutation = func(_ context.Context, paths []string) error {
		// Driver readback order and case are not stable.
		controller.storePaths([]string{strings.ToLower(paths[1]), strings.ToLower(paths[0])})
		return context.DeadlineExceeded
	}
	controller.requireFreshPathRead = true
	if err := policy.Update(context.Background(), BootstrapConfig{
		Generation: 2, Addresses: addresses, Paths: []string{`C:\One.exe`, `C:\Two.exe`},
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if !controller.sawFreshPathRead {
		t.Fatal("exclusion mutation did not use a fresh bounded readback context")
	}
	_, gotPaths := controller.snapshot()
	if want := []string{`C:\One.exe`, `C:\Two.exe`}; !equalPaths(gotPaths, want) {
		t.Fatalf("paths = %v, want %v", gotPaths, want)
	}
}

func TestPolicyRestoresPriorGenerationAfterPartialReplacement(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	priorAddresses := Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}
	priorPaths := []string{`C:\old.exe`}
	policy := newTestPolicy(t, controller, priorAddresses, priorPaths)
	failed := errors.New("set configuration failed")
	controller.pathMutation = func(_ context.Context, paths []string) error {
		if equalPaths(paths, []string{`C:\new.exe`}) {
			return failed
		}
		controller.storePaths(paths)
		return nil
	}
	err := policy.Update(context.Background(), BootstrapConfig{
		Generation: 2,
		Addresses: Addresses{
			TunnelIPv4: netip.MustParseAddr("10.0.0.2"), InternetIPv4: netip.MustParseAddr("198.51.100.2"),
		},
		Paths: []string{`C:\new.exe`},
	})
	if !errors.Is(err, failed) || errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Update() error = %v, want mutation failure without recovery", err)
	}
	gotAddresses, gotPaths := controller.snapshot()
	if gotAddresses != priorAddresses || !equalPaths(gotPaths, priorPaths) {
		t.Fatalf("restored policy = %+v %v, want %+v %v", gotAddresses, gotPaths, priorAddresses, priorPaths)
	}
	if got := policy.AppliedGeneration(); got != 1 {
		t.Fatalf("generation = %d after failed replacement, want 1", got)
	}
}

func TestPolicyReportsRecoveryWhenMutationCannotBeReadBack(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	policy := newTestPolicy(t, controller, Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}, nil)
	readErr := errors.New("address query failed")
	controller.addressMutation = func(context.Context, Addresses) error {
		controller.mu.Lock()
		controller.addressReadErrors = append(controller.addressReadErrors, readErr)
		controller.mu.Unlock()
		return context.DeadlineExceeded
	}
	err := policy.ReconcileAddresses(context.Background(), 2, Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("198.51.100.1"),
	})
	if !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, readErr) {
		t.Fatalf("ReconcileAddresses() error = %v, want recovery and readback causes", err)
	}
	if got := policy.AppliedGeneration(); got != 1 {
		t.Fatalf("generation = %d after uncertain mutation, want 1", got)
	}
}

func TestPolicyRejectsStaleGenerationWithoutNativeMutation(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	addresses := Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}
	policy := newTestPolicy(t, controller, addresses, nil)
	called := false
	controller.addressMutation = func(context.Context, Addresses) error {
		called = true
		return nil
	}
	if err := policy.ReconcileAddresses(context.Background(), 1, addresses); err == nil {
		t.Fatal("ReconcileAddresses() accepted the applied generation")
	}
	if called {
		t.Fatal("stale generation caused native mutation")
	}
}

func TestSplittingErrorEventsRequireReadbackWithoutDirectionInference(t *testing.T) {
	t.Parallel()
	controller := newPolicyController()
	errorsSeen := make(chan error, 2)
	policy := bootstrapPolicy(t, controller, Addresses{
		TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
	}, nil, func(err error) { errorsSeen <- err })
	for _, id := range []uint32{EventErrorStartSplitting, EventErrorStopSplitting} {
		controller.events <- Event{ID: id, PID: 42, NTStatus: 0xc0000001}
		select {
		case err := <-errorsSeen:
			var eventErr *EventError
			if !errors.As(err, &eventErr) || eventErr.Event.ID != id {
				t.Fatalf("OnError(%#x) = %v", id, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("event %#x did not report a reconciliation failure", id)
		}
	}
	policy.StopEvents()
}

func TestR37R40PolicyCloseJoinsEventReaderBeforeReset(t *testing.T) {
	t.Parallel()
	log := &eventLog{}
	controller := newBootstrapController(log)
	manager := &fakeWFP{resources: testResources, events: log}
	session, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment, events: log},
		Opener:   fakeOpener{controller: controller, events: log}, WFP: manager,
		CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	policy, err := Bootstrap(context.Background(), session, Dependencies{
		Resolver: fakeResolver{},
		Snapshot: fakeSnapshotter{snapshot: ProcessSnapshot{Processes: []Process{{PID: 4}}}},
	}, BootstrapConfig{
		Generation: 1,
		Addresses: Addresses{
			TunnelIPv4: netip.MustParseAddr("10.0.0.1"), InternetIPv4: netip.MustParseAddr("192.0.2.1"),
		},
	})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if err := policy.Close(); err != nil {
		t.Fatalf("Policy.Close() error = %v", err)
	}
	events := log.snapshot()
	stopIndex := slices.Index(events, "read-event-stop")
	resetIndex := slices.Index(events, "reset")
	deleteIndex := slices.Index(events, "delete-wfp")
	if stopIndex < 0 || resetIndex <= stopIndex || deleteIndex <= resetIndex {
		t.Fatalf("cleanup order = %v, want event-reader stop before reset before WFP delete", events)
	}
}

type bootstrapController struct {
	log             *eventLog
	events          chan Event
	state           State
	initializeCalls int
	birthsBuffered  bool
	processes       []Process
	addresses       Addresses
	paths           []string
}

func newBootstrapController(log *eventLog) *bootstrapController {
	return &bootstrapController{log: log, events: make(chan Event)}
}

func (c *bootstrapController) State(context.Context) (State, error) {
	if c.state == StateNone {
		return StateStarted, nil
	}
	return c.state, nil
}
func (c *bootstrapController) Initialize(context.Context, Sublayers) error {
	c.log.add("initialize")
	c.initializeCalls++
	c.state = StateInitialized
	return nil
}
func (c *bootstrapController) RegisterProcesses(_ context.Context, processes []Process) error {
	c.log.add("register")
	c.processes = cloneProcesses(processes)
	c.state = StateReady
	return nil
}
func (c *bootstrapController) SetAddresses(_ context.Context, addresses Addresses) error {
	c.log.add("addresses")
	c.addresses = addresses
	return nil
}
func (c *bootstrapController) Addresses(context.Context) (Addresses, error) {
	c.log.add("get-addresses")
	return c.addresses, nil
}
func (c *bootstrapController) SetExcludedDevicePaths(_ context.Context, paths []string) error {
	c.log.add("exclusions")
	c.paths = append([]string(nil), paths...)
	c.state = StateEngaged
	return nil
}
func (c *bootstrapController) ExcludedDevicePaths(context.Context) ([]string, error) {
	c.log.add("get-exclusions")
	return append([]string(nil), c.paths...), nil
}
func (c *bootstrapController) ReadEvent(ctx context.Context) (Event, error) {
	c.log.add("read-event")
	select {
	case event := <-c.events:
		return event, nil
	case <-ctx.Done():
		c.log.add("read-event-stop")
		return Event{}, ctx.Err()
	}
}
func (c *bootstrapController) Reset(context.Context) error {
	c.log.add("reset")
	c.state = StateStarted
	return nil
}
func (c *bootstrapController) Close() error { return nil }

func bootstrapSession(controller Controller) *Session {
	return &Session{controller: controller, resources: wfp.Resources{
		Baseline: wfp.Object{Key: "baseline"}, DNS: wfp.Object{Key: "dns"},
	}}
}

type fakeSnapshotter struct {
	log        *eventLog
	snapshot   ProcessSnapshot
	err        error
	onSnapshot func()
}

func (f fakeSnapshotter) Snapshot(context.Context) (ProcessSnapshot, error) {
	f.log.add("snapshot")
	if f.onSnapshot != nil {
		f.onSnapshot()
	}
	return f.snapshot, f.err
}

type fakeResolver struct {
	log     *eventLog
	values  map[string]string
	errPath string
	err     error
}

func (f fakeResolver) Resolve(_ context.Context, path string) (string, error) {
	f.log.add("resolve:" + path)
	if path == f.errPath {
		return "", f.err
	}
	if value, ok := f.values[path]; ok {
		return value, nil
	}
	return path, nil
}

type policyController struct {
	mu                      sync.Mutex
	addresses               Addresses
	paths                   []string
	events                  chan Event
	addressMutation         func(context.Context, Addresses) error
	pathMutation            func(context.Context, []string) error
	addressReadErrors       []error
	requireFreshAddressRead bool
	sawFreshAddressRead     bool
	requireFreshPathRead    bool
	sawFreshPathRead        bool
}

func newPolicyController() *policyController { return &policyController{events: make(chan Event)} }

func (c *policyController) State(context.Context) (State, error)               { return StateEngaged, nil }
func (c *policyController) Initialize(context.Context, Sublayers) error        { return nil }
func (c *policyController) RegisterProcesses(context.Context, []Process) error { return nil }
func (c *policyController) SetAddresses(ctx context.Context, addresses Addresses) error {
	if c.addressMutation != nil {
		return c.addressMutation(ctx, addresses)
	}
	c.storeAddresses(addresses)
	return nil
}
func (c *policyController) Addresses(ctx context.Context) (Addresses, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requireFreshAddressRead && ctx.Err() == nil {
		_, c.sawFreshAddressRead = ctx.Deadline()
	}
	if len(c.addressReadErrors) != 0 {
		err := c.addressReadErrors[0]
		c.addressReadErrors = c.addressReadErrors[1:]
		return Addresses{}, err
	}
	return c.addresses, nil
}
func (c *policyController) SetExcludedDevicePaths(ctx context.Context, paths []string) error {
	if c.pathMutation != nil {
		return c.pathMutation(ctx, append([]string(nil), paths...))
	}
	c.storePaths(paths)
	return nil
}
func (c *policyController) ExcludedDevicePaths(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requireFreshPathRead && ctx.Err() == nil {
		_, c.sawFreshPathRead = ctx.Deadline()
	}
	return append([]string(nil), c.paths...), nil
}
func (c *policyController) ReadEvent(ctx context.Context) (Event, error) {
	select {
	case event := <-c.events:
		return event, nil
	case <-ctx.Done():
		return Event{}, ctx.Err()
	}
}
func (*policyController) Reset(context.Context) error { return nil }
func (*policyController) Close() error                { return nil }

func (c *policyController) storeAddresses(addresses Addresses) {
	c.mu.Lock()
	c.addresses = addresses
	c.mu.Unlock()
}
func (c *policyController) storePaths(paths []string) {
	c.mu.Lock()
	c.paths = append([]string(nil), paths...)
	c.mu.Unlock()
}
func (c *policyController) snapshot() (Addresses, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addresses, append([]string(nil), c.paths...)
}

func newTestPolicy(t *testing.T, controller *policyController, addresses Addresses, paths []string) *Policy {
	t.Helper()
	policy := bootstrapPolicy(t, controller, addresses, paths, nil)
	t.Cleanup(policy.StopEvents)
	return policy
}

func bootstrapPolicy(t *testing.T, controller Controller, addresses Addresses, paths []string, onError func(error)) *Policy {
	t.Helper()
	policy, err := Bootstrap(context.Background(), bootstrapSession(controller), Dependencies{
		Resolver: fakeResolver{}, Snapshot: fakeSnapshotter{snapshot: ProcessSnapshot{Processes: []Process{{PID: 4}}}},
	}, BootstrapConfig{Generation: 1, Addresses: addresses, Paths: paths, OnError: onError})
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	return policy
}
