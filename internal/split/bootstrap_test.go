package split

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
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

	wantOrder := []string{"resolve:C:\\One.exe", "resolve:c:\\one.exe", "initialize", "snapshot", "register", "addresses", "exclusions", "read-event", "read-event"}
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

type bootstrapController struct {
	log             *eventLog
	events          chan Event
	initializeCalls int
	birthsBuffered  bool
	processes       []Process
	paths           []string
}

func newBootstrapController(log *eventLog) *bootstrapController {
	return &bootstrapController{log: log, events: make(chan Event)}
}

func (c *bootstrapController) State(context.Context) (State, error) { return StateStarted, nil }
func (c *bootstrapController) Initialize(context.Context, Sublayers) error {
	c.log.add("initialize")
	c.initializeCalls++
	return nil
}
func (c *bootstrapController) RegisterProcesses(_ context.Context, processes []Process) error {
	c.log.add("register")
	c.processes = cloneProcesses(processes)
	return nil
}
func (c *bootstrapController) SetAddresses(_ context.Context, addresses Addresses) error {
	c.log.add("addresses")
	return nil
}
func (c *bootstrapController) SetExcludedDevicePaths(_ context.Context, paths []string) error {
	c.log.add("exclusions")
	c.paths = append([]string(nil), paths...)
	return nil
}
func (c *bootstrapController) ReadEvent(ctx context.Context) (Event, error) {
	c.log.add("read-event")
	select {
	case event := <-c.events:
		return event, nil
	case <-ctx.Done():
		return Event{}, ctx.Err()
	}
}
func (c *bootstrapController) Reset(context.Context) error { return nil }
func (c *bootstrapController) Close() error                { return nil }

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
