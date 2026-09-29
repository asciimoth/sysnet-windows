package split

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/sysnet-windows/internal/wfp"
)

var testDeployment = Deployment{
	ServiceName: "mullvad-split-tunnel", BinaryPath: `C:\Windows\System32\drivers\mullvad-split-tunnel.sys`,
	Signer: "CN=Mullvad VPN AB", SHA256: "0123456789abcdef", Version: "1.3.0.0", ABI: "1.3.0.0",
}

var testResources = wfp.Resources{
	Provider: wfp.Object{Kind: wfp.KindProvider, Key: "provider"},
	Baseline: wfp.Object{Kind: wfp.KindBaselineSublayer, Key: "baseline"},
	DNS:      wfp.Object{Kind: wfp.KindDNSSublayer, Key: "dns"},
	Filters:  []wfp.Object{{Kind: wfp.KindFilter, Key: "filter"}},
}

func TestAcquireOrdersVerificationOpenStateAndCommittedWFP(t *testing.T) {
	t.Parallel()
	events := &eventLog{}
	controller := &fakeController{state: StateStarted, events: events}
	manager := &fakeWFP{resources: testResources, events: events}
	session, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment, events: events},
		Opener:   fakeOpener{controller: controller, events: events}, WFP: manager,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if got, want := events.snapshot(), []string{"verify-deployment", "open", "state", "open-wfp", "create-wfp", "verify-wfp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	resources := session.Resources()
	resources.Filters[0].Key = "changed"
	if got := session.Resources().Filters[0].Key; got != "filter" {
		t.Fatalf("Resources() aliases session journal: %q", got)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, want := events.snapshot(), []string{
		"verify-deployment", "open", "state", "open-wfp", "create-wfp", "verify-wfp",
		"delete-wfp", "verify-wfp-absent", "close-controller", "close-wfp",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("close events = %v, want %v", got, want)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestAcquireRejectsForeignAndUnknownDriverStatesWithoutWFPChanges(t *testing.T) {
	t.Parallel()
	states := []State{StateNone, StateInitialized, StateReady, StateEngaged, StateZombie, State(99)}
	for _, state := range states {
		state := state
		t.Run(state.String(), func(t *testing.T) {
			t.Parallel()
			events := &eventLog{}
			_, err := Acquire(context.Background(), Dependencies{
				Verifier: fakeVerifier{deployment: testDeployment, events: events},
				Opener:   fakeOpener{controller: &fakeController{state: state, events: events}, events: events},
				WFP:      &fakeWFP{resources: testResources, events: events},
			})
			if !errors.Is(err, ErrDirty) {
				t.Fatalf("Acquire() error = %v, want ErrDirty", err)
			}
			if got, want := events.snapshot(), []string{"verify-deployment", "open", "state", "close-controller"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
		})
	}
}

func TestAcquireClassifiesCompetingOwnerAndPreservesCause(t *testing.T) {
	t.Parallel()
	nativeErr := errors.New("sharing violation")
	_, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment},
		Opener:   fakeOpener{err: errors.Join(ErrBusy, nativeErr)}, WFP: &fakeWFP{},
	})
	if !errors.Is(err, ErrBusy) || !errors.Is(err, nativeErr) {
		t.Fatalf("Acquire() error = %v, want busy and native causes", err)
	}
}

func TestAcquireRejectsIncompleteProvenanceBeforeOpening(t *testing.T) {
	t.Parallel()
	events := &eventLog{}
	deployment := testDeployment
	deployment.Signer = ""
	_, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: deployment, events: events},
		Opener:   fakeOpener{controller: &fakeController{}, events: events}, WFP: &fakeWFP{},
	})
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("Acquire() error = %v, want ErrIncompatible", err)
	}
	if got, want := events.snapshot(), []string{"verify-deployment"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestAcquireRejectsIncompatibleABI(t *testing.T) {
	t.Parallel()
	deployment := testDeployment
	deployment.Version = "1.2.5.0"
	_, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: deployment},
		Opener:   fakeOpener{controller: &fakeController{}}, WFP: &fakeWFP{},
	})
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("Acquire() error = %v, want ErrIncompatible", err)
	}
}

func TestAcquireRollsBackUnverifiedWFPWithFreshBoundedContext(t *testing.T) {
	t.Parallel()
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	manager := &fakeWFP{resources: testResources, verifyErr: errors.New("missing DNS sublayer")}
	manager.onVerify = cancelRequest
	_, err := Acquire(requestCtx, Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment},
		Opener:   fakeOpener{controller: &fakeController{state: StateStarted}}, WFP: manager,
		CleanupTimeout: time.Second,
	})
	if !errors.Is(err, manager.verifyErr) {
		t.Fatalf("Acquire() error = %v, want verification failure", err)
	}
	if !manager.deleteContextActive || !manager.deleteHasDeadline {
		t.Fatalf("rollback context active=%v deadline=%v", manager.deleteContextActive, manager.deleteHasDeadline)
	}
}

func TestAcquireRetainsJournalWhenWFPVerificationCleanupFails(t *testing.T) {
	t.Parallel()
	manager := &fakeWFP{
		resources: testResources, verifyErr: errors.New("readback failed"),
		deleteErr: errors.New("delete failed"),
	}
	_, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment},
		Opener:   fakeOpener{controller: &fakeController{state: StateStarted}}, WFP: manager,
	})
	if !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, manager.deleteErr) {
		t.Fatalf("Acquire() error = %v, want recovery and delete errors", err)
	}
	var recovery *RecoveryError
	if !errors.As(err, &recovery) || !reflect.DeepEqual(recovery.Resources, testResources) {
		t.Fatalf("recovery journal = %+v, want %+v", recovery, testResources)
	}
}

func TestConcurrentCloseWaitsAndReturnsTheSameError(t *testing.T) {
	t.Parallel()
	manager := &fakeWFP{
		resources: testResources, deleteStarted: make(chan struct{}),
		continueDelete: make(chan struct{}), deleteErr: errors.New("delete failed"),
	}
	session, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment},
		Opener:   fakeOpener{controller: &fakeController{state: StateStarted}}, WFP: manager,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- session.Close() }()
	<-manager.deleteStarted
	go func() { second <- session.Close() }()
	select {
	case earlyErr := <-second:
		t.Fatalf("concurrent Close() returned before cleanup: %v", earlyErr)
	case <-time.After(20 * time.Millisecond):
	}
	close(manager.continueDelete)
	firstErr, secondErr := <-first, <-second
	if !errors.Is(firstErr, manager.deleteErr) || !errors.Is(secondErr, manager.deleteErr) {
		t.Fatalf("Close() errors = %v and %v, want delete failure", firstErr, secondErr)
	}
}

func TestSessionPreservesReferencedObjectsUntilResetIsConfirmed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		confirmed    bool
		wantDelete   bool
		wantRecovery bool
	}{
		{name: "uncertain reset", wantRecovery: true},
		{name: "confirmed reset", confirmed: true, wantDelete: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			manager := &fakeWFP{resources: testResources}
			controller := &fakeController{state: StateStarted}
			session, err := Acquire(context.Background(), Dependencies{
				Verifier: fakeVerifier{deployment: testDeployment},
				Opener:   fakeOpener{controller: controller}, WFP: manager,
			})
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			session.MarkDriverReferences()
			if test.confirmed {
				session.MarkResetConfirmed()
			} else {
				controller.state = StateEngaged
			}
			err = session.Close()
			if errors.Is(err, ErrRecoveryRequired) != test.wantRecovery {
				t.Fatalf("Close() error = %v, want recovery=%v", err, test.wantRecovery)
			}
			if (manager.deleteCalls != 0) != test.wantDelete {
				t.Fatalf("delete calls = %d, want delete=%v", manager.deleteCalls, test.wantDelete)
			}
			if secondErr := session.Close(); errors.Is(secondErr, ErrRecoveryRequired) != test.wantRecovery {
				t.Fatalf("second Close() error = %v, want recovery=%v", secondErr, test.wantRecovery)
			}
		})
	}
}

func TestSessionRetriesUnverifiedWFPDeletion(t *testing.T) {
	t.Parallel()
	deleteErr := errors.New("WFP delete failed")
	manager := &fakeWFP{resources: testResources, deleteErr: deleteErr}
	session, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment},
		Opener:   fakeOpener{controller: &fakeController{state: StateStarted}}, WFP: manager,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := session.Close(); !errors.Is(err, deleteErr) || !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("first Close() error = %v, want delete and recovery errors", err)
	}
	if session.Cleaned() {
		t.Fatal("failed WFP absence readback marked the session clean")
	}
	manager.deleteErr = nil
	if err := session.Close(); err != nil {
		t.Fatalf("recovery Close() error = %v", err)
	}
	if manager.deleteCalls != 2 || !session.Cleaned() {
		t.Fatalf("delete calls=%d cleaned=%t, want 2 and true", manager.deleteCalls, session.Cleaned())
	}
}

func TestR37R40SessionReconcilesCommittedResetError(t *testing.T) {
	t.Parallel()
	events := &eventLog{}
	resetErr := errors.New("reset completion was uncertain")
	started := StateStarted
	controller := &fakeController{state: StateStarted, events: events}
	manager := &fakeWFP{resources: testResources, events: events}
	session, err := Acquire(context.Background(), Dependencies{
		Verifier: fakeVerifier{deployment: testDeployment, events: events},
		Opener:   fakeOpener{controller: controller, events: events}, WFP: manager,
		CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	session.MarkDriverReferences()
	controller.state = StateEngaged
	controller.resetErr = resetErr
	controller.resetState = &started

	err = session.Close()
	if !errors.Is(err, resetErr) || errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Close() error = %v, want verified reset error without recovery", err)
	}
	if !controller.resetContextActive || !controller.resetHasDeadline {
		t.Fatalf("reset context active=%t deadline=%t", controller.resetContextActive, controller.resetHasDeadline)
	}
	if !session.Cleaned() || manager.deleteCalls != 1 {
		t.Fatalf("cleaned=%t delete calls=%d, want true and 1", session.Cleaned(), manager.deleteCalls)
	}
}

func TestR37R40SessionRetainsJournalAndRetriesExplicitRecovery(t *testing.T) {
	t.Parallel()
	controller := &fakeController{state: StateStarted}
	manager := &fakeWFP{resources: testResources}
	verifier := &fakeVerifier{deployment: testDeployment}
	session, err := Acquire(context.Background(), Dependencies{
		Verifier: verifier, Opener: fakeOpener{controller: controller}, WFP: manager,
		CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	session.MarkDriverReferences()
	controller.state = StateEngaged
	if err := session.Close(); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("first Close() error = %v, want recovery required", err)
	}
	if session.Cleaned() || manager.deleteCalls != 0 {
		t.Fatalf("failed recovery cleaned=%t delete calls=%d", session.Cleaned(), manager.deleteCalls)
	}

	started := StateStarted
	controller.resetState = &started
	if err := session.Close(); err != nil {
		t.Fatalf("recovery Close() error = %v", err)
	}
	if !session.Cleaned() || manager.deleteCalls != 1 || controller.resetCalls != 2 {
		t.Fatalf("recovery cleaned=%t delete calls=%d reset calls=%d", session.Cleaned(), manager.deleteCalls, controller.resetCalls)
	}
}

func TestR37R40SessionRejectsZombieAndChangedDeployment(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*fakeVerifier, *fakeController, *fakeWFP)
	}{
		{name: "zombie", mutate: func(_ *fakeVerifier, controller *fakeController, _ *fakeWFP) { controller.state = StateZombie }},
		{name: "changed deployment", mutate: func(verifier *fakeVerifier, _ *fakeController, _ *fakeWFP) { verifier.deployment.SHA256 = "different" }},
		{name: "changed WFP journal", mutate: func(_ *fakeVerifier, _ *fakeController, manager *fakeWFP) {
			manager.verifyErr = errors.New("journal differs")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			controller := &fakeController{state: StateStarted}
			manager := &fakeWFP{resources: testResources}
			verifier := &fakeVerifier{deployment: testDeployment}
			session, err := Acquire(context.Background(), Dependencies{
				Verifier: verifier, Opener: fakeOpener{controller: controller}, WFP: manager,
			})
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			session.MarkDriverReferences()
			test.mutate(verifier, controller, manager)
			if err := session.Close(); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("Close() error = %v, want recovery required", err)
			}
			if controller.resetCalls != 0 || manager.deleteCalls != 0 || session.Cleaned() {
				t.Fatalf("unsafe cleanup: reset=%d delete=%d cleaned=%t", controller.resetCalls, manager.deleteCalls, session.Cleaned())
			}
		})
	}
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}
func (l *eventLog) snapshot() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type fakeVerifier struct {
	deployment Deployment
	err        error
	events     *eventLog
}

func (f fakeVerifier) Verify(context.Context) (Deployment, error) {
	f.events.add("verify-deployment")
	return f.deployment, f.err
}

type fakeOpener struct {
	controller Controller
	err        error
	events     *eventLog
}

func (f fakeOpener) Open() (Controller, error) { f.events.add("open"); return f.controller, f.err }

type fakeController struct {
	state                                State
	stateErr, resetErr, closeErr         error
	resetState                           *State
	resetCalls                           int
	resetContextActive, resetHasDeadline bool
	events                               *eventLog
}

func (f *fakeController) State(context.Context) (State, error) {
	f.events.add("state")
	return f.state, f.stateErr
}
func (f *fakeController) Initialize(context.Context, Sublayers) error            { return nil }
func (f *fakeController) RegisterProcesses(context.Context, []Process) error     { return nil }
func (f *fakeController) SetAddresses(context.Context, Addresses) error          { return nil }
func (f *fakeController) Addresses(context.Context) (Addresses, error)           { return Addresses{}, nil }
func (f *fakeController) SetExcludedDevicePaths(context.Context, []string) error { return nil }
func (f *fakeController) ExcludedDevicePaths(context.Context) ([]string, error)  { return nil, nil }
func (f *fakeController) ReadEvent(ctx context.Context) (Event, error) {
	<-ctx.Done()
	return Event{}, ctx.Err()
}
func (f *fakeController) Reset(ctx context.Context) error {
	f.events.add("reset")
	f.resetCalls++
	f.resetContextActive = ctx.Err() == nil
	_, f.resetHasDeadline = ctx.Deadline()
	if f.resetState != nil {
		f.state = *f.resetState
	}
	return f.resetErr
}
func (f *fakeController) Close() error { f.events.add("close-controller"); return f.closeErr }

type fakeWFP struct {
	resources                                 wfp.Resources
	createErr, verifyErr, deleteErr, closeErr error
	events                                    *eventLog
	onVerify                                  func()
	deleteCalls                               int
	deleteContextActive, deleteHasDeadline    bool
	deleteStarted, continueDelete             chan struct{}
}

func (f *fakeWFP) Open(context.Context) (wfp.Manager, error) {
	f.events.add("open-wfp")
	return f, nil
}

func (f *fakeWFP) CreateSplitResources(context.Context) (wfp.Resources, error) {
	f.events.add("create-wfp")
	return f.resources, f.createErr
}
func (f *fakeWFP) VerifySplitResources(context.Context, wfp.Resources) error {
	f.events.add("verify-wfp")
	if f.onVerify != nil {
		f.onVerify()
	}
	return f.verifyErr
}
func (f *fakeWFP) VerifySplitResourcesAbsent(context.Context, wfp.Resources) error {
	f.events.add("verify-wfp-absent")
	return f.deleteErr
}
func (f *fakeWFP) DeleteSplitResources(ctx context.Context, _ wfp.Resources) error {
	f.events.add("delete-wfp")
	f.deleteCalls++
	f.deleteContextActive = ctx.Err() == nil
	_, f.deleteHasDeadline = ctx.Deadline()
	if f.deleteStarted != nil {
		close(f.deleteStarted)
	}
	if f.continueDelete != nil {
		<-f.continueDelete
	}
	return f.deleteErr
}
func (f *fakeWFP) Close() error { f.events.add("close-wfp"); return f.closeErr }
