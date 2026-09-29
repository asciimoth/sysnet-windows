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
		"close-controller", "delete-wfp", "close-wfp",
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
			session, err := Acquire(context.Background(), Dependencies{
				Verifier: fakeVerifier{deployment: testDeployment},
				Opener:   fakeOpener{controller: &fakeController{state: StateStarted}}, WFP: manager,
			})
			if err != nil {
				t.Fatalf("Acquire() error = %v", err)
			}
			session.MarkDriverReferences()
			if test.confirmed {
				session.MarkResetConfirmed()
			}
			err = session.Close()
			if errors.Is(err, ErrRecoveryRequired) != test.wantRecovery {
				t.Fatalf("Close() error = %v, want recovery=%v", err, test.wantRecovery)
			}
			if (manager.deleteCalls != 0) != test.wantDelete {
				t.Fatalf("delete calls = %d, want delete=%v", manager.deleteCalls, test.wantDelete)
			}
			if secondErr := session.Close(); !errors.Is(secondErr, err) {
				t.Fatalf("second Close() error = %v, want cached %v", secondErr, err)
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
	state              State
	stateErr, closeErr error
	events             *eventLog
}

func (f *fakeController) State(context.Context) (State, error) {
	f.events.add("state")
	return f.state, f.stateErr
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
