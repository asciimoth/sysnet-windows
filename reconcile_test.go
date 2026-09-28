package windows

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
)

func TestSystemCloseOrdersResourcesBeforeHostRollback(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	if system.worker != nil {
		t.Fatal("newSystem() started a policy worker")
	}
	var mu sync.Mutex
	var events []string
	appendEvent := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}
	entry := reconcile.Entry{
		Key: reconcile.OwnershipKey{Kind: reconcile.KindAdapter, ID: "adapter-guid"},
		Apply: func(context.Context) error {
			appendEvent("apply")
			return nil
		},
		Inverse: func(context.Context) error {
			appendEvent("undo")
			return nil
		},
		Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
			if expected == reconcile.ExpectedApplied {
				appendEvent("verify-applied")
			} else {
				appendEvent("verify-undone")
			}
			return nil
		},
	}
	if err := system.applyTransaction([]reconcile.Entry{entry}); err != nil {
		t.Fatalf("applyTransaction() error = %v", err)
	}
	if _, err := system.trackResource(systemCloseFunc(func() error {
		appendEvent("close-resource")
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	mu.Lock()
	got := append([]string(nil), events...)
	mu.Unlock()
	want := []string{"apply", "verify-applied", "close-resource", "undo", "verify-undone"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if got := system.journal.Len(); got != 0 {
		t.Fatalf("journal length after close = %d, want 0", got)
	}
	if _, err := system.trackResource(systemCloseFunc(func() error { return nil })); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("trackResource() after Close error = %v, want unavailable", err)
	}
}

func TestSystemTrackResourceLinearizesWithClose(t *testing.T) {
	for iteration := range 200 {
		system, err := newSystem(SystemConfig{}, systemDependencies{})
		if err != nil {
			t.Fatalf("iteration %d: newSystem() error = %v", iteration, err)
		}
		var closeCalls atomic.Int32
		start := make(chan struct{})
		trackResult := make(chan error, 1)
		closeResult := make(chan error, 1)
		go func() {
			<-start
			_, err := system.trackResource(systemCloseFunc(func() error {
				closeCalls.Add(1)
				return nil
			}))
			trackResult <- err
		}()
		go func() {
			<-start
			closeResult <- system.Close()
		}()
		close(start)
		trackErr := <-trackResult
		if err := <-closeResult; err != nil {
			t.Fatalf("iteration %d: Close() error = %v", iteration, err)
		}
		switch {
		case trackErr == nil:
			if got := closeCalls.Load(); got != 1 {
				t.Fatalf("iteration %d: accepted resource Close() calls = %d, want 1", iteration, got)
			}
		case errors.Is(trackErr, sysnet.ErrUnavailable):
			if got := closeCalls.Load(); got != 0 {
				t.Fatalf("iteration %d: rejected resource Close() calls = %d, want 0", iteration, got)
			}
		default:
			t.Fatalf("iteration %d: trackResource() error = %v, want nil or unavailable", iteration, trackErr)
		}
	}
}

func TestSystemReleaseDuringFailedCloseRetainsResource(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	started := make(chan struct{})
	unblock := make(chan struct{})
	closeErr := errors.New("close resource")
	var closeCalls atomic.Int32
	release, err := system.trackResource(systemCloseFunc(func() error {
		closeCalls.Add(1)
		close(started)
		<-unblock
		return closeErr
	}))
	if err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}

	result := make(chan error, 1)
	go func() { result <- system.Close() }()
	<-started
	release()
	close(unblock)
	if err := <-result; !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want resource close error", err)
	}
	if err := system.resources.CloseAll(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("resource recovery error = %v, want retained close error", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("resource Close() calls = %d, want 1", got)
	}
}

func TestSystemCloseMarksRecoveryWhenRollbackCannotBeVerified(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	readbackErr := errors.New("readback unavailable")
	entry := reconcile.Entry{
		Key:     reconcile.OwnershipKey{Kind: reconcile.KindDNS, ID: "dns-interface"},
		Apply:   func(context.Context) error { return nil },
		Inverse: func(context.Context) error { return nil },
		Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
			if expected == reconcile.ExpectedUndone {
				return readbackErr
			}
			return nil
		},
	}
	if err := system.applyTransaction([]reconcile.Entry{entry}); err != nil {
		t.Fatalf("applyTransaction() error = %v", err)
	}
	if err := system.Close(); !errors.Is(err, readbackErr) {
		t.Fatalf("Close() error = %v, want readback error", err)
	}
	system.mu.RLock()
	state := system.state
	system.mu.RUnlock()
	if state != lifecycleRecoveryRequired {
		t.Fatalf("lifecycle state = %s, want recovery-required", state)
	}
	if got := system.journal.Len(); got != 1 {
		t.Fatalf("journal length = %d, want retained ownership", got)
	}
}

func TestSystemCloseDoesNotRequireRecoveryAfterVerifiedInverseError(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	inverseErr := errors.New("inverse reported an error after restoring state")
	applied := false
	undoneVerifications := 0
	entry := reconcile.Entry{
		Key: reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: "owned-route"},
		Apply: func(context.Context) error {
			applied = true
			return nil
		},
		Inverse: func(context.Context) error {
			applied = false
			return inverseErr
		},
		Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
			if expected == reconcile.ExpectedUndone {
				undoneVerifications++
				if applied {
					return errors.New("route is still applied")
				}
			}
			return nil
		},
	}
	if err := system.applyTransaction([]reconcile.Entry{entry}); err != nil {
		t.Fatalf("applyTransaction() error = %v", err)
	}
	if err := system.Close(); !errors.Is(err, inverseErr) {
		t.Fatalf("Close() error = %v, want inverse error", err)
	}
	if undoneVerifications != 1 {
		t.Fatalf("undone verification calls = %d, want 1", undoneVerifications)
	}
	system.mu.RLock()
	state := system.state
	system.mu.RUnlock()
	if state != lifecycleClosed {
		t.Fatalf("lifecycle state = %s, want closed", state)
	}
	if got := system.journal.Len(); got != 0 {
		t.Fatalf("journal length = %d, want 0 after verified cleanup", got)
	}
}

func TestSystemApplyReturnsReadyAfterVerifiedRollbackError(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	applyErr := errors.New("apply failed after mutation")
	inverseErr := errors.New("inverse reported an error after restoring state")
	applied := false
	undoneVerifications := 0
	err = system.applyTransaction([]reconcile.Entry{{
		Key: reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: "owned-route"},
		Apply: func(context.Context) error {
			applied = true
			return applyErr
		},
		Inverse: func(context.Context) error {
			applied = false
			return inverseErr
		},
		Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
			if expected == reconcile.ExpectedUndone {
				undoneVerifications++
				if applied {
					return errors.New("route is still applied")
				}
			}
			return nil
		},
	}})
	if !errors.Is(err, applyErr) || !errors.Is(err, inverseErr) {
		t.Fatalf("applyTransaction() error = %v, want apply and inverse errors", err)
	}
	if reconcile.RequiresRecovery(err) {
		t.Fatalf("verified rollback requires recovery: %v", err)
	}
	if undoneVerifications != 1 {
		t.Fatalf("undone verification calls = %d, want 1", undoneVerifications)
	}
	if system.state != lifecycleReady {
		t.Fatalf("lifecycle state = %s, want ready", system.state)
	}
	if got := system.journal.Len(); got != 0 {
		t.Fatalf("journal length = %d, want 0 after verified rollback", got)
	}
}

func TestSystemCloseMarksRecoveryWhenResourceCloseFails(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	closeErr := errors.New("close resource")
	undoCalled := false
	var closeCalls atomic.Int32
	entry := reconcile.Entry{
		Key:     reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: "owned-route"},
		Apply:   func(context.Context) error { return nil },
		Inverse: func(context.Context) error { undoCalled = true; return nil },
		Verify:  func(context.Context, reconcile.ExpectedState) error { return nil },
	}
	if err := system.applyTransaction([]reconcile.Entry{entry}); err != nil {
		t.Fatalf("applyTransaction() error = %v", err)
	}
	if _, err := system.trackResource(systemCloseFunc(func() error {
		closeCalls.Add(1)
		return closeErr
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}
	for attempt := range 2 {
		if err := system.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("Close() attempt %d error = %v, want resource close error", attempt+1, err)
		}
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("resource Close() calls = %d, want 1", got)
	}
	system.mu.RLock()
	state := system.state
	system.mu.RUnlock()
	if state != lifecycleRecoveryRequired {
		t.Fatalf("lifecycle state = %s, want recovery-required", state)
	}
	if undoCalled {
		t.Fatal("host rollback ran while resource close state was uncertain")
	}
	if got := system.journal.Len(); got != 1 {
		t.Fatalf("journal length = %d, want retained ownership", got)
	}
}

func TestSystemCloseIsBoundedWhenResourceCloseBlocks(t *testing.T) {
	t.Parallel()
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	blocked := make(chan struct{})
	started := make(chan struct{})
	if _, err := system.trackResource(systemCloseFunc(func() error {
		close(started)
		<-blocked
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}

	begin := time.Now()
	result := make(chan error, 1)
	go func() { result <- system.Close() }()
	<-started
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close() error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not honor the resource cleanup timeout")
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("Close() took %s, want a bounded result", elapsed)
	}
	close(blocked)
	system.mu.RLock()
	state := system.state
	system.mu.RUnlock()
	if state != lifecycleRecoveryRequired {
		t.Fatalf("lifecycle state = %s, want recovery-required", state)
	}
}

func TestSystemCloseRetriesAfterResourceTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	var owned atomic.Bool
	if err := system.journal.Apply(context.Background(), []reconcile.Entry{{
		Key:   reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: "retry-owned-route"},
		Apply: func(context.Context) error { owned.Store(true); return nil },
		Inverse: func(context.Context) error {
			owned.Store(false)
			return nil
		},
		Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
			if owned.Load() == (expected == reconcile.ExpectedApplied) {
				return nil
			}
			return errors.New("owned route state differs")
		},
	}}); err != nil {
		t.Fatalf("journal Apply() error = %v", err)
	}
	blocked := make(chan struct{})
	started := make(chan struct{})
	var closeCalls atomic.Int32
	if _, err := system.trackResource(systemCloseFunc(func() error {
		closeCalls.Add(1)
		close(started)
		<-blocked
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}

	first := make(chan error, 1)
	go func() { first <- system.Close() }()
	<-started
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		close(blocked)
		t.Fatalf("first Close() error = %v, want deadline exceeded", err)
	}
	if !owned.Load() || system.journal.Len() != 1 {
		close(blocked)
		t.Fatalf("timed-out Close() changed journal ownership: owned=%t journal=%d", owned.Load(), system.journal.Len())
	}
	close(blocked)
	if err := system.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if owned.Load() || system.journal.Len() != 0 {
		t.Fatalf("Close() retry retained ownership: owned=%t journal=%d", owned.Load(), system.journal.Len())
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("resource Close() calls = %d, want 1", got)
	}
	if system.state != lifecycleClosed {
		t.Fatalf("lifecycle state = %s, want closed", system.state)
	}
}

func TestSystemCloseRetriesAfterWorkerTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	resourceClosed := make(chan struct{}, 1)
	if _, err := system.trackResource(systemCloseFunc(func() error {
		resourceClosed <- struct{}{}
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	system.worker = reconcile.NewWorker(context.Background(), system.journal, func(context.Context, []reconcile.Reason) ([]reconcile.Entry, error) {
		close(handlerStarted)
		<-releaseHandler
		return nil, nil
	}, nil)
	if !system.worker.Enqueue("blocked") {
		t.Fatal("Enqueue() rejected work")
	}
	<-handlerStarted
	if err := system.Close(); !errors.Is(err, context.DeadlineExceeded) {
		close(releaseHandler)
		t.Fatalf("first Close() error = %v, want deadline exceeded", err)
	}
	select {
	case <-resourceClosed:
		close(releaseHandler)
		t.Fatal("timed-out Close() closed a resource before worker exit")
	default:
	}
	close(releaseHandler)
	if err := system.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	select {
	case <-resourceClosed:
	default:
		t.Fatal("Close() retry did not close the retained resource")
	}
	if system.state != lifecycleClosed {
		t.Fatalf("lifecycle state = %s, want closed", system.state)
	}
}

func TestSystemCloseRetriesAfterJournalCallbackTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	var owned atomic.Bool
	applyResult := make(chan error, 1)
	go func() {
		applyResult <- system.applyTransaction([]reconcile.Entry{{
			Key: reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: "pending-retry"},
			Apply: func(context.Context) error {
				owned.Store(true)
				close(applyStarted)
				<-releaseApply
				return nil
			},
			Inverse: func(context.Context) error {
				owned.Store(false)
				return nil
			},
			Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
				if owned.Load() == (expected == reconcile.ExpectedApplied) {
					return nil
				}
				return errors.New("pending route state differs")
			},
		}})
	}()
	<-applyStarted
	if err := <-applyResult; !errors.Is(err, context.DeadlineExceeded) || !reconcile.RequiresRecovery(err) {
		close(releaseApply)
		t.Fatalf("applyTransaction() error = %v, want recovery deadline", err)
	}
	if err := system.Close(); !errors.Is(err, context.DeadlineExceeded) {
		close(releaseApply)
		t.Fatalf("first Close() error = %v, want deadline exceeded", err)
	}
	if !owned.Load() || system.journal.Len() != 1 {
		close(releaseApply)
		t.Fatalf("timed-out Close() changed pending ownership: owned=%t journal=%d", owned.Load(), system.journal.Len())
	}
	close(releaseApply)
	if err := system.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if owned.Load() || system.journal.Len() != 0 {
		t.Fatalf("Close() retry retained pending ownership: owned=%t journal=%d", owned.Load(), system.journal.Len())
	}
	if system.state != lifecycleClosed {
		t.Fatalf("lifecycle state = %s, want closed", system.state)
	}
}

func TestSystemCloseRetainsResourcesWhenWorkerDoesNotStop(t *testing.T) {
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	resourceClosed := make(chan struct{}, 1)
	if _, err := system.trackResource(systemCloseFunc(func() error {
		resourceClosed <- struct{}{}
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	system.worker = reconcile.NewWorker(context.Background(), system.journal, func(context.Context, []reconcile.Reason) ([]reconcile.Entry, error) {
		close(handlerStarted)
		<-releaseHandler
		return nil, nil
	}, nil)
	if !system.worker.Enqueue("blocked") {
		t.Fatal("Enqueue() rejected work")
	}
	<-handlerStarted

	begin := time.Now()
	closeErr := system.Close()
	if !errors.Is(closeErr, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want deadline exceeded", closeErr)
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("Close() took %s, want bounded shutdown", elapsed)
	}
	select {
	case <-resourceClosed:
		t.Fatal("Close() closed a resource before the worker exited")
	default:
	}
	close(releaseHandler)
	if err := system.worker.Stop(context.Background()); err != nil {
		t.Fatalf("worker Stop() after release error = %v", err)
	}
	if err := system.resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("resource cleanup error = %v", err)
	}
}

func TestSystemCloseRetainsResourcesWhileJournalCallbackIsPending(t *testing.T) {
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	resourceClosed := make(chan struct{}, 1)
	if _, err := system.trackResource(systemCloseFunc(func() error {
		resourceClosed <- struct{}{}
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	applyResult := make(chan error, 1)
	go func() {
		applyResult <- system.applyTransaction([]reconcile.Entry{{
			Key: reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: "blocked"},
			Apply: func(context.Context) error {
				close(applyStarted)
				<-releaseApply
				return nil
			},
			Inverse: func(context.Context) error { return nil },
			Verify:  func(context.Context, reconcile.ExpectedState) error { return nil },
		}})
	}()
	<-applyStarted
	if err := <-applyResult; !errors.Is(err, context.DeadlineExceeded) || !reconcile.RequiresRecovery(err) {
		t.Fatalf("applyTransaction() error = %v, want recovery deadline", err)
	}

	closeErr := system.Close()
	if !errors.Is(closeErr, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want deadline exceeded", closeErr)
	}
	select {
	case <-resourceClosed:
		t.Fatal("Close() closed a resource while a journal callback was pending")
	default:
	}
	if got := system.journal.Len(); got != 1 {
		t.Fatalf("journal length = %d, want uncertain ownership retained", got)
	}
	close(releaseApply)
	if err := system.journal.Quiesce(context.Background()); err != nil {
		t.Fatalf("journal Quiesce() after release error = %v", err)
	}
	if err := system.resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("resource cleanup error = %v", err)
	}
}

func TestSystemHandlesRecoveryFailureAfterNonRecoveryFailure(t *testing.T) {
	t.Parallel()
	makeFailure := func(id string, inverseErr error) error {
		journal := &reconcile.Journal{}
		return journal.Apply(context.Background(), []reconcile.Entry{{
			Key:   reconcile.OwnershipKey{Kind: reconcile.KindRoute, ID: id},
			Apply: func(context.Context) error { return errors.New("apply failed") },
			Inverse: func(context.Context) error {
				return inverseErr
			},
			Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
				if expected != reconcile.ExpectedUndone {
					return errors.New("unexpected verification state")
				}
				if inverseErr != nil {
					return errors.New("cleanup state is uncertain")
				}
				return nil
			},
		}})
	}
	nonRecovery := makeFailure("verified", nil)
	recovery := makeFailure("uncertain", errors.New("undo failed"))
	if reconcile.RequiresRecovery(nonRecovery) {
		t.Fatalf("first failure unexpectedly requires recovery: %v", nonRecovery)
	}
	if !reconcile.RequiresRecovery(recovery) {
		t.Fatalf("second failure does not require recovery: %v", recovery)
	}

	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	system.handleReconcileFailure(errors.Join(nonRecovery, recovery))
	if system.state != lifecycleRecoveryRequired {
		t.Fatalf("lifecycle state = %s, want %s", system.state, lifecycleRecoveryRequired)
	}
	if err := system.acceptingWork(); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("acceptingWork() error = %v, want unavailable", err)
	}
}

func TestSystemConcurrentCloseSharesBoundedFailure(t *testing.T) {
	const timeout = 20 * time.Millisecond
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	blocked := make(chan struct{})
	started := make(chan struct{})
	if _, err := system.trackResource(systemCloseFunc(func() error {
		close(started)
		<-blocked
		return nil
	})); err != nil {
		t.Fatalf("trackResource() error = %v", err)
	}
	results := make(chan error, 8)
	for range 8 {
		go func() { results <- system.Close() }()
	}
	<-started
	for range 8 {
		select {
		case err := <-results:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("concurrent Close() error = %v, want deadline exceeded", err)
			}
		case <-time.After(time.Second):
			close(blocked)
			t.Fatal("concurrent Close() did not return")
		}
	}
	close(blocked)
}

type systemCloseFunc func() error

func (f systemCloseFunc) Close() error { return f() }
