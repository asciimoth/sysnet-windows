package reconcile

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestJournalFailurePointsUndoExactResourcesInReverse(t *testing.T) {
	t.Parallel()
	const entryCount = 4
	for failIndex := range entryCount {
		for _, failPhase := range []string{"apply", "verify"} {
			name := fmt.Sprintf("%s_%d", failPhase, failIndex)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				host := newFakeHost("foreign")
				journal := &Journal{}
				entries := make([]Entry, 0, entryCount)
				for index := range entryCount {
					entries = append(entries, host.entry(fmt.Sprintf("owned-%d", index), failPhase, failIndex, index))
				}
				err := journal.Apply(context.Background(), entries)
				if err == nil {
					t.Fatal("Apply() error = nil, want failure")
				}
				if RequiresRecovery(err) {
					t.Fatalf("RequiresRecovery() = true after verified rollback: %v", err)
				}
				if got := host.resourceNames(); !reflect.DeepEqual(got, []string{"foreign"}) {
					t.Fatalf("host resources = %v, want foreign sentinel only", got)
				}
				if got := journal.Len(); got != 0 {
					t.Fatalf("journal length = %d, want 0", got)
				}
				completed := failIndex
				completed++
				var wantUndo []string
				for index := completed - 1; index >= 0; index-- {
					wantUndo = append(wantUndo, fmt.Sprintf("owned-%d", index))
				}
				if got := host.undoNames(); !reflect.DeepEqual(got, wantUndo) {
					t.Fatalf("undo order = %v, want %v", got, wantUndo)
				}
			})
		}
	}
}

func TestJournalRollsBackApplyThatMutatesBeforeFailure(t *testing.T) {
	t.Parallel()
	host := newFakeHost("foreign")
	entry := host.entry("owned", "", -1, 0)
	applyErr := errors.New("apply failed after mutation")
	entry.Apply = func(context.Context) error {
		host.mu.Lock()
		defer host.mu.Unlock()
		host.events = append(host.events, "apply:owned")
		host.resources["owned"] = true
		return applyErr
	}

	journal := &Journal{}
	err := journal.Apply(context.Background(), []Entry{entry})
	if !errors.Is(err, applyErr) {
		t.Fatalf("Apply() error = %v, want apply failure", err)
	}
	if RequiresRecovery(err) {
		t.Fatalf("RequiresRecovery() = true after verified rollback: %v", err)
	}
	if got := host.resourceNames(); !reflect.DeepEqual(got, []string{"foreign"}) {
		t.Fatalf("host resources = %v, want foreign sentinel only", got)
	}
}

func TestJournalRollbackHasFreshBoundedContext(t *testing.T) {
	t.Parallel()
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	cleanupContextActive := false
	entry := Entry{
		Key: OwnershipKey{Kind: KindRoute, ID: "owned"},
		Apply: func(context.Context) error {
			cancelRequest()
			return context.Canceled
		},
		Inverse: func(ctx context.Context) error {
			cleanupContextActive = ctx.Err() == nil
			_, hasDeadline := ctx.Deadline()
			if !hasDeadline {
				return errors.New("cleanup context has no deadline")
			}
			return nil
		},
		Verify: func(ctx context.Context, expected ExpectedState) error {
			if expected != ExpectedUndone || ctx.Err() != nil {
				return errors.New("cleanup verification context is canceled")
			}
			return nil
		},
	}

	err := (&Journal{}).Apply(requestCtx, []Entry{entry})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply() error = %v, want canceled", err)
	}
	if !cleanupContextActive {
		t.Fatal("rollback received a canceled context")
	}
}

func TestJournalRollsBackSuccessReturnedAfterCancellation(t *testing.T) {
	t.Parallel()
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	host := newFakeHost("foreign")
	entry := host.entry("owned", "", -1, 0)
	apply := entry.Apply
	entry.Apply = func(ctx context.Context) error {
		if err := apply(ctx); err != nil {
			return err
		}
		cancelRequest()
		return nil
	}

	err := (&Journal{}).Apply(requestCtx, []Entry{entry})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply() error = %v, want canceled", err)
	}
	if RequiresRecovery(err) {
		t.Fatalf("RequiresRecovery() = true after verified rollback: %v", err)
	}
	if got := host.resourceNames(); !reflect.DeepEqual(got, []string{"foreign"}) {
		t.Fatalf("host resources = %v, want foreign sentinel only", got)
	}
}

func TestJournalJoinsCleanupFailureAndRetainsOwnership(t *testing.T) {
	t.Parallel()
	host := newFakeHost("foreign")
	host.inverseFailure = errors.New("inverse failed")
	journal := &Journal{}
	entries := []Entry{
		host.entry("owned-0", "", -1, 0),
		host.entry("owned-1", "verify", 1, 1),
	}
	err := journal.Apply(context.Background(), entries)
	if !errors.Is(err, host.inverseFailure) {
		t.Fatalf("Apply() error = %v, want inverse failure", err)
	}
	if !RequiresRecovery(err) {
		t.Fatalf("RequiresRecovery() = false for %v", err)
	}
	if got := journal.Len(); got != 2 {
		t.Fatalf("journal length = %d, want 2 retained entries", got)
	}

	host.inverseFailure = nil
	if err := journal.UndoAll(context.Background()); err != nil {
		t.Fatalf("UndoAll() retry error = %v", err)
	}
	if got := host.resourceNames(); !reflect.DeepEqual(got, []string{"foreign"}) {
		t.Fatalf("host resources after retry = %v", got)
	}
}

func TestRequiresRecoverySearchesCompleteErrorTree(t *testing.T) {
	t.Parallel()
	plain := errors.New("plain failure")
	nonRecovery := &Failure{err: errors.New("verified rollback")}
	recovery := &Failure{err: errors.New("uncertain native state"), recoveryRequired: true}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil"},
		{name: "plain", err: plain},
		{name: "direct non-recovery", err: nonRecovery},
		{name: "direct recovery", err: recovery, want: true},
		{name: "wrapped recovery", err: fmt.Errorf("operation: %w", recovery), want: true},
		{name: "recovery first in join", err: errors.Join(recovery, nonRecovery), want: true},
		{name: "recovery last in join", err: errors.Join(nonRecovery, recovery), want: true},
		{name: "only non-recovery failures", err: errors.Join(nonRecovery, plain)},
		{
			name: "nested join and wrap",
			err: fmt.Errorf("outer: %w", errors.Join(
				fmt.Errorf("first: %w", nonRecovery),
				fmt.Errorf("second: %w", recovery),
			)),
			want: true,
		},
		{
			name: "non-recovery failure wraps recovery failure",
			err:  &Failure{err: recovery},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := RequiresRecovery(test.err); got != test.want {
				t.Fatalf("RequiresRecovery() = %t, want %t for %v", got, test.want, test.err)
			}
		})
	}
}

func TestJournalPreservesNestedRecoveryRequirementAfterVerifiedRollback(t *testing.T) {
	t.Parallel()
	inner := &Failure{err: errors.New("dependency owns uncertain state"), recoveryRequired: true}
	entry := Entry{
		Key:     OwnershipKey{Kind: KindRoute, ID: "nested-recovery"},
		Apply:   func(context.Context) error { return inner },
		Inverse: func(context.Context) error { return nil },
		Verify: func(_ context.Context, expected ExpectedState) error {
			if expected != ExpectedUndone {
				return errors.New("unexpected verification state")
			}
			return nil
		},
	}
	err := (&Journal{}).Apply(context.Background(), []Entry{entry})
	if !errors.Is(err, inner) {
		t.Fatalf("Apply() error = %v, want nested failure", err)
	}
	if !RequiresRecovery(err) {
		t.Fatalf("RequiresRecovery() = false for nested failure: %v", err)
	}
}

func TestJournalRejectsDuplicateOwnershipWithoutMutation(t *testing.T) {
	t.Parallel()
	host := newFakeHost("foreign")
	entry := host.entry("owned", "", -1, 0)
	journal := &Journal{}
	if err := journal.Apply(context.Background(), []Entry{entry}); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	if err := journal.Apply(context.Background(), []Entry{entry}); err == nil {
		t.Fatal("second Apply() error = nil, want duplicate rejection")
	}
	if got := host.applyNames(); !reflect.DeepEqual(got, []string{"owned"}) {
		t.Fatalf("apply operations = %v, want one mutation", got)
	}
}

func TestJournalBoundsEveryBlockingCallbackAndRetainsOwnership(t *testing.T) {
	for _, phase := range []string{"apply", "verify-applied", "inverse", "verify-undone"} {
		t.Run(phase, func(t *testing.T) {
			const timeout = 20 * time.Millisecond
			started := make(chan struct{})
			release := make(chan struct{})
			var startOnce sync.Once
			block := func() {
				startOnce.Do(func() { close(started) })
				<-release
			}
			applyErr := errors.New("injected apply failure")
			entry := Entry{
				Key: OwnershipKey{Kind: KindRoute, ID: phase},
				Apply: func(context.Context) error {
					if phase == "apply" {
						block()
					}
					if phase == "inverse" || phase == "verify-undone" {
						return applyErr
					}
					return nil
				},
				Inverse: func(context.Context) error {
					if phase == "inverse" {
						block()
					}
					return nil
				},
				Verify: func(_ context.Context, expected ExpectedState) error {
					if phase == "verify-applied" && expected == ExpectedApplied ||
						phase == "verify-undone" && expected == ExpectedUndone {
						block()
					}
					return nil
				},
			}
			journal := NewJournal(timeout)
			requestCtx := context.Background()
			cancel := func() {}
			if phase == "apply" || phase == "verify-applied" {
				requestCtx, cancel = context.WithTimeout(context.Background(), timeout)
			}
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- journal.Apply(requestCtx, []Entry{entry}) }()
			<-started
			select {
			case err := <-result:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Apply() error = %v, want deadline exceeded", err)
				}
				if !RequiresRecovery(err) {
					t.Fatalf("RequiresRecovery() = false for %v", err)
				}
			case <-time.After(time.Second):
				close(release)
				t.Fatal("Apply() did not honor the operation timeout")
			}
			if got := journal.Len(); got != 1 {
				t.Fatalf("journal length = %d, want uncertain entry retained", got)
			}
			if !journal.RecoveryRequired() {
				t.Fatal("RecoveryRequired() = false with uncertain ownership")
			}
			quiesceCtx, cancelQuiesce := context.WithTimeout(context.Background(), timeout)
			if err := journal.Quiesce(quiesceCtx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Quiesce() error = %v, want deadline exceeded", err)
			}
			cancelQuiesce()
			close(release)
			if err := journal.Quiesce(context.Background()); err != nil {
				t.Fatalf("Quiesce() after release error = %v", err)
			}
			if err := journal.UndoAll(context.Background()); err != nil {
				t.Fatalf("UndoAll() recovery error = %v", err)
			}
			if got := journal.Len(); got != 0 {
				t.Fatalf("journal length after recovery = %d, want 0", got)
			}
			if journal.RecoveryRequired() {
				t.Fatal("RecoveryRequired() = true after verified recovery")
			}
		})
	}
}

func TestJournalDoesNotStartNewMutationWhileCallbackIsPending(t *testing.T) {
	const timeout = 20 * time.Millisecond
	started := make(chan struct{})
	release := make(chan struct{})
	journal := &Journal{}
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), timeout)
	defer cancelFirst()
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- journal.Apply(firstCtx, []Entry{{
			Key: OwnershipKey{Kind: KindRoute, ID: "first"},
			Apply: func(context.Context) error {
				close(started)
				<-release
				return nil
			},
			Inverse: func(context.Context) error { return nil },
			Verify:  func(context.Context, ExpectedState) error { return nil },
		}})
	}()
	<-started
	if err := <-firstResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Apply() error = %v, want deadline exceeded", err)
	}
	secondCalled := false
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), timeout)
	err := journal.Apply(secondCtx, []Entry{{
		Key: OwnershipKey{Kind: KindRoute, ID: "second"},
		Apply: func(context.Context) error {
			secondCalled = true
			return nil
		},
		Inverse: func(context.Context) error { return nil },
		Verify:  func(context.Context, ExpectedState) error { return nil },
	}})
	cancelSecond()
	if !errors.Is(err, context.DeadlineExceeded) || !RequiresRecovery(err) {
		t.Fatalf("second Apply() error = %v, want recovery deadline", err)
	}
	if secondCalled {
		t.Fatal("second mutation started while the first callback was pending")
	}
	close(release)
	if err := journal.Quiesce(context.Background()); err != nil {
		t.Fatalf("Quiesce() error = %v", err)
	}
	if err := journal.Apply(context.Background(), []Entry{{
		Key: OwnershipKey{Kind: KindRoute, ID: "third"},
		Apply: func(context.Context) error {
			secondCalled = true
			return nil
		},
		Inverse: func(context.Context) error { return nil },
		Verify:  func(context.Context, ExpectedState) error { return nil },
	}}); !errors.Is(err, ErrRecoveryRequired) || !RequiresRecovery(err) {
		t.Fatalf("Apply() before recovery error = %v, want recovery required", err)
	}
	if secondCalled {
		t.Fatal("new mutation started before uncertain ownership was recovered")
	}
	if err := journal.UndoAll(context.Background()); err != nil {
		t.Fatalf("UndoAll() error = %v", err)
	}
}

func TestJournalStopsRollbackOrderAtPendingInverse(t *testing.T) {
	const timeout = 20 * time.Millisecond
	blockedStarted := make(chan struct{})
	releaseBlocked := make(chan struct{})
	var blockedOnce sync.Once
	var mu sync.Mutex
	var undoOrder []string
	entry := func(name string, block bool, failVerify bool) Entry {
		return Entry{
			Key:   OwnershipKey{Kind: KindRoute, ID: name},
			Apply: func(context.Context) error { return nil },
			Inverse: func(context.Context) error {
				mu.Lock()
				undoOrder = append(undoOrder, name)
				mu.Unlock()
				if block {
					blockedOnce.Do(func() { close(blockedStarted) })
					<-releaseBlocked
				}
				return nil
			},
			Verify: func(_ context.Context, expected ExpectedState) error {
				if failVerify && expected == ExpectedApplied {
					return errors.New("injected readback failure")
				}
				return nil
			},
		}
	}
	journal := NewJournal(timeout)
	result := make(chan error, 1)
	go func() {
		result <- journal.Apply(context.Background(), []Entry{
			entry("first", false, false),
			entry("second", true, true),
		})
	}()
	<-blockedStarted
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) || !RequiresRecovery(err) {
		t.Fatalf("Apply() error = %v, want recovery deadline", err)
	}
	mu.Lock()
	gotBeforeRecovery := append([]string(nil), undoOrder...)
	mu.Unlock()
	if !reflect.DeepEqual(gotBeforeRecovery, []string{"second"}) {
		t.Fatalf("undo order before recovery = %v, want [second]", gotBeforeRecovery)
	}
	close(releaseBlocked)
	if err := journal.Quiesce(context.Background()); err != nil {
		t.Fatalf("Quiesce() error = %v", err)
	}
	if err := journal.UndoAll(context.Background()); err != nil {
		t.Fatalf("UndoAll() error = %v", err)
	}
	mu.Lock()
	got := append([]string(nil), undoOrder...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []string{"second", "second", "first"}) {
		t.Fatalf("complete undo order = %v, want [second second first]", got)
	}
}

type fakeHost struct {
	mu             sync.Mutex
	resources      map[string]bool
	events         []string
	inverseFailure error
}

func newFakeHost(resources ...string) *fakeHost {
	host := &fakeHost{resources: make(map[string]bool)}
	for _, resource := range resources {
		host.resources[resource] = true
	}
	return host
}

func (h *fakeHost) entry(name, failPhase string, failIndex, index int) Entry {
	key := OwnershipKey{Kind: KindRoute, Scope: "test-interface", ID: name}
	return Entry{
		Key: key,
		Apply: func(context.Context) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if failPhase == "apply" && failIndex == index {
				return errors.New("injected apply failure")
			}
			h.events = append(h.events, "apply:"+name)
			h.resources[name] = true
			return nil
		},
		Inverse: func(context.Context) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, "undo:"+name)
			if h.inverseFailure != nil {
				return h.inverseFailure
			}
			delete(h.resources, name)
			return nil
		},
		Verify: func(_ context.Context, expected ExpectedState) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if expected == ExpectedApplied && failPhase == "verify" && failIndex == index {
				return errors.New("injected readback failure")
			}
			exists := h.resources[name]
			if (expected == ExpectedApplied) != exists {
				return errors.New("readback mismatch")
			}
			return nil
		},
	}
}

func (h *fakeHost) resourceNames() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]string, 0, len(h.resources))
	for name := range h.resources {
		result = append(result, name)
	}
	slicesSort(result)
	return result
}

func (h *fakeHost) applyNames() []string { return h.eventNames("apply:") }
func (h *fakeHost) undoNames() []string  { return h.eventNames("undo:") }

func (h *fakeHost) eventNames(prefix string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var result []string
	for _, event := range h.events {
		if len(event) >= len(prefix) && event[:len(prefix)] == prefix {
			result = append(result, event[len(prefix):])
		}
	}
	return result
}

func slicesSort(values []string) {
	for left := range values {
		for right := left + 1; right < len(values); right++ {
			if values[right] < values[left] {
				values[left], values[right] = values[right], values[left]
			}
		}
	}
}
