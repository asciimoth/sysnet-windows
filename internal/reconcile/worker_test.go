package reconcile

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerSerializesMutations(t *testing.T) {
	t.Parallel()
	journal := &Journal{}
	worker := NewWorker(context.Background(), journal, nil, nil)
	t.Cleanup(func() { _ = worker.Stop(context.Background()) })

	var active atomic.Int32
	var maximum atomic.Int32
	entry := func(id string) Entry {
		key := OwnershipKey{Kind: KindWFP, ID: id}
		return Entry{
			Key: key,
			Apply: func(context.Context) error {
				current := active.Add(1)
				for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {
				}
				time.Sleep(2 * time.Millisecond)
				active.Add(-1)
				return nil
			},
			Inverse: func(context.Context) error { return nil },
			Verify:  func(context.Context, ExpectedState) error { return nil },
		}
	}
	var wait sync.WaitGroup
	for index := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := worker.Submit(context.Background(), []Entry{entry(string(rune('a' + index)))}); err != nil {
				t.Errorf("Submit() error = %v", err)
			}
		}()
	}
	wait.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent mutations = %d, want 1", got)
	}
}

func TestWorkerCallbackDoesNotWaitAndCoalesces(t *testing.T) {
	t.Parallel()
	received := make(chan []Reason, 2)
	release := make(chan struct{})
	worker := NewWorker(context.Background(), nil, func(_ context.Context, reasons []Reason) ([]Entry, error) {
		received <- reasons
		<-release
		return nil, nil
	}, nil)

	if !worker.Enqueue("initial") {
		t.Fatal("Enqueue() rejected initial work")
	}
	first := <-received
	if !reflect.DeepEqual(first, []Reason{"initial"}) {
		t.Fatalf("first reasons = %v, want initial", first)
	}
	start := time.Now()
	for _, reason := range []Reason{"route-change", "address-change", "route-change"} {
		if !worker.Enqueue(reason) {
			t.Fatal("Enqueue() rejected work before stop")
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("callback enqueue took %s", elapsed)
	}
	close(release)
	second := <-received
	if !reflect.DeepEqual(second, []Reason{"route-change", "address-change"}) {
		t.Fatalf("coalesced reasons = %v", second)
	}
	if err := worker.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if worker.Enqueue("late") {
		t.Fatal("Enqueue() accepted work after stop")
	}
}

func TestWorkerStopCancelsAndIsBounded(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	worker := NewWorker(context.Background(), nil, nil, nil)
	entry := Entry{
		Key: OwnershipKey{Kind: KindSplit, ID: "session"},
		Apply: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
		Inverse: func(context.Context) error { return nil },
		Verify:  func(context.Context, ExpectedState) error { return nil },
	}
	result := make(chan error, 1)
	go func() { result <- worker.Submit(context.Background(), []Entry{entry}) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Submit() error = %v, want canceled", err)
	}
}

func TestWorkerStopSerializesWithCallbackIntake(t *testing.T) {
	t.Parallel()
	worker := NewWorker(context.Background(), nil, nil, nil)

	worker.reasonMu.Lock()
	stopped := make(chan error, 1)
	go func() { stopped <- worker.Stop(context.Background()) }()
	select {
	case <-worker.stop:
		worker.reasonMu.Unlock()
		t.Fatal("Stop closed intake without the intake lock")
	case <-time.After(20 * time.Millisecond):
	}
	worker.reasonMu.Unlock()
	if err := <-stopped; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if worker.Enqueue("late") {
		t.Fatal("Enqueue() accepted work after serialized stop")
	}
}

func TestWorkerParentCancellationStopsIdleIntake(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.Background())
	worker := NewWorker(parent, nil, nil, nil)
	cancel()

	select {
	case <-worker.done:
	case <-time.After(time.Second):
		t.Fatal("idle worker did not exit after parent cancellation")
	}
	if worker.Enqueue("late") {
		t.Fatal("Enqueue() accepted work after parent cancellation")
	}
	if err := worker.Submit(context.Background(), nil); !errors.Is(err, ErrStopped) {
		t.Fatalf("Submit() error = %v, want stopped", err)
	}
	if err := worker.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerParentCancellationReleasesSubmitter(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(context.Background())
	worker := NewWorker(parent, nil, nil, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	entry := Entry{
		Key: OwnershipKey{Kind: KindWFP, ID: "blocked"},
		Apply: func(context.Context) error {
			close(started)
			<-release
			return nil
		},
		Inverse: func(context.Context) error { return nil },
		Verify:  func(context.Context, ExpectedState) error { return nil },
	}
	result := make(chan error, 1)
	go func() { result <- worker.Submit(context.Background(), []Entry{entry}) }()
	<-started
	cancelParent()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Submit() error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Submit() did not return after parent cancellation")
	}
	close(release)
	if err := worker.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestWorkerSubmitPreservesRecoveryFailureAfterDeadline(t *testing.T) {
	const timeout = 20 * time.Millisecond
	journal := NewJournal(timeout)
	worker := NewWorker(context.Background(), journal, nil, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- worker.Submit(ctx, []Entry{{
			Key: OwnershipKey{Kind: KindRoute, ID: "blocked"},
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
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) || !RequiresRecovery(err) {
			t.Fatalf("Submit() error = %v, want recovery deadline", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Submit() did not return the bounded journal result")
	}
	close(release)
	if err := journal.Quiesce(context.Background()); err != nil {
		t.Fatalf("Quiesce() error = %v", err)
	}
	if err := worker.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestResourcesCloseInReverseAndRejectLateTrack(t *testing.T) {
	t.Parallel()
	var resources Resources
	var mu sync.Mutex
	var order []string
	for _, name := range []string{"socket", "listener", "tun"} {
		if _, err := resources.Track(closeFunc(func() error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, name)
			return nil
		})); err != nil {
			t.Fatalf("Track() error = %v", err)
		}
	}
	if err := resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"tun", "listener", "socket"}) {
		t.Fatalf("close order = %v", order)
	}
	if _, err := resources.Track(closeFunc(func() error { return nil })); !errors.Is(err, ErrStopped) {
		t.Fatalf("late Track() error = %v, want stopped", err)
	}
}

func TestResourcesCloseHonorsCancellation(t *testing.T) {
	t.Parallel()
	var resources Resources
	blocked := make(chan struct{})
	started := make(chan struct{})
	lowerClosed := make(chan struct{}, 1)
	if _, err := resources.Track(closeFunc(func() error {
		lowerClosed <- struct{}{}
		return nil
	})); err != nil {
		t.Fatalf("Track(lower) error = %v", err)
	}
	if _, err := resources.Track(closeFunc(func() error {
		close(started)
		<-blocked
		return nil
	})); err != nil {
		t.Fatalf("Track(blocked) error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- resources.CloseAll(ctx) }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("CloseAll() error = %v, want canceled", err)
	}
	select {
	case <-lowerClosed:
		t.Fatal("CloseAll() continued past a resource with uncertain close state")
	default:
	}
	close(blocked)
}

func TestResourcesCloseFailureIsStableAndNotRetried(t *testing.T) {
	t.Parallel()
	var resources Resources
	closeErr := errors.New("close failed")
	var calls atomic.Int32
	if _, err := resources.Track(closeFunc(func() error {
		calls.Add(1)
		return closeErr
	})); err != nil {
		t.Fatalf("Track() error = %v", err)
	}
	for attempt := range 2 {
		if err := resources.CloseAll(context.Background()); !errors.Is(err, closeErr) {
			t.Fatalf("CloseAll() attempt %d error = %v, want close failure", attempt+1, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Close() calls = %d, want 1", got)
	}
}

func TestResourcesCloseDoesNotCloseConcurrentlyReleasedResource(t *testing.T) {
	t.Parallel()
	var resources Resources
	releasedClosed := make(chan struct{}, 1)
	release, err := resources.Track(closeFunc(func() error {
		releasedClosed <- struct{}{}
		return nil
	}))
	if err != nil {
		t.Fatalf("Track(released) error = %v", err)
	}

	blockerStarted := make(chan struct{})
	releaseBlocker := make(chan struct{})
	if _, err := resources.Track(closeFunc(func() error {
		close(blockerStarted)
		<-releaseBlocker
		return nil
	})); err != nil {
		t.Fatalf("Track(blocker) error = %v", err)
	}

	result := make(chan error, 1)
	go func() { result <- resources.CloseAll(context.Background()) }()
	<-blockerStarted
	release()
	close(releaseBlocker)
	if err := <-result; err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
	select {
	case <-releasedClosed:
		t.Fatal("CloseAll() closed a resource after its release function returned")
	default:
	}
}

func TestResourcesReleaseBeforeCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	var resources Resources
	var closeCalls atomic.Int32
	release, err := resources.Track(closeFunc(func() error {
		closeCalls.Add(1)
		return nil
	}))
	if err != nil {
		t.Fatalf("Track() error = %v", err)
	}
	release()
	release()
	if err := resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
	if err := resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("second CloseAll() error = %v", err)
	}
	if got := closeCalls.Load(); got != 0 {
		t.Fatalf("Close() calls = %d, want 0", got)
	}
}

func TestResourcesReleasePreservesReverseCloseOrder(t *testing.T) {
	t.Parallel()
	var resources Resources
	var mu sync.Mutex
	var order []string
	track := func(name string) func() {
		release, err := resources.Track(closeFunc(func() error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, name)
			return nil
		}))
		if err != nil {
			t.Fatalf("Track(%s) error = %v", name, err)
		}
		return release
	}
	releaseFirst := track("first")
	track("second")
	track("third")
	releaseFirst()
	if err := resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []string{"third", "second"}) {
		t.Fatalf("close order = %v, want [third second]", got)
	}
}

func TestResourcesReleaseAfterCloseStartsDoesNotStartSecondClose(t *testing.T) {
	t.Parallel()
	var resources Resources
	started := make(chan struct{})
	unblock := make(chan struct{})
	var closeCalls atomic.Int32
	release, err := resources.Track(closeFunc(func() error {
		closeCalls.Add(1)
		close(started)
		<-unblock
		return nil
	}))
	if err != nil {
		t.Fatalf("Track() error = %v", err)
	}
	firstResult := make(chan error, 1)
	go func() { firstResult <- resources.CloseAll(context.Background()) }()
	<-started
	release()
	secondResult := make(chan error, 1)
	go func() { secondResult <- resources.CloseAll(context.Background()) }()
	select {
	case err := <-secondResult:
		t.Fatalf("second CloseAll() returned before the in-progress close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(unblock)
	if err := <-firstResult; err != nil {
		t.Fatalf("first CloseAll() error = %v", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second CloseAll() error = %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("Close() calls = %d, want 1", got)
	}
}

func TestResourcesReleaseDuringFailedCloseRetainsFailure(t *testing.T) {
	t.Parallel()
	var resources Resources
	started := make(chan struct{})
	unblock := make(chan struct{})
	closeErr := errors.New("close failed")
	var closeCalls atomic.Int32
	release, err := resources.Track(closeFunc(func() error {
		closeCalls.Add(1)
		close(started)
		<-unblock
		return closeErr
	}))
	if err != nil {
		t.Fatalf("Track() error = %v", err)
	}

	firstResult := make(chan error, 1)
	go func() { firstResult <- resources.CloseAll(context.Background()) }()
	<-started
	release()

	secondResult := make(chan error, 1)
	go func() { secondResult <- resources.CloseAll(context.Background()) }()
	select {
	case err := <-secondResult:
		t.Fatalf("second CloseAll() returned before the in-progress close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(unblock)
	for name, result := range map[string]<-chan error{
		"first":  firstResult,
		"second": secondResult,
	} {
		if err := <-result; !errors.Is(err, closeErr) {
			t.Fatalf("%s CloseAll() error = %v, want close failure", name, err)
		}
	}
	if err := resources.CloseAll(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("third CloseAll() error = %v, want retained close failure", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("Close() calls = %d, want 1", got)
	}
}

func TestResourcesReleaseAfterFailedCloseRetainsFailure(t *testing.T) {
	t.Parallel()
	var resources Resources
	closeErr := errors.New("close failed")
	var closeCalls atomic.Int32
	release, err := resources.Track(closeFunc(func() error {
		closeCalls.Add(1)
		return closeErr
	}))
	if err != nil {
		t.Fatalf("Track() error = %v", err)
	}
	if err := resources.CloseAll(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("first CloseAll() error = %v, want close failure", err)
	}
	release()
	if err := resources.CloseAll(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("second CloseAll() error = %v, want retained close failure", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("Close() calls = %d, want 1", got)
	}
}

func TestResourcesReleaseDuringCanceledCloseWaitsForSuccessfulClose(t *testing.T) {
	t.Parallel()
	var resources Resources
	started := make(chan struct{})
	unblock := make(chan struct{})
	var closeCalls atomic.Int32
	release, err := resources.Track(closeFunc(func() error {
		closeCalls.Add(1)
		close(started)
		<-unblock
		return nil
	}))
	if err != nil {
		t.Fatalf("Track() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() { firstResult <- resources.CloseAll(ctx) }()
	<-started
	release()
	cancel()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("first CloseAll() error = %v, want canceled", err)
	}

	secondResult := make(chan error, 1)
	go func() { secondResult <- resources.CloseAll(context.Background()) }()
	select {
	case err := <-secondResult:
		t.Fatalf("second CloseAll() returned before the in-progress close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(unblock)
	if err := <-secondResult; err != nil {
		t.Fatalf("second CloseAll() error = %v", err)
	}
	if err := resources.CloseAll(context.Background()); err != nil {
		t.Fatalf("third CloseAll() error = %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("Close() calls = %d, want 1", got)
	}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }
