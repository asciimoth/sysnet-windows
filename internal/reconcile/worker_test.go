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
	received := make(chan []Reason, 1)
	release := make(chan struct{})
	worker := NewWorker(context.Background(), nil, func(_ context.Context, reasons []Reason) ([]Entry, error) {
		received <- reasons
		<-release
		return nil, nil
	}, nil)

	start := time.Now()
	for range 1000 {
		if !worker.Enqueue("route-change") {
			t.Fatal("Enqueue() rejected work before stop")
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("callback enqueue took %s", elapsed)
	}
	<-received
	close(release)
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
	if err := resources.CloseAll(); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"tun", "listener", "socket"}) {
		t.Fatalf("close order = %v", order)
	}
	if _, err := resources.Track(closeFunc(func() error { return nil })); !errors.Is(err, ErrStopped) {
		t.Fatalf("late Track() error = %v, want stopped", err)
	}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }
