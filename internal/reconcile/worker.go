package reconcile

import (
	"context"
	"errors"
	"sync"
)

// Reason describes an asynchronous observation which requires reconciliation.
type Reason string

// Handler converts coalesced callback reasons to an exact transaction.
type Handler func(context.Context, []Reason) ([]Entry, error)

// FailureHandler receives asynchronous handler and transaction failures. It
// must return quickly and must not submit work to the same Worker.
type FailureHandler func(error)

type request struct {
	ctx       context.Context
	entries   []Entry
	operation Operation
	result    chan error
}

// Worker serializes all policy mutations through one goroutine.
type Worker struct {
	journal   *Journal
	handler   Handler
	onFailure FailureHandler

	ctx    context.Context
	cancel context.CancelFunc
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once

	requests chan request
	reasons  chan struct{}

	reasonMu       sync.Mutex
	pendingReasons []Reason
	pendingSet     map[Reason]struct{}
	stopped        bool
}

// NewWorker starts one policy worker. A nil handler is valid when the caller
// uses only Submit.
func NewWorker(parent context.Context, journal *Journal, handler Handler, onFailure FailureHandler) *Worker {
	if parent == nil {
		parent = context.Background()
	}
	if journal == nil {
		journal = &Journal{}
	}
	ctx, cancel := context.WithCancel(parent)
	worker := &Worker{
		journal:    journal,
		handler:    handler,
		onFailure:  onFailure,
		ctx:        ctx,
		cancel:     cancel,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		requests:   make(chan request),
		reasons:    make(chan struct{}, 1),
		pendingSet: make(map[Reason]struct{}),
	}
	go worker.run()
	return worker
}

// Submit waits for one serialized transaction.
func (w *Worker) Submit(ctx context.Context, entries []Entry) error {
	if ctx == nil {
		ctx = context.Background()
	}
	result := make(chan error, 1)
	req := request{ctx: ctx, entries: append([]Entry(nil), entries...), result: result}
	select {
	case <-w.stop:
		return ErrStopped
	case <-w.ctx.Done():
		return ErrStopped
	case <-ctx.Done():
		return ctx.Err()
	case w.requests <- req:
	}
	// The unbuffered send means the worker accepted this transaction. Wait for
	// its bounded journal result so cancellation cannot hide recovery status.
	return <-result
}

// Execute runs one bounded operation on the same serialized policy worker as
// journal transactions. Execute is for a mutation whose boundary already
// supplies exact rollback and readback, such as a NetIO Manager transaction.
// It does not add an entry to the ownership journal.
func (w *Worker) Execute(ctx context.Context, operation Operation) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if operation == nil {
		return errors.New("execute nil reconciliation operation")
	}
	result := make(chan error, 1)
	req := request{ctx: ctx, operation: operation, result: result}
	select {
	case <-w.stop:
		return ErrStopped
	case <-w.ctx.Done():
		return ErrStopped
	case <-ctx.Done():
		return ctx.Err()
	case w.requests <- req:
	}
	return <-result
}

// Enqueue queues a callback reason without waiting. A full queue coalesces the
// reason with already pending work.
func (w *Worker) Enqueue(reason Reason) bool {
	w.reasonMu.Lock()
	defer w.reasonMu.Unlock()
	if w.stopped || w.ctx.Err() != nil {
		return false
	}
	if _, exists := w.pendingSet[reason]; !exists {
		w.pendingSet[reason] = struct{}{}
		w.pendingReasons = append(w.pendingReasons, reason)
	}
	select {
	case w.reasons <- struct{}{}:
	default:
	}
	return true
}

// Stop stops intake, cancels active work, and waits for the worker to exit.
func (w *Worker) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	w.once.Do(func() {
		w.reasonMu.Lock()
		w.stopped = true
		close(w.stop)
		w.cancel()
		w.reasonMu.Unlock()
	})
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) run() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case <-w.ctx.Done():
			return
		case req := <-w.requests:
			ctx, cancel := mergeContext(w.ctx, req.ctx)
			if req.operation != nil {
				w.execute(ctx, req)
			} else {
				req.result <- w.journal.Apply(ctx, req.entries)
			}
			cancel()
		case <-w.reasons:
			w.handleReasons()
		}
	}
}

func (w *Worker) execute(ctx context.Context, req request) {
	result := make(chan error, 1)
	go func() { result <- req.operation(ctx) }()
	select {
	case err := <-result:
		req.result <- err
	case <-ctx.Done():
		// Prefer a completed call when completion raced the deadline.
		select {
		case err := <-result:
			req.result <- err
			return
		default:
		}
		// The operation can have changed native state before it observed
		// cancellation. Release the caller with an explicit recovery result, but
		// keep this worker serialized until the native call returns.
		req.result <- &Failure{err: ctx.Err(), recoveryRequired: true}
		<-result
	}
}

func (w *Worker) handleReasons() {
	if w.handler == nil {
		w.takeReasons()
		return
	}
	reasons := w.takeReasons()
	if len(reasons) == 0 {
		return
	}
	entries, err := w.handler(w.ctx, reasons)
	if err == nil {
		err = w.journal.Apply(w.ctx, entries)
	}
	if err != nil && w.onFailure != nil {
		w.onFailure(err)
	}
}

func (w *Worker) takeReasons() []Reason {
	w.reasonMu.Lock()
	defer w.reasonMu.Unlock()
	reasons := append([]Reason(nil), w.pendingReasons...)
	w.pendingReasons = nil
	clear(w.pendingSet)
	return reasons
}

func mergeContext(worker, request context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(request)
	stop := context.AfterFunc(worker, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// ErrStopped means the policy worker no longer accepts work.
var ErrStopped = errors.New("reconciliation worker stopped")
