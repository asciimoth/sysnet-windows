package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const rollbackTimeout = 30 * time.Second

// ExpectedState tells a verification operation which exact state to read back.
type ExpectedState uint8

const (
	ExpectedApplied ExpectedState = iota + 1
	ExpectedUndone
)

// Operation applies or undoes one exact owned resource.
type Operation func(context.Context) error

// Verification reads native state independently of the mutation operation.
type Verification func(context.Context, ExpectedState) error

// Entry is one reversible resource mutation. Inverse must affect only Key and
// must restore the pre-apply state even when Apply returns an error.
type Entry struct {
	Key     OwnershipKey
	Apply   Operation
	Inverse Operation
	Verify  Verification
}

// Failure reports whether cleanup could not prove a safe native state.
type Failure struct {
	err              error
	recoveryRequired bool
}

func (e *Failure) Error() string { return e.err.Error() }
func (e *Failure) Unwrap() error { return e.err }

// RecoveryRequired reports whether manual or later owned recovery is needed.
func (e *Failure) RecoveryRequired() bool { return e.recoveryRequired }

// RequiresRecovery reports whether err contains a reconciliation failure whose
// cleanup could not prove a safe state.
func RequiresRecovery(err error) bool {
	var failure *Failure
	return errors.As(err, &failure) && failure.RecoveryRequired()
}

// Journal stores only mutations which can still own native state.
type Journal struct {
	mu             sync.Mutex
	entries        []Entry
	cleanupTimeout time.Duration
	pending        *pendingOperation
	recoveryNeeded bool
}

type pendingOperation struct {
	done chan struct{}
}

// NewJournal creates an ownership journal with a bounded rollback timeout.
func NewJournal(cleanupTimeout time.Duration) *Journal {
	return &Journal{cleanupTimeout: cleanupTimeout}
}

// Apply performs and verifies all entries. It undoes this transaction in exact
// reverse order if an operation fails. Previously committed entries remain.
func (j *Journal) Apply(ctx context.Context, entries []Entry) error {
	if ctx == nil {
		ctx = context.Background()
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.awaitPendingLocked(ctx); err != nil {
		return &Failure{err: err, recoveryRequired: true}
	}
	if j.recoveryNeeded {
		return &Failure{err: ErrRecoveryRequired, recoveryRequired: true}
	}
	if err := validateEntries(j.entries, entries); err != nil {
		return err
	}
	completed := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return j.fail(ctx, err, completed)
		}
		// An OS call can change native state before it reports an error. Include
		// the current entry before Apply so every uncertain mutation is undone.
		completed = append(completed, entry)
		if err := j.invokeLocked(ctx, entry.Apply); err != nil {
			return j.fail(ctx, fmt.Errorf("apply resource %v: %w", entry.Key, err), completed)
		}
		if err := ctx.Err(); err != nil {
			return j.fail(ctx, err, completed)
		}
		if err := j.invokeLocked(ctx, func(ctx context.Context) error {
			return entry.Verify(ctx, ExpectedApplied)
		}); err != nil {
			return j.fail(ctx, fmt.Errorf("verify applied resource %v: %w", entry.Key, err), completed)
		}
		if err := ctx.Err(); err != nil {
			return j.fail(ctx, err, completed)
		}
	}
	j.entries = append(j.entries, completed...)
	return nil
}

func (j *Journal) fail(ctx context.Context, primary error, completed []Entry) error {
	if j.pending != nil {
		j.entries = append(j.entries, completed...)
		j.recoveryNeeded = true
		return &Failure{err: primary, recoveryRequired: true}
	}
	// Request cancellation stops forward progress, but it must not also disable
	// rollback. Preserve context values and give cleanup its own bounded time.
	timeout := j.cleanupTimeout
	if timeout <= 0 {
		timeout = rollbackTimeout
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	remaining, cleanupErr := j.undoLocked(cleanupCtx, completed)
	if len(remaining) != 0 {
		j.entries = append(j.entries, remaining...)
	}
	if cleanupErr == nil {
		return &Failure{err: primary}
	}
	j.recoveryNeeded = true
	return &Failure{
		err:              errors.Join(primary, cleanupErr),
		recoveryRequired: true,
	}
}

// UndoAll undoes every committed entry in reverse order. Entries whose cleanup
// cannot be verified stay in the journal so a later recovery can retry them.
func (j *Journal) UndoAll(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.awaitPendingLocked(ctx); err != nil {
		return &Failure{err: err, recoveryRequired: true}
	}
	remaining, err := j.undoLocked(ctx, j.entries)
	j.entries = remaining
	if err != nil {
		j.recoveryNeeded = true
		return &Failure{err: err, recoveryRequired: true}
	}
	j.recoveryNeeded = false
	return nil
}

// Quiesce waits until a callback which outlived its context has returned. It
// does not retry or verify the uncertain operation.
func (j *Journal) Quiesce(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.awaitPendingLocked(ctx)
}

// Len returns the count of entries which can still own native state.
func (j *Journal) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.entries)
}

// RecoveryRequired reports whether an uncertain callback or failed cleanup
// left journal ownership which must be recovered before new policy work.
func (j *Journal) RecoveryRequired() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.recoveryNeeded
}

func (j *Journal) undoLocked(ctx context.Context, entries []Entry) ([]Entry, error) {
	failed := make(map[int]struct{})
	var cleanupErr error
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if err := ctx.Err(); err != nil {
			markRemaining(failed, index)
			cleanupErr = errors.Join(cleanupErr, err)
			break
		}
		if err := j.invokeLocked(ctx, entry.Inverse); err != nil {
			failed[index] = struct{}{}
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("undo resource %v: %w", entry.Key, err))
			if j.pending != nil || ctx.Err() != nil {
				markRemaining(failed, index-1)
				break
			}
			continue
		}
		if err := j.invokeLocked(ctx, func(ctx context.Context) error {
			return entry.Verify(ctx, ExpectedUndone)
		}); err != nil {
			failed[index] = struct{}{}
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify undone resource %v: %w", entry.Key, err))
			if j.pending != nil || ctx.Err() != nil {
				markRemaining(failed, index-1)
				break
			}
		}
	}
	remaining := make([]Entry, 0, len(failed))
	for index, entry := range entries {
		if _, ok := failed[index]; ok {
			remaining = append(remaining, entry)
		}
	}
	return remaining, cleanupErr
}

func (j *Journal) invokeLocked(ctx context.Context, operation Operation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pending := &pendingOperation{done: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		result <- operation(ctx)
		close(pending.done)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		// Prefer a completed call when completion raced the deadline.
		select {
		case err := <-result:
			return err
		default:
		}
		j.pending = pending
		return ctx.Err()
	}
}

func (j *Journal) awaitPendingLocked(ctx context.Context) error {
	if j.pending == nil {
		return nil
	}
	select {
	case <-j.pending.done:
		j.pending = nil
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func markRemaining(failed map[int]struct{}, last int) {
	for index := 0; index <= last; index++ {
		failed[index] = struct{}{}
	}
}

// ErrRecoveryRequired means uncertain journal ownership must be undone before
// another transaction can start.
var ErrRecoveryRequired = errors.New("journal recovery is required")

func validateEntries(committed, pending []Entry) error {
	keys := make(map[OwnershipKey]struct{}, len(committed)+len(pending))
	for _, entry := range committed {
		keys[entry.Key] = struct{}{}
	}
	for _, entry := range pending {
		if entry.Key.Kind == 0 || entry.Key.ID == "" {
			return fmt.Errorf("invalid ownership key %v", entry.Key)
		}
		if entry.Apply == nil || entry.Inverse == nil || entry.Verify == nil {
			return fmt.Errorf("resource %v has an incomplete journal operation", entry.Key)
		}
		if _, exists := keys[entry.Key]; exists {
			return fmt.Errorf("duplicate ownership key %v", entry.Key)
		}
		keys[entry.Key] = struct{}{}
	}
	return nil
}
