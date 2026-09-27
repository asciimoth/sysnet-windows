package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Resources tracks sockets, listeners, and TUNs owned by a System.
type Resources struct {
	mu      sync.Mutex
	closed  bool
	nextID  uint64
	entries []*resourceEntry
}

type resourceEntry struct {
	id        uint64
	closer    io.Closer
	closeDone chan struct{}
	closeErr  error
	started   bool
	released  bool
}

// Track adds a resource and returns an idempotent release function. A release
// transfers cleanup responsibility to the caller if tracked cleanup has not
// started. It does not cancel a Close call which has already started. Track
// rejects resources after shutdown intake has stopped.
func (r *Resources) Track(closer io.Closer) (func(), error) {
	if closer == nil {
		return nil, errors.New("track nil resource")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrStopped
	}
	r.nextID++
	id := r.nextID
	r.entries = append(r.entries, &resourceEntry{
		id: id, closer: closer, closeDone: make(chan struct{}),
	})
	var once sync.Once
	return func() {
		once.Do(func() { r.release(id) })
	}, nil
}

// CloseAll stops intake and closes tracked resources in reverse order. It
// returns when ctx ends, even if a resource does not return from Close.
func (r *Resources) CloseAll(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	r.closed = true
	entries := append([]*resourceEntry(nil), r.entries...)
	r.mu.Unlock()

	var result error
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if !r.startClose(entry) {
			continue
		}
		select {
		case <-entry.closeDone:
			if entry.closeErr != nil {
				result = errors.Join(result, fmt.Errorf("close resource %d: %w", entry.id, entry.closeErr))
			}
		case <-ctx.Done():
			return errors.Join(result, fmt.Errorf("close resource %d: %w", entry.id, ctx.Err()))
		}
	}
	return result
}

func (r *Resources) startClose(entry *resourceEntry) bool {
	r.mu.Lock()
	if entry.released {
		r.mu.Unlock()
		return false
	}
	if entry.started {
		r.mu.Unlock()
		return true
	}
	entry.started = true
	r.mu.Unlock()
	go func() {
		err := entry.closer.Close()
		r.mu.Lock()
		entry.closeErr = err
		if err == nil {
			r.removeLocked(entry.id)
		}
		r.mu.Unlock()
		close(entry.closeDone)
	}()
	return true
}

func (r *Resources) release(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range r.entries {
		if entry.id == id {
			// Tracked cleanup owns the result after Close starts. Keep the
			// entry so concurrent and later cleanup sees its final result.
			if entry.started {
				return
			}
			entry.released = true
			r.removeLocked(id)
			return
		}
	}
}

func (r *Resources) removeLocked(id uint64) {
	for index := range r.entries {
		if r.entries[index].id == id {
			r.entries = append(r.entries[:index], r.entries[index+1:]...)
			return
		}
	}
}
