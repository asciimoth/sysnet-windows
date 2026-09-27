package reconcile

import (
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
	entries []resourceEntry
}

type resourceEntry struct {
	id     uint64
	closer io.Closer
}

// Track adds a resource and returns an idempotent release function. Track
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
	r.entries = append(r.entries, resourceEntry{id: id, closer: closer})
	var once sync.Once
	return func() {
		once.Do(func() { r.remove(id) })
	}, nil
}

// CloseAll stops intake and closes tracked resources in reverse order.
func (r *Resources) CloseAll() error {
	r.mu.Lock()
	r.closed = true
	entries := r.entries
	r.entries = nil
	r.mu.Unlock()

	var result error
	for index := len(entries) - 1; index >= 0; index-- {
		if err := entries[index].closer.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close resource %d: %w", entries[index].id, err))
		}
	}
	return result
}

func (r *Resources) remove(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.entries {
		if r.entries[index].id == id {
			r.entries = append(r.entries[:index], r.entries[index+1:]...)
			return
		}
	}
}
