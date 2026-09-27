package reconcile

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
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
				if failPhase == "verify" {
					completed++
				}
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
