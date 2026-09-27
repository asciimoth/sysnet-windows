package windows

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
)

func TestSystemCloseOrdersResourcesBeforeHostRollback(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
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

type systemCloseFunc func() error

func (f systemCloseFunc) Close() error { return f() }
