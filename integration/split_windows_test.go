//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"slices"
	"syscall"
	"testing"
	"time"

	internalsplit "github.com/asciimoth/sysnet-windows/internal/split"
	internalwfp "github.com/asciimoth/sysnet-windows/internal/wfp"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// TestC01C03R37R40NativeSplitAcquisition verifies the real exclusive device
// and WFP ownership boundaries. The test never initializes or resets the
// driver. A foreign provider proves that exact cleanup does not flush WFP.
func TestC01C03R37R40NativeSplitAcquisition(t *testing.T) {
	foreignSession, err := wf.New(&wf.Options{
		Name: "sysnet-windows foreign sentinel", Dynamic: false,
		TransactionStartTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("open foreign WFP session: %v", err)
	}
	t.Cleanup(func() {
		if err := foreignSession.Close(); err != nil {
			t.Errorf("close foreign WFP session: %v", err)
		}
	})
	foreignGUID, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("generate foreign provider GUID: %v", err)
	}
	foreignID := wf.ProviderID(foreignGUID)
	if err := foreignSession.AddProvider(&wf.Provider{
		ID: foreignID, Name: "sysnet-windows foreign sentinel",
	}); err != nil {
		t.Fatalf("add foreign WFP provider: %v", err)
	}
	t.Cleanup(func() {
		if err := foreignSession.DeleteProvider(foreignID); err != nil &&
			!errors.Is(err, syscall.Errno(windows.FWP_E_PROVIDER_NOT_FOUND)) {
			t.Errorf("delete foreign WFP provider: %v", err)
		}
	})

	dependencies := internalsplit.Dependencies{
		Verifier: internalsplit.NativeVerifier{}, Opener: internalsplit.NativeOpener{},
		WFP:            internalwfp.NativeFactory{TransactionStartTimeout: 10 * time.Second},
		CleanupTimeout: 10 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, err := internalsplit.Acquire(ctx, dependencies)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("cleanup split session: %v", err)
		}
	})
	resources := session.Resources()
	if err := resources.Validate(); err != nil {
		t.Fatalf("acquired resource journal: %v", err)
	}
	if deployment := session.Deployment(); deployment.Version != "1.3.0.0" || deployment.ABI != "1.3.0.0" {
		t.Fatalf("deployment = %+v, want pinned 1.3.0.0 ABI", deployment)
	}

	if competing, err := internalsplit.Acquire(ctx, dependencies); !errors.Is(err, internalsplit.ErrBusy) {
		if competing != nil {
			_ = competing.Close()
		}
		t.Fatalf("competing Acquire() = %v, %v, want ErrBusy", competing, err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session Close() error = %v", err)
	}

	providers, err := foreignSession.Providers()
	if err != nil {
		t.Fatalf("enumerate WFP providers after close: %v", err)
	}
	if !slices.ContainsFunc(providers, func(provider *wf.Provider) bool { return provider.ID == foreignID }) {
		t.Fatal("foreign WFP provider was removed")
	}
	ownedProvider, err := windows.GUIDFromString(resources.Provider.Key)
	if err != nil {
		t.Fatalf("parse owned provider GUID: %v", err)
	}
	if slices.ContainsFunc(providers, func(provider *wf.Provider) bool {
		return provider.ID == wf.ProviderID(ownedProvider)
	}) {
		t.Fatal("owned WFP provider remains after clean close")
	}
}
