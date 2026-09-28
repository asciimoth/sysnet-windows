//go:build windows

package windows

import (
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	"golang.zx2c4.com/wintun"
)

func TestNativeWintunCapabilityReflectsDLLAvailability(t *testing.T) {
	system, err := New(SystemConfig{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	if wintun.Version() != "" {
		return
	}
	capability := system.Capabilities().Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: sysnet.OpCreate, Family: sysnet.FamilyIPv4,
	})
	if capability.State != sysnet.CapabilityUnavailable ||
		!containsReason(capability.Reasons, sysnet.ReasonMissingDependency) {
		t.Fatalf("create capability without wintun.dll = %+v, want missing dependency", capability)
	}
}

// TestNativeNoResourceSmoke verifies that the baseline can construct and close
// the package without Wintun, the split driver, or a network mutation.
func TestNativeNoResourceSmoke(t *testing.T) {
	system, err := New(SystemConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if report := system.Capabilities(); report.Revision == 0 {
		t.Fatal("Capabilities returned a zero revision")
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestNativeHostAwareAllocation verifies that the Windows NetIO reader can
// obtain complete unicast-address and route snapshots without elevation. It
// reserves address space only in memory and does not change host networking.
func TestNativeHostAwareAllocation(t *testing.T) {
	system, err := New(SystemConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		if err := system.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if network := system.AllocSubnet().AllocSubnet4(24); network == nil {
		t.Fatalf("AllocSubnet4: %v", system.allocator.LastError())
	}
}
