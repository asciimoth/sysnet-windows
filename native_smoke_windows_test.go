//go:build windows

package windows

import "testing"

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
