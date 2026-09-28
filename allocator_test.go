package windows

import (
	"context"
	"net/netip"
	"testing"

	"github.com/asciimoth/sysnet-windows/internal/netio"
)

func TestSystemAllocatorsShareReservationsAndStopAtClose(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{
		allocationReader: emptyHostReader{},
	})
	if err != nil {
		t.Fatalf("newSystem: %v", err)
	}
	ipAllocator := system.AllocIP()
	subnetAllocator := system.AllocSubnet()
	if ipAllocator == nil || subnetAllocator == nil {
		t.Fatal("System returned a nil allocator")
	}
	if any(ipAllocator) != any(subnetAllocator) {
		t.Fatal("AllocIP and AllocSubnet do not share reservation state")
	}
	if ip, _ := ipAllocator.AllocIP4(); ip == nil {
		t.Fatal("AllocIP4 returned nil before close")
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := subnetAllocator.AllocSubnet4(24); got != nil {
		t.Fatalf("AllocSubnet4 after close = %v, want nil", got)
	}
}

type emptyHostReader struct{}

func (emptyHostReader) ReadHostState(context.Context) (netio.HostState, error) {
	return netio.HostState{
		Routes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}, nil
}
