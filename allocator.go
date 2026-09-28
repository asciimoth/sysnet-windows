package windows

import (
	"net"
	"sync"

	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
)

// systemAllocator keeps the shared gonnect allocator behind the same feature
// and lifecycle gates that the System capability report uses. Release methods
// remain available so callers can discard reservations during recovery and
// shutdown.
type systemAllocator struct {
	system   *System
	delegate *internalallocator.Allocator
	mu       sync.Mutex
}

func (a *systemAllocator) ReserveIP(ip net.IP) {
	family, _ := ipFamily(ip)
	if !a.begin(sysnet.OpAllocateIP, family) {
		return
	}
	defer a.end()
	a.delegate.ReserveIP(ip)
}

func (a *systemAllocator) AllocIP4() (net.IP, *net.IPNet) {
	if !a.begin(sysnet.OpAllocateIP, 4) {
		return nil, nil
	}
	defer a.end()
	return a.delegate.AllocIP4()
}

func (a *systemAllocator) AllocIP6() (net.IP, *net.IPNet) {
	if !a.begin(sysnet.OpAllocateIP, 6) {
		return nil, nil
	}
	defer a.end()
	return a.delegate.AllocIP6()
}

func (a *systemAllocator) FreeIP(ip net.IP) { a.delegate.FreeIP(ip) }

func (a *systemAllocator) FreeAllIP() { a.delegate.FreeAllIP() }

func (a *systemAllocator) ReserveSubnet(network *net.IPNet) {
	family, _ := subnetFamily(network)
	if !a.begin(sysnet.OpAllocateSubnet, family) {
		return
	}
	defer a.end()
	a.delegate.ReserveSubnet(network)
}

func (a *systemAllocator) AllocSubnet4(prefix int) *net.IPNet {
	if !a.begin(sysnet.OpAllocateSubnet, 4) {
		return nil
	}
	defer a.end()
	return a.delegate.AllocSubnet4(prefix)
}

func (a *systemAllocator) AllocSubnet6(prefix int) *net.IPNet {
	if !a.begin(sysnet.OpAllocateSubnet, 6) {
		return nil
	}
	defer a.end()
	return a.delegate.AllocSubnet6(prefix)
}

func (a *systemAllocator) FreeSubnet(network *net.IPNet) { a.delegate.FreeSubnet(network) }

func (a *systemAllocator) FreeAllSubnets() { a.delegate.FreeAllSubnets() }

func (a *systemAllocator) begin(operation sysnet.Operation, family int) bool {
	if a == nil || a.system == nil || a.delegate == nil {
		return false
	}
	a.mu.Lock()
	if _, err := a.system.finalPreflight(); err != nil {
		a.mu.Unlock()
		return false
	}
	a.system.mu.RLock()
	addressFamily := sysnet.FamilyNone
	switch family {
	case 4:
		addressFamily = sysnet.FamilyIPv4
	case 6:
		addressFamily = sysnet.FamilyIPv6
	}
	capability := a.system.capabilities.snapshot().Operation(sysnet.OperationKey{
		Target: sysnet.TargetSystem, Operation: operation, Family: addressFamily,
	})
	if a.system.acceptingWorkLocked() != nil || capability.State != sysnet.CapabilityAvailable {
		a.system.mu.RUnlock()
		a.mu.Unlock()
		return false
	}
	return true
}

func (a *systemAllocator) end() {
	a.system.mu.RUnlock()
	a.mu.Unlock()
}

func ipFamily(ip net.IP) (int, bool) {
	if ip.To4() != nil {
		return 4, true
	}
	if ip.To16() != nil {
		return 6, true
	}
	return 0, false
}

func subnetFamily(network *net.IPNet) (int, bool) {
	if network == nil {
		return 0, false
	}
	return ipFamily(network.IP)
}

var (
	_ subnet.IPAllocator     = (*systemAllocator)(nil)
	_ subnet.SubnetAllocator = (*systemAllocator)(nil)
)
