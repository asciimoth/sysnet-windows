package windows

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/netio"
)

func TestSystemAllocatorsShareReservationsAndStopAtClose(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, availableAllocatorDependencies(emptyHostReader{}))
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

func TestSystemAllocatorsRejectUnavailableWork(t *testing.T) {
	for _, test := range []struct {
		name   string
		config SystemConfig
		family sysnet.AddressFamily
		ip     func(*System) bool
		subnet func(*System) bool
	}{
		{
			name: "disabled IPv4", config: SystemConfig{Features: FeatureConfig{DisableIPv4: true}},
			family: sysnet.FamilyIPv4,
			ip: func(system *System) bool {
				ip, network := system.AllocIP().AllocIP4()
				return ip != nil || network != nil
			},
			subnet: func(system *System) bool { return system.AllocSubnet().AllocSubnet4(24) != nil },
		},
		{
			name: "disabled IPv6", config: SystemConfig{Features: FeatureConfig{DisableIPv6: true}},
			family: sysnet.FamilyIPv6,
			ip: func(system *System) bool {
				ip, network := system.AllocIP().AllocIP6()
				return ip != nil || network != nil
			},
			subnet: func(system *System) bool { return system.AllocSubnet().AllocSubnet6(64) != nil },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			system, err := newSystem(SystemConfig{
				Features: test.config.Features,
			}, systemDependencies{allocationReader: emptyHostReader{}})
			if err != nil {
				t.Fatalf("newSystem: %v", err)
			}
			t.Cleanup(func() { _ = system.Close() })

			for _, operation := range []sysnet.Operation{sysnet.OpAllocateIP, sysnet.OpAllocateSubnet} {
				capability := system.Capabilities().Operation(operationKey(sysnet.TargetSystem, operation, test.family))
				if capability.State != sysnet.CapabilityUnsupported {
					t.Fatalf("%s IPv6 capability = %+v, want unsupported", operation, capability)
				}
			}
			if test.ip(system) {
				t.Error("IP allocation succeeded for a disabled family")
			}
			if test.subnet(system) {
				t.Error("subnet allocation succeeded for a disabled family")
			}
		})
	}

	for _, state := range []lifecycleState{lifecycleApplying, lifecycleRecoveryRequired, lifecycleClosing} {
		t.Run(state.String(), func(t *testing.T) {
			system, err := newSystem(SystemConfig{}, systemDependencies{
				allocationReader: emptyHostReader{},
			})
			if err != nil {
				t.Fatalf("newSystem: %v", err)
			}
			t.Cleanup(func() { _ = system.Close() })

			system.mu.Lock()
			if err := system.transitionLocked(state); err != nil {
				system.mu.Unlock()
				t.Fatalf("transition to %s: %v", state, err)
			}
			system.rebuildCapabilitiesLocked()
			system.mu.Unlock()

			capability := system.Capabilities().Operation(operationKey(
				sysnet.TargetSystem, sysnet.OpAllocateIP, sysnet.FamilyIPv4,
			))
			if capability.State != sysnet.CapabilityUnavailable {
				t.Fatalf("IPv4 allocation capability = %+v, want unavailable", capability)
			}
			if ip, network := system.AllocIP().AllocIP4(); ip != nil || network != nil {
				t.Errorf("AllocIP4() = (%v, %v), want nils in %s", ip, network, state)
			}
			if network := system.AllocSubnet().AllocSubnet4(24); network != nil {
				t.Errorf("AllocSubnet4() = %v, want nil in %s", network, state)
			}
		})
	}
}

func TestSystemAllocatorReleaseMethodsRemainAvailableDuringRecovery(t *testing.T) {
	system, err := newSystem(SystemConfig{}, availableAllocatorDependencies(emptyHostReader{}))
	if err != nil {
		t.Fatalf("newSystem: %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })

	ip, _ := system.AllocIP().AllocIP4()
	subnet := system.AllocSubnet().AllocSubnet6(64)
	if ip == nil || subnet == nil {
		t.Fatal("initial allocations failed")
	}
	system.mu.Lock()
	_ = system.transitionLocked(lifecycleRecoveryRequired)
	system.rebuildCapabilitiesLocked()
	system.mu.Unlock()

	// Release operations must not be blocked by the new-work gate.
	system.AllocIP().FreeIP(ip)
	system.AllocIP().FreeAllIP()
	system.AllocSubnet().FreeSubnet(subnet)
	system.AllocSubnet().FreeAllSubnets()
}

func TestSystemAllocatorHonorsDependencyCapability(t *testing.T) {
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	unavailable := unavailableCapability(sysnet.ReasonPermissionDenied)
	tests := []struct {
		name         string
		dependencies systemDependencies
	}{
		{
			name: "missing reader",
			dependencies: systemDependencies{
				capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{netIO: available}},
			},
		},
		{
			name: "unavailable reader",
			dependencies: systemDependencies{
				allocationReader: emptyHostReader{},
				capabilityProbe:  staticCapabilityProbe{facts: capabilityProbeFacts{netIO: unavailable}},
			},
		},
		{
			name:         "probe not run",
			dependencies: systemDependencies{allocationReader: emptyHostReader{}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system, err := newSystem(SystemConfig{}, test.dependencies)
			if err != nil {
				t.Fatalf("newSystem: %v", err)
			}
			t.Cleanup(func() { _ = system.Close() })
			if ip, network := system.AllocIP().AllocIP4(); ip != nil || network != nil {
				t.Errorf("AllocIP4() = (%v, %v), want nils", ip, network)
			}
			if network := system.AllocSubnet().AllocSubnet6(64); network != nil {
				t.Errorf("AllocSubnet6() = %v, want nil", network)
			}
		})
	}
}

func TestSystemAllocatorUsesRefreshedCapability(t *testing.T) {
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	unavailable := unavailableCapability(sysnet.ReasonResourceBusy)
	probe := &sequenceCapabilityProbe{facts: []capabilityProbeFacts{
		{netIO: unavailable},
		{netIO: unavailable},
		{netIO: available},
	}}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		allocationReader: emptyHostReader{}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem: %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	if ip, network := system.AllocIP().AllocIP4(); ip != nil || network != nil {
		t.Fatalf("AllocIP4() before refresh = (%v, %v), want nils", ip, network)
	}
	if _, err := system.finalPreflight(); err != nil {
		t.Fatalf("finalPreflight() error = %v", err)
	}
	if ip, network := system.AllocIP().AllocIP4(); ip == nil || network == nil {
		t.Fatalf("AllocIP4() after refresh = (%v, %v), want allocation", ip, network)
	}
}

func TestSystemAllocatorLinearizesWithLifecycleTransition(t *testing.T) {
	reader := &blockingHostReader{started: make(chan struct{}), release: make(chan struct{})}
	system, err := newSystem(SystemConfig{}, availableAllocatorDependencies(reader))
	if err != nil {
		t.Fatalf("newSystem: %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })

	allocationDone := make(chan struct{})
	go func() {
		defer close(allocationDone)
		_, _ = system.AllocIP().AllocIP4()
	}()
	<-reader.started
	transitionDone := make(chan error, 1)
	go func() { transitionDone <- system.beginApply() }()
	select {
	case err := <-transitionDone:
		t.Fatalf("beginApply() completed before allocation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	<-allocationDone
	if err := <-transitionDone; err != nil {
		t.Fatalf("beginApply() error = %v", err)
	}
	if err := system.finishApply(false, false); err != nil {
		t.Fatalf("finishApply() error = %v", err)
	}
}

func TestSystemAllocatorSerializesConcurrentPreflights(t *testing.T) {
	system, err := newSystem(SystemConfig{}, availableAllocatorDependencies(emptyHostReader{}))
	if err != nil {
		t.Fatalf("newSystem: %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })

	const count = 16
	results := make(chan string, count)
	var group sync.WaitGroup
	group.Add(count)
	for range count {
		go func() {
			defer group.Done()
			ip, network := system.AllocIP().AllocIP4()
			if ip == nil || network == nil {
				results <- ""
				return
			}
			results <- ip.String()
		}()
	}
	group.Wait()
	close(results)
	unique := make(map[string]struct{}, count)
	for address := range results {
		if address == "" {
			t.Error("concurrent allocation returned nil")
			continue
		}
		if _, exists := unique[address]; exists {
			t.Errorf("concurrent allocation repeated %s", address)
		}
		unique[address] = struct{}{}
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

func availableAllocatorDependencies(reader netio.Reader) systemDependencies {
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	return systemDependencies{
		allocationReader: reader,
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			netIO: available, split: available,
		}},
	}
}

type blockingHostReader struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (r *blockingHostReader) ReadHostState(context.Context) (netio.HostState, error) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return netio.HostState{}, nil
}
