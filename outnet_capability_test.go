package windows

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	internalnetwork "github.com/asciimoth/sysnet-windows/internal/network"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

func TestOutNetCapabilityRequiresSelectedFamily(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	source := staticUnderlaySource{candidates: []underlay.Candidate{{
		Interface:       underlay.Interface{LUID: 4, Index: 4, Name: "IPv4 only"},
		Operational:     true,
		InterfaceMetric: 5,
		Addresses: []underlay.Address{{
			Address: netip.MustParseAddr("192.0.2.10"),
			Usable:  true,
		}},
		Routes: []underlay.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Metric:      5,
		}},
	}}}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		underlay: source,
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			underlay: available,
		}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })

	if snapshot := system.underlayMonitor.Snapshot(); snapshot.IPv4 == nil || snapshot.IPv6 != nil {
		t.Fatalf("underlay snapshot = %+v, want only IPv4", snapshot)
	}
	capability := system.Capabilities().Operation(sysnet.OperationKey{
		Target: sysnet.TargetOutNet, Operation: sysnet.OpDialTCP, Family: sysnet.FamilyIPv6,
	})
	_, err = system.OutNet().Dial(context.Background(), "tcp6", "[2001:db8::1]:443")
	if !errors.Is(err, internalnetwork.ErrUnderlayUnavailable) {
		t.Fatalf("IPv6 OutNet dial error = %v, want ErrUnderlayUnavailable", err)
	}
	if capability.State == sysnet.CapabilityAvailable {
		t.Fatalf("IPv6 OutNet capability = %+v, want unavailable without an IPv6 underlay", capability)
	}
}

func TestDefaultTunCapabilityRequiresSelectedFamily(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		underlay:       staticUnderlaySource{candidates: []underlay.Candidate{outNetCandidate(false)}},
		capabilityCode: implementationSupport{defaultTun: true, defaultTunDual: true},
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			netIO: available, underlay: available,
		}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	report := system.Capabilities()
	if got := report.Operation(sysnet.OperationKey{Target: sysnet.TargetDefaultTun, Operation: sysnet.OpCreate, Family: sysnet.FamilyIPv4}); got.State != sysnet.CapabilityAvailable {
		t.Fatalf("IPv4 default TUN capability = %+v, want available", got)
	}
	if got := report.Operation(sysnet.OperationKey{Target: sysnet.TargetDefaultTun, Operation: sysnet.OpCreate, Family: sysnet.FamilyIPv6}); got.State != sysnet.CapabilityUnavailable || len(got.Reasons) != 1 || got.Reasons[0] != sysnet.ReasonNoUnderlay {
		t.Fatalf("IPv6 default TUN capability = %+v, want unavailable/no_underlay", got)
	}
	if got := report.DefaultTunProfile(sysnet.RoutingProfileKey{Family: sysnet.FamilyDual, Mode: sysnet.RoutingFull}); got.State != sysnet.CapabilityUnavailable {
		t.Fatalf("dual default TUN profile = %+v, want unavailable", got)
	}
}

func TestOutNetCapabilitiesMatchEverySelectedFamily(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		candidates []underlay.Candidate
		ipv4       bool
		ipv6       bool
	}{
		{name: "no underlay"},
		{name: "IPv4 only", candidates: []underlay.Candidate{outNetCandidate(false)}, ipv4: true},
		{name: "IPv6 only", candidates: []underlay.Candidate{outNetCandidate(true)}, ipv6: true},
		{name: "dual stack", candidates: []underlay.Candidate{outNetCandidate(false), outNetCandidate(true)}, ipv4: true, ipv6: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			system := newOutNetCapabilitySystem(t, staticUnderlaySource{candidates: test.candidates})
			report := system.Capabilities()
			assertOutNetFamilyCapabilities(t, report, sysnet.FamilyIPv4, test.ipv4)
			assertOutNetFamilyCapabilities(t, report, sysnet.FamilyIPv6, test.ipv6)
			for _, operation := range []sysnet.Operation{sysnet.OpResolve, sysnet.OpInterfaces} {
				assertOutNetCapability(t, report.Operation(sysnet.OperationKey{
					Target: sysnet.TargetOutNet, Operation: operation, Family: sysnet.FamilyNone,
				}), test.ipv4 || test.ipv6)
			}
		})
	}
}

func TestOutNetCapabilitiesFollowLiveUnderlayChanges(t *testing.T) {
	t.Parallel()
	source := &mutableUnderlaySource{candidates: []underlay.Candidate{outNetCandidate(false), outNetCandidate(true)}}
	system := newOutNetCapabilitySystem(t, source)
	initial := system.Capabilities()
	assertOutNetFamilyCapabilities(t, initial, sysnet.FamilyIPv4, true)
	assertOutNetFamilyCapabilities(t, initial, sysnet.FamilyIPv6, true)

	source.set([]underlay.Candidate{outNetCandidate(false)})
	if err := system.underlayMonitor.Refresh(context.Background()); err != nil {
		t.Fatalf("remove IPv6 underlay: %v", err)
	}
	ipv4Only := system.Capabilities()
	if ipv4Only.Revision <= initial.Revision {
		t.Fatalf("IPv4-only revision = %d, want greater than %d", ipv4Only.Revision, initial.Revision)
	}
	assertOutNetFamilyCapabilities(t, ipv4Only, sysnet.FamilyIPv4, true)
	assertOutNetFamilyCapabilities(t, ipv4Only, sysnet.FamilyIPv6, false)
	if repeated := system.Capabilities().Revision; repeated != ipv4Only.Revision {
		t.Fatalf("unchanged underlay revision = %d, want %d", repeated, ipv4Only.Revision)
	}

	source.set(nil)
	if err := system.underlayMonitor.Refresh(context.Background()); err != nil {
		t.Fatalf("remove all underlays: %v", err)
	}
	noUnderlay := system.Capabilities()
	if noUnderlay.Revision <= ipv4Only.Revision {
		t.Fatalf("no-underlay revision = %d, want greater than %d", noUnderlay.Revision, ipv4Only.Revision)
	}
	for _, operation := range []sysnet.Operation{sysnet.OpResolve, sysnet.OpInterfaces} {
		assertOutNetCapability(t, noUnderlay.Operation(sysnet.OperationKey{
			Target: sysnet.TargetOutNet, Operation: operation, Family: sysnet.FamilyNone,
		}), false)
	}

	source.set([]underlay.Candidate{outNetCandidate(false), outNetCandidate(true)})
	if err := system.underlayMonitor.Refresh(context.Background()); err != nil {
		t.Fatalf("restore underlays: %v", err)
	}
	restored := system.Capabilities()
	assertOutNetFamilyCapabilities(t, restored, sysnet.FamilyIPv4, true)
	assertOutNetFamilyCapabilities(t, restored, sysnet.FamilyIPv6, true)
}

func newOutNetCapabilitySystem(t *testing.T, source underlay.Source) *System {
	t.Helper()
	system, err := newSystem(SystemConfig{}, systemDependencies{
		underlay: source,
		capabilityProbe: staticCapabilityProbe{facts: capabilityProbeFacts{
			underlay: sysnet.Capability{State: sysnet.CapabilityAvailable},
		}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	return system
}

func assertOutNetFamilyCapabilities(t *testing.T, report sysnet.CapabilityReport, family sysnet.AddressFamily, available bool) {
	t.Helper()
	for _, operation := range []sysnet.Operation{
		sysnet.OpDialTCP, sysnet.OpDialUDP, sysnet.OpPacketDialUDP,
		sysnet.OpListenTCP, sysnet.OpListenUDP, sysnet.OpListenPacketUDP,
	} {
		assertOutNetCapability(t, report.Operation(sysnet.OperationKey{
			Target: sysnet.TargetOutNet, Operation: operation, Family: family,
		}), available)
	}
}

func assertOutNetCapability(t *testing.T, capability sysnet.Capability, available bool) {
	t.Helper()
	if available {
		if capability.State != sysnet.CapabilityAvailable {
			t.Fatalf("capability = %+v, want available", capability)
		}
		return
	}
	if capability.State != sysnet.CapabilityUnavailable || len(capability.Reasons) != 1 || capability.Reasons[0] != sysnet.ReasonNoUnderlay {
		t.Fatalf("capability = %+v, want unavailable/no_underlay", capability)
	}
}

func outNetCandidate(ipv6 bool) underlay.Candidate {
	if ipv6 {
		return underlay.Candidate{
			Interface:       underlay.Interface{LUID: 6, Index: 6, Name: "IPv6"},
			IPv6:            true,
			Operational:     true,
			InterfaceMetric: 5,
			Addresses:       []underlay.Address{{Address: netip.MustParseAddr("2001:db8::10"), Usable: true}},
			Routes:          []underlay.Route{{Destination: netip.MustParsePrefix("::/0"), Metric: 5}},
		}
	}
	return underlay.Candidate{
		Interface:       underlay.Interface{LUID: 4, Index: 4, Name: "IPv4"},
		Operational:     true,
		InterfaceMetric: 5,
		Addresses:       []underlay.Address{{Address: netip.MustParseAddr("192.0.2.10"), Usable: true}},
		Routes:          []underlay.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Metric: 5}},
	}
}

type staticUnderlaySource struct {
	candidates []underlay.Candidate
}

func (s staticUnderlaySource) ReadCandidates(context.Context) ([]underlay.Candidate, error) {
	return append([]underlay.Candidate(nil), s.candidates...), nil
}

func (staticUnderlaySource) SubscribeChanges(func()) (underlay.Subscription, error) {
	return staticUnderlaySubscription{}, nil
}

type staticUnderlaySubscription struct{}

func (staticUnderlaySubscription) Close() error { return nil }

type mutableUnderlaySource struct {
	mu         sync.Mutex
	candidates []underlay.Candidate
}

func (s *mutableUnderlaySource) ReadCandidates(context.Context) ([]underlay.Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]underlay.Candidate(nil), s.candidates...), nil
}

func (*mutableUnderlaySource) SubscribeChanges(func()) (underlay.Subscription, error) {
	return staticUnderlaySubscription{}, nil
}

func (s *mutableUnderlaySource) set(candidates []underlay.Candidate) {
	s.mu.Lock()
	s.candidates = append([]underlay.Candidate(nil), candidates...)
	s.mu.Unlock()
}
