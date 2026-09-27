package windows

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
)

func TestSystemContractScaffold(t *testing.T) {
	t.Parallel()

	system := &System{}
	if err := system.Capabilities().Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error = %v", err)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{}).Err(); !errors.Is(err, sysnet.ErrCapabilityUnknown) {
		t.Fatalf("CheckTunOpts() error = %v, want capability unknown", err)
	}
}

func TestDynamicTunOperationsRejectUnknownHandlesFirst(t *testing.T) {
	t.Parallel()

	ready, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem(ready) error = %v", err)
	}
	closed, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem(closed) error = %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	foreign, peer := gtun.Pipe(1, 1500, 0, 0)
	t.Cleanup(func() {
		if err := foreign.Close(); err != nil {
			t.Errorf("foreign Close() error = %v", err)
		}
		if err := peer.Close(); err != nil {
			t.Errorf("peer Close() error = %v", err)
		}
	})

	systems := []struct {
		name   string
		system *System
	}{
		{name: "ready", system: ready},
		{name: "closed", system: closed},
		{name: "uninitialized", system: &System{}},
		{name: "nil receiver"},
	}
	handles := []struct {
		name   string
		handle gtun.Tun
	}{
		{name: "nil"},
		{name: "foreign", handle: foreign},
	}
	operations := []struct {
		name string
		call func(*System, gtun.Tun) error
	}{
		{name: "capabilities", call: func(system *System, device gtun.Tun) error {
			_, err := system.CapabilitiesForTun(device)
			return err
		}},
		{name: "set MTU", call: func(system *System, device gtun.Tun) error {
			return system.SetTunMTU(device, maxTunMTU+1)
		}},
		{name: "set addresses", call: func(system *System, device gtun.Tun) error {
			return system.SetTunAddrs(device, []string{"not-a-prefix"})
		}},
		{name: "add address", call: func(system *System, device gtun.Tun) error {
			return system.AddTunAddr(device, "not-a-prefix")
		}},
		{name: "get addresses", call: func(system *System, device gtun.Tun) error {
			_, err := system.GetTunAddrs(device)
			return err
		}},
		{name: "set routes", call: func(system *System, device gtun.Tun) error {
			return system.SetTunRoutes(device, []string{"not-a-prefix"})
		}},
		{name: "add route", call: func(system *System, device gtun.Tun) error {
			return system.AddTunRoute(device, "not-a-prefix")
		}},
		{name: "get routes", call: func(system *System, device gtun.Tun) error {
			_, err := system.GetTunRoutes(device)
			return err
		}},
		{name: "set name", call: func(system *System, device gtun.Tun) error {
			return system.SetTunName(device, "renamed")
		}},
	}

	for _, state := range systems {
		for _, handle := range handles {
			for _, operation := range operations {
				t.Run(state.name+"/"+handle.name+"/"+operation.name, func(t *testing.T) {
					err := operation.call(state.system, handle.handle)
					if !errors.Is(err, sysnet.ErrUnknownTun) {
						t.Fatalf("error = %v, want ErrUnknownTun", err)
					}
				})
			}
		}
	}
}

func TestValidationReportsExactCapabilityAndLifecycle(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode: implementationSupport{
			regularTun: true,
			defaultTun: true,
		},
		capabilityProbe: &sequenceCapabilityProbe{facts: []capabilityProbeFacts{{
			netIO: available, split: available,
		}}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{TunAddrs: []string{"192.0.2.1/24"}}).Err(); err != nil {
		t.Fatalf("CheckTunOpts() error = %v", err)
	}
	if err := system.CheckDefaultTunOpts(sysnet.DefaultTunOpts{}).Err(); err != nil {
		t.Fatalf("CheckDefaultTunOpts() error = %v", err)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{Name: "named"}).Err(); !errors.Is(err, sysnet.ErrNotSupported) {
		t.Fatalf("named CheckTunOpts() error = %v, want not supported", err)
	}
	if got := system.Capabilities().Operation(operationKey(sysnet.TargetTun, sysnet.OpCreateNamed, sysnet.FamilyNone)); got.State != sysnet.CapabilityUnsupported {
		t.Fatalf("named create capability = %+v, want unsupported", got)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	report := system.CheckTunOpts(sysnet.TunOpts{TunAddrs: []string{"192.0.2.1/24"}})
	if err := report.Err(); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("CheckTunOpts() after Close error = %v, want unavailable", err)
	}
	if report.CapabilityRevision != system.Capabilities().Revision {
		t.Fatalf("validation revision = %d, capability revision = %d", report.CapabilityRevision, system.Capabilities().Revision)
	}
}

func TestCurrentImplementationAdvertisesOnlyCompletedGates(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	report := system.Capabilities()
	if err := report.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error = %v", err)
	}
	for _, operation := range report.Operations {
		if operation.State == sysnet.CapabilityAvailable {
			t.Fatalf("operation enabled before implementation gate: %+v", operation.Key)
		}
	}
	for _, ruleType := range []string{ruleExecutableTree, ruleExecutablePath, rulePID} {
		if got := report.Rule(ruleType).Validation.State; got != sysnet.CapabilityAvailable {
			t.Fatalf("%s validation state = %v, want available", ruleType, got)
		}
	}
}

func TestCapabilityDependencyIsolation(t *testing.T) {
	t.Parallel()
	config := defaultNormalizedSystemConfig()
	support := implementationSupport{
		regularTun: true,
		defaultTun: true,
		exclusions: true,
		matchers:   true,
	}
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	tests := []struct {
		name   string
		split  sysnet.Capability
		state  sysnet.CapabilityState
		reason sysnet.CapabilityReason
	}{
		{name: "available", split: available, state: sysnet.CapabilityAvailable},
		{name: "absent", split: unavailableCapability(sysnet.ReasonMissingDependency), state: sysnet.CapabilityUnavailable, reason: sysnet.ReasonMissingDependency},
		{name: "incompatible", split: unavailableCapability(sysnet.ReasonDependencyIncompatible), state: sysnet.CapabilityUnavailable, reason: sysnet.ReasonDependencyIncompatible},
		{name: "busy", split: unavailableCapability(sysnet.ReasonResourceBusy), state: sysnet.CapabilityUnavailable, reason: sysnet.ReasonResourceBusy},
		{name: "unknown", split: sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun}}, state: sysnet.CapabilityUnknown, reason: sysnet.ReasonProbeNotRun},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := buildCapabilityReport(config, support, capabilityProbeFacts{netIO: available, split: test.split}, lifecycleReady)
			if err := report.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			exclude := report.DefaultTunProfile(sysnet.RoutingProfileKey{Family: sysnet.FamilyIPv4, Mode: sysnet.RoutingExclude})
			if exclude.State != test.state || test.reason != "" && !containsReason(exclude.Reasons, test.reason) {
				t.Fatalf("exclude capability = %+v, want state %v reason %q", exclude.Capability, test.state, test.reason)
			}
			full := report.DefaultTunProfile(sysnet.RoutingProfileKey{Family: sysnet.FamilyIPv4, Mode: sysnet.RoutingFull})
			if full.State != sysnet.CapabilityAvailable {
				t.Fatalf("full profile state = %v, want available", full.State)
			}
			matcher := matcherProfile(report.Rule(rulePID), sysnet.MatcherProfileKey{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP})
			if matcher.State != sysnet.CapabilityAvailable {
				t.Fatalf("matcher state = %v, want available", matcher.State)
			}
		})
	}
}

func TestCapabilityConfigAndNetIOFacts(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	support := implementationSupport{regularTun: true, defaultTun: true, exclusions: true, matchers: true}
	config := defaultNormalizedSystemConfig()
	config.exclusions = false
	config.ipv6 = false
	report := buildCapabilityReport(config, support, capabilityProbeFacts{
		netIO: unavailableCapability(sysnet.ReasonPermissionDenied),
		split: available,
	}, lifecycleReady)
	if err := report.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	v4 := report.Operation(operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4))
	if v4.State != sysnet.CapabilityUnavailable || !containsReason(v4.Reasons, sysnet.ReasonPermissionDenied) {
		t.Fatalf("IPv4 create = %+v", v4)
	}
	v6 := report.Operation(operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv6))
	if v6.State != sysnet.CapabilityUnsupported || !containsReason(v6.Reasons, sysnet.ReasonDisabledByConfig) {
		t.Fatalf("IPv6 create = %+v", v6)
	}
	dual := report.Operation(operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyDual))
	if dual.State != sysnet.CapabilityUnsupported || !containsReason(dual.Reasons, sysnet.ReasonNotImplemented) {
		t.Fatalf("dual create = %+v; separate family support must not imply dual support", dual)
	}
	exclude := report.DefaultTunProfile(sysnet.RoutingProfileKey{Family: sysnet.FamilyIPv4, Mode: sysnet.RoutingExclude})
	if exclude.State != sysnet.CapabilityUnsupported || !containsReason(exclude.Reasons, sysnet.ReasonDisabledByConfig) {
		t.Fatalf("disabled exclude = %+v", exclude.Capability)
	}
}

func TestCapabilityReportContainsExactRoutingProfileMatrix(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	report := buildCapabilityReport(
		defaultNormalizedSystemConfig(),
		implementationSupport{
			defaultTun: true, defaultTunDual: true,
			exclusions: true, exclusionsDual: true,
		},
		capabilityProbeFacts{netIO: available, split: available},
		lifecycleReady,
	)
	if err := report.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	families := []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6, sysnet.FamilyDual}
	modes := []sysnet.RoutingMode{sysnet.RoutingFull, sysnet.RoutingExclude, sysnet.RoutingInclude}
	if got, want := len(report.DefaultTunProfiles), len(families)*len(modes)*2; got != want {
		t.Fatalf("profile count = %d, want %d", got, want)
	}
	for _, family := range families {
		for _, mode := range modes {
			for _, strict := range []bool{false, true} {
				key := sysnet.RoutingProfileKey{Family: family, Mode: mode, Strict: strict}
				profile := report.DefaultTunProfile(key)
				if profile.Key != key {
					t.Errorf("profile lookup for %+v returned key %+v", key, profile.Key)
					continue
				}
				want := sysnet.CapabilityAvailable
				if strict || mode == sysnet.RoutingInclude {
					want = sysnet.CapabilityUnsupported
				}
				if profile.State != want {
					t.Errorf("profile %+v state = %v, want %v", key, profile.State, want)
				}
				if strict && !containsReason(profile.Reasons, sysnet.ReasonNotImplemented) {
					t.Errorf("strict profile %+v reasons = %v, want not implemented", key, profile.Reasons)
				}
			}
		}
	}
}

func TestStrictProfileValidationIsNeverUnknown(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	for _, test := range []struct {
		name string
		opts sysnet.DefaultTunOpts
	}{
		{name: "full", opts: sysnet.DefaultTunOpts{Strict: true}},
		{name: "exclude", opts: sysnet.DefaultTunOpts{Strict: true, Exclude: []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\app.exe`}}}},
		{name: "include", opts: sysnet.DefaultTunOpts{Strict: true, Include: []sysnet.Rule{{Type: ruleExecutableTree, Rule: `C:\app.exe`}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := system.CheckDefaultTunOpts(test.opts)
			if err := report.Err(); !errors.Is(err, sysnet.ErrNotSupported) {
				t.Fatalf("validation error = %v, want not supported", err)
			}
			if errors.Is(report.Err(), sysnet.ErrCapabilityUnknown) {
				t.Fatalf("validation error = %v, must not contain capability unknown", report.Err())
			}
			for _, issue := range report.Issues {
				if issue.Path == "DefaultTun.Profile" && issue.State != sysnet.CapabilityUnsupported {
					t.Errorf("profile issue = %+v, want unsupported", issue)
				}
			}
		})
	}
}

func TestCapabilitySnapshotCopyRevisionAndConcurrency(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode:  implementationSupport{regularTun: true},
		capabilityProbe: &sequenceCapabilityProbe{facts: []capabilityProbeFacts{{netIO: available, split: available}}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	first := system.Capabilities()
	if first.Revision == 0 {
		t.Fatal("initial revision is zero")
	}
	first.Operations[0].Reasons = append(first.Operations[0].Reasons, sysnet.ReasonProbeFailed)
	if reflect.DeepEqual(first, system.Capabilities()) {
		t.Fatal("Capabilities() aliases internal report")
	}
	probe := system.dependencies.capabilityProbe.(*sequenceCapabilityProbe)
	probe.mu.Lock()
	probeCalls := probe.next
	probe.mu.Unlock()
	for range 10 {
		_ = system.Capabilities()
	}
	probe.mu.Lock()
	if probe.next != probeCalls {
		t.Errorf("Capabilities() ran probe: calls = %d, want %d", probe.next, probeCalls)
	}
	probe.mu.Unlock()

	system.mu.Lock()
	system.rebuildCapabilitiesLocked()
	system.mu.Unlock()
	if got := system.Capabilities().Revision; got != first.Revision {
		t.Fatalf("unchanged revision = %d, want %d", got, first.Revision)
	}

	const readers = 16
	var wait sync.WaitGroup
	wait.Add(readers)
	for range readers {
		go func() {
			defer wait.Done()
			for range 100 {
				snapshot := system.Capabilities()
				if err := snapshot.Validate(); err != nil {
					t.Errorf("concurrent Validate() error = %v", err)
					return
				}
			}
		}()
	}
	for range 20 {
		system.mu.Lock()
		system.probeFacts.netIO.Detail = "changed"
		system.rebuildCapabilitiesLocked()
		system.probeFacts.netIO.Detail = ""
		system.rebuildCapabilitiesLocked()
		system.mu.Unlock()
	}
	wait.Wait()
}

func TestCapabilityUnknownIsResolvedByBuild(t *testing.T) {
	t.Parallel()
	unknown := sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun}}
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	probe := &sequenceCapabilityProbe{facts: []capabilityProbeFacts{
		{netIO: unknown, split: unknown},
		{netIO: available, split: available},
	}}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode:  implementationSupport{regularTun: true},
		capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	if got := system.Capabilities().Operation(key).State; got != sysnet.CapabilityUnknown {
		t.Fatalf("initial state = %v, want unknown", got)
	}
	_, err = system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"192.0.2.1/24"}})
	if !errors.Is(err, sysnet.ErrNotSupported) {
		t.Fatalf("BuildTun() error = %v, want current implementation stub", err)
	}
	if got := system.Capabilities().Operation(key).State; got != sysnet.CapabilityAvailable {
		t.Fatalf("resolved state = %v, want available", got)
	}
}

func TestCapabilityFinalPreflightRefreshesStaleFacts(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	busy := unavailableCapability(sysnet.ReasonResourceBusy)
	probe := &sequenceCapabilityProbe{facts: []capabilityProbeFacts{
		{netIO: available, split: available},
		{netIO: busy, split: available},
	}}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode:  implementationSupport{regularTun: true},
		capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	if got := system.Capabilities().Operation(key).State; got != sysnet.CapabilityAvailable {
		t.Fatalf("initial state = %v, want available", got)
	}
	_, err = system.BuildTun(sysnet.TunOpts{TunAddrs: []string{"192.0.2.1/24"}})
	if !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("BuildTun() error = %v, want unavailable", err)
	}
	updated := system.Capabilities().Operation(key)
	if updated.State != sysnet.CapabilityUnavailable || !containsReason(updated.Reasons, sysnet.ReasonResourceBusy) {
		t.Fatalf("updated capability = %+v", updated)
	}
}

func TestCapabilityProbeCannotReportAvailableAfterDeadline(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{OperationTimeout: time.Millisecond}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true},
		capabilityProbe: capabilityProbeFunc(func(ctx context.Context) capabilityProbeFacts {
			<-ctx.Done()
			available := sysnet.Capability{State: sysnet.CapabilityAvailable}
			return capabilityProbeFacts{netIO: available, split: available}
		}),
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	capability := system.Capabilities().Operation(operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4))
	if capability.State != sysnet.CapabilityUnknown || !containsReason(capability.Reasons, sysnet.ReasonProbeFailed) {
		t.Fatalf("create capability = %+v, want failed probe", capability)
	}
}

func TestCapabilityProbeDeadlineDoesNotDependOnProbeCooperation(t *testing.T) {
	t.Parallel()
	const timeout = 20 * time.Millisecond
	blocked := make(chan struct{})
	started := make(chan struct{})
	result := make(chan *System, 1)
	errorsCh := make(chan error, 1)
	go func() {
		system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{
			capabilityCode: implementationSupport{regularTun: true},
			capabilityProbe: capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
				close(started)
				<-blocked
				available := sysnet.Capability{State: sysnet.CapabilityAvailable}
				return capabilityProbeFacts{netIO: available, split: available}
			}),
		})
		result <- system
		errorsCh <- err
	}()
	<-started
	var system *System
	select {
	case system = <-result:
		if err := <-errorsCh; err != nil {
			t.Fatalf("newSystem() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("newSystem() waited for a probe that ignored cancellation")
	}
	close(blocked)
	t.Cleanup(func() { _ = system.Close() })
	capability := system.Capabilities().Operation(operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4))
	if capability.State != sysnet.CapabilityUnknown || !containsReason(capability.Reasons, sysnet.ReasonProbeFailed) {
		t.Fatalf("create capability = %+v, want failed probe", capability)
	}
}

func TestFinalPreflightRejectsSupersededResult(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	busy := unavailableCapability(sysnet.ReasonResourceBusy)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	probe := capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
		switch calls.Add(1) {
		case 1:
			return capabilityProbeFacts{netIO: available, split: available}
		case 2:
			facts := capabilityProbeFacts{netIO: available, split: available}
			close(firstStarted)
			<-releaseFirst
			return facts
		default:
			return capabilityProbeFacts{netIO: busy, split: available}
		}
	})
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	firstErr := make(chan error, 1)
	go func() {
		_, err := system.finalPreflight()
		firstErr <- err
	}()
	<-firstStarted
	second, err := system.finalPreflight()
	if err != nil {
		t.Fatalf("second finalPreflight() error = %v", err)
	}
	close(releaseFirst)
	if err := <-firstErr; !isSupersededProbeError(err) {
		t.Fatalf("first finalPreflight() error = %v, want superseded probe", err)
	}

	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	secondCapability := second.Operation(key)
	if secondCapability.State != sysnet.CapabilityUnavailable || !containsReason(secondCapability.Reasons, sysnet.ReasonResourceBusy) {
		t.Fatalf("second snapshot capability = %+v, want busy", secondCapability)
	}
	capability := system.Capabilities().Operation(key)
	if capability.State != sysnet.CapabilityUnavailable || !containsReason(capability.Reasons, sysnet.ReasonResourceBusy) {
		t.Fatalf("capability after newer busy probe = %+v, want busy", capability)
	}
}

func TestBuildTunRejectsSupersededPreflight(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	busy := unavailableCapability(sysnet.ReasonResourceBusy)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	probe := capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
		switch calls.Add(1) {
		case 1:
			return capabilityProbeFacts{netIO: available, split: available}
		case 2:
			facts := capabilityProbeFacts{netIO: available, split: available}
			close(firstStarted)
			<-releaseFirst
			return facts
		default:
			return capabilityProbeFacts{netIO: busy, split: available}
		}
	})
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	opts := sysnet.TunOpts{TunAddrs: []string{"192.0.2.1/24"}}
	firstErr := make(chan error, 1)
	go func() {
		_, err := system.BuildTun(opts)
		firstErr <- err
	}()
	<-firstStarted
	if _, err := system.BuildTun(opts); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("newer BuildTun() error = %v, want unavailable", err)
	}
	close(releaseFirst)
	if err := <-firstErr; !isSupersededProbeError(err) {
		t.Fatalf("older BuildTun() error = %v, want superseded probe", err)
	}
}

func TestFinalPreflightRejectsOldResultWhileNewProbeIsPending(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	busy := unavailableCapability(sysnet.ReasonResourceBusy)
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	var calls atomic.Int32
	probe := capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
		switch calls.Add(1) {
		case 1:
			return capabilityProbeFacts{netIO: available, split: available}
		case 2:
			facts := capabilityProbeFacts{netIO: busy, split: available}
			close(firstStarted)
			<-releaseFirst
			return facts
		default:
			facts := capabilityProbeFacts{netIO: available, split: available}
			close(secondStarted)
			<-releaseSecond
			return facts
		}
	})
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })

	firstErr := make(chan error, 1)
	go func() {
		_, err := system.finalPreflight()
		firstErr <- err
	}()
	<-firstStarted
	secondErr := make(chan error, 1)
	go func() {
		_, err := system.finalPreflight()
		secondErr <- err
	}()
	<-secondStarted
	close(releaseFirst)
	if err := <-firstErr; !isSupersededProbeError(err) {
		t.Fatalf("first finalPreflight() error = %v, want superseded probe", err)
	}

	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	if got := system.Capabilities().Operation(key).State; got != sysnet.CapabilityAvailable {
		t.Fatalf("capability while newer probe is pending = %v, want initial available", got)
	}
	close(releaseSecond)
	if err := <-secondErr; err != nil {
		t.Fatalf("second finalPreflight() error = %v", err)
	}
	if got := system.Capabilities().Operation(key).State; got != sysnet.CapabilityAvailable {
		t.Fatalf("capability after newer probe = %v, want available", got)
	}
}

func TestFinalPreflightCloseSupersedesPendingProbe(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	probe := capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
		if calls.Add(1) == 1 {
			return capabilityProbeFacts{netIO: available, split: available}
		}
		close(started)
		<-release
		return capabilityProbeFacts{netIO: available, split: available}
	})
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	probeErr := make(chan error, 1)
	go func() {
		_, err := system.finalPreflight()
		probeErr <- err
	}()
	<-started
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	close(release)
	if err := <-probeErr; !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("finalPreflight() error = %v, want unavailable", err)
	}
	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	capability := system.Capabilities().Operation(key)
	if capability.State != sysnet.CapabilityUnavailable || !containsReason(capability.Reasons, sysnet.ReasonSystemClosed) {
		t.Fatalf("capability after close = %+v, want system closed", capability)
	}
}

func TestFinalPreflightTimeoutCannotReplaceNewerProbeFacts(t *testing.T) {
	t.Parallel()
	const timeout = 20 * time.Millisecond
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	busy := unavailableCapability(sysnet.ReasonResourceBusy)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	probe := capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
		switch calls.Add(1) {
		case 1:
			return capabilityProbeFacts{netIO: available, split: available}
		case 2:
			close(started)
			<-release
			return capabilityProbeFacts{netIO: available, split: available}
		default:
			return capabilityProbeFacts{netIO: busy, split: available}
		}
	})
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })

	oldErr := make(chan error, 1)
	go func() {
		_, err := system.finalPreflight()
		oldErr <- err
	}()
	<-started
	if _, err := system.finalPreflight(); err != nil {
		t.Fatalf("newer finalPreflight() error = %v", err)
	}
	if err := <-oldErr; !isSupersededProbeError(err) {
		t.Fatalf("old finalPreflight() error = %v, want superseded probe", err)
	}
	close(release)

	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	capability := system.Capabilities().Operation(key)
	if capability.State != sysnet.CapabilityUnavailable || !containsReason(capability.Reasons, sysnet.ReasonResourceBusy) {
		t.Fatalf("capability after old probe timeout = %+v, want busy", capability)
	}
}

func isSupersededProbeError(err error) bool {
	var validationErr *sysnet.ValidationError
	return errors.Is(err, sysnet.ErrUnavailable) && errors.As(err, &validationErr) &&
		validationErr.Issue.Path == "System.CapabilityProbe" &&
		validationErr.Issue.Reason == sysnet.ReasonResourceBusy
}

func TestFinalPreflightBoundsUncooperativeProbe(t *testing.T) {
	t.Parallel()
	const timeout = 20 * time.Millisecond
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	blocked := make(chan struct{})
	started := make(chan struct{})
	var calls atomic.Int32
	probe := capabilityProbeFunc(func(context.Context) capabilityProbeFacts {
		if calls.Add(1) == 1 {
			return capabilityProbeFacts{netIO: available, split: available}
		}
		close(started)
		<-blocked
		return capabilityProbeFacts{netIO: available, split: available}
	})
	system, err := newSystem(SystemConfig{OperationTimeout: timeout}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true}, capabilityProbe: probe,
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	result := make(chan sysnet.CapabilityReport, 1)
	errorsCh := make(chan error, 1)
	go func() {
		report, err := system.finalPreflight()
		result <- report
		errorsCh <- err
	}()
	<-started
	var report sysnet.CapabilityReport
	select {
	case report = <-result:
		if err := <-errorsCh; err != nil {
			t.Fatalf("finalPreflight() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("finalPreflight() waited for a probe that ignored cancellation")
	}
	close(blocked)
	t.Cleanup(func() { _ = system.Close() })
	capability := report.Operation(operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4))
	if capability.State != sysnet.CapabilityUnknown || !containsReason(capability.Reasons, sysnet.ReasonProbeFailed) {
		t.Fatalf("create capability = %+v, want failed probe", capability)
	}
}

func TestLifecycleTransitionsAndClose(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode:  implementationSupport{regularTun: true},
		capabilityProbe: &sequenceCapabilityProbe{facts: []capabilityProbeFacts{{netIO: available, split: available}}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	if err := system.beginApply(); err != nil {
		t.Fatalf("beginApply() error = %v", err)
	}
	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	applying := system.Capabilities().Operation(key)
	if applying.State != sysnet.CapabilityUnavailable || !containsReason(applying.Reasons, sysnet.ReasonResourceBusy) {
		t.Fatalf("applying capability = %+v", applying)
	}
	if err := system.finishApply(true, false); err != nil {
		t.Fatalf("finishApply() error = %v", err)
	}
	if got := system.Capabilities().Operation(key).State; got != sysnet.CapabilityAvailable {
		t.Fatalf("active capability state = %v, want available", got)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	closed := system.Capabilities().Operation(key)
	if closed.State != sysnet.CapabilityUnavailable || !containsReason(closed.Reasons, sysnet.ReasonSystemClosed) {
		t.Fatalf("closed capability = %+v", closed)
	}
	if _, err := system.BuildTun(sysnet.TunOpts{}); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("BuildTun() after Close error = %v, want unavailable", err)
	}
	unsupportedRename := system.Capabilities().Operation(operationKey(sysnet.TargetTun, sysnet.OpRename, sysnet.FamilyNone))
	if unsupportedRename.State != sysnet.CapabilityUnsupported {
		t.Fatalf("static unsupported row changed on close: %+v", unsupportedRename)
	}
}

func TestCloseOverridesUnknownCapabilityFacts(t *testing.T) {
	t.Parallel()
	unknown := sysnet.Capability{
		State:   sysnet.CapabilityUnknown,
		Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
	}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode: implementationSupport{regularTun: true},
		capabilityProbe: &sequenceCapabilityProbe{facts: []capabilityProbeFacts{{
			netIO: unknown, split: unknown,
		}}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	beforeRevision := system.Capabilities().Revision
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	capability := system.Capabilities().Operation(key)
	if capability.State != sysnet.CapabilityUnavailable ||
		!containsReason(capability.Reasons, sysnet.ReasonSystemClosed) {
		t.Errorf("capability after Close = %+v, want system closed", capability)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{
		TunAddrs: []string{"192.0.2.1/24"},
	}).Err(); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("CheckTunOpts() after Close error = %v, want unavailable", err)
	}
	if got := system.Capabilities().Revision; got <= beforeRevision {
		t.Fatalf("capability revision after Close = %d, want greater than %d", got, beforeRevision)
	}
}

func TestLifecycleCapabilityPrecedence(t *testing.T) {
	t.Parallel()
	bases := []struct {
		name       string
		capability sysnet.Capability
	}{
		{name: "available", capability: sysnet.Capability{State: sysnet.CapabilityAvailable}},
		{name: "unknown", capability: sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun}}},
		{name: "unavailable", capability: unavailableCapability(sysnet.ReasonPermissionDenied)},
		{name: "unsupported", capability: unsupported(sysnet.ReasonDisabledByConfig, "disabled")},
	}
	states := []struct {
		name   string
		state  lifecycleState
		reason sysnet.CapabilityReason
	}{
		{name: "applying", state: lifecycleApplying, reason: sysnet.ReasonResourceBusy},
		{name: "closing", state: lifecycleClosing, reason: sysnet.ReasonSystemClosed},
		{name: "closed", state: lifecycleClosed, reason: sysnet.ReasonSystemClosed},
		{name: "recovery", state: lifecycleRecoveryRequired, reason: sysnet.ReasonRecoveryRequired},
	}
	for _, state := range states {
		for _, base := range bases {
			t.Run(state.name+"/"+base.name, func(t *testing.T) {
				t.Parallel()
				got := lifecycleCapability(base.capability, state.state)
				if base.capability.State == sysnet.CapabilityUnsupported {
					if !reflect.DeepEqual(got, base.capability) {
						t.Fatalf("capability = %+v, want unchanged unsupported capability %+v", got, base.capability)
					}
					return
				}
				if got.State != sysnet.CapabilityUnavailable || !containsReason(got.Reasons, state.reason) {
					t.Fatalf("capability = %+v, want unavailable reason %q", got, state.reason)
				}
			})
		}
	}
}

func TestLifecycleAppliesToEveryCapabilitySurface(t *testing.T) {
	t.Parallel()
	config := defaultNormalizedSystemConfig()
	config.ipv6 = false
	unknown := sysnet.Capability{
		State:   sysnet.CapabilityUnknown,
		Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
	}
	support := implementationSupport{
		regularTun: true, regularTunDual: true, regularTunNamed: true,
		defaultTun: true, defaultTunDual: true, defaultTunNamed: true,
		exclusions: true, exclusionsDual: true, matchers: true,
		exclusionRuleValidation: true, matcherRuleValidation: true,
	}
	facts := capabilityProbeFacts{netIO: unknown, split: unknown}
	ready := reportCapabilityList(buildCapabilityReport(config, support, facts, lifecycleReady))
	states := []struct {
		name   string
		state  lifecycleState
		reason sysnet.CapabilityReason
	}{
		{name: "applying", state: lifecycleApplying, reason: sysnet.ReasonResourceBusy},
		{name: "closed", state: lifecycleClosed, reason: sysnet.ReasonSystemClosed},
		{name: "recovery", state: lifecycleRecoveryRequired, reason: sysnet.ReasonRecoveryRequired},
	}
	for _, test := range states {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := buildCapabilityReport(config, support, facts, test.state)
			if err := report.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			got := reportCapabilityList(report)
			if len(got) != len(ready) {
				t.Fatalf("capability count = %d, want %d", len(got), len(ready))
			}
			for index := range ready {
				if got[index].name != ready[index].name {
					t.Fatalf("capability[%d] name = %q, want %q", index, got[index].name, ready[index].name)
				}
				if ready[index].capability.State == sysnet.CapabilityUnsupported {
					if !reflect.DeepEqual(got[index].capability, ready[index].capability) {
						t.Errorf("%s = %+v, want unchanged unsupported capability %+v", got[index].name, got[index].capability, ready[index].capability)
					}
					continue
				}
				if got[index].capability.State != sysnet.CapabilityUnavailable ||
					!containsReason(got[index].capability.Reasons, test.reason) {
					t.Errorf("%s = %+v, want unavailable reason %q", got[index].name, got[index].capability, test.reason)
				}
			}
		})
	}
}

type namedCapability struct {
	name       string
	capability sysnet.Capability
}

func reportCapabilityList(report sysnet.CapabilityReport) []namedCapability {
	var result []namedCapability
	for _, operation := range report.Operations {
		result = append(result, namedCapability{name: fmt.Sprintf("operation/%+v", operation.Key), capability: operation.Capability})
	}
	for _, profile := range report.DefaultTunProfiles {
		result = append(result, namedCapability{name: fmt.Sprintf("profile/%+v", profile.Key), capability: profile.Capability})
		for _, binding := range profile.Rules {
			result = append(result, namedCapability{name: fmt.Sprintf("profile/%+v/rule/%s", profile.Key, binding.Type), capability: binding.Capability})
		}
	}
	for _, rule := range report.Rules {
		result = append(result,
			namedCapability{name: "rule/" + rule.Type + "/validation", capability: rule.Validation},
			namedCapability{name: "rule/" + rule.Type + "/completion", capability: rule.Completion},
		)
		for _, matcher := range rule.Matchers {
			result = append(result, namedCapability{name: fmt.Sprintf("rule/%s/matcher/%+v", rule.Type, matcher.Key), capability: matcher.Capability})
		}
	}
	for _, ownership := range report.Ownership {
		result = append(result, namedCapability{name: fmt.Sprintf("owner/%+v", ownership.Key), capability: ownership.Capability})
		for _, field := range ownership.Fields {
			result = append(result, namedCapability{name: fmt.Sprintf("owner/%+v/field/%s", ownership.Key, field.Field), capability: field.Capability})
		}
	}
	return result
}

func TestRecoveryRequiredLifecycle(t *testing.T) {
	t.Parallel()
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	system, err := newSystem(SystemConfig{}, systemDependencies{
		capabilityCode:  implementationSupport{regularTun: true},
		capabilityProbe: &sequenceCapabilityProbe{facts: []capabilityProbeFacts{{netIO: available, split: available}}},
	})
	if err != nil {
		t.Fatalf("newSystem() error = %v", err)
	}
	if err := system.beginApply(); err != nil {
		t.Fatalf("beginApply() error = %v", err)
	}
	if err := system.finishApply(false, true); err != nil {
		t.Fatalf("finishApply() error = %v", err)
	}
	key := operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4)
	capability := system.Capabilities().Operation(key)
	if capability.State != sysnet.CapabilityUnavailable || !containsReason(capability.Reasons, sysnet.ReasonRecoveryRequired) {
		t.Fatalf("recovery capability = %+v", capability)
	}
	if _, err := system.BuildTun(sysnet.TunOpts{}); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("BuildTun() in recovery state error = %v, want unavailable", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func unavailableCapability(reason sysnet.CapabilityReason) sysnet.Capability {
	return sysnet.Capability{State: sysnet.CapabilityUnavailable, Reasons: []sysnet.CapabilityReason{reason}}
}

func containsReason(reasons []sysnet.CapabilityReason, want sysnet.CapabilityReason) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

type sequenceCapabilityProbe struct {
	mu    sync.Mutex
	facts []capabilityProbeFacts
	next  int
}

type capabilityProbeFunc func(context.Context) capabilityProbeFacts

func (f capabilityProbeFunc) Probe(ctx context.Context) capabilityProbeFacts { return f(ctx) }

func (p *sequenceCapabilityProbe) Probe(context.Context) capabilityProbeFacts {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := p.next
	if index >= len(p.facts) {
		index = len(p.facts) - 1
	} else {
		p.next++
	}
	return p.facts[index]
}

func TestLegacyCapabilityProjection(t *testing.T) {
	t.Parallel()

	available := sysnet.Capability{State: sysnet.CapabilityAvailable}
	unavailable := sysnet.Capability{State: sysnet.CapabilityUnavailable}
	operations := []sysnet.OperationCapability{
		{Key: operationKey(sysnet.TargetTun, sysnet.OpCreate, sysnet.FamilyIPv4), Capability: available},
		{Key: operationKey(sysnet.TargetDefaultTun, sysnet.OpCreate, sysnet.FamilyIPv4), Capability: available},
		{Key: operationKey(sysnet.TargetTun, sysnet.OpSetMTU, sysnet.FamilyNone), Capability: available},
		{Key: operationKey(sysnet.TargetTun, sysnet.OpSetAddresses, sysnet.FamilyIPv4), Capability: available},
		{Key: operationKey(sysnet.TargetTun, sysnet.OpAddAddress, sysnet.FamilyIPv4), Capability: available},
		{Key: operationKey(sysnet.TargetTun, sysnet.OpSetRoutes, sysnet.FamilyIPv4), Capability: available},
		{Key: operationKey(sysnet.TargetTun, sysnet.OpAddRoute, sysnet.FamilyIPv4), Capability: available},
		{Key: operationKey(sysnet.TargetTun, sysnet.OpRename, sysnet.FamilyNone), Capability: available},
		{Key: operationKey(sysnet.TargetDefaultTun, sysnet.OpSourceRoutes, sysnet.FamilyIPv4), Capability: unavailable},
	}
	report := sysnet.CapabilityReport{
		SchemaVersion: sysnet.CapabilitySchemaVersion,
		Operations:    operations,
		DefaultTunProfiles: []sysnet.DefaultTunProfile{
			{
				Key:        sysnet.RoutingProfileKey{Family: sysnet.FamilyIPv4, Mode: sysnet.RoutingFull},
				Capability: available,
			},
			{
				Key:        sysnet.RoutingProfileKey{Family: sysnet.FamilyIPv4, Mode: sysnet.RoutingExclude, Strict: true},
				Capability: available,
				Rules: []sysnet.RuleBinding{
					{Type: "win-exe-tree", Capability: available},
					{Type: "win-exe-tree", Capability: available},
				},
			},
		},
		Rules: []sysnet.RuleCapability{
			{
				Type:        "win-exe-tree",
				Description: "executable tree",
				Validation:  available,
				Completion:  available,
			},
			{
				Type:        "win-pid",
				Description: "process identifier",
				Validation:  available,
				Completion:  available,
				Matchers: []sysnet.MatcherProfile{{
					Key:        sysnet.MatcherProfileKey{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP},
					Capability: available,
				}},
			},
		},
	}

	features, rules := projectLegacyCapabilities(capabilityModel{report: report})
	wantFeatures := legacyFeatures{
		Tun:        true,
		DefaultTun: true,
		DynTun:     true,
		TunNames:   true,
		StrictMode: true,
	}
	if features != wantFeatures {
		t.Fatalf("features = %+v, want %+v", features, wantFeatures)
	}
	wantRules := legacyRulesInfo{
		TunRules: []legacyRuleTypeInfo{{
			Type: "win-exe-tree", Description: "executable tree",
		}},
		MatcherRules: []legacyRuleTypeInfo{{
			Type: "win-pid", Description: "process identifier",
		}},
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("rules = %+v, want %+v", rules, wantRules)
	}
}

func operationKey(target sysnet.Target, operation sysnet.Operation, family sysnet.AddressFamily) sysnet.OperationKey {
	return sysnet.OperationKey{Target: target, Operation: operation, Family: family}
}
