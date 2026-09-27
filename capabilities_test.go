package windows

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
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
