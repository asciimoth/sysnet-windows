package windows

import (
	"reflect"
	"sort"

	"github.com/asciimoth/gonnect/sysnet"
)

const (
	ruleExecutableTree = "win-exe-tree"
	ruleExecutablePath = "win-exe-path"
	rulePID            = "win-pid"
)

// capabilityModel is the package's single capability source. The selected
// gonnect contract includes the capability API, so this package stores its
// types instead of publishing a second capability API. System.mu protects it.
type capabilityModel struct {
	report sysnet.CapabilityReport
}

func (m capabilityModel) snapshot() sysnet.CapabilityReport {
	report := m.report.Clone()
	if report.SchemaVersion == 0 {
		report.SchemaVersion = sysnet.CapabilitySchemaVersion
	}
	return report
}

// replace updates the report and its instance-local revision. Revision is not
// part of semantic equality.
func (m *capabilityModel) replace(next sysnet.CapabilityReport) bool {
	next.SchemaVersion = sysnet.CapabilitySchemaVersion
	next.Revision = 0
	current := m.report.Clone()
	current.SchemaVersion = sysnet.CapabilitySchemaVersion
	current.Revision = 0
	if reflect.DeepEqual(current, next) {
		return false
	}
	next.Revision = m.report.Revision + 1
	m.report = next.Clone()
	return true
}

// implementationSupport records code that has passed its implementation gate.
// Dependency facts must never turn a false support bit into an available row.
type implementationSupport struct {
	regularTun              bool
	regularTunDual          bool
	defaultTun              bool
	defaultTunDual          bool
	exclusions              bool
	exclusionsDual          bool
	matchers                bool
	exclusionRuleValidation bool
	matcherRuleValidation   bool
}

func currentImplementationSupport() implementationSupport {
	// Steps 1 through 4 implement policy and reporting only. Later milestones
	// enable each bit after its native and packet-path gates pass.
	return implementationSupport{
		exclusionRuleValidation: true,
		matcherRuleValidation:   true,
	}
}

type capabilityProbeFacts struct {
	netIO sysnet.Capability
	split sysnet.Capability
}

func initialProbeFacts() capabilityProbeFacts {
	unknown := sysnet.Capability{
		State:   sysnet.CapabilityUnknown,
		Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
	}
	return capabilityProbeFacts{netIO: unknown.Clone(), split: unknown.Clone()}
}

func buildCapabilityReport(
	config normalizedSystemConfig,
	support implementationSupport,
	facts capabilityProbeFacts,
	state lifecycleState,
) sysnet.CapabilityReport {
	report := sysnet.CapabilityReport{SchemaVersion: sysnet.CapabilitySchemaVersion}
	families := []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6, sysnet.FamilyDual}

	for _, family := range append([]sysnet.AddressFamily{sysnet.FamilyNone}, families...) {
		implemented := support.regularTun
		if family == sysnet.FamilyDual {
			implemented = support.regularTunDual
		}
		capability := implementedCapability(implemented)
		if family != sysnet.FamilyNone {
			capability = familyCapability(capability, config, family)
			capability = dependentCapability(capability, facts.netIO)
		}
		report.Operations = append(report.Operations, operationCapability(
			sysnet.TargetTun, sysnet.OpCreate, family, lifecycleCapability(capability, state),
		))
	}
	report.Operations = append(report.Operations,
		operationCapability(sysnet.TargetTun, sysnet.OpSetMTU, sysnet.FamilyNone,
			lifecycleCapability(dependentCapability(implementedCapability(support.regularTun), facts.netIO), state)),
		operationCapability(sysnet.TargetTun, sysnet.OpRename, sysnet.FamilyNone,
			unsupported(sysnet.ReasonNotImplemented, "renaming a TUN is not implemented")),
	)
	for _, operation := range []sysnet.Operation{
		sysnet.OpSetAddresses, sysnet.OpAddAddress, sysnet.OpGetAddresses,
		sysnet.OpSetRoutes, sysnet.OpAddRoute, sysnet.OpGetRoutes,
	} {
		for _, family := range families {
			implemented := support.regularTun
			if family == sysnet.FamilyDual {
				implemented = support.regularTunDual
			}
			capability := familyCapability(implementedCapability(implemented), config, family)
			capability = dependentCapability(capability, facts.netIO)
			report.Operations = append(report.Operations, operationCapability(
				sysnet.TargetTun, operation, family, lifecycleCapability(capability, state),
			))
		}
	}

	for _, family := range families {
		implemented := support.defaultTun
		if family == sysnet.FamilyDual {
			implemented = support.defaultTunDual
		}
		base := lifecycleCapability(
			dependentCapability(familyCapability(implementedCapability(implemented), config, family), facts.netIO), state,
		)
		report.Operations = append(report.Operations,
			operationCapability(sysnet.TargetDefaultTun, sysnet.OpCreate, family, base),
			operationCapability(sysnet.TargetDefaultTun, sysnet.OpSourceRoutes, family,
				unsupported(sysnet.ReasonNotImplemented, "preferred-source routes are not implemented")),
		)
		report.DefaultTunProfiles = append(report.DefaultTunProfiles,
			sysnet.DefaultTunProfile{
				Key:        sysnet.RoutingProfileKey{Family: family, Mode: sysnet.RoutingFull},
				Capability: base.Clone(),
			},
			exclusionProfile(config, support, facts, state, family),
			sysnet.DefaultTunProfile{
				Key:        sysnet.RoutingProfileKey{Family: family, Mode: sysnet.RoutingInclude},
				Capability: unsupported(sysnet.ReasonNotImplemented, "include routing is not implemented"),
			},
			sysnet.DefaultTunProfile{
				Key:        sysnet.RoutingProfileKey{Family: family, Mode: sysnet.RoutingFull, Strict: true},
				Capability: unsupported(sysnet.ReasonNotImplemented, "strict routing is not implemented"),
			},
		)
	}

	report.Rules = ruleCapabilities(config, support, state, families)
	report.Ownership = ownerCapabilities(config, support, state)
	report.Operations = append(report.Operations, unsupportedOperationCatalog(families)...)
	return report
}

func unsupportedOperationCatalog(families []sysnet.AddressFamily) []sysnet.OperationCapability {
	notImplemented := unsupported(sysnet.ReasonNotImplemented, "implementation gate has not passed")
	operations := []sysnet.OperationCapability{
		operationCapability(sysnet.TargetSystem, sysnet.OpAllocateIP, sysnet.FamilyIPv4, notImplemented),
		operationCapability(sysnet.TargetSystem, sysnet.OpAllocateIP, sysnet.FamilyIPv6, notImplemented),
		operationCapability(sysnet.TargetSystem, sysnet.OpAllocateSubnet, sysnet.FamilyIPv4, notImplemented),
		operationCapability(sysnet.TargetSystem, sysnet.OpAllocateSubnet, sysnet.FamilyIPv6, notImplemented),
		operationCapability(sysnet.TargetDefaultTun, sysnet.OpSetMTU, sysnet.FamilyNone, notImplemented),
		operationCapability(sysnet.TargetDefaultTun, sysnet.OpRename, sysnet.FamilyNone, notImplemented),
		operationCapability(sysnet.TargetOutNet, sysnet.OpResolve, sysnet.FamilyNone, notImplemented),
		operationCapability(sysnet.TargetOutNet, sysnet.OpInterfaces, sysnet.FamilyNone, notImplemented),
		operationCapability(sysnet.TargetLocalNet, sysnet.OpResolve, sysnet.FamilyNone, notImplemented),
		operationCapability(sysnet.TargetLocalNet, sysnet.OpInterfaces, sysnet.FamilyNone, notImplemented),
	}
	for _, operation := range []sysnet.Operation{
		sysnet.OpSetAddresses, sysnet.OpAddAddress, sysnet.OpGetAddresses,
		sysnet.OpSetRoutes, sysnet.OpAddRoute, sysnet.OpGetRoutes,
		sysnet.OpReconfigureInPlace, sysnet.OpDNSProvider, sysnet.OpDNSConfigure,
		sysnet.OpDNSPort53Exclusive, sysnet.OpDNSSystemExclusive,
	} {
		for _, family := range families {
			operations = append(operations, operationCapability(sysnet.TargetDefaultTun, operation, family, notImplemented))
		}
	}
	for _, target := range []sysnet.Target{sysnet.TargetOutNet, sysnet.TargetLocalNet} {
		for _, operation := range []sysnet.Operation{
			sysnet.OpDialTCP, sysnet.OpDialUDP, sysnet.OpPacketDialUDP,
			sysnet.OpListenTCP, sysnet.OpListenUDP, sysnet.OpListenPacketUDP,
			sysnet.OpMulticastUDP,
		} {
			for _, family := range families {
				operations = append(operations, operationCapability(target, operation, family, notImplemented))
			}
		}
	}
	for _, operation := range []sysnet.Operation{sysnet.OpQueryUDP, sysnet.OpQueryTCP} {
		for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
			operations = append(operations, operationCapability(sysnet.TargetOutDNS, operation, family, notImplemented))
		}
	}
	return operations
}

func exclusionProfile(
	config normalizedSystemConfig,
	support implementationSupport,
	facts capabilityProbeFacts,
	state lifecycleState,
	family sysnet.AddressFamily,
) sysnet.DefaultTunProfile {
	implemented := support.exclusions
	if family == sysnet.FamilyDual {
		implemented = support.exclusionsDual
	}
	capability := familyCapability(implementedCapability(implemented), config, family)
	if !config.exclusions {
		capability = unsupported(sysnet.ReasonDisabledByConfig, "executable exclusions are disabled")
	} else {
		capability = dependentCapability(capability, facts.netIO)
		capability = dependentCapability(capability, facts.split)
		capability = lifecycleCapability(capability, state)
	}
	return sysnet.DefaultTunProfile{
		Key:        sysnet.RoutingProfileKey{Family: family, Mode: sysnet.RoutingExclude},
		Capability: capability.Clone(),
		Rules: []sysnet.RuleBinding{{
			Type:       ruleExecutableTree,
			Capability: capability.Clone(),
		}},
	}
}

func familyCapability(capability sysnet.Capability, config normalizedSystemConfig, family sysnet.AddressFamily) sysnet.Capability {
	if capability.State != sysnet.CapabilityAvailable {
		return capability.Clone()
	}
	enabled := family == sysnet.FamilyIPv4 && config.ipv4 ||
		family == sysnet.FamilyIPv6 && config.ipv6 ||
		family == sysnet.FamilyDual && config.ipv4 && config.ipv6
	if !enabled {
		return unsupported(sysnet.ReasonDisabledByConfig, "address family is disabled")
	}
	return capability.Clone()
}

func ruleCapabilities(
	config normalizedSystemConfig,
	support implementationSupport,
	state lifecycleState,
	families []sysnet.AddressFamily,
) []sysnet.RuleCapability {
	exclusionValidation := implementedCapability(support.exclusionRuleValidation || support.exclusions)
	if !config.exclusions {
		exclusionValidation = unsupported(sysnet.ReasonDisabledByConfig, "executable exclusions are disabled")
	}
	matcherValidation := implementedCapability(support.matcherRuleValidation || support.matchers)
	matcher := implementedCapability(support.matchers)
	if !config.matchers {
		matcherValidation = unsupported(sysnet.ReasonDisabledByConfig, "matchers are disabled")
		matcher = unsupported(sysnet.ReasonDisabledByConfig, "matchers are disabled")
	}
	matcher = lifecycleCapability(matcher, state)

	rules := []sysnet.RuleCapability{{
		Type:        ruleExecutableTree,
		Description: "executable path and its descendant processes",
		ValueKind:   sysnet.RuleValuePath,
		SemanticsID: "windows.nt-path-descendants.v1",
		Validation:  exclusionValidation.Clone(),
		Completion:  unsupported(sysnet.ReasonNotImplemented, "rule completion is not implemented"),
	}}
	for _, ruleType := range []string{ruleExecutablePath, rulePID} {
		valueKind := sysnet.RuleValuePath
		semantics := "windows.executable-path.v1"
		if ruleType == rulePID {
			valueKind = sysnet.RuleValuePID
			semantics = "windows.pid.v1"
		}
		rule := sysnet.RuleCapability{
			Type:        ruleType,
			Description: map[string]string{ruleExecutablePath: "owning executable path", rulePID: "owning process identifier"}[ruleType],
			ValueKind:   valueKind,
			SemanticsID: semantics,
			Validation:  matcherValidation.Clone(),
			Completion:  unsupported(sysnet.ReasonNotImplemented, "rule completion is not implemented"),
		}
		for _, family := range families {
			if family == sysnet.FamilyDual {
				continue
			}
			familyMatcher := familyCapability(matcher, config, family)
			for _, transport := range []sysnet.Transport{sysnet.TransportTCP, sysnet.TransportUDP} {
				quality := sysnet.MatchQualityBestEffortTuple
				if transport == sysnet.TransportUDP {
					quality = sysnet.MatchQualityBestEffortLocalEndpoint
				}
				rule.Matchers = append(rule.Matchers, sysnet.MatcherProfile{
					Key:        sysnet.MatcherProfileKey{Family: family, Transport: transport},
					Capability: familyMatcher.Clone(), Quality: quality,
				})
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

func ownerCapabilities(config normalizedSystemConfig, support implementationSupport, state lifecycleState) []sysnet.OwnerCapability {
	capability := implementedCapability(support.matchers)
	if !config.matchers {
		capability = unsupported(sysnet.ReasonDisabledByConfig, "matchers are disabled")
	}
	capability = lifecycleCapability(capability, state)
	result := make([]sysnet.OwnerCapability, 0, 4)
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		familyOwner := familyCapability(capability, config, family)
		for _, transport := range []sysnet.Transport{sysnet.TransportTCP, sysnet.TransportUDP} {
			quality := sysnet.MatchQualityBestEffortTuple
			if transport == sysnet.TransportUDP {
				quality = sysnet.MatchQualityBestEffortLocalEndpoint
			}
			result = append(result, sysnet.OwnerCapability{
				Key:        sysnet.MatcherProfileKey{Family: family, Transport: transport},
				Capability: familyOwner.Clone(), Quality: quality,
				Fields: []sysnet.OwnerFieldCapability{
					{Field: sysnet.OwnerPID, Capability: familyOwner.Clone()},
					{Field: sysnet.OwnerExecutablePath, Capability: familyOwner.Clone()},
				},
			})
		}
	}
	return result
}

func implementedCapability(implemented bool) sysnet.Capability {
	if implemented {
		return sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	return unsupported(sysnet.ReasonNotImplemented, "implementation gate has not passed")
}

func dependentCapability(base, dependency sysnet.Capability) sysnet.Capability {
	if base.State != sysnet.CapabilityAvailable {
		return base.Clone()
	}
	return dependency.Clone()
}

func lifecycleCapability(capability sysnet.Capability, state lifecycleState) sysnet.Capability {
	if capability.State != sysnet.CapabilityAvailable {
		return capability.Clone()
	}
	switch state {
	case lifecycleClosing, lifecycleClosed:
		return sysnet.Capability{State: sysnet.CapabilityUnavailable, Reasons: []sysnet.CapabilityReason{sysnet.ReasonSystemClosed}}
	case lifecycleRecoveryRequired:
		return sysnet.Capability{State: sysnet.CapabilityUnavailable, Reasons: []sysnet.CapabilityReason{sysnet.ReasonRecoveryRequired}}
	case lifecycleNew, lifecycleApplying:
		return sysnet.Capability{State: sysnet.CapabilityUnavailable, Reasons: []sysnet.CapabilityReason{sysnet.ReasonResourceBusy}}
	case lifecycleReady, lifecycleActive:
		return capability.Clone()
	default:
		return sysnet.Capability{State: sysnet.CapabilityUnknown, Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeFailed}}
	}
}

func unsupported(reason sysnet.CapabilityReason, detail string) sysnet.Capability {
	return sysnet.Capability{State: sysnet.CapabilityUnsupported, Reasons: []sysnet.CapabilityReason{reason}, Detail: detail}
}

func operationCapability(target sysnet.Target, operation sysnet.Operation, family sysnet.AddressFamily, capability sysnet.Capability) sysnet.OperationCapability {
	return sysnet.OperationCapability{Key: sysnet.OperationKey{Target: target, Operation: operation, Family: family}, Capability: capability}
}

// legacyFeatures and legacyRulesInfo mirror the read-only projections in the
// gonnect v0.54 contract. They stay private because gonnect v0.55 removed that
// API. Tests use them to prevent accidental changes to the migration mapping.
type legacyFeatures struct {
	Tun                    bool
	DefaultTun             bool
	DynTun                 bool
	DynDefaultTun          bool
	TunNames               bool
	DefaultTunNames        bool
	StrictMode             bool
	DefaultTunSourceRoutes bool
}

type legacyRuleTypeInfo struct {
	Type        string
	Description string
}

type legacyRulesInfo struct {
	TunRules     []legacyRuleTypeInfo
	MatcherRules []legacyRuleTypeInfo
}

func projectLegacyCapabilities(model capabilityModel) (legacyFeatures, legacyRulesInfo) {
	report := model.snapshot()
	features := legacyFeatures{
		Tun:                    anyCreate(report, sysnet.TargetTun),
		DefaultTun:             anyDefaultCreate(report),
		DynTun:                 anyMutationBundle(report, sysnet.TargetTun),
		DynDefaultTun:          anyMutationBundle(report, sysnet.TargetDefaultTun),
		TunNames:               operationAvailable(report, sysnet.OperationKey{Target: sysnet.TargetTun, Operation: sysnet.OpRename, Family: sysnet.FamilyNone}),
		DefaultTunNames:        false,
		StrictMode:             anyProfile(report, true),
		DefaultTunSourceRoutes: anyOperation(report, sysnet.TargetDefaultTun, sysnet.OpSourceRoutes),
	}
	return features, projectLegacyRules(report)
}

func anyCreate(report sysnet.CapabilityReport, target sysnet.Target) bool {
	return anyOperation(report, target, sysnet.OpCreate)
}

func anyDefaultCreate(report sysnet.CapabilityReport) bool {
	for _, operation := range report.Operations {
		if operation.Key.Target != sysnet.TargetDefaultTun || operation.Key.Operation != sysnet.OpCreate || operation.State != sysnet.CapabilityAvailable {
			continue
		}
		key := sysnet.RoutingProfileKey{Family: operation.Key.Family, Mode: sysnet.RoutingFull}
		if report.DefaultTunProfile(key).State == sysnet.CapabilityAvailable {
			return true
		}
	}
	return false
}

func anyMutationBundle(report sysnet.CapabilityReport, target sysnet.Target) bool {
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6, sysnet.FamilyDual} {
		keys := []sysnet.OperationKey{
			{Target: target, Operation: sysnet.OpSetMTU, Family: sysnet.FamilyNone},
			{Target: target, Operation: sysnet.OpSetAddresses, Family: family},
			{Target: target, Operation: sysnet.OpAddAddress, Family: family},
			{Target: target, Operation: sysnet.OpSetRoutes, Family: family},
			{Target: target, Operation: sysnet.OpAddRoute, Family: family},
		}
		available := true
		for _, key := range keys {
			available = available && operationAvailable(report, key)
		}
		if available {
			return true
		}
	}
	return false
}

func anyProfile(report sysnet.CapabilityReport, strict bool) bool {
	for _, profile := range report.DefaultTunProfiles {
		if profile.Key.Strict == strict && profile.State == sysnet.CapabilityAvailable {
			return true
		}
	}
	return false
}

func anyOperation(report sysnet.CapabilityReport, target sysnet.Target, operation sysnet.Operation) bool {
	for _, candidate := range report.Operations {
		if candidate.Key.Target == target && candidate.Key.Operation == operation && candidate.State == sysnet.CapabilityAvailable {
			return true
		}
	}
	return false
}

func operationAvailable(report sysnet.CapabilityReport, key sysnet.OperationKey) bool {
	return report.Operation(key).State == sysnet.CapabilityAvailable
}

func projectLegacyRules(report sysnet.CapabilityReport) legacyRulesInfo {
	descriptions := make(map[string]string, len(report.Rules))
	matcherTypes := make(map[string]bool, len(report.Rules))
	for _, rule := range report.Rules {
		descriptions[rule.Type] = rule.Description
		for _, matcher := range rule.Matchers {
			matcherTypes[rule.Type] = matcherTypes[rule.Type] || matcher.State == sysnet.CapabilityAvailable
		}
	}
	routingTypes := make(map[string]bool, len(report.Rules))
	for _, profile := range report.DefaultTunProfiles {
		if profile.State != sysnet.CapabilityAvailable {
			continue
		}
		for _, binding := range profile.Rules {
			routingTypes[binding.Type] = routingTypes[binding.Type] || binding.State == sysnet.CapabilityAvailable
		}
	}
	return legacyRulesInfo{TunRules: legacyRuleList(routingTypes, descriptions), MatcherRules: legacyRuleList(matcherTypes, descriptions)}
}

func legacyRuleList(available map[string]bool, descriptions map[string]string) []legacyRuleTypeInfo {
	types := make([]string, 0, len(available))
	for ruleType, enabled := range available {
		if enabled {
			types = append(types, ruleType)
		}
	}
	sort.Strings(types)
	result := make([]legacyRuleTypeInfo, 0, len(types))
	for _, ruleType := range types {
		result = append(result, legacyRuleTypeInfo{Type: ruleType, Description: descriptions[ruleType]})
	}
	return result
}
