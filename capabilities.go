package windows

import (
	"sort"

	"github.com/asciimoth/gonnect/sysnet"
)

// capabilityModel is the package's single capability source. The selected
// gonnect contract includes the capability API, so this package stores its
// types instead of publishing a second capability API.
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
		if operation.Key.Target != sysnet.TargetDefaultTun ||
			operation.Key.Operation != sysnet.OpCreate ||
			operation.State != sysnet.CapabilityAvailable {
			continue
		}
		key := sysnet.RoutingProfileKey{
			Family: operation.Key.Family,
			Mode:   sysnet.RoutingFull,
		}
		if report.DefaultTunProfile(key).State == sysnet.CapabilityAvailable {
			return true
		}
	}
	return false
}

func anyMutationBundle(report sysnet.CapabilityReport, target sysnet.Target) bool {
	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
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
		if candidate.Key.Target == target && candidate.Key.Operation == operation &&
			candidate.State == sysnet.CapabilityAvailable {
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
			matcherTypes[rule.Type] = matcherTypes[rule.Type] ||
				matcher.State == sysnet.CapabilityAvailable
		}
	}

	routingTypes := make(map[string]bool, len(report.Rules))
	for _, profile := range report.DefaultTunProfiles {
		if profile.State != sysnet.CapabilityAvailable {
			continue
		}
		for _, binding := range profile.Rules {
			routingTypes[binding.Type] = routingTypes[binding.Type] ||
				binding.State == sysnet.CapabilityAvailable
		}
	}

	return legacyRulesInfo{
		TunRules:     legacyRuleList(routingTypes, descriptions),
		MatcherRules: legacyRuleList(matcherTypes, descriptions),
	}
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
		result = append(result, legacyRuleTypeInfo{
			Type:        ruleType,
			Description: descriptions[ruleType],
		})
	}
	return result
}
