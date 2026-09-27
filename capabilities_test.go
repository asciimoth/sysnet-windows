package windows

import (
	"reflect"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
)

func TestSystemContractScaffold(t *testing.T) {
	t.Parallel()

	system := &System{}
	if err := system.Capabilities().Validate(); err != nil {
		t.Fatalf("Capabilities().Validate() error = %v", err)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{}).Err(); err != nil {
		t.Fatalf("CheckTunOpts() error = %v", err)
	}
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
