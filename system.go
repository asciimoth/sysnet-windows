package windows

import (
	"errors"
	"sync"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

// System is the Windows implementation of the gonnect system contract.
type System struct {
	mu           sync.RWMutex
	state        lifecycleState
	config       normalizedSystemConfig
	dependencies systemDependencies
	capabilities capabilityModel
}

// This assertion intentionally uses the selected gonnect version. In older
// contracts the route getter was misspelled GetTunRotue. gonnect v0.55.0 uses
// GetTunRoutes and includes capability reporting and validation in System.
var _ sysnet.System = (*System)(nil)

func (s *System) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == lifecycleClosed {
		return nil
	}
	s.state = lifecycleClosed
	return nil
}

func (s *System) Capabilities() sysnet.CapabilityReport {
	return s.capabilities.snapshot()
}

func (*System) CapabilitiesForTun(tun.Tun) (sysnet.TunCapabilityReport, error) {
	return sysnet.TunCapabilityReport{}, sysnet.ErrUnknownTun
}

func (s *System) CheckTunOpts(opts sysnet.TunOpts) sysnet.ValidationReport {
	_, report := normalizeTunOpts(s.policyConfig(), opts)
	return report
}

func (s *System) CheckDefaultTunOpts(opts sysnet.DefaultTunOpts) sysnet.ValidationReport {
	_, report := normalizeDefaultTunOpts(s.policyConfig(), opts)
	return report
}

func (s *System) CheckRule(rule sysnet.Rule, context sysnet.RuleContext) sysnet.ValidationReport {
	_, report := normalizeRule(s.policyConfig(), rule, context)
	return report
}

func (*System) CompleteRule(sysnet.Rule, sysnet.RuleContext) ([]string, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) AllocIP() subnet.IPAllocator { return nil }

func (*System) AllocSubnet() subnet.SubnetAllocator { return nil }

func (*System) OutDNS() dns.Interface { return nil }

func (*System) OutNet() gonnect.Network { return &gonnect.RejectNetwork{} }

func (*System) LocalNet() gonnect.Network { return &gonnect.RejectNetwork{} }

func (s *System) BuildMatcher(rule sysnet.Rule) (sysnet.Matcher, error) {
	if report := validateMatcherRule(s.policyConfig(), rule); report.Err() != nil {
		return nil, report.Err()
	}
	return nil, sysnet.ErrNotSupported
}

func (s *System) BuildDefaultTun(opts sysnet.DefaultTunOpts) (sysnet.DefaultTun, error) {
	if _, report := normalizeDefaultTunOpts(s.policyConfig(), opts); report.Err() != nil {
		return nil, report.Err()
	}
	return nil, sysnet.ErrNotSupported
}

func (*System) DefaultTunWarnings(sysnet.DefaultTun) []sysnet.Warning { return nil }

func (s *System) BuildTun(opts sysnet.TunOpts) (tun.Tun, error) {
	if _, report := normalizeTunOpts(s.policyConfig(), opts); report.Err() != nil {
		return nil, report.Err()
	}
	return nil, sysnet.ErrNotSupported
}

func (*System) TunWarnings(tun.Tun) []sysnet.Warning { return nil }

func (s *System) SetTunMTU(_ tun.Tun, mtu int) error {
	_, report := normalizeMTU(s.policyConfig(), mtu, "Tun.MTU", false)
	if err := report.Err(); err != nil {
		return err
	}
	return sysnet.ErrNotSupported
}

func (s *System) SetTunAddrs(_ tun.Tun, addrs []string) error {
	_, report := normalizePrefixes(s.policyConfig(), addrs, "Tun.TunAddrs", prefixAddress)
	if err := report.Err(); err != nil {
		return err
	}
	return sysnet.ErrNotSupported
}

func (s *System) AddTunAddr(device tun.Tun, addr string) error {
	return s.SetTunAddrs(device, []string{addr})
}

func (*System) GetTunAddrs(tun.Tun) ([]string, error) {
	return nil, sysnet.ErrNotSupported
}

func (s *System) SetTunRoutes(_ tun.Tun, routes []string) error {
	_, report := normalizePrefixes(s.policyConfig(), routes, "Tun.TunRoutes", prefixRoute)
	if err := report.Err(); err != nil {
		return err
	}
	return sysnet.ErrNotSupported
}

func (s *System) AddTunRoute(device tun.Tun, route string) error {
	return s.SetTunRoutes(device, []string{route})
}

func (*System) GetTunRoutes(tun.Tun) ([]string, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) SetTunName(tun.Tun, string) error {
	return validationError(validationIssue(
		"Tun.Name",
		sysnet.CapabilityUnsupported,
		sysnet.ReasonNotImplemented,
		"renaming a TUN is not supported",
		nil,
	))
}

func (s *System) policyConfig() normalizedSystemConfig {
	if s == nil {
		return defaultNormalizedSystemConfig()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config == (normalizedSystemConfig{}) {
		return defaultNormalizedSystemConfig()
	}
	return s.config
}

func validationError(issue sysnet.ValidationIssue) error {
	return sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{issue}}.Err()
}

func invalidCause(cause error) error {
	if cause == nil {
		return sysnet.ErrInvalidOptions
	}
	return errors.Join(sysnet.ErrInvalidOptions, cause)
}
