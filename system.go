package windows

import (
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

// System is the Windows implementation of the gonnect system contract.
//
// Step 1 freezes the public method set. Later implementation steps replace the
// unsupported results with native Windows behavior.
type System struct {
	capabilities capabilityModel
}

// This assertion intentionally uses the selected gonnect version. In older
// contracts the route getter was misspelled GetTunRotue. gonnect v0.55.0 uses
// GetTunRoutes and includes capability reporting and validation in System.
var _ sysnet.System = (*System)(nil)

func (*System) Close() error { return nil }

func (s *System) Capabilities() sysnet.CapabilityReport {
	return s.capabilities.snapshot()
}

func (*System) CapabilitiesForTun(tun.Tun) (sysnet.TunCapabilityReport, error) {
	return sysnet.TunCapabilityReport{}, sysnet.ErrUnknownTun
}

func (*System) CheckTunOpts(sysnet.TunOpts) sysnet.ValidationReport {
	return unsupportedValidation("Tun")
}

func (*System) CheckDefaultTunOpts(sysnet.DefaultTunOpts) sysnet.ValidationReport {
	return unsupportedValidation("DefaultTun")
}

func (*System) CheckRule(sysnet.Rule, sysnet.RuleContext) sysnet.ValidationReport {
	return unsupportedValidation("Rule")
}

func (*System) CompleteRule(sysnet.Rule, sysnet.RuleContext) ([]string, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) AllocIP() subnet.IPAllocator { return nil }

func (*System) AllocSubnet() subnet.SubnetAllocator { return nil }

func (*System) OutDNS() dns.Interface { return nil }

func (*System) OutNet() gonnect.Network { return &gonnect.RejectNetwork{} }

func (*System) LocalNet() gonnect.Network { return &gonnect.RejectNetwork{} }

func (*System) BuildMatcher(sysnet.Rule) (sysnet.Matcher, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) BuildDefaultTun(sysnet.DefaultTunOpts) (sysnet.DefaultTun, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) DefaultTunWarnings(sysnet.DefaultTun) []sysnet.Warning { return nil }

func (*System) BuildTun(sysnet.TunOpts) (tun.Tun, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) TunWarnings(tun.Tun) []sysnet.Warning { return nil }

func (*System) SetTunMTU(tun.Tun, int) error { return sysnet.ErrNotSupported }

func (*System) SetTunAddrs(tun.Tun, []string) error { return sysnet.ErrNotSupported }

func (*System) AddTunAddr(tun.Tun, string) error { return sysnet.ErrNotSupported }

func (*System) GetTunAddrs(tun.Tun) ([]string, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) SetTunRoutes(tun.Tun, []string) error { return sysnet.ErrNotSupported }

func (*System) AddTunRoute(tun.Tun, string) error { return sysnet.ErrNotSupported }

func (*System) GetTunRoutes(tun.Tun) ([]string, error) {
	return nil, sysnet.ErrNotSupported
}

func (*System) SetTunName(tun.Tun, string) error { return sysnet.ErrNotSupported }

func unsupportedValidation(path string) sysnet.ValidationReport {
	return sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{{
		Path:   path,
		Reason: sysnet.ReasonNotImplemented,
		State:  sysnet.CapabilityUnsupported,
	}}}
}
