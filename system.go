package windows

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
)

// System is the Windows implementation of the gonnect system contract.
type System struct {
	mu           sync.RWMutex
	state        lifecycleState
	config       normalizedSystemConfig
	dependencies systemDependencies
	capabilities capabilityModel
	probeFacts   capabilityProbeFacts
	support      implementationSupport
	journal      *reconcile.Journal
	worker       *reconcile.Worker
	resources    reconcile.Resources
	closeOnce    sync.Once
	closeErr     error
}

// This assertion intentionally uses the selected gonnect version. In older
// contracts the route getter was misspelled GetTunRotue. gonnect v0.55.0 uses
// GetTunRoutes and includes capability reporting and validation in System.
var _ sysnet.System = (*System)(nil)

func (s *System) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { s.closeErr = s.close() })
	return s.closeErr
}

func (s *System) close() error {
	s.mu.Lock()
	if s.state != lifecycleClosing {
		if err := s.transitionLocked(lifecycleClosing); err != nil {
			s.mu.Unlock()
			return err
		}
		s.rebuildCapabilitiesLocked()
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	defer cancel()
	var stopErr error
	if s.worker != nil {
		stopErr = s.worker.Stop(ctx)
	}
	resourceErr := s.resources.CloseAll()
	var cleanupErr error
	if stopErr == nil && s.journal != nil {
		cleanupErr = s.journal.UndoAll(ctx)
	}
	result := errors.Join(stopErr, resourceErr, cleanupErr)

	s.mu.Lock()
	next := lifecycleClosed
	if stopErr != nil || reconcile.RequiresRecovery(cleanupErr) {
		next = lifecycleRecoveryRequired
	}
	transitionErr := s.transitionLocked(next)
	s.rebuildCapabilitiesLocked()
	s.mu.Unlock()
	return errors.Join(result, transitionErr)
}

// applyTransaction is the single path for native policy mutations. The later
// TUN, DNS, WFP, and split implementations provide exact journal entries here.
func (s *System) applyTransaction(entries []reconcile.Entry) error {
	if err := s.beginApply(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	defer cancel()
	err := s.worker.Submit(ctx, entries)
	recoveryRequired := reconcile.RequiresRecovery(err)
	active := s.journal.Len() != 0
	return errors.Join(err, s.finishApply(active, recoveryRequired))
}

func (s *System) handleReconcileFailure(err error) {
	if !reconcile.RequiresRecovery(err) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == lifecycleReady || s.state == lifecycleActive || s.state == lifecycleApplying {
		_ = s.transitionLocked(lifecycleRecoveryRequired)
		s.rebuildCapabilitiesLocked()
	}
}

// trackResource adds a socket, listener, or TUN to ordered System cleanup.
func (s *System) trackResource(resource io.Closer) (func(), error) {
	if err := s.acceptingWork(); err != nil {
		return nil, err
	}
	return s.resources.Track(resource)
}

func (s *System) Capabilities() sysnet.CapabilityReport {
	if s == nil {
		return capabilityModel{}.snapshot()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.capabilities.snapshot()
}

func (*System) CapabilitiesForTun(tun.Tun) (sysnet.TunCapabilityReport, error) {
	return sysnet.TunCapabilityReport{}, sysnet.ErrUnknownTun
}

func (s *System) CheckTunOpts(opts sysnet.TunOpts) sysnet.ValidationReport {
	_, report := normalizeTunOpts(s.policyConfig(), opts)
	report.CapabilityRevision = s.Capabilities().Revision
	return report
}

func (s *System) CheckDefaultTunOpts(opts sysnet.DefaultTunOpts) sysnet.ValidationReport {
	_, report := normalizeDefaultTunOpts(s.policyConfig(), opts)
	report.CapabilityRevision = s.Capabilities().Revision
	return report
}

func (s *System) CheckRule(rule sysnet.Rule, context sysnet.RuleContext) sysnet.ValidationReport {
	_, report := normalizeRule(s.policyConfig(), rule, context)
	report.CapabilityRevision = s.Capabilities().Revision
	return report
}

func (s *System) CompleteRule(sysnet.Rule, sysnet.RuleContext) ([]string, error) {
	if err := s.acceptingWork(); err != nil {
		return nil, err
	}
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
	if err := s.finalPreflight(); err != nil {
		return nil, err
	}
	report := s.Capabilities()
	var unavailable error
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		profile := matcherProfile(report.Rule(rule.Type), sysnet.MatcherProfileKey{Family: family, Transport: sysnet.TransportTCP})
		if profile.State == sysnet.CapabilityAvailable {
			return nil, sysnet.ErrNotSupported
		}
		if unavailable == nil && (profile.State != sysnet.CapabilityUnknown || len(profile.Reasons) != 0) {
			unavailable = capabilityError("Matcher", profile.Capability)
		}
	}
	if unavailable != nil {
		return nil, unavailable
	}
	return nil, sysnet.ErrNotSupported
}

func (s *System) BuildDefaultTun(opts sysnet.DefaultTunOpts) (sysnet.DefaultTun, error) {
	desired, report := normalizeDefaultTunOpts(s.policyConfig(), opts)
	if report.Err() != nil {
		return nil, report.Err()
	}
	if err := s.finalPreflight(); err != nil {
		return nil, err
	}
	mode := sysnet.RoutingFull
	if len(desired.excludes) != 0 {
		mode = sysnet.RoutingExclude
	}
	capability := s.Capabilities().DefaultTunProfile(sysnet.RoutingProfileKey{Family: desired.family, Mode: mode}).Capability
	if capability.State != sysnet.CapabilityAvailable {
		return nil, capabilityError("DefaultTun.Profile", capability)
	}
	return nil, sysnet.ErrNotSupported
}

func (*System) DefaultTunWarnings(sysnet.DefaultTun) []sysnet.Warning { return nil }

func (s *System) BuildTun(opts sysnet.TunOpts) (tun.Tun, error) {
	desired, report := normalizeTunOpts(s.policyConfig(), opts)
	if report.Err() != nil {
		return nil, report.Err()
	}
	if err := s.finalPreflight(); err != nil {
		return nil, err
	}
	family := familyForPrefixes(desired.addresses, desired.routes)
	capability := s.Capabilities().Operation(sysnet.OperationKey{Target: sysnet.TargetTun, Operation: sysnet.OpCreate, Family: family})
	if capability.State != sysnet.CapabilityAvailable {
		return nil, capabilityError("Tun.Create", capability)
	}
	return nil, sysnet.ErrNotSupported
}

func (*System) TunWarnings(tun.Tun) []sysnet.Warning { return nil }

func (s *System) SetTunMTU(_ tun.Tun, mtu int) error {
	_, report := normalizeMTU(s.policyConfig(), mtu, "Tun.MTU", false)
	if err := report.Err(); err != nil {
		return err
	}
	if err := s.finalPreflight(); err != nil {
		return err
	}
	if capability := s.Capabilities().Operation(sysnet.OperationKey{Target: sysnet.TargetTun, Operation: sysnet.OpSetMTU, Family: sysnet.FamilyNone}); capability.State != sysnet.CapabilityAvailable {
		return capabilityError("Tun.MTU", capability)
	}
	return sysnet.ErrNotSupported
}

func (s *System) SetTunAddrs(_ tun.Tun, addrs []string) error {
	_, report := normalizePrefixes(s.policyConfig(), addrs, "Tun.TunAddrs", prefixAddress)
	if err := report.Err(); err != nil {
		return err
	}
	if err := s.finalPreflight(); err != nil {
		return err
	}
	return sysnet.ErrNotSupported
}

func (s *System) AddTunAddr(device tun.Tun, addr string) error {
	return s.SetTunAddrs(device, []string{addr})
}

func (s *System) GetTunAddrs(tun.Tun) ([]string, error) {
	if err := s.acceptingWork(); err != nil {
		return nil, err
	}
	return nil, sysnet.ErrNotSupported
}

func (s *System) SetTunRoutes(_ tun.Tun, routes []string) error {
	_, report := normalizePrefixes(s.policyConfig(), routes, "Tun.TunRoutes", prefixRoute)
	if err := report.Err(); err != nil {
		return err
	}
	if err := s.finalPreflight(); err != nil {
		return err
	}
	return sysnet.ErrNotSupported
}

func (s *System) AddTunRoute(device tun.Tun, route string) error {
	return s.SetTunRoutes(device, []string{route})
}

func (s *System) GetTunRoutes(tun.Tun) ([]string, error) {
	if err := s.acceptingWork(); err != nil {
		return nil, err
	}
	return nil, sysnet.ErrNotSupported
}

func (s *System) SetTunName(tun.Tun, string) error {
	if err := s.acceptingWork(); err != nil {
		return err
	}
	return validationError(validationIssue(
		"Tun.Name",
		sysnet.CapabilityUnsupported,
		sysnet.ReasonNotImplemented,
		"renaming a TUN is not supported",
		nil,
	))
}

func (s *System) acceptingWork() error {
	if s == nil {
		return stateValidationError(sysnet.ReasonSystemClosed, "system is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.acceptingWorkLocked()
}

// finalPreflight refreshes read-only dependency facts. Cached capability
// snapshots guide callers but never authorize an operation by themselves.
func (s *System) finalPreflight() error {
	if err := s.acceptingWork(); err != nil {
		return err
	}
	if s.dependencies.capabilityProbe == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	facts := s.dependencies.capabilityProbe.Probe(ctx)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.acceptingWorkLocked(); err != nil {
		return err
	}
	s.probeFacts = facts
	s.rebuildCapabilitiesLocked()
	return nil
}

func matcherProfile(rule sysnet.RuleCapability, key sysnet.MatcherProfileKey) sysnet.MatcherProfile {
	for _, profile := range rule.Matchers {
		if profile.Key == key {
			return profile
		}
	}
	return sysnet.MatcherProfile{Key: key, Capability: sysnet.Capability{State: sysnet.CapabilityUnknown}}
}

func capabilityError(path string, capability sysnet.Capability) error {
	reason := sysnet.ReasonProbeNotRun
	if len(capability.Reasons) != 0 {
		reason = capability.Reasons[0]
	}
	return validationError(validationIssue(path, capability.State, reason, capability.Detail, nil))
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
