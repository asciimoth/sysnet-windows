package windows

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
	"github.com/asciimoth/sysnet-windows/internal/split"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

// System is the Windows implementation of the gonnect system contract.
type System struct {
	mu              sync.RWMutex
	state           lifecycleState
	config          normalizedSystemConfig
	dependencies    systemDependencies
	capabilities    capabilityModel
	probeFacts      capabilityProbeFacts
	support         implementationSupport
	journal         *reconcile.Journal
	worker          *reconcile.Worker
	resources       reconcile.Resources
	allocator       *internalallocator.Allocator
	publicAllocator *systemAllocator
	underlayMonitor *underlay.Monitor
	outDNS          dns.Interface
	upstreamDNS     *internaldns.UpstreamProvider
	outNet          gonnect.Network
	localNet        gonnect.Network
	underlayOwnedMu sync.RWMutex
	underlayOwned   map[*regularTun]underlay.Interface
	regularTunsMu   sync.Mutex
	regularTuns     map[*regularTun]struct{}
	nextRegularTun  uint64
	defaultTunMu    sync.Mutex
	defaultTun      *defaultTun
	activeSplitTun  atomic.Pointer[defaultTun]
	nextDefaultTun  uint64
	closeMu         sync.Mutex
	closeErr        error
	probeGeneration uint64
}

// This assertion intentionally uses the selected gonnect version. In older
// contracts the route getter was misspelled GetTunRotue. gonnect v0.55.0 uses
// GetTunRoutes and includes capability reporting and validation in System.
var _ sysnet.System = (*System)(nil)

func (s *System) Close() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.RLock()
	closed := s.state == lifecycleClosed
	s.mu.RUnlock()
	if closed {
		return s.closeErr
	}
	err := s.close()
	s.mu.RLock()
	closed = s.state == lifecycleClosed
	s.mu.RUnlock()
	// A bounded shutdown can return while a worker, resource, or journal
	// callback is still finishing. Keep recovery-required shutdown retryable.
	// Cache the result only after all owned state reached the closed state.
	if closed {
		s.closeErr = err
	}
	return err
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

	var underlayErr error
	if s.underlayMonitor != nil {
		underlayErr = s.underlayMonitor.Close()
	}
	var stopErr error
	if s.worker != nil {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), s.config.operationTimeout)
		stopErr = s.worker.Stop(stopCtx)
		cancelStop()
	}
	var quiesceErr error
	if stopErr == nil && s.journal != nil {
		quiesceCtx, cancelQuiesce := context.WithTimeout(context.Background(), s.config.operationTimeout)
		quiesceErr = s.journal.Quiesce(quiesceCtx)
		cancelQuiesce()
	}
	var resourceErr error
	if stopErr == nil && quiesceErr == nil {
		resourceCtx, cancelResources := context.WithTimeout(context.Background(), s.config.operationTimeout)
		resourceErr = s.resources.CloseAll(resourceCtx)
		cancelResources()
	}
	if s.allocator != nil {
		s.allocator.Close()
	}
	var cleanupErr error
	if stopErr == nil && quiesceErr == nil && resourceErr == nil && s.journal != nil {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), s.config.operationTimeout)
		cleanupErr = s.journal.UndoAll(cleanupCtx)
		cancelCleanup()
	}
	result := errors.Join(underlayErr, stopErr, quiesceErr, resourceErr, cleanupErr)

	s.mu.Lock()
	next := lifecycleClosed
	if underlayErr != nil || stopErr != nil || quiesceErr != nil || resourceErr != nil || reconcile.RequiresRecovery(cleanupErr) {
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
	active := s.journal.Len() != 0
	recoveryRequired := reconcile.RequiresRecovery(err) || s.journal.RecoveryRequired()
	return errors.Join(err, s.finishApply(active, recoveryRequired))
}

// applyOperation serializes a native transaction which provides its own exact
// rollback and readback through the same worker used by journal operations.
func (s *System) applyOperation(operation reconcile.Operation) error {
	if err := s.beginApply(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	defer cancel()
	err := s.worker.Execute(ctx, operation)
	recoveryRequired := reconcile.RequiresRecovery(err)
	return errors.Join(err, s.finishApply(s.journal.Len() != 0, recoveryRequired))
}

func (s *System) handleReconcileFailure(err error) {
	if s.dependencies.logger != nil {
		s.dependencies.logger.Printf("asynchronous network policy reconciliation failed: %v", err)
	}
	if !reconcile.RequiresRecovery(err) && !errors.Is(err, split.ErrRecoveryRequired) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == lifecycleReady || s.state == lifecycleActive || s.state == lifecycleApplying {
		_ = s.transitionLocked(lifecycleRecoveryRequired)
		s.rebuildCapabilitiesLocked()
	}
}

func (s *System) handleReconcileReasons(ctx context.Context, reasons []reconcile.Reason) ([]reconcile.Entry, error) {
	reconcileSplit := false
	forceReadback := false
	for _, reason := range reasons {
		if reason == reconcile.Reason("underlay-change") || reason == reconcile.Reason("split-driver-error") {
			reconcileSplit = true
		}
		if reason == reconcile.Reason("split-driver-error") {
			forceReadback = true
		}
	}
	if !reconcileSplit {
		return nil, nil
	}
	device := s.activeSplitTun.Load()
	if device == nil || device.splitPolicy == nil || device.retired.Load() || device.closed.Load() {
		return nil, nil
	}
	addresses, err := splitAddresses(device.splitPrefixes, s.underlayMonitor.Snapshot())
	if err != nil {
		return nil, err
	}
	if !forceReadback && device.splitPolicy.AppliedAddresses() == addresses {
		return nil, nil
	}
	generation := device.splitPolicy.AppliedGeneration()
	if generation == ^uint64(0) {
		return nil, errors.New("split policy generation overflow")
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.config.operationTimeout)
	defer cancel()
	if err := device.splitPolicy.ReconcileAddresses(operationCtx, generation+1, addresses); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *System) enqueueReconcileReason(reason reconcile.Reason) {
	if s == nil {
		return
	}
	s.mu.RLock()
	worker := s.worker
	s.mu.RUnlock()
	if worker != nil {
		worker.Enqueue(reason)
	}
}

// trackResource adds a socket, listener, or TUN to ordered System cleanup.
func (s *System) trackResource(resource io.Closer) (func(), error) {
	if s == nil {
		return nil, stateValidationError(sysnet.ReasonSystemClosed, "system is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.acceptingWorkLocked(); err != nil {
		return nil, err
	}
	return s.resources.Track(resource)
}

func (s *System) Capabilities() sysnet.CapabilityReport {
	if s == nil {
		return capabilityModel{}.snapshot()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != lifecycleNew {
		s.rebuildCapabilitiesLocked()
	}
	return s.capabilities.snapshot()
}

func (s *System) CapabilitiesForTun(device tun.Tun) (sysnet.TunCapabilityReport, error) {
	if _, ok := device.(*defaultTun); ok {
		return s.defaultTunCapabilities(device)
	}
	return s.regularTunCapabilities(device)
}

func (s *System) CheckTunOpts(opts sysnet.TunOpts) sysnet.ValidationReport {
	desired, result := normalizeTunOpts(s.policyConfig(), opts)
	report := s.Capabilities()
	result.CapabilityRevision = report.Revision
	operation := sysnet.OpCreate
	if desired.name != "" {
		operation = sysnet.OpCreateNamed
	}
	appendCapabilityIssue(&result, "Tun.Create", report.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: operation,
		Family: familyForPrefixes(desired.addresses, desired.routes),
	}))
	return result
}

func (s *System) CheckDefaultTunOpts(opts sysnet.DefaultTunOpts) sysnet.ValidationReport {
	desired, result := normalizeDefaultTunOpts(s.policyConfig(), opts)
	report := s.Capabilities()
	result.CapabilityRevision = report.Revision
	operation := sysnet.OpCreate
	if desired.tun.name != "" {
		operation = sysnet.OpCreateNamed
	}
	appendCapabilityIssue(&result, "DefaultTun.Create", report.Operation(sysnet.OperationKey{
		Target: sysnet.TargetDefaultTun, Operation: operation, Family: desired.family,
	}))
	mode := sysnet.RoutingFull
	if len(opts.Exclude) != 0 {
		mode = sysnet.RoutingExclude
	} else if len(opts.Include) != 0 {
		mode = sysnet.RoutingInclude
	}
	appendCapabilityIssue(&result, "DefaultTun.Profile", report.DefaultTunProfile(sysnet.RoutingProfileKey{
		Family: desired.family, Mode: mode, Strict: opts.Strict,
	}).Capability)
	return result
}

func (s *System) CheckRule(rule sysnet.Rule, context sysnet.RuleContext) sysnet.ValidationReport {
	_, result := normalizeRule(s.policyConfig(), rule, context)
	report := s.Capabilities()
	result.CapabilityRevision = report.Revision
	if len(result.Issues) != 0 {
		return result
	}
	ruleCapability := report.Rule(strings.TrimSpace(rule.Type))
	appendCapabilityIssue(&result, "Rule.Type", ruleCapability.Validation)
	if context.Routing != nil {
		profile := report.DefaultTunProfile(*context.Routing)
		appendCapabilityIssue(&result, "Rule.Context", profile.Capability)
		binding := sysnet.Capability{State: sysnet.CapabilityUnknown}
		for _, candidate := range profile.Rules {
			if candidate.Type == strings.TrimSpace(rule.Type) {
				binding = candidate.Capability
				break
			}
		}
		appendCapabilityIssue(&result, "Rule.Type", binding)
	} else if context.Matcher != nil {
		appendCapabilityIssue(&result, "Rule.Context", matcherProfile(ruleCapability, *context.Matcher).Capability)
	}
	return result
}

func (s *System) CompleteRule(rule sysnet.Rule, context sysnet.RuleContext) ([]string, error) {
	if err := s.acceptingWork(); err != nil {
		return nil, err
	}
	normalized, validation := normalizeRule(s.policyConfig(), rule, context)
	if err := validation.Err(); err != nil {
		return nil, err
	}
	ruleCapability := s.Capabilities().Rule(normalized.typeName)
	if ruleCapability.Completion.State != sysnet.CapabilityAvailable {
		return nil, capabilityError("Rule.Completion", ruleCapability.Completion)
	}
	return []string{normalized.value}, nil
}

// AllocIP returns the System's shared host-aware IP allocator.
func (s *System) AllocIP() subnet.IPAllocator {
	if s == nil {
		return nil
	}
	return s.publicAllocator
}

// AllocSubnet returns the same shared reservation state as AllocIP.
func (s *System) AllocSubnet() subnet.SubnetAllocator {
	if s == nil {
		return nil
	}
	return s.publicAllocator
}

// OutDNS returns the DNS transport used by OutNet name lookups. The provider
// uses bound sockets and is owned by this System.
func (s *System) OutDNS() dns.Interface {
	if s == nil {
		return nil
	}
	return s.outDNS
}

// OutNet returns a stable policy wrapper. It reports IsNative=false because a
// native shortcut could omit underlay binding, DNS routing, or resource
// tracking.
func (s *System) OutNet() gonnect.Network {
	if s == nil || s.outNet == nil {
		return &gonnect.RejectNetwork{}
	}
	return s.outNet
}

// LocalNet returns a stable, loopback-only policy wrapper. It reports
// IsNative=false because a native shortcut could omit endpoint validation or
// resource tracking.
func (s *System) LocalNet() gonnect.Network {
	if s == nil || s.localNet == nil {
		return &gonnect.RejectNetwork{}
	}
	return s.localNet
}

func (s *System) BuildMatcher(rule sysnet.Rule) (sysnet.Matcher, error) {
	normalized, validation := validateMatcherRule(s.policyConfig(), rule)
	if validation.Err() != nil {
		return nil, validation.Err()
	}
	capabilities, err := s.finalPreflight()
	if err != nil {
		return nil, err
	}
	var unavailable error
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		for _, transport := range []sysnet.Transport{sysnet.TransportTCP, sysnet.TransportUDP} {
			profile := matcherProfile(capabilities.Rule(normalized.typeName), sysnet.MatcherProfileKey{Family: family, Transport: transport})
			if profile.State == sysnet.CapabilityAvailable {
				if s.dependencies.ownerLookup == nil {
					return nil, capabilityError("Matcher", missingDependencyCapability("owner lookup is not configured"))
				}
				built := newMatcher(s.dependencies.ownerLookup, s.config.operationTimeout, normalized)
				release, trackErr := s.trackResource(built)
				if trackErr != nil {
					return nil, trackErr
				}
				if err := built.setRelease(release); err != nil {
					release()
					return nil, err
				}
				return built, nil
			}
			if unavailable == nil && (profile.State != sysnet.CapabilityUnknown || len(profile.Reasons) != 0) {
				unavailable = capabilityError("Matcher", profile.Capability)
			}
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
	capabilities, err := s.finalPreflight()
	if err != nil {
		return nil, err
	}
	operation := sysnet.OpCreate
	if desired.tun.name != "" {
		operation = sysnet.OpCreateNamed
	}
	create := capabilities.Operation(sysnet.OperationKey{
		Target: sysnet.TargetDefaultTun, Operation: operation, Family: desired.family,
	})
	if create.State != sysnet.CapabilityAvailable {
		return nil, capabilityError("DefaultTun.Create", create)
	}
	mode := sysnet.RoutingFull
	if len(desired.excludes) != 0 {
		mode = sysnet.RoutingExclude
	}
	capability := capabilities.DefaultTunProfile(sysnet.RoutingProfileKey{Family: desired.family, Mode: mode}).Capability
	// Split ownership is deliberately unknown until this explicit exclusion
	// operation lazily acquires and verifies the global driver session.
	resolveSplit := len(desired.excludes) != 0 && capability.State == sysnet.CapabilityUnknown
	if capability.State != sysnet.CapabilityAvailable && !resolveSplit {
		return nil, capabilityError("DefaultTun.Profile", capability)
	}
	return s.buildDefaultTun(opts, desired)
}

func (s *System) recordSplitCapability(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	capability := sysnet.Capability{State: sysnet.CapabilityAvailable}
	if err != nil {
		reason := sysnet.ReasonProbeFailed
		switch {
		case errors.Is(err, split.ErrUnavailable):
			reason = sysnet.ReasonMissingDependency
		case errors.Is(err, split.ErrBusy):
			reason = sysnet.ReasonResourceBusy
		case errors.Is(err, split.ErrIncompatible):
			reason = sysnet.ReasonDependencyIncompatible
		case errors.Is(err, split.ErrDirty), errors.Is(err, split.ErrRecoveryRequired):
			reason = sysnet.ReasonRecoveryRequired
		}
		capability = sysnet.Capability{State: sysnet.CapabilityUnavailable, Reasons: []sysnet.CapabilityReason{reason}, Detail: err.Error()}
	}
	s.probeFacts.split = capability
	s.rebuildCapabilitiesLocked()
}

// DefaultTunWarnings returns no warnings for a default TUN.
func (*System) DefaultTunWarnings(sysnet.DefaultTun) []sysnet.Warning {
	return nil
}

func (s *System) BuildTun(opts sysnet.TunOpts) (tun.Tun, error) {
	return s.buildRegularTun(opts)
}

func (s *System) TunWarnings(device tun.Tun) []sysnet.Warning {
	if _, err := s.lookupRegularTun(device); err != nil {
		return nil
	}
	return nil
}

func (s *System) SetTunMTU(device tun.Tun, mtu int) error {
	return s.setRegularTunMTU(device, mtu)
}

func (s *System) SetTunAddrs(device tun.Tun, addrs []string) error {
	return s.changeTunPrefixes(device, addrs, "Tun.TunAddrs", prefixAddress, sysnet.OpSetAddresses)
}

func (s *System) AddTunAddr(device tun.Tun, addr string) error {
	return s.changeTunPrefixes(device, []string{addr}, "Tun.TunAddrs", prefixAddress, sysnet.OpAddAddress)
}

func (s *System) GetTunAddrs(device tun.Tun) ([]string, error) {
	return s.getRegularTunPrefixes(device, prefixAddress)
}

func (s *System) SetTunRoutes(device tun.Tun, routes []string) error {
	return s.changeTunPrefixes(device, routes, "Tun.TunRoutes", prefixRoute, sysnet.OpSetRoutes)
}

func (s *System) changeTunPrefixes(device tun.Tun, raw []string, path string, kind prefixKind, operation sysnet.Operation) error {
	if err := s.requireOwnedTun(device); err != nil {
		return err
	}
	prefixes, report := normalizePrefixes(s.policyConfig(), raw, path, kind)
	if err := report.Err(); err != nil {
		return err
	}
	return s.changeRegularTunPrefixes(device, prefixes, path, kind, operation)
}

func (s *System) AddTunRoute(device tun.Tun, route string) error {
	return s.changeTunPrefixes(device, []string{route}, "Tun.TunRoutes", prefixRoute, sysnet.OpAddRoute)
}

func (s *System) GetTunRoutes(device tun.Tun) ([]string, error) {
	return s.getRegularTunPrefixes(device, prefixRoute)
}

func (s *System) SetTunName(device tun.Tun, _ string) error {
	if err := s.requireOwnedTun(device); err != nil {
		return err
	}
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

// requireOwnedTun rejects foreign, stale, and closed handles before option or
// capability checks.
func (s *System) requireOwnedTun(device tun.Tun) error {
	_, err := s.requireKnownRegularTun(device)
	return err
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
func (s *System) finalPreflight() (sysnet.CapabilityReport, error) {
	if s == nil {
		return sysnet.CapabilityReport{}, stateValidationError(sysnet.ReasonSystemClosed, "system is nil")
	}
	if s.dependencies.capabilityProbe == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.acceptingWorkLocked(); err != nil {
			return sysnet.CapabilityReport{}, err
		}
		s.rebuildCapabilitiesLocked()
		return s.capabilities.snapshot(), nil
	}
	s.mu.Lock()
	if err := s.acceptingWorkLocked(); err != nil {
		s.mu.Unlock()
		return sysnet.CapabilityReport{}, err
	}
	s.probeGeneration++
	probeGeneration := s.probeGeneration
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	facts := runCapabilityProbe(ctx, s.dependencies.capabilityProbe)
	cancel()
	facts = s.dependencies.constrainCapabilityFacts(facts)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.acceptingWorkLocked(); err != nil {
		return sysnet.CapabilityReport{}, err
	}
	if probeGeneration != s.probeGeneration {
		return sysnet.CapabilityReport{}, validationError(validationIssue(
			"System.CapabilityProbe",
			sysnet.CapabilityUnavailable,
			sysnet.ReasonResourceBusy,
			"capability probe was superseded by a newer preflight",
			nil,
		))
	}
	s.probeFacts = facts
	s.rebuildCapabilitiesLocked()
	return s.capabilities.snapshot(), nil
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

func appendCapabilityIssue(report *sysnet.ValidationReport, path string, capability sysnet.Capability) {
	if capability.State == sysnet.CapabilityAvailable {
		return
	}
	reason := sysnet.ReasonProbeNotRun
	if len(capability.Reasons) != 0 {
		reason = capability.Reasons[0]
	}
	report.Issues = append(report.Issues, validationIssue(path, capability.State, reason, capability.Detail, nil))
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
