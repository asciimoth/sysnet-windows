package windows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
)

const regularTunRouteMetric uint32 = 5

// regularTun is the handle returned to a caller. Keeping the wrapper private
// makes System ownership an object identity check instead of a comparison of
// mutable names or current Windows interface numbers.
type regularTun struct {
	owner    *System
	id       uint64
	native   internaltun.ManagedTun
	metadata internaltun.Metadata

	mu               sync.RWMutex
	desired          netio.Config
	mtu              int
	instanceRevision uint64
	failed           error
	unknown          bool
	closed           atomic.Bool
	closeMu          sync.Mutex
	closeErr         error
}

func (t *regularTun) File() *os.File { return t.native.File() }
func (t *regularTun) IsNative() bool { return t.native.IsNative() }
func (t *regularTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if t.closed.Load() {
		return 0, os.ErrClosed
	}
	return t.native.Read(bufs, sizes, offset)
}
func (t *regularTun) Write(bufs [][]byte, offset int) (int, error) {
	if t.closed.Load() {
		return 0, os.ErrClosed
	}
	return t.native.Write(bufs, offset)
}
func (t *regularTun) MWO() int                  { return t.native.MWO() }
func (t *regularTun) MRO() int                  { return t.native.MRO() }
func (t *regularTun) MTU() (int, error)         { return t.native.MTU() }
func (t *regularTun) Name() (string, error)     { return t.native.Name() }
func (t *regularTun) Events() <-chan gtun.Event { return t.native.Events() }
func (t *regularTun) BatchSize() int            { return t.native.BatchSize() }

func (t *regularTun) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed.Load() {
		return t.closeErr
	}
	completed, err := t.owner.closeRegularTun(t)
	// A lifecycle or worker rejection can happen before cleanup starts. Do not
	// make that transient error terminal. Once this attempt completes registry
	// cleanup, retain the result so concurrent and repeated Close calls remain
	// stable. Another concurrent shutdown can close the native TUN without
	// making this rejected attempt terminal.
	if completed {
		t.closeErr = err
	}
	return err
}

func (t *regularTun) interfaceID() netio.Interface {
	return netio.Interface{LUID: t.metadata.LUID, Index: t.metadata.Index, GUID: t.metadata.GUID}
}

func (t *regularTun) snapshot() (netio.Config, int, uint64, error, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return cloneNetIOConfig(t.desired), t.mtu, t.instanceRevision, t.failed, t.unknown
}

func (t *regularTun) commit(config netio.Config, mtu int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.desired = cloneNetIOConfig(config)
	t.mtu = mtu
	t.instanceRevision++
}

func (t *regularTun) markFailed(err error, unknown bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failed == nil {
		t.instanceRevision++
	}
	t.failed = errors.Join(t.failed, err)
	t.unknown = t.unknown || unknown
}

func (t *regularTun) closeNative() error {
	if t == nil || t.native == nil || t.closed.Load() {
		return nil
	}
	err := t.native.Close()
	if err == nil {
		t.closed.Store(true)
	}
	return err
}

func (s *System) nextRegularTunID() uint64 {
	s.regularTunsMu.Lock()
	defer s.regularTunsMu.Unlock()
	s.nextRegularTun++
	return s.nextRegularTun
}

func (s *System) buildRegularTun(opts sysnet.TunOpts) (gtun.Tun, error) {
	desired, report := normalizeTunOpts(s.policyConfig(), opts)
	if err := report.Err(); err != nil {
		return nil, err
	}
	capabilities, err := s.finalPreflight()
	if err != nil {
		return nil, err
	}
	family := familyForPrefixes(desired.addresses, desired.routes)
	operation := sysnet.OpCreate
	if desired.name != "" {
		operation = sysnet.OpCreateNamed
	}
	if capability := capabilities.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: operation, Family: family,
	}); capability.State != sysnet.CapabilityAvailable {
		return nil, capabilityError("Tun.Create", capability)
	}
	if s.dependencies.tunFactory == nil || s.dependencies.netIO == nil {
		return nil, stateValidationError(sysnet.ReasonMissingDependency, "regular TUN dependencies are not configured")
	}

	id := s.nextRegularTunID()
	reservationID := fmt.Sprintf("regular-tun-%d", id)
	if err := s.allocator.ReserveOwnedIPs(reservationID, desired.addresses); err != nil {
		return nil, fmt.Errorf("reserve regular TUN addresses: %w", err)
	}
	keepReservation := false
	defer func() {
		if !keepReservation {
			s.allocator.ReleaseOwnedIPs(reservationID)
		}
	}()
	want := regularTunNetIOConfig(s.config, desired.addresses, desired.routes, desired.mtu)
	var result *regularTun
	adapterKey := reconcile.OwnershipKey{Kind: reconcile.KindAdapter, Scope: "regular-tun", ID: fmt.Sprint(id)}
	configKey := reconcile.OwnershipKey{Kind: reconcile.KindAddress, Scope: "regular-tun", ID: fmt.Sprint(id)}
	entries := []reconcile.Entry{
		{
			Key: adapterKey,
			Apply: func(ctx context.Context) error {
				// Normalize again at the last boundary. This prevents a later
				// policy change from bypassing validation in BuildTun.
				if _, validation := normalizeTunOpts(s.policyConfig(), opts); validation.Err() != nil {
					return validation.Err()
				}
				native, createErr := s.dependencies.tunFactory.Create(ctx, internaltun.Config{
					Name: desired.name, NamePrefix: s.config.adapterNamePrefix,
					GUID: s.config.stableGUID, MTU: desired.mtu,
				})
				if createErr != nil {
					return createErr
				}
				metadata := native.Metadata()
				result = &regularTun{
					owner: s, id: id, native: native, metadata: metadata,
					desired: cloneNetIOConfig(want), mtu: desired.mtu, instanceRevision: 1,
				}
				s.registerOwnedUnderlay(result)
				return nil
			},
			Inverse: func(ctx context.Context) error {
				if result == nil {
					return nil
				}
				if result.closed.Load() {
					s.unregisterOwnedUnderlay(result)
					s.allocator.ReleaseOwnedIPs(reservationID)
					return nil
				}
				observed, readErr := s.dependencies.netIO.Read(ctx, result.interfaceID())
				if readErr != nil {
					return fmt.Errorf("verify NetIO cleanup before adapter close: %w", readErr)
				}
				if !netIOConfigEmpty(observed) {
					return errors.New("cannot close regular TUN while owned NetIO state remains")
				}
				closeErr := result.closeNative()
				if closeErr == nil {
					s.unregisterOwnedUnderlay(result)
					s.allocator.ReleaseOwnedIPs(reservationID)
				}
				return closeErr
			},
			Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
				if expected == reconcile.ExpectedUndone {
					if result == nil || result.closed.Load() {
						return nil
					}
					return errors.New("regular TUN is still open")
				}
				if result == nil || result.closed.Load() {
					return errors.New("regular TUN was not created")
				}
				return nil
			},
		},
		{
			Key: configKey,
			Apply: func(ctx context.Context) error {
				if result == nil {
					return errors.New("regular TUN adapter is unavailable")
				}
				if err := s.allocator.VerifyOwnedIPsAvailable(reservationID); err != nil {
					return fmt.Errorf("recheck regular TUN addresses: %w", err)
				}
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), want)
			},
			Inverse: func(ctx context.Context) error {
				if result == nil || result.closed.Load() {
					return nil
				}
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), netio.Config{})
			},
			Verify: func(ctx context.Context, expected reconcile.ExpectedState) error {
				if result == nil {
					return nil
				}
				if result.closed.Load() && expected == reconcile.ExpectedUndone {
					return nil
				}
				if expected == reconcile.ExpectedUndone {
					return s.dependencies.netIO.Verify(ctx, result.interfaceID(), netio.Config{})
				}
				return s.dependencies.netIO.Verify(ctx, result.interfaceID(), want)
			},
		},
	}
	if err := s.applyTransaction(entries); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("regular TUN transaction returned no adapter")
	}
	s.mu.RLock()
	acceptErr := s.acceptingWorkLocked()
	if acceptErr == nil {
		s.regularTunsMu.Lock()
		s.regularTuns[result] = struct{}{}
		s.regularTunsMu.Unlock()
	}
	s.mu.RUnlock()
	if acceptErr != nil {
		return nil, acceptErr
	}
	keepReservation = true
	return result, nil
}

func (s *System) lookupRegularTun(device gtun.Tun) (*regularTun, error) {
	owned, ok := device.(*regularTun)
	if !ok || owned == nil || owned.owner != s || owned.closed.Load() {
		return nil, sysnet.ErrUnknownTun
	}
	s.regularTunsMu.Lock()
	_, ok = s.regularTuns[owned]
	s.regularTunsMu.Unlock()
	if !ok {
		return nil, sysnet.ErrUnknownTun
	}
	_, _, _, failed, unknown := owned.snapshot()
	if unknown {
		return nil, errors.Join(sysnet.ErrUnknownTun, failed)
	}
	if failed != nil {
		return nil, errors.Join(stateValidationError(sysnet.ReasonRecoveryRequired, "regular TUN reconciliation failed"), failed)
	}
	return owned, nil
}

func (s *System) observeRegularTun(ctx context.Context, device *regularTun) (netio.Config, error) {
	want, _, _, _, _ := device.snapshot()
	if err := s.dependencies.netIO.Verify(ctx, device.interfaceID(), want); err != nil {
		return netio.Config{}, s.failRegularTun(device, err)
	}
	return want, nil
}

func (s *System) failRegularTun(device *regularTun, cause error) error {
	unknown := errors.Is(cause, netio.ErrIdentityMismatch)
	device.markFailed(cause, unknown)
	s.mu.Lock()
	if s.state == lifecycleReady || s.state == lifecycleActive || s.state == lifecycleApplying {
		_ = s.transitionLocked(lifecycleRecoveryRequired)
		s.rebuildCapabilitiesLocked()
	}
	s.mu.Unlock()
	if unknown {
		s.regularTunsMu.Lock()
		delete(s.regularTuns, device)
		s.regularTunsMu.Unlock()
		return errors.Join(sysnet.ErrUnknownTun, cause)
	}
	return errors.Join(stateValidationError(sysnet.ReasonRecoveryRequired, "regular TUN native state is not verified"), cause)
}

func (s *System) regularTunCapabilities(device gtun.Tun) (sysnet.TunCapabilityReport, error) {
	owned, err := s.requireKnownRegularTun(device)
	if err != nil {
		return sysnet.TunCapabilityReport{}, err
	}
	report, err := s.finalPreflight()
	if err != nil {
		return sysnet.TunCapabilityReport{}, err
	}
	desired, _, _, _, _ := owned.snapshot()
	family := familyForNetIOConfig(desired)
	if family == sysnet.FamilyNone {
		family = defaultTunFamily(s.policyConfig())
	}
	readCapability := report.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: sysnet.OpGetAddresses, Family: family,
	})
	if readCapability.State != sysnet.CapabilityAvailable {
		return sysnet.TunCapabilityReport{}, capabilityError("Tun.Capabilities", readCapability)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	_, err = s.observeRegularTun(ctx, owned)
	cancel()
	if err != nil {
		return sysnet.TunCapabilityReport{}, err
	}
	_, _, revision, _, _ := owned.snapshot()
	result := sysnet.TunCapabilityReport{SystemRevision: report.Revision, InstanceRevision: revision}
	for _, operation := range report.Operations {
		if operation.Key.Target != sysnet.TargetTun || operation.Key.Operation == sysnet.OpCreate || operation.Key.Operation == sysnet.OpCreateNamed {
			continue
		}
		result.Operations = append(result.Operations, operation)
	}
	return result.Clone(), nil
}

func (s *System) setRegularTunMTU(device gtun.Tun, raw int) error {
	owned, err := s.requireKnownRegularTun(device)
	if err != nil {
		return err
	}
	// Keep the MTU valid for every family that this System can add later.
	// Otherwise an IPv4-only TUN can accept an IPv4-sized MTU and then reject
	// an advertised IPv6 address or route operation at the NetIO boundary.
	config := s.policyConfig()
	mtu, validation := normalizeMTU(config, raw, "Tun.MTU", config.ipv6)
	if err := validation.Err(); err != nil {
		return err
	}
	capabilities, err := s.finalPreflight()
	if err != nil {
		return err
	}
	capability := capabilities.Operation(sysnet.OperationKey{Target: sysnet.TargetTun, Operation: sysnet.OpSetMTU, Family: sysnet.FamilyNone})
	if capability.State != sysnet.CapabilityAvailable {
		return capabilityError("Tun.MTU", capability)
	}
	return s.applyOperation(func(ctx context.Context) error {
		current, lookupErr := s.lookupRegularTun(owned)
		if lookupErr != nil {
			return lookupErr
		}
		observed, observeErr := s.observeRegularTun(ctx, current)
		if observeErr != nil {
			return observeErr
		}
		previous, _, _, _, _ := current.snapshot()
		next := cloneNetIOConfig(observed)
		for index := range next.Properties {
			next.Properties[index].MTU = uint32(mtu)
		}
		if err := s.dependencies.netIO.Apply(ctx, current.interfaceID(), next); err != nil {
			return s.translateRegularTunMutationError(ctx, current, observed, err)
		}
		if err := current.native.UpdateReportedMTU(mtu); err != nil {
			rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), s.config.operationTimeout)
			rollbackErr := s.dependencies.netIO.Apply(rollbackCtx, current.interfaceID(), previous)
			cancelRollback()
			if rollbackErr != nil {
				return s.verifyRegularTunStateAfterError(ctx, current, previous,
					errors.Join(err, fmt.Errorf("restore NetIO MTU: %w", rollbackErr)))
			}
			return err
		}
		current.commit(next, mtu)
		return nil
	})
}

func (s *System) changeRegularTunPrefixes(
	device gtun.Tun,
	prefixes []netip.Prefix,
	path string,
	kind prefixKind,
	operation sysnet.Operation,
) error {
	owned, err := s.lookupRegularTun(device)
	if err != nil {
		return err
	}
	capabilities, err := s.finalPreflight()
	if err != nil {
		return err
	}
	base, mtu, _, _, _ := owned.snapshot()
	planned, err := s.nextRegularTunConfig(base, prefixes, kind, operation, mtu)
	if err != nil {
		return err
	}
	family := familyForNetIOConfig(planned)
	if family == sysnet.FamilyNone {
		family = defaultTunFamily(s.config)
	}
	capability := capabilities.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: operation, Family: family,
	})
	if capability.State != sysnet.CapabilityAvailable {
		return capabilityError(path, capability)
	}
	return s.applyOperation(func(ctx context.Context) error {
		current, lookupErr := s.lookupRegularTun(owned)
		if lookupErr != nil {
			return lookupErr
		}
		observed, observeErr := s.observeRegularTun(ctx, current)
		if observeErr != nil {
			return observeErr
		}
		_, mtu, _, _, _ := current.snapshot()
		next, configErr := s.nextRegularTunConfig(observed, prefixes, kind, operation, mtu)
		if configErr != nil {
			return configErr
		}
		family := familyForNetIOConfig(next)
		if family == sysnet.FamilyNone {
			family = defaultTunFamily(s.config)
		}
		capability := capabilities.Operation(sysnet.OperationKey{Target: sysnet.TargetTun, Operation: operation, Family: family})
		if capability.State != sysnet.CapabilityAvailable {
			return capabilityError(path, capability)
		}
		if netIOConfigEqual(observed, next) {
			return nil
		}
		reservationsChanged := kind == prefixAddress
		reservationID := fmt.Sprintf("regular-tun-%d", current.id)
		if reservationsChanged {
			if err := s.allocator.ReplaceOwnedIPs(reservationID, next.Addresses); err != nil {
				return fmt.Errorf("reserve updated regular TUN addresses: %w", err)
			}
		}
		if err := s.dependencies.netIO.Apply(ctx, current.interfaceID(), next); err != nil {
			if reservationsChanged {
				reservationErr := s.allocator.RestoreOwnedIPs(reservationID, observed.Addresses)
				err = errors.Join(err, reservationErr)
			}
			return s.translateRegularTunMutationError(ctx, current, observed, err)
		}
		current.commit(next, mtu)
		return nil
	})
}

func (s *System) nextRegularTunConfig(
	current netio.Config,
	prefixes []netip.Prefix,
	kind prefixKind,
	operation sysnet.Operation,
	mtu int,
) (netio.Config, error) {
	next := cloneNetIOConfig(current)
	switch kind {
	case prefixAddress:
		if operation == sysnet.OpAddAddress {
			next.Addresses = appendUniquePrefixes(next.Addresses, prefixes...)
		} else {
			next.Addresses = append([]netip.Prefix(nil), prefixes...)
		}
	case prefixRoute:
		routes := routesFromPrefixes(prefixes)
		if operation == sysnet.OpAddRoute {
			next.Routes = appendUniqueRoutes(next.Routes, routes...)
		} else {
			next.Routes = routes
		}
	default:
		return netio.Config{}, errors.New("invalid regular TUN prefix kind")
	}
	next.Properties = propertiesForConfig(s.config, next, mtu)
	return next, nil
}

func (s *System) getRegularTunPrefixes(device gtun.Tun, kind prefixKind) ([]string, error) {
	owned, err := s.requireKnownRegularTun(device)
	if err != nil {
		return nil, err
	}
	desired, _, _, _, _ := owned.snapshot()
	family := familyForNetIOConfig(desired)
	if family == sysnet.FamilyNone {
		family = defaultTunFamily(s.policyConfig())
	}
	operation := sysnet.OpGetRoutes
	path := "Tun.TunRoutes"
	if kind == prefixAddress {
		operation = sysnet.OpGetAddresses
		path = "Tun.TunAddrs"
	}
	capabilities, err := s.finalPreflight()
	if err != nil {
		return nil, err
	}
	capability := capabilities.Operation(sysnet.OperationKey{
		Target: sysnet.TargetTun, Operation: operation, Family: family,
	})
	if capability.State != sysnet.CapabilityAvailable {
		return nil, capabilityError(path, capability)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.operationTimeout)
	observed, err := s.observeRegularTun(ctx, owned)
	cancel()
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	if kind == prefixAddress {
		prefixes = observed.Addresses
	} else {
		prefixes = make([]netip.Prefix, 0, len(observed.Routes))
		for _, route := range observed.Routes {
			prefixes = append(prefixes, route.Destination)
		}
	}
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result, nil
}

func (s *System) translateRegularTunMutationError(
	ctx context.Context,
	device *regularTun,
	expected netio.Config,
	err error,
) error {
	if netio.RequiresRecovery(err) || errors.Is(err, netio.ErrIdentityMismatch) {
		return s.failRegularTun(device, err)
	}
	if !errors.Is(err, netio.ErrResourceConflict) && !errors.Is(err, netio.ErrReadback) {
		return err
	}
	return s.verifyRegularTunStateAfterError(ctx, device, expected, err)
}

func (s *System) verifyRegularTunStateAfterError(
	ctx context.Context,
	device *regularTun,
	expected netio.Config,
	err error,
) error {
	if netio.RequiresRecovery(err) || errors.Is(err, netio.ErrIdentityMismatch) {
		return s.failRegularTun(device, err)
	}
	// ExactManager can report a native conflict or readback error after its
	// rollback independently proves that the preceding configuration is still
	// intact. An MTU report failure can also require a second NetIO transaction
	// to restore packet/native agreement. Keep the TUN usable only after another
	// read confirms the required state.
	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.operationTimeout)
	readErr := s.dependencies.netIO.Verify(verifyCtx, device.interfaceID(), expected)
	cancel()
	if readErr != nil {
		return s.failRegularTun(device, errors.Join(err,
			fmt.Errorf("verify regular TUN state after failed mutation: %w", readErr)))
	}
	return err
}

func (s *System) closeRegularTun(device *regularTun) (bool, error) {
	if _, err := s.lookupRegularTun(device); err != nil {
		if device != nil && device.closed.Load() {
			return true, nil
		}
		return false, err
	}
	var completed atomic.Bool
	err := s.applyOperation(func(ctx context.Context) error {
		id := fmt.Sprint(device.id)
		undoErr := s.journal.Undo(ctx,
			reconcile.OwnershipKey{Kind: reconcile.KindAddress, Scope: "regular-tun", ID: id},
			reconcile.OwnershipKey{Kind: reconcile.KindAdapter, Scope: "regular-tun", ID: id},
		)
		if undoErr != nil && reconcile.RequiresRecovery(undoErr) {
			return undoErr
		}
		s.regularTunsMu.Lock()
		delete(s.regularTuns, device)
		s.regularTunsMu.Unlock()
		s.allocator.ReleaseOwnedIPs(fmt.Sprintf("regular-tun-%d", device.id))
		completed.Store(true)
		return undoErr
	})
	return completed.Load(), err
}

func (s *System) requireKnownRegularTun(device gtun.Tun) (*regularTun, error) {
	owned, err := s.lookupRegularTun(device)
	if err != nil {
		return nil, err
	}
	if err := s.acceptingWork(); err != nil {
		return nil, err
	}
	return owned, nil
}

func regularTunNetIOConfig(config normalizedSystemConfig, addresses, routes []netip.Prefix, mtu int) netio.Config {
	result := netio.Config{
		Addresses: append([]netip.Prefix(nil), addresses...),
		Routes:    routesFromPrefixes(routes),
	}
	result.Properties = propertiesForConfig(config, result, mtu)
	return result
}

func propertiesForConfig(config normalizedSystemConfig, state netio.Config, mtu int) []netio.Properties {
	family := familyForNetIOConfig(state)
	var families []netio.Family
	if family == sysnet.FamilyIPv4 || family == sysnet.FamilyDual || family == sysnet.FamilyNone && config.ipv4 {
		families = append(families, netio.FamilyIPv4)
	}
	if family == sysnet.FamilyIPv6 || family == sysnet.FamilyDual || family == sysnet.FamilyNone && config.ipv6 {
		families = append(families, netio.FamilyIPv6)
	}
	result := make([]netio.Properties, 0, len(families))
	for _, item := range families {
		result = append(result, netio.Properties{Family: item, MTU: uint32(mtu), Metric: regularTunRouteMetric})
	}
	return result
}

func routesFromPrefixes(prefixes []netip.Prefix) []netio.Route {
	result := make([]netio.Route, 0, len(prefixes))
	for _, prefix := range prefixes {
		nextHop := netip.IPv6Unspecified()
		if prefix.Addr().Is4() {
			nextHop = netip.IPv4Unspecified()
		}
		result = append(result, netio.Route{Destination: prefix.Masked(), NextHop: nextHop, Metric: regularTunRouteMetric})
	}
	return result
}

func familyForNetIOConfig(config netio.Config) sysnet.AddressFamily {
	prefixes := append([]netip.Prefix(nil), config.Addresses...)
	for _, route := range config.Routes {
		prefixes = append(prefixes, route.Destination)
	}
	return familyForPrefixes(prefixes)
}

func appendUniquePrefixes(current []netip.Prefix, values ...netip.Prefix) []netip.Prefix {
	result := append([]netip.Prefix(nil), current...)
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func appendUniqueRoutes(current []netio.Route, values ...netio.Route) []netio.Route {
	result := append([]netio.Route(nil), current...)
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func cloneNetIOConfig(config netio.Config) netio.Config {
	return netio.Config{
		Addresses:  append([]netip.Prefix(nil), config.Addresses...),
		Routes:     append([]netio.Route(nil), config.Routes...),
		Properties: append([]netio.Properties(nil), config.Properties...),
	}
}

func netIOConfigEmpty(config netio.Config) bool {
	return len(config.Addresses) == 0 && len(config.Routes) == 0 && len(config.Properties) == 0
}

func netIOConfigEqual(left, right netio.Config) bool {
	return sameValues(left.Addresses, right.Addresses) &&
		sameValues(left.Routes, right.Routes) &&
		sameValues(left.Properties, right.Properties)
}

func sameValues[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !slices.Contains(right, value) {
			return false
		}
	}
	return true
}

var _ gtun.Tun = (*regularTun)(nil)
