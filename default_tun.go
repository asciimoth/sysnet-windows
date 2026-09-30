package windows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
	"github.com/asciimoth/sysnet-windows/internal/split"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

const defaultTunRouteMetric uint32 = 1

// defaultTun is intentionally a different concrete type from regularTun.
// Thus, regular-TUN setters reject it until default-policy reconciliation is
// implemented for those setters.
type defaultTun struct {
	*regularTun
	reservationID string
	retired       atomic.Bool
	dnsProxy      internaldns.ManagedProxy
	dnsPrior      internaldns.State
	dnsApplied    internaldns.State
	splitPolicy   *split.Policy
	splitPrefixes []netip.Prefix
}

// SetDNS atomically replaces the provider used by this TUN's local proxy. A nil
// provider intentionally drops requests; it never selects a host resolver.
func (t *defaultTun) SetDNS(provider dns.Interface) error {
	if t == nil || t.owner == nil {
		return sysnet.ErrUnknownTun
	}
	return t.owner.setDefaultTunDNS(t, provider)
}

func (t *defaultTun) Close() error {
	if t == nil || t.owner == nil {
		return nil
	}
	return t.owner.closeDefaultTun(t)
}

func (s *System) buildDefaultTun(opts sysnet.DefaultTunOpts, desired desiredDefaultTun) (sysnet.DefaultTun, error) {
	if s.dependencies.tunFactory == nil || s.dependencies.netIO == nil || s.dependencies.dnsConfigurator == nil || s.dependencies.dnsProxyFactory == nil || s.underlayMonitor == nil {
		return nil, stateValidationError(sysnet.ReasonMissingDependency, "default TUN dependencies are not configured")
	}
	if err := requireUnderlays(s.underlayMonitor.Snapshot(), desired.family); err != nil {
		return nil, err
	}

	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	old := s.defaultTun
	s.nextDefaultTun++
	id := s.nextDefaultTun
	reservationID := fmt.Sprintf("default-tun-%d", id)
	var replacedReservation string
	if old != nil {
		replacedReservation = old.reservationID
	}
	if len(desired.tun.addresses) == 0 {
		ipv4 := desired.family == sysnet.FamilyIPv4 || desired.family == sysnet.FamilyDual
		ipv6 := desired.family == sysnet.FamilyIPv6 || desired.family == sysnet.FamilyDual
		prefixes, err := s.allocator.AllocateOwnedIPs(reservationID, ipv4, ipv6)
		if err != nil {
			return nil, fmt.Errorf("allocate default TUN address: %w", err)
		}
		desired.tun.addresses = prefixes
		desired.dnsIP = prefixes[0].Addr()
	} else if err := s.allocator.ReserveOwnedIPsForReplacement(reservationID, desired.tun.addresses, replacedReservation); err != nil {
		return nil, fmt.Errorf("reserve default TUN addresses: %w", err)
	}
	keepReservation := false
	defer func() {
		if !keepReservation {
			s.allocator.ReleaseOwnedIPs(reservationID)
		}
	}()

	var result *defaultTun
	adapterKey := reconcile.OwnershipKey{Kind: reconcile.KindAdapter, Scope: "default-tun", ID: fmt.Sprint(id)}
	baseKey := reconcile.OwnershipKey{Kind: reconcile.KindAddress, Scope: "default-tun-base", ID: fmt.Sprint(id)}
	configKey := reconcile.OwnershipKey{Kind: reconcile.KindAddress, Scope: "default-tun", ID: fmt.Sprint(id)}
	dnsKey := reconcile.OwnershipKey{Kind: reconcile.KindDNS, Scope: "default-tun", ID: fmt.Sprint(id)}
	routeKey := reconcile.OwnershipKey{Kind: reconcile.KindRoute, Scope: "default-tun", ID: fmt.Sprint(id)}
	splitKey := reconcile.OwnershipKey{Kind: reconcile.KindSplit, Scope: "default-tun", ID: fmt.Sprint(id)}
	preRoute := defaultTunPreRouteConfig(s.config, desired)
	final := defaultTunFinalConfig(preRoute, desired.family)
	base := netio.Config{Properties: append([]netio.Properties(nil), preRoute.Properties...)}
	entries := []reconcile.Entry{
		{
			Key: adapterKey,
			Apply: func(ctx context.Context) error {
				if _, validation := normalizeDefaultTunOpts(s.policyConfig(), opts); validation.Err() != nil {
					return validation.Err()
				}
				native, err := s.dependencies.tunFactory.Create(ctx, internaltun.Config{
					Name: desired.tun.name, NamePrefix: s.config.adapterNamePrefix,
					GUID: s.config.stableGUID, MTU: desired.tun.mtu,
				})
				if err != nil {
					return err
				}
				base := &regularTun{owner: s, id: id, native: native, metadata: native.Metadata(), desired: cloneNetIOConfig(final), mtu: desired.tun.mtu, instanceRevision: 1}
				result = &defaultTun{regularTun: base, reservationID: reservationID}
				s.registerOwnedUnderlay(base)
				return nil
			},
			Inverse: func(ctx context.Context) error {
				if result == nil || result.closed.Load() {
					return nil
				}
				observed, err := s.dependencies.netIO.Read(ctx, result.interfaceID())
				if err != nil {
					return fmt.Errorf("verify NetIO cleanup before default adapter close: %w", err)
				}
				if !netIOConfigEmpty(observed) {
					return errors.New("cannot close default TUN while owned NetIO state remains")
				}
				err = result.closeNative()
				if err == nil {
					s.unregisterOwnedUnderlay(result.regularTun)
					s.allocator.ReleaseOwnedIPs(reservationID)
				}
				return err
			},
			Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
				if expected == reconcile.ExpectedUndone {
					if result == nil || result.closed.Load() {
						return nil
					}
					return errors.New("default TUN is still open")
				}
				if result == nil || result.closed.Load() {
					return errors.New("default TUN was not created")
				}
				return nil
			},
		},
		{
			Key: baseKey,
			Apply: func(ctx context.Context) error {
				if result == nil {
					return errors.New("default TUN adapter is unavailable")
				}
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), base)
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
				if expected == reconcile.ExpectedUndone {
					return s.dependencies.netIO.Verify(ctx, result.interfaceID(), netio.Config{})
				}
				return s.dependencies.netIO.Verify(ctx, result.interfaceID(), base)
			},
		},
	}

	retired := false
	// Windows cannot create two adapters with one explicit name or GUID. In
	// that case validation and reservation still finish first, but the old
	// identity must retire before the factory can create its replacement.
	sameName := false
	if old != nil && desired.tun.name != "" {
		oldName, err := old.Name()
		if err != nil {
			return nil, fmt.Errorf("read old default TUN name: %w", err)
		}
		sameName = strings.EqualFold(oldName, desired.tun.name)
	}
	retireBeforeCreate := old != nil && (sameName || s.config.stableGUID != "")
	err := s.applyOperation(func(ctx context.Context) error {
		configApplied := false
		dnsApplied := false
		splitApplied := false
		routeApplied := false
		retireOld := func() error {
			retireErr := s.undoDefaultTun(ctx, old)
			if retireErr != nil {
				want, _, _, _, _ := old.snapshot()
				if old.closed.Load() || s.dependencies.netIO.Verify(ctx, old.interfaceID(), want) != nil {
					// Cleanup did not restore a usable old policy. The journal keeps
					// any uncertain ownership, but callers must see no active default.
					s.defaultTun = nil
					s.activeSplitTun.CompareAndSwap(old, nil)
					retired = true
				}
				return retireErr
			}
			old.retired.Store(true)
			s.defaultTun = nil
			s.activeSplitTun.CompareAndSwap(old, nil)
			retired = true
			return nil
		}
		if retireBeforeCreate {
			if err := retireOld(); err != nil {
				return err
			}
		}
		if err := s.journal.Apply(ctx, entries); err != nil {
			return err
		}
		cleanupNew := func(primary error) error {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.operationTimeout)
			defer cancel()
			keys := []reconcile.OwnershipKey{baseKey, adapterKey}
			if configApplied {
				keys = append([]reconcile.OwnershipKey{configKey}, keys...)
			}
			if dnsApplied {
				keys = append([]reconcile.OwnershipKey{dnsKey}, keys...)
			}
			if routeApplied {
				keys = append([]reconcile.OwnershipKey{routeKey}, keys...)
			}
			if splitApplied {
				keys = append([]reconcile.OwnershipKey{splitKey}, keys...)
			}
			cleanupErr := s.journal.Undo(cleanupCtx, keys...)
			return errors.Join(primary, cleanupErr)
		}
		if old != nil && !retireBeforeCreate {
			if err := retireOld(); err != nil {
				return cleanupNew(err)
			}
		}
		if err := s.allocator.VerifyOwnedIPsAvailable(reservationID); err != nil {
			return cleanupNew(fmt.Errorf("recheck default TUN addresses: %w", err))
		}
		configEntry := reconcile.Entry{
			Key: configKey,
			Apply: func(ctx context.Context) error {
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), preRoute)
			},
			Inverse: func(ctx context.Context) error {
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), base)
			},
			Verify: func(ctx context.Context, expected reconcile.ExpectedState) error {
				want := preRoute
				if expected == reconcile.ExpectedUndone {
					want = base
				}
				return s.dependencies.netIO.Verify(ctx, result.interfaceID(), want)
			},
		}
		if err := s.journal.Apply(ctx, []reconcile.Entry{configEntry}); err != nil {
			configApplied = s.journal.Has(configKey)
			return cleanupNew(err)
		}
		configApplied = true
		// Bind both transports and apply the resolver before publishing default
		// routes. The inverse restores only state that still exactly matches this
		// System's write, so an external change is never overwritten.
		dnsEntry := reconcile.Entry{
			Key: dnsKey,
			Apply: func(ctx context.Context) error {
				proxy, proxyErr := s.dependencies.dnsProxyFactory.Create(desired.dnsIP, s.config.operationTimeout)
				if proxyErr != nil {
					return proxyErr
				}
				result.dnsProxy = proxy
				prior, readErr := s.dependencies.dnsConfigurator.Read(ctx, result.metadata.LUID)
				if readErr != nil {
					return fmt.Errorf("read previous DNS state: %w", readErr)
				}
				result.dnsPrior = internaldns.CloneState(prior)
				result.dnsApplied = internaldns.WithProxy(result.dnsPrior, desired.dnsIP)
				if applyErr := s.dependencies.dnsConfigurator.Apply(ctx, result.metadata.LUID, result.dnsApplied); applyErr != nil {
					return fmt.Errorf("apply managed DNS state: %w", applyErr)
				}
				current, readErr := s.dependencies.dnsConfigurator.Read(ctx, result.metadata.LUID)
				if readErr != nil {
					return fmt.Errorf("read back managed DNS state: %w", readErr)
				}
				if !internaldns.EqualState(current, result.dnsApplied) {
					return fmt.Errorf("managed DNS readback = %+v, want %+v", current, result.dnsApplied)
				}
				if s.upstreamDNS != nil {
					s.upstreamDNS.SetExcluded(desired.dnsIP)
				}
				return nil
			},
			Inverse: func(ctx context.Context) error {
				if result == nil || result.dnsProxy == nil {
					return nil
				}
				current, readErr := s.dependencies.dnsConfigurator.Read(ctx, result.metadata.LUID)
				var restoreErr error
				if readErr != nil {
					restoreErr = fmt.Errorf("read DNS state before restore: %w", readErr)
				} else if internaldns.EqualState(current, result.dnsApplied) {
					restoreErr = s.dependencies.dnsConfigurator.Apply(ctx, result.metadata.LUID, result.dnsPrior)
				}
				if s.upstreamDNS != nil {
					s.upstreamDNS.SetExcluded()
				}
				return errors.Join(restoreErr, result.dnsProxy.Close())
			},
			Verify: func(ctx context.Context, expected reconcile.ExpectedState) error {
				if result == nil || result.dnsProxy == nil {
					if expected == reconcile.ExpectedUndone {
						return nil
					}
					return errors.New("default TUN DNS proxy was not created")
				}
				if result.dnsProxy.Closed() == (expected == reconcile.ExpectedApplied) {
					return errors.New("default TUN DNS proxy state does not match journal state")
				}
				if expected == reconcile.ExpectedApplied {
					current, err := s.dependencies.dnsConfigurator.Read(ctx, result.metadata.LUID)
					if err != nil {
						return err
					}
					if !internaldns.EqualState(current, result.dnsApplied) {
						return errors.New("managed DNS state changed before publication")
					}
				}
				return nil
			},
		}
		if err := s.journal.Apply(ctx, []reconcile.Entry{dnsEntry}); err != nil {
			dnsApplied = s.journal.Has(dnsKey)
			return cleanupNew(err)
		}
		dnsApplied = true
		if err := requireUnderlays(s.underlayMonitor.Snapshot(), desired.family); err != nil {
			return cleanupNew(err)
		}
		if len(desired.excludes) != 0 {
			splitEntry := reconcile.Entry{
				Key: splitKey,
				Apply: func(ctx context.Context) error {
					addresses, addressErr := splitAddresses(desired.tun.addresses, s.underlayMonitor.Snapshot())
					if addressErr != nil {
						return addressErr
					}
					paths := make([]string, len(desired.excludes))
					for index, rule := range desired.excludes {
						paths[index] = rule.value
					}
					session, acquireErr := split.Acquire(ctx, s.dependencies.splitDependencies)
					if acquireErr != nil {
						if session != nil {
							// Acquire returns a session with an error only when committed
							// WFP ownership still needs verified cleanup. Publish that owner
							// before the journal starts its rollback.
							result.splitPolicy = split.NewPolicy(session, s.dependencies.splitDependencies)
						}
						s.recordSplitCapability(acquireErr)
						return acquireErr
					}
					policy := split.NewPolicy(session, s.dependencies.splitDependencies)
					// Publish cleanup ownership before Bootstrap sends the first
					// initialization IOCTL. The journal can then retry cleanup if
					// both bootstrap and its first rollback attempt fail.
					result.splitPolicy = policy
					bootstrapErr := policy.Bootstrap(ctx, s.dependencies.splitDependencies, split.BootstrapConfig{
						Generation: id,
						Addresses:  addresses,
						Paths:      paths,
						OnEvent: func(split.Event) {
							s.enqueueReconcileReason(reconcile.Reason("split-process-change"))
						},
						OnError: func(eventErr error) {
							if s.dependencies.logger != nil {
								s.dependencies.logger.Printf("split event reader stopped: %v", eventErr)
							}
							var splitEventErr *split.EventError
							if errors.As(eventErr, &splitEventErr) {
								s.enqueueReconcileReason(reconcile.Reason("split-driver-error"))
							}
						},
					})
					if bootstrapErr != nil {
						return bootstrapErr
					}
					result.splitPrefixes = append([]netip.Prefix(nil), desired.tun.addresses...)
					s.recordSplitCapability(nil)
					return nil
				},
				Inverse: func(context.Context) error {
					if result == nil || result.splitPolicy == nil {
						return nil
					}
					return result.splitPolicy.Close()
				},
				Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
					if expected == reconcile.ExpectedApplied {
						if result == nil || result.splitPolicy == nil || result.splitPolicy.AppliedGeneration() != id {
							return errors.New("split policy generation was not applied")
						}
						return nil
					}
					if result == nil || result.splitPolicy == nil || result.splitPolicy.Cleaned() {
						return nil
					}
					return split.ErrRecoveryRequired
				},
			}
			if err := s.journal.Apply(ctx, []reconcile.Entry{splitEntry}); err != nil {
				splitApplied = s.journal.Has(splitKey)
				return cleanupNew(err)
			}
			splitApplied = true
		}
		routeEntry := reconcile.Entry{
			Key: routeKey,
			Apply: func(ctx context.Context) error {
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), final)
			},
			Inverse: func(ctx context.Context) error {
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), preRoute)
			},
			Verify: func(ctx context.Context, expected reconcile.ExpectedState) error {
				want := final
				if expected == reconcile.ExpectedUndone {
					want = preRoute
				}
				return s.dependencies.netIO.Verify(ctx, result.interfaceID(), want)
			},
		}
		if err := s.journal.Apply(ctx, []reconcile.Entry{routeEntry}); err != nil {
			routeApplied = s.journal.Has(routeKey)
			return cleanupNew(err)
		}
		routeApplied = true
		s.defaultTun = result
		if result.splitPolicy != nil {
			s.activeSplitTun.Store(result)
		}
		return nil
	})
	if err != nil {
		if retired {
			s.defaultTun = nil
			s.activeSplitTun.Store(nil)
		}
		return nil, err
	}
	keepReservation = true
	return result, nil
}

func (s *System) undoDefaultTun(ctx context.Context, device *defaultTun) error {
	id := fmt.Sprint(device.id)
	keys := []reconcile.OwnershipKey{
		{Kind: reconcile.KindRoute, Scope: "default-tun", ID: id},
		{Kind: reconcile.KindDNS, Scope: "default-tun", ID: id},
		{Kind: reconcile.KindAddress, Scope: "default-tun", ID: id},
		{Kind: reconcile.KindAddress, Scope: "default-tun-base", ID: id},
		{Kind: reconcile.KindAdapter, Scope: "default-tun", ID: id},
	}
	if device.splitPolicy != nil {
		keys = slices.Insert(keys, 1, reconcile.OwnershipKey{Kind: reconcile.KindSplit, Scope: "default-tun", ID: id})
	}
	err := s.journal.Undo(ctx, keys...)
	if err == nil {
		device.retired.Store(true)
	}
	return err
}

func splitAddresses(prefixes []netip.Prefix, snapshot underlay.Snapshot) (split.Addresses, error) {
	var result split.Addresses
	for _, prefix := range prefixes {
		address := prefix.Addr()
		if address.Is4() && !result.TunnelIPv4.IsValid() {
			result.TunnelIPv4 = address
		}
		if address.Is6() && !address.Is4In6() && !result.TunnelIPv6.IsValid() {
			result.TunnelIPv6 = address
		}
	}
	if result.TunnelIPv4.IsValid() && snapshot.IPv4 != nil {
		result.InternetIPv4 = snapshot.IPv4.Source
	}
	if result.TunnelIPv6.IsValid() && snapshot.IPv6 != nil {
		result.InternetIPv6 = snapshot.IPv6.Source
	}
	if result.TunnelIPv4.IsValid() != result.InternetIPv4.IsValid() || result.TunnelIPv6.IsValid() != result.InternetIPv6.IsValid() {
		return split.Addresses{}, errors.New("split policy requires a current local underlay address for each tunnel family")
	}
	return result, nil
}

func (s *System) setDefaultTunDNS(device *defaultTun, provider dns.Interface) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	if device.retired.Load() || device.closed.Load() || s.defaultTun != device || device.dnsProxy == nil || device.dnsProxy.Closed() {
		return sysnet.ErrUnknownTun
	}
	device.dnsProxy.Attach(provider)
	return nil
}

func (s *System) closeDefaultTun(device *defaultTun) error {
	s.defaultTunMu.Lock()
	defer s.defaultTunMu.Unlock()
	if device.retired.Load() || device.closed.Load() {
		return nil
	}
	if s.defaultTun != device {
		return sysnet.ErrUnknownTun
	}
	err := s.applyOperation(func(ctx context.Context) error { return s.undoDefaultTun(ctx, device) })
	// Cleanup can return a native error even when independent readback proves
	// that every default-TUN resource except a retained split recovery journal
	// is gone. Do not keep a closed adapter published as the active default.
	if err == nil || device.closed.Load() {
		device.retired.Store(true)
		s.defaultTun = nil
		s.activeSplitTun.CompareAndSwap(device, nil)
	}
	return err
}

func defaultTunPreRouteConfig(config normalizedSystemConfig, desired desiredDefaultTun) netio.Config {
	result := regularTunNetIOConfig(config, desired.tun.addresses, desired.tun.routes, desired.tun.mtu)
	// A caller-supplied default route is still the policy activation point. Do
	// not apply it with the extra routes before addresses and metrics are ready.
	result.Routes = slices.DeleteFunc(result.Routes, func(route netio.Route) bool {
		return route.Destination.Bits() == 0
	})
	for index := range result.Properties {
		result.Properties[index].Metric = defaultTunRouteMetric
	}
	return result
}

func defaultTunFinalConfig(preRoute netio.Config, family sysnet.AddressFamily) netio.Config {
	result := cloneNetIOConfig(preRoute)
	if family == sysnet.FamilyIPv4 || family == sysnet.FamilyDual {
		result.Routes = appendUniqueRoutes(result.Routes, netio.Route{Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHop: netip.IPv4Unspecified(), Metric: defaultTunRouteMetric})
	}
	if family == sysnet.FamilyIPv6 || family == sysnet.FamilyDual {
		result.Routes = appendUniqueRoutes(result.Routes, netio.Route{Destination: netip.MustParsePrefix("::/0"), NextHop: netip.IPv6Unspecified(), Metric: defaultTunRouteMetric})
	}
	return result
}

func requireUnderlays(snapshot underlay.Snapshot, family sysnet.AddressFamily) error {
	if (family == sysnet.FamilyIPv4 || family == sysnet.FamilyDual) && snapshot.IPv4 == nil {
		return stateValidationError(sysnet.ReasonNoUnderlay, "no usable IPv4 underlay is selected")
	}
	if (family == sysnet.FamilyIPv6 || family == sysnet.FamilyDual) && snapshot.IPv6 == nil {
		return stateValidationError(sysnet.ReasonNoUnderlay, "no usable IPv6 underlay is selected")
	}
	return nil
}

var _ sysnet.DefaultTun = (*defaultTun)(nil)
var _ gtun.Tun = (*defaultTun)(nil)
