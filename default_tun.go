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
	if s.dependencies.tunFactory == nil || s.dependencies.netIO == nil || s.dependencies.dnsProxyFactory == nil || s.underlayMonitor == nil {
		return nil, stateValidationError(sysnet.ReasonMissingDependency, "default TUN dependencies are not configured")
	}
	if len(desired.excludes) != 0 {
		return nil, sysnet.ErrNotSupported
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
	configKey := reconcile.OwnershipKey{Kind: reconcile.KindAddress, Scope: "default-tun", ID: fmt.Sprint(id)}
	dnsKey := reconcile.OwnershipKey{Kind: reconcile.KindDNS, Scope: "default-tun", ID: fmt.Sprint(id)}
	preRoute := defaultTunPreRouteConfig(s.config, desired)
	final := defaultTunFinalConfig(preRoute, desired.family)
	applied := netio.Config{Properties: append([]netio.Properties(nil), preRoute.Properties...)}
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
			Key: configKey,
			Apply: func(ctx context.Context) error {
				if result == nil {
					return errors.New("default TUN adapter is unavailable")
				}
				return s.dependencies.netIO.Apply(ctx, result.interfaceID(), applied)
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
				return s.dependencies.netIO.Verify(ctx, result.interfaceID(), applied)
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
		dnsApplied := false
		retireOld := func() error {
			retireErr := s.undoDefaultTun(ctx, old)
			if retireErr != nil {
				want, _, _, _, _ := old.snapshot()
				if old.closed.Load() || s.dependencies.netIO.Verify(ctx, old.interfaceID(), want) != nil {
					// Cleanup did not restore a usable old policy. The journal keeps
					// any uncertain ownership, but callers must see no active default.
					s.defaultTun = nil
					retired = true
				}
				return retireErr
			}
			old.retired.Store(true)
			s.defaultTun = nil
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
			keys := []reconcile.OwnershipKey{configKey, adapterKey}
			if dnsApplied {
				keys = append([]reconcile.OwnershipKey{dnsKey}, keys...)
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
		applied = cloneNetIOConfig(preRoute)
		if err := s.dependencies.netIO.Apply(ctx, result.interfaceID(), applied); err != nil {
			return cleanupNew(err)
		}
		if err := s.dependencies.netIO.Verify(ctx, result.interfaceID(), applied); err != nil {
			return cleanupNew(err)
		}
		// Bind both transports after the address is usable and before publishing
		// default routes. Step 18 inserts OS DNS configuration after this entry.
		dnsEntry := reconcile.Entry{
			Key: dnsKey,
			Apply: func(context.Context) error {
				proxy, proxyErr := s.dependencies.dnsProxyFactory.Create(desired.dnsIP, s.config.operationTimeout)
				if proxyErr == nil {
					result.dnsProxy = proxy
				}
				return proxyErr
			},
			Inverse: func(context.Context) error {
				if result == nil || result.dnsProxy == nil {
					return nil
				}
				return result.dnsProxy.Close()
			},
			Verify: func(_ context.Context, expected reconcile.ExpectedState) error {
				if result == nil || result.dnsProxy == nil {
					if expected == reconcile.ExpectedUndone {
						return nil
					}
					return errors.New("default TUN DNS proxy was not created")
				}
				if result.dnsProxy.Closed() == (expected == reconcile.ExpectedApplied) {
					return errors.New("default TUN DNS proxy state does not match journal state")
				}
				return nil
			},
		}
		if err := s.journal.Apply(ctx, []reconcile.Entry{dnsEntry}); err != nil {
			return cleanupNew(err)
		}
		dnsApplied = true
		if err := requireUnderlays(s.underlayMonitor.Snapshot(), desired.family); err != nil {
			return cleanupNew(err)
		}
		applied = cloneNetIOConfig(final)
		if err := s.dependencies.netIO.Apply(ctx, result.interfaceID(), applied); err != nil {
			return cleanupNew(err)
		}
		if err := s.dependencies.netIO.Verify(ctx, result.interfaceID(), applied); err != nil {
			return cleanupNew(err)
		}
		s.defaultTun = result
		return nil
	})
	if err != nil {
		if retired {
			s.defaultTun = nil
		}
		return nil, err
	}
	keepReservation = true
	return result, nil
}

func (s *System) undoDefaultTun(ctx context.Context, device *defaultTun) error {
	id := fmt.Sprint(device.id)
	err := s.journal.Undo(ctx,
		reconcile.OwnershipKey{Kind: reconcile.KindDNS, Scope: "default-tun", ID: id},
		reconcile.OwnershipKey{Kind: reconcile.KindAddress, Scope: "default-tun", ID: id},
		reconcile.OwnershipKey{Kind: reconcile.KindAdapter, Scope: "default-tun", ID: id},
	)
	if err == nil {
		device.retired.Store(true)
	}
	return err
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
	if err == nil {
		s.defaultTun = nil
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
