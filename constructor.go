package windows

import (
	"context"
	"errors"
	"strings"

	"github.com/asciimoth/gonnect"
	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	internalnetwork "github.com/asciimoth/sysnet-windows/internal/network"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

func newSystem(config SystemConfig, dependencies systemDependencies) (*System, error) {
	normalized, err := normalizeSystemConfig(config)
	if err != nil {
		return nil, err
	}
	dependencies.setLogger(config.Logger)
	// Resolve all boundary fields during construction. This is deliberately
	// read-only and keeps missing optional integrations independent.
	dependencies.inspect()
	system := &System{
		state:         lifecycleNew,
		config:        normalized,
		dependencies:  dependencies,
		probeFacts:    initialProbeFacts(),
		support:       dependencies.capabilityCode,
		journal:       reconcile.NewJournal(normalized.operationTimeout),
		allocator:     internalallocator.New(dependencies.allocationReader, normalized.operationTimeout),
		regularTuns:   make(map[*regularTun]struct{}),
		underlayOwned: make(map[*regularTun]underlay.Interface),
	}
	system.publicAllocator = &systemAllocator{system: system, delegate: system.allocator}
	if system.support == (implementationSupport{}) {
		system.support = currentImplementationSupport()
	}
	if dependencies.capabilityProbe != nil {
		ctx, cancel := context.WithTimeout(context.Background(), normalized.operationTimeout)
		system.probeFacts = runCapabilityProbe(ctx, dependencies.capabilityProbe)
		cancel()
	}
	system.probeFacts = dependencies.constrainCapabilityFacts(system.probeFacts)
	if err := system.transitionLocked(lifecycleReady); err != nil {
		return nil, err
	}
	if err := system.buildLocalNetwork(); err != nil {
		return nil, err
	}
	if dependencies.underlay != nil {
		monitor, monitorErr := underlay.NewMonitor(
			dependencies.underlay,
			normalized.underlaySelector,
			system.ownsUnderlayInterface,
			normalized.operationTimeout,
		)
		if monitorErr != nil {
			return nil, monitorErr
		}
		system.underlayMonitor = monitor
		if err := system.buildOutboundNetwork(); err != nil {
			_ = monitor.Close()
			return nil, err
		}
	}
	system.rebuildCapabilitiesLocked()
	return system, nil
}

// buildLocalNetwork is intentionally independent from the underlay and DNS
// proxy paths. In particular, a later DNS listener on a non-loopback TUN
// address must not gain LocalNet's public socket semantics.
func (s *System) buildLocalNetwork() error {
	native := gonnect.NativeConfig{}.Build()
	local, err := internalnetwork.NewLocal(native, native, internalnetwork.Families{
		IPv4: s.config.ipv4,
		IPv6: s.config.ipv6,
	}, s.acceptingWork, s.trackResource)
	if err != nil {
		return err
	}
	s.localNet = local
	return nil
}

// buildOutboundNetwork connects the selected-underlay monitor to the mandatory
// socket binder. OutDNS reads numeric servers from the selected underlay and
// uses bound sockets. It does not call the host resolver because that resolver
// can point back to the managed proxy after a default TUN becomes active.
func (s *System) buildOutboundNetwork() error {
	binder, err := internalnetwork.NewBinder(s.underlayMonitor)
	if err != nil {
		return err
	}
	bound, err := internalnetwork.NewBoundNetwork(binder, s.underlayMonitor, internalnetwork.Families{
		IPv4: s.config.ipv4,
		IPv6: s.config.ipv6,
	})
	if err != nil {
		return err
	}
	provider, err := internaldns.NewUpstreamProvider(
		s.underlayMonitor, s.dependencies.dnsConfigurator,
		bound.Dial, s.config.operationTimeout,
	)
	if err != nil {
		return err
	}
	releaseProvider, err := s.trackResource(provider)
	if err != nil {
		return errors.Join(err, provider.Close())
	}
	outbound, err := internalnetwork.NewOutbound(bound, provider, s.acceptingWork, s.trackResource)
	if err != nil {
		closeErr := provider.Close()
		if closeErr == nil {
			releaseProvider()
		}
		return errors.Join(err, closeErr)
	}
	s.outDNS = provider
	s.upstreamDNS = provider
	s.outNet = outbound
	return nil
}

func (s *System) ownsUnderlayInterface(iface underlay.Interface) bool {
	s.underlayOwnedMu.RLock()
	defer s.underlayOwnedMu.RUnlock()
	for _, owned := range s.underlayOwned {
		if owned.LUID == iface.LUID && owned.Index == iface.Index {
			return true
		}
		if owned.GUID != "" && iface.GUID != "" && strings.EqualFold(owned.GUID, iface.GUID) {
			return true
		}
	}
	return false
}

func (s *System) registerOwnedUnderlay(device *regularTun) {
	metadata := device.metadata
	s.underlayOwnedMu.Lock()
	s.underlayOwned[device] = underlay.Interface{
		LUID: metadata.LUID, Index: metadata.Index, GUID: metadata.GUID,
	}
	s.underlayOwnedMu.Unlock()
	if s.underlayMonitor != nil {
		s.underlayMonitor.NotifyOwnedChange()
	}
}

func (s *System) unregisterOwnedUnderlay(device *regularTun) {
	s.underlayOwnedMu.Lock()
	delete(s.underlayOwned, device)
	s.underlayOwnedMu.Unlock()
	if s.underlayMonitor != nil {
		s.underlayMonitor.NotifyOwnedChange()
	}
}

func runCapabilityProbe(ctx context.Context, probe capabilityProber) capabilityProbeFacts {
	result := make(chan capabilityProbeFacts, 1)
	go func() { result <- probe.Probe(ctx) }()
	select {
	case facts := <-result:
		if err := ctx.Err(); err != nil {
			return failedProbeFacts(err)
		}
		return facts
	case <-ctx.Done():
		return failedProbeFacts(ctx.Err())
	}
}
