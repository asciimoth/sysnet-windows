package windows

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/asciimoth/gonnect/dns"
	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
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

// buildOutboundNetwork connects the selected-underlay monitor to the mandatory
// socket binder. The temporary resolver provider uses the host's current DNS
// server list, but its UDP and TCP transports use the bound network. Step 19
// replaces server discovery with ownership-aware original-DNS snapshots before
// managed DNS takeover is enabled.
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
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return bound.Dial(ctx, network, address)
		},
	}
	provider := dns.NewResolverProvider(resolver, time.Minute, nil)
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
