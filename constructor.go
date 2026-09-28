package windows

import (
	"context"
	"strings"

	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
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
	}
	system.rebuildCapabilitiesLocked()
	return system, nil
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
