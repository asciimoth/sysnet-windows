package windows

import (
	"context"

	internalallocator "github.com/asciimoth/sysnet-windows/internal/allocator"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
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
		state:        lifecycleNew,
		config:       normalized,
		dependencies: dependencies,
		probeFacts:   initialProbeFacts(),
		support:      dependencies.capabilityCode,
		journal:      reconcile.NewJournal(normalized.operationTimeout),
		allocator:    internalallocator.New(dependencies.allocationReader, normalized.operationTimeout),
	}
	if system.support == (implementationSupport{}) {
		system.support = currentImplementationSupport()
	}
	if dependencies.capabilityProbe != nil {
		ctx, cancel := context.WithTimeout(context.Background(), normalized.operationTimeout)
		system.probeFacts = runCapabilityProbe(ctx, dependencies.capabilityProbe)
		cancel()
	}
	if err := system.transitionLocked(lifecycleReady); err != nil {
		return nil, err
	}
	system.rebuildCapabilitiesLocked()
	return system, nil
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
