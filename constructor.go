package windows

import (
	"context"

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
	}
	if system.support == (implementationSupport{}) {
		system.support = currentImplementationSupport()
	}
	if dependencies.capabilityProbe != nil {
		ctx, cancel := context.WithTimeout(context.Background(), normalized.operationTimeout)
		system.probeFacts = dependencies.capabilityProbe.Probe(ctx)
		if err := ctx.Err(); err != nil {
			system.probeFacts = failedProbeFacts(err)
		}
		cancel()
	}
	if err := system.transitionLocked(lifecycleReady); err != nil {
		return nil, err
	}
	system.rebuildCapabilitiesLocked()
	return system, nil
}
