package windows

func newSystem(config SystemConfig, dependencies systemDependencies) (*System, error) {
	normalized, err := normalizeSystemConfig(config)
	if err != nil {
		return nil, err
	}
	dependencies.setLogger(config.Logger)
	// Resolve all boundary fields during construction. This is deliberately
	// read-only and keeps missing optional integrations independent.
	dependencies.inspect()
	return &System{
		state:        lifecycleReady,
		config:       normalized,
		dependencies: dependencies,
		capabilities: capabilityModel{},
	}, nil
}
