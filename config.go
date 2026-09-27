package windows

import (
	"time"

	"github.com/asciimoth/gonnect/sysnet"
)

const defaultOperationTimeout = 30 * time.Second

// FeatureConfig selects optional behavior. The zero value enables both address
// families. A disabled family is rejected during validation.
type FeatureConfig struct {
	DisableIPv4       bool
	DisableIPv6       bool
	DisableExclusions bool
	DisableMatchers   bool
}

// RecoveryPolicy selects how New handles state left by an earlier process.
type RecoveryPolicy uint8

const (
	// RecoveryInspect reports abandoned state but does not change it.
	RecoveryInspect RecoveryPolicy = iota
	// RecoveryOwned permits cleanup only after ownership is proved.
	RecoveryOwned
)

// SystemConfig configures a Windows System. New does not install drivers or
// change host networking while it processes this value.
type SystemConfig struct {
	AdapterNamePrefix string
	StableGUID        string
	UnderlaySelector  string
	Features          FeatureConfig
	OperationTimeout  time.Duration
	Recovery          RecoveryPolicy
	Logger            Logger
}

// Logger receives diagnostic messages. Implementations must be safe for
// concurrent use.
type Logger interface {
	Printf(format string, args ...any)
}

type normalizedSystemConfig struct {
	ipv4             bool
	ipv6             bool
	exclusions       bool
	matchers         bool
	operationTimeout time.Duration
}

func normalizeSystemConfig(config SystemConfig) (normalizedSystemConfig, error) {
	if config.OperationTimeout < 0 {
		return normalizedSystemConfig{}, validationError(validationIssue(
			"SystemConfig.OperationTimeout",
			0,
			"",
			"operation timeout must not be negative",
			sysnet.ErrInvalidOptions,
		))
	}
	if config.Recovery > RecoveryOwned {
		return normalizedSystemConfig{}, validationError(validationIssue(
			"SystemConfig.Recovery",
			0,
			"",
			"recovery policy is not valid",
			sysnet.ErrInvalidOptions,
		))
	}
	timeout := config.OperationTimeout
	if timeout == 0 {
		timeout = defaultOperationTimeout
	}
	return normalizedSystemConfig{
		ipv4:             !config.Features.DisableIPv4,
		ipv6:             !config.Features.DisableIPv6,
		exclusions:       !config.Features.DisableExclusions,
		matchers:         !config.Features.DisableMatchers,
		operationTimeout: timeout,
	}, nil
}

func defaultNormalizedSystemConfig() normalizedSystemConfig {
	config, _ := normalizeSystemConfig(SystemConfig{})
	return config
}
