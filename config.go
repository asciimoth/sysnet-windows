package windows

import (
	"errors"
	"strings"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
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
	// AdapterNamePrefix prefixes automatically generated Wintun names. The
	// default is "gonnect".
	AdapterNamePrefix string
	// StableGUID optionally requests one stable Windows adapter GUID. Both the
	// braced and unbraced 8-4-4-4-12 forms are accepted.
	StableGUID string
	// UnderlaySelector prefers an outbound interface whose name or GUID matches
	// this value, without excluding other usable interfaces as fallback paths.
	UnderlaySelector string
	Features         FeatureConfig
	OperationTimeout time.Duration
	Recovery         RecoveryPolicy
	Logger           Logger
}

// Logger receives diagnostic messages. Implementations must be safe for
// concurrent use.
type Logger interface {
	Printf(format string, args ...any)
}

type normalizedSystemConfig struct {
	adapterNamePrefix string
	stableGUID        string
	underlaySelector  string
	ipv4              bool
	ipv6              bool
	exclusions        bool
	matchers          bool
	operationTimeout  time.Duration
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
	prefix := strings.TrimSpace(config.AdapterNamePrefix)
	if prefix == "" {
		prefix = internaltun.DefaultNamePrefix
	}
	// Leave space for the generated hyphen and 12-character GUID suffix.
	if err := internaltun.ValidateName(prefix + "-000000000000"); err != nil {
		return normalizedSystemConfig{}, validationError(validationIssue(
			"SystemConfig.AdapterNamePrefix",
			0,
			"",
			"adapter name prefix is not valid",
			errors.Join(sysnet.ErrInvalidOptions, err),
		))
	}
	stableGUID, err := internaltun.NormalizeGUID(config.StableGUID)
	if err != nil {
		return normalizedSystemConfig{}, validationError(validationIssue(
			"SystemConfig.StableGUID",
			0,
			"",
			"stable adapter GUID is not valid",
			errors.Join(sysnet.ErrInvalidOptions, err),
		))
	}
	timeout := config.OperationTimeout
	if timeout == 0 {
		timeout = defaultOperationTimeout
	}
	return normalizedSystemConfig{
		adapterNamePrefix: prefix,
		stableGUID:        stableGUID,
		underlaySelector:  strings.TrimSpace(config.UnderlaySelector),
		ipv4:              !config.Features.DisableIPv4,
		ipv6:              !config.Features.DisableIPv6,
		exclusions:        !config.Features.DisableExclusions,
		matchers:          !config.Features.DisableMatchers,
		operationTimeout:  timeout,
	}, nil
}

func defaultNormalizedSystemConfig() normalizedSystemConfig {
	config, _ := normalizeSystemConfig(SystemConfig{})
	return config
}
