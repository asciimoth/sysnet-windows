//go:build !windows

package windows

import (
	"fmt"
	"runtime"

	"github.com/asciimoth/gonnect/sysnet"
)

// New reports that native Windows integration is unavailable on this host.
// Portable policy tests use the package-private injectable constructor.
func New(config SystemConfig) (*System, error) {
	if _, err := normalizeSystemConfig(config); err != nil {
		return nil, err
	}
	return nil, &PlatformError{GOOS: runtime.GOOS}
}

// PlatformError reports an attempt to create native integration on a host
// that is not Windows.
type PlatformError struct {
	GOOS string
}

func (e *PlatformError) Error() string {
	return fmt.Sprintf("sysnet-windows is not supported on %s", e.GOOS)
}

func (*PlatformError) Unwrap() error { return sysnet.ErrNotSupported }
