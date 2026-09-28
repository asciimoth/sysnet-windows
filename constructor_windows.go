//go:build windows

package windows

import "github.com/asciimoth/sysnet-windows/internal/netio"

// New creates a Windows System. Construction does not install a driver, start
// a worker, or change host networking. Native resources are acquired lazily by
// later operations.
func New(config SystemConfig) (*System, error) {
	return newSystem(config, nativeDependencies())
}

func nativeDependencies() systemDependencies {
	return systemDependencies{allocationReader: netio.NativeReader{}}
}
