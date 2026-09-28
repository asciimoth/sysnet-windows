//go:build windows

package windows

import (
	"github.com/asciimoth/sysnet-windows/internal/netio"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
)

// New creates a Windows System. Construction does not install a driver, start
// a worker, or change host networking. Native resources are acquired lazily by
// later operations.
func New(config SystemConfig) (*System, error) {
	return newSystem(config, nativeDependencies())
}

func nativeDependencies() systemDependencies {
	netIO, err := netio.NewManager(netio.NativeStore{})
	if err != nil {
		// NativeStore is a non-nil value. Keep the invariant explicit if the
		// manager constructor gains more validation later.
		panic(err)
	}
	return systemDependencies{
		tunFactory:       internaltun.NativeFactory{},
		netIO:            netIO,
		allocationReader: netio.NativeReader{},
	}
}
