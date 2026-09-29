//go:build windows

package windows

import (
	"context"
	"errors"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// New creates a Windows System. Construction registers read-only network-change
// monitoring, but does not install a driver or change host networking. Native
// mutation resources are acquired lazily by later operations.
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
	reader := netio.NativeReader{}
	return systemDependencies{
		tunFactory:       internaltun.NativeFactory{},
		netIO:            netIO,
		allocationReader: reader,
		underlay:         underlay.NativeSource{},
		capabilityProbe:  nativeCapabilityProbe{reader: reader},
	}
}

// nativeCapabilityProbe reports only dependencies which can be inspected
// without creating an adapter or acquiring the exclusive split driver.
type nativeCapabilityProbe struct {
	reader netio.Reader
}

func (p nativeCapabilityProbe) Probe(ctx context.Context) capabilityProbeFacts {
	if err := ctx.Err(); err != nil {
		return failedProbeFacts(err)
	}
	netIOCapability := sysnet.Capability{State: sysnet.CapabilityAvailable}
	if _, err := p.reader.ReadHostState(ctx); err != nil {
		reason := sysnet.ReasonProbeFailed
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			reason = sysnet.ReasonPermissionDenied
		}
		netIOCapability = sysnet.Capability{
			State: sysnet.CapabilityUnavailable, Reasons: []sysnet.CapabilityReason{reason},
			Detail: err.Error(),
		}
	}
	tunFactoryCapability := sysnet.Capability{State: sysnet.CapabilityAvailable}
	if version := wintun.Version(); version == "" {
		tunFactoryCapability = missingDependencyCapability("wintun.dll is not available to the process")
	}
	return capabilityProbeFacts{
		allocation: netIOCapability.Clone(),
		tunFactory: tunFactoryCapability,
		netIO:      netIOCapability,
		underlay:   netIOCapability.Clone(),
		split: sysnet.Capability{
			State:   sysnet.CapabilityUnknown,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
			Detail:  "split-driver ownership is resolved only when exclusions are requested",
		},
	}
}
