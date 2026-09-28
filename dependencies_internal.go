package windows

import (
	"context"

	internalclock "github.com/asciimoth/sysnet-windows/internal/clock"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	"github.com/asciimoth/sysnet-windows/internal/owner"
	"github.com/asciimoth/sysnet-windows/internal/split"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
	"github.com/asciimoth/sysnet-windows/internal/wfp"
)

// capabilityProber performs read-only dependency checks. It must not acquire
// an exclusive driver, install a service, or change host networking.
type capabilityProber interface {
	Probe(context.Context) capabilityProbeFacts
}

// systemDependencies contains OS boundaries. Keep this private so New remains
// the stable integration path while package tests can inject deterministic
// fakes through newSystem.
type systemDependencies struct {
	tunFactory       internaltun.Factory
	netIO            netio.Manager
	allocationReader netio.Reader
	underlay         underlay.Source
	dnsConfigurator  internaldns.Configurator
	splitController  split.Controller
	wfpManager       wfp.Manager
	ownerLookup      owner.Lookup
	clock            internalclock.Clock
	logger           Logger
	capabilityProbe  capabilityProber
	capabilityCode   implementationSupport
}

func (d *systemDependencies) setLogger(logger Logger) {
	if d.logger == nil {
		d.logger = logger
	}
}

func (d systemDependencies) inspect() {
	_ = d.tunFactory
	_ = d.netIO
	_ = d.allocationReader
	_ = d.underlay
	_ = d.dnsConfigurator
	_ = d.splitController
	_ = d.wfpManager
	_ = d.ownerLookup
	_ = d.clock
	_ = d.logger
	_ = d.capabilityProbe
}
