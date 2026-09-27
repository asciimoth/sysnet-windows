package windows

import (
	internalclock "github.com/asciimoth/sysnet-windows/internal/clock"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	"github.com/asciimoth/sysnet-windows/internal/owner"
	"github.com/asciimoth/sysnet-windows/internal/split"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
	"github.com/asciimoth/sysnet-windows/internal/wfp"
)

// systemDependencies contains OS boundaries. Keep this private so New remains
// the stable integration path while package tests can inject deterministic
// fakes through newSystem.
type systemDependencies struct {
	tunFactory      internaltun.Factory
	netIO           netio.Manager
	underlay        underlay.Source
	dnsConfigurator internaldns.Configurator
	splitController split.Controller
	wfpManager      wfp.Manager
	ownerLookup     owner.Lookup
	clock           internalclock.Clock
	logger          Logger
}

func (d *systemDependencies) setLogger(logger Logger) {
	if d.logger == nil {
		d.logger = logger
	}
}

func (d systemDependencies) inspect() {
	_ = d.tunFactory
	_ = d.netIO
	_ = d.underlay
	_ = d.dnsConfigurator
	_ = d.splitController
	_ = d.wfpManager
	_ = d.ownerLookup
	_ = d.clock
	_ = d.logger
}
