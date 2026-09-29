package windows

import (
	"context"

	"github.com/asciimoth/gonnect/sysnet"
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

func (d systemDependencies) constrainCapabilityFacts(facts capabilityProbeFacts) capabilityProbeFacts {
	// capabilityCode is a test-only override used to exercise an abstract
	// implementation matrix without production OS dependencies. The normal
	// constructor path uses the zero value and must include every concrete
	// dependency in its capability facts.
	if d.capabilityCode != (implementationSupport{}) {
		return facts
	}
	if d.allocationReader == nil {
		facts.allocation = missingDependencyCapability("host network state reader is not configured")
	} else {
		facts.allocation = facts.netIO.Clone()
	}
	if d.netIO == nil {
		facts.netIO = missingDependencyCapability("NetIO manager is not configured")
	}
	if d.tunFactory == nil {
		facts.tunFactory = missingDependencyCapability("TUN factory is not configured")
	} else if !capabilityFactSet(facts.tunFactory) {
		facts.tunFactory = sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	if d.underlay == nil {
		facts.underlay = missingDependencyCapability("underlay source is not configured")
	} else if !capabilityFactSet(facts.underlay) {
		facts.underlay = sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	return facts
}

func missingDependencyCapability(detail string) sysnet.Capability {
	return sysnet.Capability{
		State:   sysnet.CapabilityUnavailable,
		Reasons: []sysnet.CapabilityReason{sysnet.ReasonMissingDependency},
		Detail:  detail,
	}
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
