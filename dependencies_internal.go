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
	if d.dnsProxyFactory == nil {
		facts.dnsProxy = missingDependencyCapability("DNS proxy factory is not configured")
	} else if !capabilityFactSet(facts.dnsProxy) {
		facts.dnsProxy = sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	if d.dnsConfigurator == nil {
		facts.dnsConfig = missingDependencyCapability("Windows DNS configurator is not configured")
	} else if !capabilityFactSet(facts.dnsConfig) {
		facts.dnsConfig = sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	if d.ownerLookup == nil {
		facts.ownerLookup = missingDependencyCapability("owner lookup is not configured")
	} else {
		// A configured Lookup is the complete matcher dependency. Unlike native
		// mutation boundaries, it needs no eager host probe: individual socket
		// and process access failures remain per-match errors.
		facts.ownerLookup = sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	if d.splitDependencies.Verifier == nil || d.splitDependencies.Opener == nil ||
		d.splitDependencies.WFP == nil || d.splitDependencies.Snapshot == nil || d.splitDependencies.Resolver == nil {
		facts.split = missingDependencyCapability("split-driver bootstrap dependencies are not configured")
	} else if !capabilityFactSet(facts.split) {
		facts.split = sysnet.Capability{
			State:   sysnet.CapabilityUnknown,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
			Detail:  "split-driver ownership is resolved only when exclusions are requested",
		}
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
	tunFactory        internaltun.Factory
	netIO             netio.Manager
	allocationReader  netio.Reader
	underlay          underlay.Source
	dnsConfigurator   internaldns.Configurator
	dnsProxyFactory   internaldns.ProxyFactory
	splitDependencies split.Dependencies
	ownerLookup       owner.Lookup
	clock             internalclock.Clock
	logger            Logger
	capabilityProbe   capabilityProber
	capabilityCode    implementationSupport
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
	_ = d.dnsProxyFactory
	_ = d.splitDependencies
	_ = d.ownerLookup
	_ = d.clock
	_ = d.logger
	_ = d.capabilityProbe
}
