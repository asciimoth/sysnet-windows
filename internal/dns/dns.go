// Package dns defines the Windows resolver-configuration boundary.
package dns

import (
	"context"
	"net/netip"
)

// State records resolver mode and server values for exact restoration.
type State struct {
	DHCP    bool
	Servers []netip.Addr
}

// Configurator changes resolver state for one interface.
type Configurator interface {
	Read(context.Context, uint64) (State, error)
	Apply(context.Context, uint64, State) error
}
