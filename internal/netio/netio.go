// Package netio defines exact Windows address, route, and interface mutation
// boundaries.
package netio

import (
	"context"
	"net/netip"
)

// HostState is one complete view of host address use. Addresses contains usable
// unicast addresses. InterfacePrefixes contains the on-link prefixes assigned
// to interfaces. Routes contains route destinations. A Reader must not return
// a partial HostState as a successful read.
type HostState struct {
	Addresses         []netip.Addr
	InterfacePrefixes []netip.Prefix
	Routes            []netip.Prefix
}

// Reader enumerates the host state used to reject conflicting allocations.
// Implementations must return an error if any address, prefix, or route table
// that forms the snapshot cannot be read completely.
type Reader interface {
	ReadHostState(context.Context) (HostState, error)
}

// Interface identifies one current Windows network interface instance.
type Interface struct {
	LUID  uint64
	Index uint32
}

// Config is the complete owned interface state for one apply operation.
type Config struct {
	MTU       int
	Addresses []netip.Prefix
	Routes    []netip.Prefix
}

// Manager applies and reads only resources owned by this package.
type Manager interface {
	Apply(context.Context, Interface, Config) error
	Read(context.Context, Interface) (Config, error)
}
