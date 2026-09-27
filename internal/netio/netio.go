// Package netio defines exact Windows address, route, and interface mutation
// boundaries.
package netio

import (
	"context"
	"net/netip"
)

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
