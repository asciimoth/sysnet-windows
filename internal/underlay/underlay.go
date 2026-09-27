// Package underlay defines host route and interface observation boundaries.
package underlay

import (
	"context"
	"net/netip"
)

// Path is one selected outbound path for an address family.
type Path struct {
	InterfaceIndex uint32
	Source         netip.Addr
}

// Snapshot contains coherent IPv4 and IPv6 underlay selections.
type Snapshot struct {
	IPv4 *Path
	IPv6 *Path
}

// Source reads and monitors non-owned host paths.
type Source interface {
	Snapshot(context.Context) (Snapshot, error)
	Changes() <-chan struct{}
}
