// Package owner parses socket flows and resolves their best-effort Windows
// process ownership. Packet parsing is portable and does not call native APIs.
package owner

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
)

var (
	// ErrUnknownOwner means that the socket table had no usable owner. This is
	// distinct from a confirmed matcher nonmatch.
	ErrUnknownOwner = errors.New("socket owner is unknown")
	// ErrAmbiguousOwner means that more than one process can own the flow.
	ErrAmbiguousOwner = errors.New("socket owner is ambiguous")
)

// Process identifies one PID incarnation. CreationTime prevents a cached path
// from being assigned to a later process which reuses the same PID.
type Process struct {
	PID            int
	ExecutablePath string
	CreationTime   time.Time
	EnrichmentErr  error
}

// Result is a best-effort socket-table result and its process enrichment.
// Processes can contain an entry with EnrichmentErr when the PID is known but
// Windows denies access or the process exits during lookup.
type Result struct {
	Owner     sockowner.SocketOwner
	Processes []Process
}

// Lookup resolves a flow owner without applying matcher policy. Unknown and
// ambiguous results are errors and must not be treated as nonmatches.
type Lookup interface {
	Owner(context.Context, sockowner.FlowTuple) (*Result, error)
}

// OutgoingPacketFlow parses a raw IP packet from a TUN and orients its tuple
// towards the local socket. The returned errors include sockowner.ErrProtocol,
// ErrNonFirstFragment, ErrShortPacket, and ErrMalformedPacket.
func OutgoingPacketFlow(packet []byte) (sockowner.FlowTuple, error) {
	flow, err := sockowner.FlowTupleFromOutgoingIPPacket(packet)
	if err != nil {
		return sockowner.FlowTuple{}, err
	}
	// IPv4-mapped bytes are valid inside an IPv6 header, but FlowTuple treats
	// them as IPv4 addresses. Reject a mixed result here instead of passing an
	// unusable tuple to a native table lookup.
	if _, err := flow.FlowFamily(); err != nil {
		return sockowner.FlowTuple{}, err
	}
	return flow, nil
}

// LocalPeerFlow creates the peer-oriented tuple needed to identify the client
// side of a connection accepted from LocalNet. Reversing these endpoints is
// essential: the ordinary local-to-remote orientation identifies the listener.
func LocalPeerFlow(connection net.Conn) (sockowner.FlowTuple, error) {
	flow, err := sockowner.IncomingConnPeerFlow(connection)
	if err != nil {
		return sockowner.FlowTuple{}, err
	}
	return *flow, nil
}
