// Package netio defines exact Windows address, route, and IP-interface
// operations. The policy code in this package is platform independent. Native
// calls are isolated in files with a Windows build constraint.
package netio

import (
	"context"
	"errors"
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

// Interface identifies one current Windows network interface instance. LUID
// and Index are checked together so a stale identity is not applied to a
// recreated adapter.
type Interface struct {
	LUID  uint64
	Index uint32
	// GUID is the durable adapter identity. It is optional for stores which do
	// not expose a GUID, but native callers supply it so LUID/index reuse is
	// detected before an owned row is changed.
	GUID string
}

// Family identifies one Windows IP-interface row.
type Family uint8

const (
	FamilyIPv4 Family = 4
	FamilyIPv6 Family = 6
)

// Address is the stable value of one unicast-address row. Windows identifies a
// unicast row by interface and address; Prefix is therefore a value, not part
// of its key. Usable reports a preferred or deprecated DAD state.
type Address struct {
	Prefix netip.Prefix
	Usable bool
}

// Route is the stable value of one forward row. Destination and NextHop form
// the route key on one interface. Metric is the owned mutable value.
type Route struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Metric      uint32
}

// Properties is the owned part of a per-family IP-interface row. AutomaticMetric
// is recorded because restoring only the numeric metric changes host policy.
type Properties struct {
	Family          Family
	MTU             uint32
	Metric          uint32
	AutomaticMetric bool
}

// State is one complete snapshot of the rows relevant to an interface. Store
// implementations must not return partial snapshots as successful reads.
type State struct {
	Interface  Interface
	Addresses  []Address
	Routes     []Route
	Properties []Properties
}

// Config is the complete state desired by one Manager. Addresses and routes
// are owned rows. Properties can already have the desired value, in which case
// the manager preserves them without taking ownership.
type Config struct {
	Addresses  []netip.Prefix
	Routes     []Route
	Properties []Properties
}

// Store is the narrow native NetIO boundary. Each mutation affects one exact
// row. In particular, implementations must never flush an address or route
// table. Manager independently reads state after each mutation.
type Store interface {
	Snapshot(context.Context, Interface) (State, error)
	CreateAddress(context.Context, Interface, netip.Prefix) error
	DeleteAddress(context.Context, Interface, netip.Prefix) error
	WaitAddressUsable(context.Context, Interface, netip.Addr) error
	CreateRoute(context.Context, Interface, Route) error
	DeleteRoute(context.Context, Interface, Route) error
	SetProperties(context.Context, Interface, Properties) error
}

// Manager applies exact owned deltas and restores changed interface properties.
// Apply is serialized per manager. Passing an empty Config removes all rows
// owned by the manager and restores the properties that it changed.
type Manager interface {
	Apply(context.Context, Interface, Config) error
	Read(context.Context, Interface) (Config, error)
	// Verify compares desired state with owned rows and effective properties.
	Verify(context.Context, Interface, Config) error
}

var (
	// ErrInvalidConfig reports a value which cannot identify a valid NetIO row.
	ErrInvalidConfig = errors.New("invalid NetIO configuration")
	// ErrIdentityMismatch reports a stale or incorrect interface identity.
	ErrIdentityMismatch = errors.New("network interface identity changed")
	// ErrResourceConflict reports a desired or owned key occupied by a value
	// which this manager did not apply.
	ErrResourceConflict = errors.New("NetIO resource ownership conflict")
	// ErrReadback reports that an independent snapshot did not contain the value
	// reported as successfully applied by the native API.
	ErrReadback = errors.New("NetIO readback does not match applied value")
)

// Failure reports a Manager transaction whose rollback could not prove that
// its inventory is safe for later cleanup.
type Failure struct {
	err error
}

func (e *Failure) Error() string { return e.err.Error() }
func (e *Failure) Unwrap() error { return e.err }

// RequiresRecovery reports whether a failed Manager transaction retained
// observed ownership or could not read the state needed to decide.
func RequiresRecovery(err error) bool {
	var failure *Failure
	return errors.As(err, &failure)
}
