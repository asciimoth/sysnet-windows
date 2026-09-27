// Package reconcile contains serialized desired-state application and exact
// ownership journals.
package reconcile

import "net/netip"

// Kind identifies the native subsystem that owns a resource.
type Kind uint8

const (
	KindAdapter Kind = iota + 1
	KindAddress
	KindRoute
	KindDNS
	KindWFP
	KindSplit
)

// OwnershipKey identifies one resource owned by one System. ID must be stable
// for the lifetime of the journal. Scope identifies its containing interface,
// provider, or controller session.
type OwnershipKey struct {
	Kind  Kind
	Scope string
	ID    string
}

// AdapterRecord separates durable adapter identity from current-instance
// identifiers.
type AdapterRecord struct {
	Key   OwnershipKey
	GUID  string
	LUID  uint64
	Index uint32
}

// AddressRecord identifies one exact interface address.
type AddressRecord struct {
	Key       OwnershipKey
	Interface OwnershipKey
	Prefix    netip.Prefix
}

// RouteRecord identifies one exact route row.
type RouteRecord struct {
	Key       OwnershipKey
	Interface OwnershipKey
	Prefix    netip.Prefix
	Metric    uint32
}

// DNSRecord contains the previous and applied resolver values for one
// interface. Values are opaque here because the DNS boundary owns their native
// representation.
type DNSRecord struct {
	Key      OwnershipKey
	Previous any
	Value    any
}

// WFPRecord identifies one caller-owned WFP object.
type WFPRecord struct {
	Key OwnershipKey
}

// SplitRecord records the policy for one exclusive controller session.
type SplitRecord struct {
	Key    OwnershipKey
	Policy any
}

// State is one complete reconciliation view. Desired, Observed, and Applied
// states use the same representation so comparisons cannot omit a subsystem.
type State struct {
	Adapters  []AdapterRecord
	Addresses []AddressRecord
	Routes    []RouteRecord
	DNS       []DNSRecord
	WFP       []WFPRecord
	Split     []SplitRecord
}

// Records keeps policy intent, native readback, and verified applied state
// separate.
type Records struct {
	Desired  State
	Observed State
	Applied  State
}
