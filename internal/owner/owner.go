// Package owner defines socket ownership and executable enrichment boundaries.
package owner

import (
	"context"

	"github.com/asciimoth/gonnect/sockowner"
)

// Lookup resolves a flow owner without applying matcher policy.
type Lookup interface {
	Owner(context.Context, sockowner.FlowTuple) (*sockowner.SocketOwner, error)
}
