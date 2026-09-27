// Package split defines the exclusive split-driver controller boundary.
package split

import "context"

// Policy is the complete executable exclusion policy.
type Policy struct {
	ExecutablePaths []string
}

// Controller owns one exclusive split-driver session.
type Controller interface {
	Apply(context.Context, Policy) error
	Reset(context.Context) error
	Close() error
}
