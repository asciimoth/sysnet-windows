// Package wfp defines ownership operations for caller-created WFP objects.
package wfp

import "context"

// Object identifies one owned WFP object.
type Object struct {
	Key string
}

// Manager creates and removes exact caller-owned WFP objects.
type Manager interface {
	Create(context.Context, Object) error
	Delete(context.Context, Object) error
}
