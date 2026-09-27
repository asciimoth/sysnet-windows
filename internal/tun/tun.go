// Package tun contains the Wintun construction boundary.
package tun

import (
	"context"

	gtun "github.com/asciimoth/gonnect/tun"
)

// Config is the normalized device configuration used at creation time.
type Config struct {
	Name string
	MTU  int
}

// Factory creates one Wintun device. Implementations must not install drivers.
type Factory interface {
	Create(context.Context, Config) (gtun.Tun, error)
}
