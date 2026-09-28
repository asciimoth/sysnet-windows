//go:build !windows

package network

import "errors"

type nativeSocketOptions struct{}

func (nativeSocketOptions) get(uintptr, Family) (uint32, error) {
	return 0, errors.New("windows socket binding is unavailable on this platform")
}

func (nativeSocketOptions) set(uintptr, Family, uint32) error {
	return errors.New("windows socket binding is unavailable on this platform")
}
