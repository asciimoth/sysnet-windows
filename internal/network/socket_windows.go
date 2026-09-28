//go:build windows

package network

import (
	"math/bits"

	"golang.org/x/sys/windows"
)

// Windows uses option number 31 for both family-specific unicast-interface
// options. IP_UNICAST_IF takes a network-byte-order index, while
// IPV6_UNICAST_IF takes a host-byte-order index.
const (
	ipUnicastInterface   = 31
	ipv6UnicastInterface = 31
)

type nativeSocketOptions struct{}

func (nativeSocketOptions) get(descriptor uintptr, family Family) (uint32, error) {
	level, option := nativeOption(family)
	value, err := windows.GetsockoptInt(windows.Handle(descriptor), level, option)
	if err != nil {
		return 0, err
	}
	// Winsock accepts IP_UNICAST_IF in network byte order but returns both
	// IP_UNICAST_IF and IPV6_UNICAST_IF as host-order integer values.
	return uint32(value), nil
}

func (nativeSocketOptions) set(descriptor uintptr, family Family, index uint32) error {
	level, option := nativeOption(family)
	value := index
	if family == FamilyIPv4 {
		value = bits.ReverseBytes32(value)
	}
	return windows.SetsockoptInt(windows.Handle(descriptor), level, option, int(value))
}

func nativeOption(family Family) (int, int) {
	if family == FamilyIPv6 {
		return windows.IPPROTO_IPV6, ipv6UnicastInterface
	}
	return windows.IPPROTO_IP, ipUnicastInterface
}
