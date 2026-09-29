package dns

import (
	"net/netip"
	"testing"
)

func TestEqualStateIgnoresObservedServersForAutomaticFamilies(t *testing.T) {
	left := State{
		AutomaticIPv6: true,
		Servers: []netip.Addr{
			netip.MustParseAddr("192.0.2.53"),
			netip.MustParseAddr("fec0::1"),
		},
	}
	right := State{
		AutomaticIPv6: true,
		Servers:       []netip.Addr{netip.MustParseAddr("192.0.2.53")},
	}
	if !EqualState(left, right) {
		t.Fatal("automatic-family observation changed DNS configuration equality")
	}

	right.Servers[0] = netip.MustParseAddr("198.51.100.53")
	if EqualState(left, right) {
		t.Fatal("different static IPv4 servers compare equal")
	}

	right = CloneState(left)
	right.AutomaticIPv6 = false
	if EqualState(left, right) {
		t.Fatal("automatic and static IPv6 modes compare equal")
	}
}
