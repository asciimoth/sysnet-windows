package allocator

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	gonnectsubnet "github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/sysnet-windows/internal/netio"
)

func TestT25HostAwareAllocation(t *testing.T) {
	t.Parallel()
	state := netio.HostState{
		Addresses: []netip.Addr{
			netip.MustParseAddr("10.20.1.7"),
			netip.MustParseAddr("127.0.0.1"),
		},
		InterfacePrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.20.0.0/16"), // LAN
			netip.MustParsePrefix("10.40.0.0/16"), // Hyper-V
			netip.MustParsePrefix("10.50.0.0/16"), // WSL
			netip.MustParsePrefix("10.60.0.0/16"), // another VPN
			netip.MustParsePrefix("127.0.0.0/8"),
		},
		Routes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
			netip.MustParsePrefix("10.70.0.0/16"),
		},
	}

	for _, candidate := range []string{
		"10.20.0.0/24",
		"10.40.0.0/16",
		"10.50.128.0/17",
		"10.60.1.0/24",
		"10.70.0.0/15",
	} {
		if !conflictsSubnet(state, netip.MustParsePrefix(candidate)) {
			t.Errorf("conflictsSubnet(%s) = false, want true", candidate)
		}
	}
	if conflictsSubnet(state, netip.MustParsePrefix("10.80.0.0/16")) {
		t.Fatal("unrelated subnet conflicts with host state")
	}
	if conflictsIP(state, netip.MustParseAddr("10.80.0.1")) {
		t.Fatal("unrelated address conflicts with default route")
	}

	allocator := New(staticReader{state: state}, time.Second)
	if got := allocator.AllocSubnet4(24); got == nil {
		t.Fatal("AllocSubnet4 returned nil when only default routes were broad")
	}
}

func TestAllocatorRechecksCandidateBeforeReservation(t *testing.T) {
	t.Parallel()
	reference := gonnectsubnet.NewDefaultAllocator(gonnectsubnet.DefaultAllocatorConfig{})
	first := reference.AllocSubnet4(24)
	if first == nil {
		t.Fatal("reference AllocSubnet4 returned nil")
	}
	firstPrefix := mustPrefix(t, first)

	reader := &sequenceReader{states: []netio.HostState{
		{},
		{InterfacePrefixes: []netip.Prefix{firstPrefix}},
	}}
	allocator := New(reader, time.Second)
	got := allocator.AllocSubnet4(24)
	if got == nil {
		t.Fatal("AllocSubnet4 returned nil after the first candidate became unavailable")
	}
	if got.String() == first.String() {
		t.Fatalf("AllocSubnet4 = %s, want a candidate other than newly occupied %s", got, first)
	}
	if reader.Calls() < 3 {
		t.Fatalf("host-state reads = %d, want initial read and candidate rechecks", reader.Calls())
	}
}

func TestOwnedIPReservationDoesNotConsumeCallerReservation(t *testing.T) {
	t.Parallel()
	reference := New(staticReader{}, time.Second)
	first, _ := reference.AllocIP4()
	if first == nil {
		t.Fatal("reference AllocIP4 returned nil")
	}
	address, ok := netip.AddrFromSlice(first)
	if !ok {
		t.Fatalf("reference address %v is invalid", first)
	}

	allocator := New(staticReader{}, time.Second)
	if err := allocator.ReserveOwnedIPs("tun-1", []netip.Prefix{netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())}); err != nil {
		t.Fatalf("ReserveOwnedIPs() error = %v", err)
	}
	got, _ := allocator.AllocIP4()
	if got == nil || got.Equal(first) {
		t.Fatalf("AllocIP4() = %v, want an address other than owned %v", got, first)
	}

	shared := New(staticReader{}, time.Second)
	callerIP, _ := shared.AllocIP4()
	callerAddress, ok := netip.AddrFromSlice(callerIP)
	if !ok {
		t.Fatalf("caller address %v is invalid", callerIP)
	}
	if err := shared.ReserveOwnedIPs("tun-2", []netip.Prefix{netip.PrefixFrom(callerAddress.Unmap(), callerAddress.Unmap().BitLen())}); err != nil {
		t.Fatalf("shared ReserveOwnedIPs() error = %v", err)
	}
	shared.ReleaseOwnedIPs("tun-2")
	next, _ := shared.AllocIP4()
	if next == nil || next.Equal(callerIP) {
		t.Fatalf("AllocIP4() after owned release = %v, want caller reservation %v preserved", next, callerIP)
	}
}

func TestReplaceOwnedIPsDistinguishesOwnedAndForeignPrefixes(t *testing.T) {
	t.Parallel()
	oldPrefix := netip.MustParsePrefix("10.20.1.1/16")
	newPrefix := netip.MustParsePrefix("10.20.2.1/16")
	tests := []struct {
		name      string
		state     netio.HostState
		wantError bool
	}{
		{
			name: "foreign broader interface prefix",
			state: netio.HostState{
				Addresses:         []netip.Addr{oldPrefix.Addr()},
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			wantError: true,
		},
		{
			name: "foreign broader route",
			state: netio.HostState{
				Addresses: []netip.Addr{oldPrefix.Addr()},
				Routes:    []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			wantError: true,
		},
		{
			name: "foreign narrower interface prefix",
			state: netio.HostState{
				Addresses:         []netip.Addr{oldPrefix.Addr()},
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.200.0/24")},
			},
			wantError: true,
		},
		{
			name: "exact owned interface prefix",
			state: netio.HostState{
				Addresses:         []netip.Addr{oldPrefix.Addr()},
				InterfacePrefixes: []netip.Prefix{oldPrefix.Masked()},
			},
		},
		{
			name: "exact owned on-link route",
			state: netio.HostState{
				Addresses: []netip.Addr{oldPrefix.Addr()},
				Routes:    []netip.Prefix{oldPrefix.Masked()},
			},
		},
		{
			name: "default route",
			state: netio.HostState{
				Addresses: []netip.Addr{oldPrefix.Addr()},
				Routes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reader := &sequenceReader{states: []netio.HostState{{}, test.state}}
			allocator := New(reader, time.Second)
			if err := allocator.ReserveOwnedIPs("tun-1", []netip.Prefix{oldPrefix}); err != nil {
				t.Fatalf("ReserveOwnedIPs() error = %v", err)
			}
			err := allocator.ReplaceOwnedIPs("tun-1", []netip.Prefix{oldPrefix, newPrefix})
			if test.wantError && !errors.Is(err, ErrReservationConflict) {
				t.Fatalf("ReplaceOwnedIPs() error = %v, want ErrReservationConflict", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("ReplaceOwnedIPs() error = %v, want nil", err)
			}
		})
	}
}

func TestReserveOwnedIPsRejectsEveryOverlappingHostResource(t *testing.T) {
	t.Parallel()
	candidate := netip.MustParsePrefix("10.60.1.1/16")
	tests := []struct {
		name  string
		state netio.HostState
	}{
		{
			name: "address elsewhere in configured prefix",
			state: netio.HostState{Addresses: []netip.Addr{
				netip.MustParseAddr("10.60.200.1"),
			}},
		},
		{
			name: "narrower interface prefix",
			state: netio.HostState{InterfacePrefixes: []netip.Prefix{
				netip.MustParsePrefix("10.60.200.0/24"),
			}},
		},
		{
			name: "broader interface prefix",
			state: netio.HostState{InterfacePrefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
			}},
		},
		{
			name: "narrower route",
			state: netio.HostState{Routes: []netip.Prefix{
				netip.MustParsePrefix("10.60.200.0/24"),
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			allocator := New(staticReader{state: test.state}, time.Second)
			if err := allocator.ReserveOwnedIPs("tun-1", []netip.Prefix{candidate}); !errors.Is(err, ErrReservationConflict) {
				t.Fatalf("ReserveOwnedIPs() error = %v, want ErrReservationConflict", err)
			}
		})
	}
}

func TestReserveOwnedIPsAllowsDefaultAndUnrelatedRoutes(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{state: netio.HostState{Routes: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}}}, time.Second)
	if err := allocator.ReserveOwnedIPs("tun-1", []netip.Prefix{
		netip.MustParsePrefix("10.70.1.1/16"),
	}); err != nil {
		t.Fatalf("ReserveOwnedIPs() error = %v", err)
	}
}

func TestVerifyOwnedIPsAvailableRechecksCompletePrefix(t *testing.T) {
	t.Parallel()
	candidate := netip.MustParsePrefix("10.75.1.1/16")
	reader := &sequenceReader{states: []netio.HostState{
		{},
		{InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.75.200.0/24")}},
	}}
	allocator := New(reader, time.Second)
	if err := allocator.ReserveOwnedIPs("tun-1", []netip.Prefix{candidate}); err != nil {
		t.Fatalf("ReserveOwnedIPs() error = %v", err)
	}
	if err := allocator.VerifyOwnedIPsAvailable("tun-1"); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("VerifyOwnedIPsAvailable() error = %v, want ErrReservationConflict", err)
	}
	if allocator.ownedIPRefs[candidate.Addr()] != 1 {
		t.Fatalf("reservation was lost after failed verification: %v", allocator.ownedIPRefs)
	}
}

func TestReplaceOwnedIPsConflictDoesNotChangeReservations(t *testing.T) {
	t.Parallel()
	oldPrefix := netip.MustParsePrefix("10.30.1.1/16")
	blockedPrefix := netip.MustParsePrefix("10.40.1.1/16")
	replacementPrefix := netip.MustParsePrefix("10.30.2.1/16")
	reader := &sequenceReader{states: []netio.HostState{
		{},
		{
			Addresses:         []netip.Addr{oldPrefix.Addr()},
			InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
		{
			Addresses:         []netip.Addr{oldPrefix.Addr()},
			InterfacePrefixes: []netip.Prefix{oldPrefix.Masked()},
		},
	}}
	allocator := New(reader, time.Second)
	if err := allocator.ReserveOwnedIPs("tun-1", []netip.Prefix{oldPrefix}); err != nil {
		t.Fatalf("ReserveOwnedIPs() error = %v", err)
	}
	if err := allocator.ReplaceOwnedIPs("tun-1", []netip.Prefix{blockedPrefix}); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("conflicting ReplaceOwnedIPs() error = %v, want ErrReservationConflict", err)
	}
	if allocator.ownedIPRefs[oldPrefix.Addr()] != 1 || allocator.ownedIPRefs[blockedPrefix.Addr()] != 0 {
		t.Fatalf("reservations changed after conflict: %v", allocator.ownedIPRefs)
	}
	if err := allocator.ReplaceOwnedIPs("tun-1", []netip.Prefix{oldPrefix, replacementPrefix}); err != nil {
		t.Fatalf("ReplaceOwnedIPs() after conflict error = %v", err)
	}
	if allocator.ownedIPRefs[oldPrefix.Addr()] != 1 || allocator.ownedIPRefs[replacementPrefix.Addr()] != 1 {
		t.Fatalf("replacement reservations = %v", allocator.ownedIPRefs)
	}
	allocator.ReleaseOwnedIPs("tun-1")
	if got, _ := allocator.AllocIP4(); got == nil {
		t.Fatal("AllocIP4() after release returned nil")
	}
}

func TestOwnedPrefixesRejectOverlappingOwners(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{name: "IPv4 exact network", first: "10.201.1.1/16", second: "10.201.2.1/16"},
		{name: "IPv4 narrower", first: "10.202.1.1/16", second: "10.202.2.1/24"},
		{name: "IPv4 broader", first: "10.203.1.1/24", second: "10.203.2.1/16"},
		{name: "IPv6 exact network", first: "fd20:1::1/64", second: "fd20:1::2/64"},
		{name: "IPv6 narrower", first: "fd20:2::1/48", second: "fd20:2:0:1::1/64"},
		{name: "IPv6 broader", first: "fd20:3:0:1::1/64", second: "fd20:3::1/48"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			allocator := New(staticReader{}, time.Second)
			if err := allocator.ReserveOwnedIPs("first", []netip.Prefix{
				netip.MustParsePrefix(test.first),
			}); err != nil {
				t.Fatalf("first ReserveOwnedIPs() error = %v", err)
			}
			if err := allocator.ReserveOwnedIPs("second", []netip.Prefix{
				netip.MustParsePrefix(test.second),
			}); !errors.Is(err, ErrReservationConflict) {
				t.Fatalf("second ReserveOwnedIPs() error = %v, want ErrReservationConflict", err)
			}
		})
	}
}

func TestOwnedPrefixesPermitSameOwnerAndUnrelatedOwners(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)
	if err := allocator.ReserveOwnedIPs("first", []netip.Prefix{
		netip.MustParsePrefix("10.204.1.1/16"),
		netip.MustParsePrefix("10.204.2.1/24"),
		netip.MustParsePrefix("fd20:4::1/48"),
		netip.MustParsePrefix("fd20:4:0:1::1/64"),
	}); err != nil {
		t.Fatalf("same-owner ReserveOwnedIPs() error = %v", err)
	}
	if err := allocator.ReserveOwnedIPs("second", []netip.Prefix{
		netip.MustParsePrefix("10.205.1.1/16"),
		netip.MustParsePrefix("fd20:5::1/48"),
	}); err != nil {
		t.Fatalf("unrelated ReserveOwnedIPs() error = %v", err)
	}
}

func TestOwnedPrefixesBlockIPAndSubnetAllocationUntilRelease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		ownedPrefix    netip.Prefix
		allocateIP     func(*Allocator) net.IP
		allocateSubnet func(*Allocator) *net.IPNet
	}{
		{
			name: "IPv4", ownedPrefix: netip.MustParsePrefix("10.0.0.1/8"),
			allocateIP: func(allocator *Allocator) net.IP {
				ip, _ := allocator.AllocIP4()
				return ip
			},
			allocateSubnet: func(allocator *Allocator) *net.IPNet { return allocator.AllocSubnet4(16) },
		},
		{
			name: "IPv6", ownedPrefix: defaultIPv6ParentPrefix(t),
			allocateIP: func(allocator *Allocator) net.IP {
				ip, _ := allocator.AllocIP6()
				return ip
			},
			allocateSubnet: func(allocator *Allocator) *net.IPNet { return allocator.AllocSubnet6(64) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			allocator := New(staticReader{}, time.Second)
			if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{test.ownedPrefix}); err != nil {
				t.Fatalf("ReserveOwnedIPs() error = %v", err)
			}
			if got := test.allocateIP(allocator); got != nil {
				t.Fatalf("IP allocation = %v, want nil while %s is owned", got, test.ownedPrefix)
			}
			if got := test.allocateSubnet(allocator); got != nil {
				t.Fatalf("subnet allocation = %v, want nil while %s is owned", got, test.ownedPrefix)
			}
			allocator.ReleaseOwnedIPs("tun")
			if got := test.allocateIP(allocator); got == nil {
				t.Fatal("IP allocation after release = nil")
			}
			if got := test.allocateSubnet(allocator); got == nil {
				t.Fatal("subnet allocation after release = nil")
			}
		})
	}
}

func TestOwnedPrefixesRejectCallerReservations(t *testing.T) {
	t.Parallel()
	t.Run("allocated IPv4 subnet", func(t *testing.T) {
		allocator := New(staticReader{}, time.Second)
		network := allocator.AllocSubnet4(16)
		if network == nil {
			t.Fatal("AllocSubnet4() = nil")
		}
		prefix := mustPrefix(t, network)
		candidate := netip.PrefixFrom(prefix.Addr().Next(), prefix.Bits())
		if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); !errors.Is(err, ErrReservationConflict) {
			t.Fatalf("ReserveOwnedIPs() error = %v, want ErrReservationConflict", err)
		}
		allocator.FreeSubnet(network)
		if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); err != nil {
			t.Fatalf("ReserveOwnedIPs() after FreeSubnet() error = %v", err)
		}
	})

	t.Run("reserved IPv6 subnet", func(t *testing.T) {
		allocator := New(staticReader{}, time.Second)
		prefix := netip.MustParsePrefix("fd30:1::/64")
		network := &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), 128)}
		allocator.ReserveSubnet(network)
		candidate := netip.MustParsePrefix("fd30:1::1/80")
		if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); !errors.Is(err, ErrReservationConflict) {
			t.Fatalf("ReserveOwnedIPs() error = %v, want ErrReservationConflict", err)
		}
		allocator.FreeAllSubnets()
		if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); err != nil {
			t.Fatalf("ReserveOwnedIPs() after FreeAllSubnets() error = %v", err)
		}
	})

	t.Run("allocated IP", func(t *testing.T) {
		allocator := New(staticReader{}, time.Second)
		ip, _ := allocator.AllocIP4()
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			t.Fatalf("AllocIP4() = %v", ip)
		}
		address = address.Unmap()
		candidate := netip.PrefixFrom(address.Next(), 24)
		if !candidate.Masked().Contains(address) {
			t.Fatalf("test candidate %s does not contain allocated address %s", candidate, address)
		}
		if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); !errors.Is(err, ErrReservationConflict) {
			t.Fatalf("ReserveOwnedIPs() error = %v, want ErrReservationConflict", err)
		}
		allocator.FreeIP(ip)
		if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); err != nil {
			t.Fatalf("ReserveOwnedIPs() after FreeIP() error = %v", err)
		}
	})
}

func TestCallerSubnetReferenceCountsProtectOwnedReservations(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)
	prefix := netip.MustParsePrefix("10.209.0.0/16")
	network := &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), 32)}
	candidate := netip.MustParsePrefix("10.209.1.1/24")
	allocator.ReserveSubnet(network)
	allocator.ReserveSubnet(network)
	allocator.FreeSubnet(network)
	if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("ReserveOwnedIPs() after one FreeSubnet() error = %v, want ErrReservationConflict", err)
	}
	allocator.FreeSubnet(network)
	if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{candidate}); err != nil {
		t.Fatalf("ReserveOwnedIPs() after final FreeSubnet() error = %v", err)
	}
}

func TestReplaceOwnedIPsRechecksPrefixLengthChanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		old     string
		next    string
		foreign string
	}{
		{name: "IPv4 expansion", old: "10.206.1.1/24", next: "10.206.1.1/16", foreign: "10.206.2.0/24"},
		{name: "IPv6 expansion", old: "fd20:6:1:1::1/64", next: "fd20:6:1:1::1/48", foreign: "fd20:6:1:2::/64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			oldPrefix := netip.MustParsePrefix(test.old)
			reader := &sequenceReader{states: []netio.HostState{
				{},
				{
					Addresses:         []netip.Addr{oldPrefix.Addr()},
					InterfacePrefixes: []netip.Prefix{oldPrefix.Masked(), netip.MustParsePrefix(test.foreign)},
				},
			}}
			allocator := New(reader, time.Second)
			if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{oldPrefix}); err != nil {
				t.Fatalf("ReserveOwnedIPs() error = %v", err)
			}
			if err := allocator.ReplaceOwnedIPs("tun", []netip.Prefix{
				netip.MustParsePrefix(test.next),
			}); !errors.Is(err, ErrReservationConflict) {
				t.Fatalf("ReplaceOwnedIPs() error = %v, want ErrReservationConflict", err)
			}
			if got := reader.Calls(); got != 2 {
				t.Fatalf("host-state reads = %d, want 2", got)
			}
			if got := allocator.ownedIPs["tun"]; !slices.Equal(got, []netip.Prefix{oldPrefix}) {
				t.Fatalf("owned prefixes after conflict = %v, want [%s]", got, oldPrefix)
			}
		})
	}
}

func TestReplaceOwnedIPsRejectsOverlapWithAnotherPendingOwner(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)
	first := netip.MustParsePrefix("10.207.1.1/24")
	second := netip.MustParsePrefix("10.207.2.1/24")
	if err := allocator.ReserveOwnedIPs("first", []netip.Prefix{first}); err != nil {
		t.Fatalf("first ReserveOwnedIPs() error = %v", err)
	}
	if err := allocator.ReserveOwnedIPs("second", []netip.Prefix{second}); err != nil {
		t.Fatalf("second ReserveOwnedIPs() error = %v", err)
	}
	if err := allocator.ReplaceOwnedIPs("first", []netip.Prefix{
		netip.MustParsePrefix("10.207.1.1/16"),
	}); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("ReplaceOwnedIPs() error = %v, want ErrReservationConflict", err)
	}
}

func TestRestoreOwnedIPsRestoresCompletePrefixFilters(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)
	oldPrefix := netip.MustParsePrefix("10.210.1.1/24")
	newPrefix := netip.MustParsePrefix("10.211.1.1/24")
	if err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{oldPrefix}); err != nil {
		t.Fatalf("ReserveOwnedIPs() error = %v", err)
	}
	if err := allocator.ReplaceOwnedIPs("tun", []netip.Prefix{newPrefix}); err != nil {
		t.Fatalf("ReplaceOwnedIPs() error = %v", err)
	}
	if err := allocator.RestoreOwnedIPs("tun", []netip.Prefix{oldPrefix}); err != nil {
		t.Fatalf("RestoreOwnedIPs() error = %v", err)
	}
	if !allocator.conflictsOwnedSubnetLocked(oldPrefix.Masked()) {
		t.Fatalf("restored prefix %s does not block allocation", oldPrefix)
	}
	if allocator.conflictsOwnedSubnetLocked(newPrefix.Masked()) {
		t.Fatalf("rolled-back prefix %s still blocks allocation", newPrefix)
	}
}

func TestOwnedPrefixesRejectDuplicateAddressWithDifferentLengths(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)
	err := allocator.ReserveOwnedIPs("tun", []netip.Prefix{
		netip.MustParsePrefix("10.208.1.1/24"),
		netip.MustParsePrefix("10.208.1.1/16"),
	})
	if err == nil || errors.Is(err, ErrReservationConflict) {
		t.Fatalf("ReserveOwnedIPs() error = %v, want invalid duplicate address", err)
	}
	if len(allocator.ownedIPs) != 0 {
		t.Fatalf("failed reservation changed owners: %v", allocator.ownedIPs)
	}
}

func TestT26ConcurrentAllocation(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)

	const calls = 64
	results := make(chan *net.IPNet, calls)
	var wait sync.WaitGroup
	for index := range calls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if index%2 == 0 {
				ip, network := allocator.AllocIP4()
				if ip == nil || network == nil {
					results <- nil
					return
				}
				results <- &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				return
			}
			results <- allocator.AllocSubnet4(24)
		}()
	}
	wait.Wait()
	close(results)

	var reserved []netip.Prefix
	for network := range results {
		if network == nil {
			t.Fatal("concurrent allocation returned nil")
		}
		prefix := mustPrefix(t, network)
		for _, prior := range reserved {
			if prefixesOverlap(prefix, prior) {
				t.Fatalf("concurrent reservations overlap: %s and %s", prefix, prior)
			}
		}
		reserved = append(reserved, prefix)
	}
	if len(reserved) != calls {
		t.Fatalf("reservations = %d, want %d", len(reserved), calls)
	}
}

func TestT27EnumerationFailureAfterSelection(t *testing.T) {
	t.Parallel()
	enumerationErr := errors.New("route table changed during enumeration")
	reader := &sequenceReader{
		states: []netio.HostState{{}},
		errors: []error{nil, enumerationErr},
	}
	allocator := New(reader, time.Second)
	if got := allocator.AllocSubnet4(24); got != nil {
		t.Fatalf("AllocSubnet4 = %s, want nil after final enumeration error", got)
	}
	if !errors.Is(allocator.LastError(), enumerationErr) {
		t.Fatalf("LastError = %v, want %v", allocator.LastError(), enumerationErr)
	}
	if got := reader.Calls(); got != 2 {
		t.Fatalf("host-state reads = %d, want 2", got)
	}
}

func TestFailedIPRecheckDoesNotConsumeReservation(t *testing.T) {
	t.Parallel()
	reader := &sequenceReader{}
	allocator := New(reader, time.Second)
	first, _ := allocator.AllocIP4()
	if first == nil {
		t.Fatal("first AllocIP4 returned nil")
	}

	// The existing address pool makes the second allocation recheck the IP
	// candidate directly. A failed final read must not reserve that candidate.
	enumerationErr := errors.New("address enumeration failed")
	reader.SetErrors(nil, enumerationErr)
	if ip, network := allocator.AllocIP4(); ip != nil || network != nil {
		t.Fatalf("AllocIP4 with failed recheck = (%v, %v), want nil values", ip, network)
	}
	reader.SetErrors()
	got, _ := allocator.AllocIP4()
	if got == nil {
		t.Fatal("AllocIP4 after restored enumeration returned nil")
	}
	want := nextIP(first)
	if !got.Equal(want) {
		t.Fatalf("AllocIP4 after failed recheck = %v, want unconsumed candidate %v", got, want)
	}
}

func TestAllocatorRejectsMalformedPartialSnapshot(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{state: netio.HostState{
		InterfacePrefixes: []netip.Prefix{{}},
	}}, time.Second)
	if ip, network := allocator.AllocIP4(); ip != nil || network != nil {
		t.Fatalf("AllocIP4 = (%v, %v), want nil values", ip, network)
	}
	if !errors.Is(allocator.LastError(), ErrIncompleteHostState) {
		t.Fatalf("LastError = %v, want ErrIncompleteHostState", allocator.LastError())
	}
}

func TestAllocatorCloseReleasesAndStopsReservations(t *testing.T) {
	t.Parallel()
	allocator := New(staticReader{}, time.Second)
	if ip, _ := allocator.AllocIP4(); ip == nil {
		t.Fatal("AllocIP4 returned nil before Close")
	}
	allocator.Close()
	if ip, network := allocator.AllocIP4(); ip != nil || network != nil {
		t.Fatalf("AllocIP4 after Close = (%v, %v), want nil values", ip, network)
	}
	if !errors.Is(allocator.LastError(), ErrClosed) {
		t.Fatalf("LastError after Close = %v, want ErrClosed", allocator.LastError())
	}
}

type staticReader struct {
	state netio.HostState
	err   error
}

func (r staticReader) ReadHostState(context.Context) (netio.HostState, error) {
	return r.state, r.err
}

type sequenceReader struct {
	mu     sync.Mutex
	states []netio.HostState
	errors []error
	calls  int
}

func (r *sequenceReader) ReadHostState(context.Context) (netio.HostState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.calls
	r.calls++
	var state netio.HostState
	if len(r.states) != 0 {
		stateIndex := min(index, len(r.states)-1)
		state = r.states[stateIndex]
	}
	var err error
	if len(r.errors) != 0 {
		errorIndex := min(index, len(r.errors)-1)
		err = r.errors[errorIndex]
	}
	return state, err
}

func (r *sequenceReader) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *sequenceReader) SetErrors(errs ...error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = errs
	r.calls = 0
}

func mustPrefix(t *testing.T, network *net.IPNet) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(network.String())
	if err != nil {
		t.Fatalf("parse prefix %q: %v", network, err)
	}
	return prefix.Masked()
}

func defaultIPv6ParentPrefix(t *testing.T) netip.Prefix {
	t.Helper()
	reference := New(staticReader{}, time.Second)
	network := reference.AllocSubnet6(48)
	if network == nil {
		t.Fatal("reference AllocSubnet6(48) = nil")
	}
	prefix := mustPrefix(t, network)
	return netip.PrefixFrom(prefix.Addr().Next(), prefix.Bits())
}

func nextIP(ip net.IP) net.IP {
	result := append(net.IP(nil), ip...)
	for index := len(result) - 1; index >= 0; index-- {
		result[index]++
		if result[index] != 0 {
			break
		}
	}
	return result
}
