package allocator

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
