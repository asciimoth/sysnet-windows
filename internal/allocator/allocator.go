package allocator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	gonnectsubnet "github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/sysnet-windows/internal/netio"
)

var (
	// ErrHostStateUnavailable reports that allocation cannot safely continue
	// because no host-state reader is configured.
	ErrHostStateUnavailable = errors.New("host network state is unavailable")
	// ErrIncompleteHostState reports a malformed snapshot. A malformed item is
	// treated as incomplete enumeration instead of being silently omitted.
	ErrIncompleteHostState = errors.New("host network state is incomplete")
	// ErrClosed reports an allocation attempted after its owning System closed.
	ErrClosed = errors.New("allocator is closed")
)

// Allocator uses one reservation table for IP and subnet allocations. It
// serializes the initial host snapshot, candidate selection, final host-state
// read, and reservation so concurrent calls cannot select overlapping space.
type Allocator struct {
	mu       sync.Mutex
	reader   netio.Reader
	timeout  time.Duration
	delegate *gonnectsubnet.CombinedAllocator
	attempt  allocationAttempt
	closed   bool
	lastErr  error
}

type allocationAttempt struct {
	state            netio.HostState
	verifiedIPPrefix netip.Prefix
	failed           bool
}

// New creates an allocator for the gonnect private address pools. Host state is
// read only when an allocation is requested.
func New(reader netio.Reader, timeout time.Duration) *Allocator {
	allocator := &Allocator{reader: reader, timeout: timeout}
	allocator.delegate = gonnectsubnet.NewDefaultAllocator(gonnectsubnet.DefaultAllocatorConfig{
		IPFilter:     allocator.allowIP,
		SubnetFilter: allocator.allowSubnet,
	})
	return allocator
}

// LastError returns the reason for the most recent failed allocation read. The
// gonnect allocation interfaces return nil instead of an error, so this method
// is for package diagnostics and tests.
func (a *Allocator) LastError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// Close releases all reservations and prevents use through allocator handles
// retained after the owning System closes.
func (a *Allocator) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.delegate.FreeAllIP()
	a.delegate.FreeAllSubnets()
	a.attempt = allocationAttempt{}
}

// ReserveIP implements subnet.IPAllocator.
func (a *Allocator) ReserveIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.ReserveIP(ip)
	}
}

// AllocIP4 implements subnet.IPAllocator.
func (a *Allocator) AllocIP4() (net.IP, *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.startAttempt() {
		return nil, nil
	}
	ip, network := a.delegate.AllocIP4()
	a.finishAttempt(ip != nil)
	return ip, network
}

// AllocIP6 implements subnet.IPAllocator.
func (a *Allocator) AllocIP6() (net.IP, *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.startAttempt() {
		return nil, nil
	}
	ip, network := a.delegate.AllocIP6()
	a.finishAttempt(ip != nil)
	return ip, network
}

// FreeIP implements subnet.IPAllocator.
func (a *Allocator) FreeIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.FreeIP(ip)
	}
}

// FreeAllIP implements subnet.IPAllocator.
func (a *Allocator) FreeAllIP() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.FreeAllIP()
	}
}

// ReserveSubnet implements subnet.SubnetAllocator.
func (a *Allocator) ReserveSubnet(network *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.ReserveSubnet(network)
	}
}

// AllocSubnet4 implements subnet.SubnetAllocator.
func (a *Allocator) AllocSubnet4(prefix int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.startAttempt() {
		return nil
	}
	network := a.delegate.AllocSubnet4(prefix)
	a.finishAttempt(network != nil)
	return network
}

// AllocSubnet6 implements subnet.SubnetAllocator.
func (a *Allocator) AllocSubnet6(prefix int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.startAttempt() {
		return nil
	}
	network := a.delegate.AllocSubnet6(prefix)
	a.finishAttempt(network != nil)
	return network
}

// FreeSubnet implements subnet.SubnetAllocator.
func (a *Allocator) FreeSubnet(network *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.FreeSubnet(network)
	}
}

// FreeAllSubnets implements subnet.SubnetAllocator.
func (a *Allocator) FreeAllSubnets() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.FreeAllSubnets()
	}
}

func (a *Allocator) startAttempt() bool {
	a.lastErr = nil
	if a.closed {
		a.lastErr = ErrClosed
		return false
	}
	state, err := a.readHostState()
	if err != nil {
		a.lastErr = err
		return false
	}
	a.attempt = allocationAttempt{state: state}
	return true
}

func (a *Allocator) finishAttempt(allocated bool) {
	if !allocated && a.lastErr == nil && a.attempt.failed {
		a.lastErr = ErrHostStateUnavailable
	}
	a.attempt = allocationAttempt{}
}

func (a *Allocator) allowIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		a.failAttempt(ErrIncompleteHostState)
		return false
	}
	address = address.Unmap()
	if conflictsIP(a.attempt.state, address) {
		return false
	}
	// AllocIP can create a backing pool through allowSubnet. That callback
	// revalidates the complete pool immediately before the delegate reserves
	// it. Do not read again between the pool reservation and its first address:
	// an error there would leave an empty internal pool reserved. An address
	// from an older pool has no verified prefix and is revalidated below.
	if a.attempt.verifiedIPPrefix.IsValid() && a.attempt.verifiedIPPrefix.Contains(address) {
		return true
	}
	state, err := a.readHostState()
	if err != nil {
		a.failAttempt(err)
		return false
	}
	a.attempt.state = state
	return !conflictsIP(state, address)
}

func (a *Allocator) allowSubnet(network *net.IPNet) bool {
	prefix, err := netip.ParsePrefix(network.String())
	if err != nil {
		a.failAttempt(ErrIncompleteHostState)
		return false
	}
	prefix = prefix.Masked()
	if conflictsSubnet(a.attempt.state, prefix) {
		return false
	}
	state, err := a.readHostState()
	if err != nil {
		a.failAttempt(err)
		return false
	}
	a.attempt.state = state
	if conflictsSubnet(state, prefix) {
		return false
	}
	a.attempt.verifiedIPPrefix = prefix
	return true
}

func (a *Allocator) failAttempt(err error) {
	if a.lastErr == nil {
		a.lastErr = err
	}
	a.attempt.failed = true
}

func (a *Allocator) readHostState() (netio.HostState, error) {
	if a.attempt.failed {
		return netio.HostState{}, a.lastErr
	}
	if a.reader == nil {
		return netio.HostState{}, ErrHostStateUnavailable
	}
	ctx := context.Background()
	cancel := func() {}
	if a.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
	}
	defer cancel()
	state, err := a.reader.ReadHostState(ctx)
	if err != nil {
		return netio.HostState{}, fmt.Errorf("read host network state: %w", err)
	}
	if err := validateHostState(state); err != nil {
		return netio.HostState{}, err
	}
	return state, nil
}

func validateHostState(state netio.HostState) error {
	for _, address := range state.Addresses {
		if !address.IsValid() || address.Is4In6() || address.Zone() != "" {
			return ErrIncompleteHostState
		}
	}
	for _, prefixes := range [][]netip.Prefix{state.InterfacePrefixes, state.Routes} {
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				return ErrIncompleteHostState
			}
		}
	}
	return nil
}

func conflictsIP(state netio.HostState, candidate netip.Addr) bool {
	if !usableCandidate(candidate) {
		return true
	}
	for _, address := range state.Addresses {
		if usableHostAddress(address) && address == candidate {
			return true
		}
	}
	for _, prefix := range state.InterfacePrefixes {
		if usableHostPrefix(prefix) && prefix.Contains(candidate) {
			return true
		}
	}
	for _, route := range state.Routes {
		if usableRoute(route) && route.Contains(candidate) {
			return true
		}
	}
	return false
}

func conflictsSubnet(state netio.HostState, candidate netip.Prefix) bool {
	candidate = candidate.Masked()
	if !usableCandidate(candidate.Addr()) {
		return true
	}
	for _, address := range state.Addresses {
		if usableHostAddress(address) && candidate.Contains(address) {
			return true
		}
	}
	for _, prefix := range state.InterfacePrefixes {
		if usableHostPrefix(prefix) && prefixesOverlap(candidate, prefix.Masked()) {
			return true
		}
	}
	for _, route := range state.Routes {
		if usableRoute(route) && prefixesOverlap(candidate, route.Masked()) {
			return true
		}
	}
	return false
}

func usableCandidate(address netip.Addr) bool {
	return address.IsValid() && !address.IsLoopback() && !address.IsUnspecified() && !address.IsMulticast()
}

func usableHostAddress(address netip.Addr) bool {
	return usableCandidate(address)
}

func usableHostPrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && usableCandidate(prefix.Addr())
}

func usableRoute(prefix netip.Prefix) bool {
	// A default route proves reachability. It does not mean that the complete
	// address family is locally occupied.
	return prefix.IsValid() && prefix.Bits() != 0 && usableCandidate(prefix.Addr())
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() &&
		(left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

var (
	_ gonnectsubnet.IPAllocator     = (*Allocator)(nil)
	_ gonnectsubnet.SubnetAllocator = (*Allocator)(nil)
)
