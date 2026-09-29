package allocator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	// ErrReservationConflict reports an address already configured by this
	// System or observed in current host state.
	ErrReservationConflict = errors.New("address reservation conflicts with host state")
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

	ipRefs      map[netip.Addr]int
	subnetRefs  map[netip.Prefix]int
	ownedIPRefs map[netip.Addr]int
	ownedIPs    map[string][]netip.Prefix
}

type allocationAttempt struct {
	state            netio.HostState
	verifiedIPPrefix netip.Prefix
	failed           bool
}

// New creates an allocator for the gonnect private address pools. Host state is
// read only when an allocation is requested.
func New(reader netio.Reader, timeout time.Duration) *Allocator {
	allocator := &Allocator{
		reader: reader, timeout: timeout,
		ipRefs: make(map[netip.Addr]int), subnetRefs: make(map[netip.Prefix]int),
		ownedIPRefs: make(map[netip.Addr]int),
		ownedIPs:    make(map[string][]netip.Prefix),
	}
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
	clear(a.ipRefs)
	clear(a.subnetRefs)
	clear(a.ownedIPRefs)
	clear(a.ownedIPs)
	a.attempt = allocationAttempt{}
}

// ReserveIP implements subnet.IPAllocator.
func (a *Allocator) ReserveIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	address, ok := canonicalIP(ip)
	if !a.closed && ok {
		if a.ipRefs[address]+a.ownedIPRefs[address] == 0 {
			a.delegate.ReserveIP(ip)
		}
		a.ipRefs[address]++
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
	a.recordAllocatedIP(ip)
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
	a.recordAllocatedIP(ip)
	a.finishAttempt(ip != nil)
	return ip, network
}

// AllocateOwnedIPs selects and reserves one address for each requested family.
// The host-state checks, candidate selection, and ownership transfer are atomic
// with other allocations.
func (a *Allocator) AllocateOwnedIPs(owner string, ipv4, ipv6 bool) ([]netip.Prefix, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	if owner == "" {
		return nil, errors.New("allocator reservation owner is empty")
	}
	if _, exists := a.ownedIPs[owner]; exists {
		return nil, errors.New("allocator reservation owner already exists")
	}
	if !ipv4 && !ipv6 {
		return nil, errors.New("allocator address family is empty")
	}
	prefixes := make([]netip.Prefix, 0, 2)
	allocated := make([]net.IP, 0, 2)
	rollback := func() {
		for _, ip := range allocated {
			a.delegate.FreeIP(ip)
		}
	}
	for _, useIPv6 := range []bool{false, true} {
		if useIPv6 && !ipv6 || !useIPv6 && !ipv4 {
			continue
		}
		if !a.startAttempt() {
			rollback()
			return nil, a.lastErr
		}
		var ip net.IP
		var network *net.IPNet
		if useIPv6 {
			ip, network = a.delegate.AllocIP6()
		} else {
			ip, network = a.delegate.AllocIP4()
		}
		succeeded := ip != nil && network != nil
		a.finishAttempt(succeeded)
		if !succeeded {
			if ip != nil {
				a.delegate.FreeIP(ip)
			}
			rollback()
			return nil, errors.New("no conflict-free TUN address is available")
		}
		address, ok := canonicalIP(ip)
		ones, bits := network.Mask.Size()
		if !ok || ones < 0 || bits != address.BitLen() {
			a.delegate.FreeIP(ip)
			rollback()
			return nil, errors.New("allocator returned an invalid address prefix")
		}
		allocated = append(allocated, ip)
		prefixes = append(prefixes, netip.PrefixFrom(address, ones))
	}
	for _, prefix := range prefixes {
		a.ownedIPRefs[prefix.Addr()]++
	}
	a.ownedIPs[owner] = prefixes
	return append([]netip.Prefix(nil), prefixes...), nil
}

// FreeIP implements subnet.IPAllocator.
func (a *Allocator) FreeIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	address, ok := canonicalIP(ip)
	if a.closed || !ok || a.ipRefs[address] == 0 {
		return
	}
	a.ipRefs[address]--
	if a.ipRefs[address] != 0 {
		return
	}
	delete(a.ipRefs, address)
	if a.ownedIPRefs[address] == 0 {
		a.delegate.FreeIP(ip)
	}
}

// FreeAllIP implements subnet.IPAllocator.
func (a *Allocator) FreeAllIP() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		clear(a.ipRefs)
		a.delegate.FreeAllIP()
		for address := range a.ownedIPRefs {
			a.delegate.ReserveIP(net.IP(address.AsSlice()))
		}
	}
}

// ReserveOwnedIPs reserves configured adapter addresses without consuming a
// caller's existing allocator reservation for the same address. owner must be
// unique until ReleaseOwnedIPs is called.
func (a *Allocator) ReserveOwnedIPs(owner string, prefixes []netip.Prefix) error {
	return a.reserveOwnedIPs(owner, prefixes, "")
}

// ReserveOwnedIPsForReplacement reserves addresses before an old owner is
// retired. Only host addresses and prefixes held by replacedOwner can overlap.
// Those rows are removed at the explicit replacement boundary before the new
// addresses are applied.
func (a *Allocator) ReserveOwnedIPsForReplacement(owner string, prefixes []netip.Prefix, replacedOwner string) error {
	return a.reserveOwnedIPs(owner, prefixes, replacedOwner)
}

func (a *Allocator) reserveOwnedIPs(owner string, prefixes []netip.Prefix, replacedOwner string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if owner == "" {
		return errors.New("allocator reservation owner is empty")
	}
	if _, exists := a.ownedIPs[owner]; exists {
		return errors.New("allocator reservation owner already exists")
	}
	unique, err := normalizeOwnedPrefixes(prefixes, "reserve")
	if err != nil {
		return err
	}
	if len(unique) == 0 {
		a.ownedIPs[owner] = nil
		return nil
	}
	state, err := a.readHostState()
	if err != nil {
		return err
	}
	replaced := a.ownedIPs[replacedOwner]
	for _, prefix := range unique {
		address := prefix.Addr()
		if a.conflictsReservationLocked(prefix, replacedOwner) || conflictsPrefixExceptOwner(state, prefix, replaced) {
			return fmt.Errorf("%w: %s", ErrReservationConflict, address)
		}
	}
	for _, prefix := range unique {
		address := prefix.Addr()
		if a.ipRefs[address]+a.ownedIPRefs[address] == 0 {
			a.delegate.ReserveIP(net.IP(address.AsSlice()))
		}
		a.ownedIPRefs[address]++
	}
	a.ownedIPs[owner] = unique
	return nil
}

func normalizeOwnedPrefixes(prefixes []netip.Prefix, operation string) ([]netip.Prefix, error) {
	unique := make([]netip.Prefix, 0, len(prefixes))
	byAddress := make(map[netip.Addr]netip.Prefix, len(prefixes))
	for _, prefix := range prefixes {
		address := prefix.Addr().Unmap()
		if !usableCandidate(address) {
			return nil, fmt.Errorf("%s invalid configured address %s", operation, address)
		}
		bits := prefix.Bits()
		if prefix.Addr().Is4In6() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return nil, fmt.Errorf("%s invalid configured prefix %s", operation, prefix)
		}
		normalized := netip.PrefixFrom(address, bits)
		if previous, exists := byAddress[address]; exists && previous != normalized {
			return nil, fmt.Errorf("%s duplicate configured address %s with different prefixes", operation, address)
		}
		byAddress[address] = normalized
		if !slices.Contains(unique, normalized) {
			unique = append(unique, normalized)
		}
	}
	return unique, nil
}

// ReplaceOwnedIPs atomically changes an existing owner's address reservation.
// Caller reservations for the same addresses are not changed.
func (a *Allocator) ReplaceOwnedIPs(owner string, prefixes []netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	old, exists := a.ownedIPs[owner]
	if !exists {
		return errors.New("allocator reservation owner does not exist")
	}
	unique, err := normalizeOwnedPrefixes(prefixes, "reserve")
	if err != nil {
		return err
	}
	hasAddition := false
	for _, prefix := range unique {
		if slices.Contains(old, prefix) {
			continue
		}
		hasAddition = true
	}
	var state netio.HostState
	if hasAddition {
		var err error
		state, err = a.readHostState()
		if err != nil {
			return err
		}
	}
	for _, prefix := range unique {
		address := prefix.Addr()
		if slices.Contains(old, prefix) {
			continue
		}
		if a.conflictsReservationLocked(prefix, owner) || conflictsPrefixExceptOwner(state, prefix, old) {
			return fmt.Errorf("%w: %s", ErrReservationConflict, address)
		}
	}
	a.replaceOwnedIPsLocked(owner, old, unique)
	return nil
}

// RestoreOwnedIPs restores a previously verified owner reservation after its
// corresponding native transaction rolls back. It does not treat the owner's
// restored native addresses as foreign host conflicts.
func (a *Allocator) RestoreOwnedIPs(owner string, prefixes []netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	old, exists := a.ownedIPs[owner]
	if !exists {
		return errors.New("allocator reservation owner does not exist")
	}
	unique, err := normalizeOwnedPrefixes(prefixes, "restore")
	if err != nil {
		return err
	}
	a.replaceOwnedIPsLocked(owner, old, unique)
	return nil
}

func (a *Allocator) replaceOwnedIPsLocked(owner string, old, unique []netip.Prefix) {
	for _, prefix := range unique {
		address := prefix.Addr()
		if containsOwnedAddress(old, address) {
			continue
		}
		if a.ipRefs[address]+a.ownedIPRefs[address] == 0 {
			a.delegate.ReserveIP(net.IP(address.AsSlice()))
		}
		a.ownedIPRefs[address]++
	}
	for _, prefix := range old {
		address := prefix.Addr()
		if containsOwnedAddress(unique, address) {
			continue
		}
		a.ownedIPRefs[address]--
		if a.ownedIPRefs[address] == 0 {
			delete(a.ownedIPRefs, address)
			if a.ipRefs[address] == 0 {
				a.delegate.FreeIP(net.IP(address.AsSlice()))
			}
		}
	}
	a.ownedIPs[owner] = unique
}

// VerifyOwnedIPsAvailable re-reads host state immediately before an adapter
// first applies its reserved addresses.
func (a *Allocator) VerifyOwnedIPsAvailable(owner string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	addresses, exists := a.ownedIPs[owner]
	if !exists {
		return errors.New("allocator reservation owner does not exist")
	}
	if len(addresses) == 0 {
		return nil
	}
	state, err := a.readHostState()
	if err != nil {
		return err
	}
	for _, prefix := range addresses {
		address := prefix.Addr()
		if conflictsOwnedPrefix(state, prefix) {
			return fmt.Errorf("%w: %s", ErrReservationConflict, address)
		}
	}
	return nil
}

// ReleaseOwnedIPs releases only the references installed for owner. A caller
// allocation or explicit reservation for the same address remains reserved.
func (a *Allocator) ReleaseOwnedIPs(owner string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	addresses, exists := a.ownedIPs[owner]
	if !exists {
		return
	}
	delete(a.ownedIPs, owner)
	if a.closed {
		return
	}
	for _, prefix := range addresses {
		address := prefix.Addr()
		a.ownedIPRefs[address]--
		if a.ownedIPRefs[address] == 0 {
			delete(a.ownedIPRefs, address)
			if a.ipRefs[address] == 0 {
				a.delegate.FreeIP(net.IP(address.AsSlice()))
			}
		}
	}
}

func (a *Allocator) conflictsReservationLocked(candidate netip.Prefix, exceptOwner string) bool {
	assignedAddress := candidate.Addr()
	candidate = candidate.Masked()
	for owner, prefixes := range a.ownedIPs {
		if owner == exceptOwner {
			continue
		}
		for _, prefix := range prefixes {
			if prefixesOverlap(candidate, prefix.Masked()) {
				return true
			}
		}
	}
	for address := range a.ipRefs {
		// A caller can turn its exact allocated address into a TUN address.
		// The owned reference must not consume or invalidate that allocation.
		if address != assignedAddress && candidate.Contains(address) {
			return true
		}
	}
	for prefix := range a.subnetRefs {
		if prefixesOverlap(candidate, prefix) {
			return true
		}
	}
	return false
}

// ReserveSubnet implements subnet.SubnetAllocator.
func (a *Allocator) ReserveSubnet(network *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.ReserveSubnet(network)
		if prefix, ok := canonicalSubnet(network); ok {
			a.subnetRefs[prefix]++
		}
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
	a.recordAllocatedSubnet(network)
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
	a.recordAllocatedSubnet(network)
	a.finishAttempt(network != nil)
	return network
}

// FreeSubnet implements subnet.SubnetAllocator.
func (a *Allocator) FreeSubnet(network *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.delegate.FreeSubnet(network)
		if prefix, ok := canonicalSubnet(network); ok && a.subnetRefs[prefix] != 0 {
			a.subnetRefs[prefix]--
			if a.subnetRefs[prefix] == 0 {
				delete(a.subnetRefs, prefix)
			}
		}
	}
}

// FreeAllSubnets implements subnet.SubnetAllocator.
func (a *Allocator) FreeAllSubnets() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		clear(a.subnetRefs)
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

func (a *Allocator) recordAllocatedIP(ip net.IP) {
	if ip == nil {
		return
	}
	address, ok := canonicalIP(ip)
	if ok {
		a.ipRefs[address]++
	}
}

func (a *Allocator) recordAllocatedSubnet(network *net.IPNet) {
	if prefix, ok := canonicalSubnet(network); ok {
		a.subnetRefs[prefix]++
	}
}

func canonicalSubnet(network *net.IPNet) (netip.Prefix, bool) {
	if network == nil {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(network.String())
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

func canonicalIP(ip net.IP) (netip.Addr, bool) {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func containsOwnedAddress(prefixes []netip.Prefix, want netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return prefix.Addr() == want
	})
}

func (a *Allocator) allowIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		a.failAttempt(ErrIncompleteHostState)
		return false
	}
	address = address.Unmap()
	if a.conflictsOwnedIPLocked(address) || conflictsIP(a.attempt.state, address) {
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
	return !a.conflictsOwnedIPLocked(address) && !conflictsIP(state, address)
}

func (a *Allocator) allowSubnet(network *net.IPNet) bool {
	prefix, err := netip.ParsePrefix(network.String())
	if err != nil {
		a.failAttempt(ErrIncompleteHostState)
		return false
	}
	prefix = prefix.Masked()
	if a.conflictsOwnedSubnetLocked(prefix) || conflictsSubnet(a.attempt.state, prefix) {
		return false
	}
	state, err := a.readHostState()
	if err != nil {
		a.failAttempt(err)
		return false
	}
	a.attempt.state = state
	if a.conflictsOwnedSubnetLocked(prefix) || conflictsSubnet(state, prefix) {
		return false
	}
	a.attempt.verifiedIPPrefix = prefix
	return true
}

func (a *Allocator) conflictsOwnedIPLocked(candidate netip.Addr) bool {
	for _, prefixes := range a.ownedIPs {
		for _, prefix := range prefixes {
			if prefix.Masked().Contains(candidate) {
				return true
			}
		}
	}
	return false
}

func (a *Allocator) conflictsOwnedSubnetLocked(candidate netip.Prefix) bool {
	for _, prefixes := range a.ownedIPs {
		for _, prefix := range prefixes {
			if prefixesOverlap(candidate, prefix.Masked()) {
				return true
			}
		}
	}
	return false
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

func conflictsOwnedPrefix(state netio.HostState, candidate netip.Prefix) bool {
	return conflictsPrefixExceptOwner(state, candidate, nil)
}

func conflictsPrefixExceptOwner(state netio.HostState, candidate netip.Prefix, owner []netip.Prefix) bool {
	candidate = candidate.Masked()
	if !candidate.IsValid() || !usableCandidate(candidate.Addr()) {
		return true
	}
	ownedAddresses := make(map[netip.Addr]int, len(owner))
	ownedPrefixes := make(map[netip.Prefix]int, len(owner))
	ownedRoutes := make(map[netip.Prefix]int, len(owner)*3)
	for _, prefix := range owner {
		address := prefix.Addr().Unmap()
		prefix = netip.PrefixFrom(address, prefix.Bits()).Masked()
		ownedAddresses[address]++
		ownedPrefixes[prefix]++
		ownedRoutes[prefix]++
		host := netip.PrefixFrom(address, address.BitLen())
		ownedRoutes[host]++
		if prefix.Addr().Is4() && prefix.Bits() <= 30 {
			broadcast := netip.PrefixFrom(ipv4DirectedBroadcast(prefix), 32)
			ownedRoutes[broadcast]++
		}
	}
	for _, address := range state.Addresses {
		if usableHostAddress(address) && candidate.Contains(address) {
			if ownedAddresses[address] > 0 {
				ownedAddresses[address]--
				continue
			}
			return true
		}
	}
	for _, prefix := range state.InterfacePrefixes {
		prefix = prefix.Masked()
		if usableHostPrefix(prefix) && prefixesOverlap(candidate, prefix) {
			if ownedPrefixes[prefix] > 0 {
				ownedPrefixes[prefix]--
				continue
			}
			return true
		}
	}
	for _, route := range state.Routes {
		route = route.Masked()
		if usableRoute(route) && prefixesOverlap(candidate, route) {
			if ownedRoutes[route] > 0 {
				ownedRoutes[route]--
				continue
			}
			return true
		}
	}
	return false
}

// containsOwnedRoute reports whether an address assignment derives a route.
// Windows creates the on-link, host, and IPv4 directed-broadcast rows.
func containsOwnedRoute(prefixes []netip.Prefix, want netip.Prefix) bool {
	want = want.Masked()
	for _, prefix := range prefixes {
		prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits())
		if want == prefix.Masked() {
			return true
		}
		if want.Bits() != prefix.Addr().BitLen() {
			continue
		}
		if want.Addr() == prefix.Addr() {
			return true
		}
		if prefix.Addr().Is4() && prefix.Bits() <= 30 && want.Addr() == ipv4DirectedBroadcast(prefix) {
			return true
		}
	}
	return false
}

func ipv4DirectedBroadcast(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	bytes := prefix.Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(bytes)
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
	return usableNonDefaultPrefix(prefix)
}

func usableRoute(prefix netip.Prefix) bool {
	// A default route proves reachability. It does not mean that the complete
	// address family is locally occupied.
	return usableNonDefaultPrefix(prefix)
}

func usableNonDefaultPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Bits() == 0 {
		return false
	}
	address := prefix.Addr()
	return !address.IsLoopback() && !address.IsMulticast()
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() &&
		(left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

var (
	_ gonnectsubnet.IPAllocator     = (*Allocator)(nil)
	_ gonnectsubnet.SubnetAllocator = (*Allocator)(nil)
)
