// Package underlay selects and monitors the host paths used to bypass an
// owned tunnel.
package underlay

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultDebounce = 100 * time.Millisecond

// Interface identifies one current interface instance. GUID is stable across
// index changes, while LUID and Index identify only the current instance.
type Interface struct {
	LUID  uint64
	Index uint32
	GUID  string
	Name  string
}

// Address is a possible source address. Usable is false for tentative,
// duplicate, invalid, or skip-as-source Windows address rows.
type Address struct {
	Address netip.Addr
	Usable  bool
}

// Route is one reachable destination and its route metric.
type Route struct {
	Destination netip.Prefix
	Metric      uint32
}

// Candidate contains all selection facts for one interface. InterfaceMetric
// and routes are family-specific, so a source can return two candidates for
// one dual-stack interface.
type Candidate struct {
	Interface
	IPv6            bool
	Operational     bool
	InterfaceMetric uint32
	Addresses       []Address
	Routes          []Route
}

// Path is one selected outbound path for an address family.
type Path struct {
	InterfaceIndex  uint32
	InterfaceLUID   uint64
	InterfaceGUID   string
	InterfaceName   string
	Source          netip.Addr
	RouteMetric     uint32
	InterfaceMetric uint32
}

// Snapshot contains coherent IPv4 and IPv6 selections. A nil path means that
// the family has no usable underlay. Snapshot values are immutable.
type Snapshot struct {
	IPv4 *Path
	IPv6 *Path
}

// Subscription releases native change callbacks.
type Subscription interface {
	io.Closer
}

// Source reads host path candidates and registers interface, route, and
// address change callbacks. A callback must return quickly and can be called
// concurrently. ReadCandidates must not return a partial snapshot as success.
type Source interface {
	ReadCandidates(context.Context) ([]Candidate, error)
	SubscribeChanges(func()) (Subscription, error)
}

// Owned reports whether an interface belongs to this System.
type Owned func(Interface) bool

// Monitor debounces native notifications and atomically publishes both family
// selections from one candidate read.
type Monitor struct {
	source   Source
	selector string
	owned    Owned
	timeout  time.Duration
	debounce time.Duration

	current   atomic.Pointer[Snapshot]
	changes   chan struct{}
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
	sub       Subscription
	closeMu   sync.Mutex
	subClosed bool
	closeErr  error

	errMu     sync.RWMutex
	err       error
	refreshMu sync.Mutex
}

// NewMonitor subscribes before its first read so a change during startup is
// not lost. The initial snapshot is read synchronously.
func NewMonitor(source Source, selector string, owned Owned, timeout time.Duration) (*Monitor, error) {
	return newMonitor(source, selector, owned, timeout, defaultDebounce)
}

func newMonitor(source Source, selector string, owned Owned, timeout, debounce time.Duration) (*Monitor, error) {
	if source == nil {
		return nil, errors.New("underlay source is not configured")
	}
	if timeout <= 0 {
		return nil, errors.New("underlay read timeout must be positive")
	}
	if debounce < 0 {
		return nil, errors.New("underlay debounce must not be negative")
	}
	m := &Monitor{
		source: source, selector: strings.TrimSpace(selector), owned: owned,
		timeout: timeout, debounce: debounce, changes: make(chan struct{}, 1),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	sub, err := source.SubscribeChanges(m.notify)
	if err != nil {
		return nil, err
	}
	m.sub = sub
	if err := m.Refresh(context.Background()); err != nil {
		return nil, errors.Join(err, sub.Close())
	}
	go m.run()
	return m, nil
}

// Snapshot returns a deep copy of the last complete published selection.
func (m *Monitor) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	value := m.current.Load()
	if value == nil {
		return Snapshot{}
	}
	return cloneSnapshot(*value)
}

// LastError returns the most recent asynchronous refresh error. A failed read
// marks both families unavailable instead of retaining stale interface data.
func (m *Monitor) LastError() error {
	if m == nil {
		return nil
	}
	m.errMu.RLock()
	defer m.errMu.RUnlock()
	return m.err
}

// Refresh reads and publishes one complete replacement snapshot.
func (m *Monitor) Refresh(parent context.Context) error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, m.timeout)
	defer cancel()
	candidates, err := m.source.ReadCandidates(ctx)
	if err != nil {
		m.publish(Snapshot{}, err)
		return err
	}
	m.publish(Select(candidates, m.selector, m.owned), nil)
	return nil
}

// Close unregisters callbacks and joins the monitor worker. It is idempotent.
func (m *Monitor) Close() error {
	if m == nil {
		return nil
	}
	m.once.Do(func() {
		close(m.stop)
		<-m.done
	})
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.sub != nil && !m.subClosed {
		m.closeErr = m.sub.Close()
		m.subClosed = m.closeErr == nil
	}
	return m.closeErr
}

// NotifyOwnedChange requests a debounced refresh after the System ownership
// registry changes. Native interface callbacks normally also report this
// change, but this explicit signal closes the registration race.
func (m *Monitor) NotifyOwnedChange() {
	if m != nil {
		m.notify()
	}
}

func (m *Monitor) notify() {
	select {
	case m.changes <- struct{}{}:
	default:
	}
}

func (m *Monitor) run() {
	defer close(m.done)
	for {
		select {
		case <-m.stop:
			return
		case <-m.changes:
		}
		timer := time.NewTimer(m.debounce)
	debounce:
		for {
			select {
			case <-m.stop:
				stopTimer(timer)
				return
			case <-m.changes:
				stopTimer(timer)
				timer.Reset(m.debounce)
			case <-timer.C:
				break debounce
			}
		}
		_ = m.Refresh(context.Background())
	}
}

func stopTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (m *Monitor) publish(snapshot Snapshot, err error) {
	copy := cloneSnapshot(snapshot)
	m.current.Store(&copy)
	m.errMu.Lock()
	m.err = err
	m.errMu.Unlock()
}

// Select chooses each family independently. It considers only operational,
// non-owned candidates with a usable global or private unicast source and a
// default route. An explicit selector prefers a case-insensitive interface
// name or GUID match. It does not hide other VPN adapters.
func Select(candidates []Candidate, selector string, owned Owned) Snapshot {
	selector = strings.TrimSpace(selector)
	return Snapshot{
		IPv4: selectFamily(candidates, false, selector, owned),
		IPv6: selectFamily(candidates, true, selector, owned),
	}
}

type rankedPath struct {
	path     Path
	selected bool
}

func selectFamily(candidates []Candidate, ipv6 bool, selector string, owned Owned) *Path {
	ranked := make([]rankedPath, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.IPv6 != ipv6 || !candidate.Operational || candidate.Index == 0 {
			continue
		}
		if owned != nil && owned(candidate.Interface) {
			continue
		}
		source, ok := bestSource(candidate.Addresses, ipv6)
		if !ok {
			continue
		}
		routeMetric, ok := defaultRouteMetric(candidate.Routes, ipv6)
		if !ok {
			continue
		}
		ranked = append(ranked, rankedPath{path: Path{
			InterfaceIndex: candidate.Index, InterfaceLUID: candidate.LUID,
			InterfaceGUID: candidate.GUID, InterfaceName: candidate.Name,
			Source: source, RouteMetric: routeMetric, InterfaceMetric: candidate.InterfaceMetric,
		}, selected: selectorMatches(selector, candidate)})
	}
	if len(ranked) == 0 {
		return nil
	}
	slices.SortFunc(ranked, compareRankedPath)
	result := ranked[0].path
	return &result
}

func selectorMatches(selector string, candidate Candidate) bool {
	if selector == "" {
		return false
	}
	if strings.EqualFold(selector, candidate.Name) || strings.EqualFold(selector, candidate.GUID) {
		return true
	}
	selectorGUID := strings.Trim(selector, "{}")
	candidateGUID := strings.Trim(candidate.GUID, "{}")
	return selectorGUID != "" && candidateGUID != "" && strings.EqualFold(selectorGUID, candidateGUID)
}

func compareRankedPath(a, b rankedPath) int {
	if a.selected != b.selected {
		if a.selected {
			return -1
		}
		return 1
	}
	aTotal := uint64(a.path.RouteMetric) + uint64(a.path.InterfaceMetric)
	bTotal := uint64(b.path.RouteMetric) + uint64(b.path.InterfaceMetric)
	if aTotal < bTotal {
		return -1
	}
	if aTotal > bTotal {
		return 1
	}
	if value := compareUint32(a.path.RouteMetric, b.path.RouteMetric); value != 0 {
		return value
	}
	if value := compareUint32(a.path.InterfaceMetric, b.path.InterfaceMetric); value != 0 {
		return value
	}
	if value := strings.Compare(strings.ToLower(a.path.InterfaceGUID), strings.ToLower(b.path.InterfaceGUID)); value != 0 {
		return value
	}
	if value := strings.Compare(strings.ToLower(a.path.InterfaceName), strings.ToLower(b.path.InterfaceName)); value != 0 {
		return value
	}
	if a.path.InterfaceLUID < b.path.InterfaceLUID {
		return -1
	}
	if a.path.InterfaceLUID > b.path.InterfaceLUID {
		return 1
	}
	if value := compareUint32(a.path.InterfaceIndex, b.path.InterfaceIndex); value != 0 {
		return value
	}
	return a.path.Source.Compare(b.path.Source)
}

func bestSource(addresses []Address, ipv6 bool) (netip.Addr, bool) {
	var result netip.Addr
	for _, item := range addresses {
		address := item.Address.Unmap()
		if !item.Usable || !address.IsValid() || address.Is6() != ipv6 ||
			!address.IsGlobalUnicast() || address.IsLinkLocalUnicast() {
			continue
		}
		if !result.IsValid() || address.Compare(result) < 0 {
			result = address
		}
	}
	return result, result.IsValid()
}

func defaultRouteMetric(routes []Route, ipv6 bool) (uint32, bool) {
	var metric uint32
	found := false
	for _, route := range routes {
		destination := route.Destination.Masked()
		if !destination.IsValid() || destination.Addr().Is6() != ipv6 || destination.Bits() != 0 {
			continue
		}
		if !found || route.Metric < metric {
			metric, found = route.Metric, true
		}
	}
	return metric, found
}

func compareUint32(a, b uint32) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	result := Snapshot{}
	if snapshot.IPv4 != nil {
		path := *snapshot.IPv4
		result.IPv4 = &path
	}
	if snapshot.IPv6 != nil {
		path := *snapshot.IPv6
		result.IPv6 = &path
	}
	return result
}
