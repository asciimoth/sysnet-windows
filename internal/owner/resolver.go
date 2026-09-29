package owner

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
)

const (
	defaultCacheEntries  = 1024
	defaultPositiveTTL   = 2 * time.Second
	defaultNegativeTTL   = 200 * time.Millisecond
	defaultLookupRetries = 3
)

// Config controls bounded owner caches. Zero values select conservative
// defaults suitable for packet-path lookup.
type Config struct {
	MaxFlowEntries    int
	MaxProcessEntries int
	PositiveTTL       time.Duration
	NegativeTTL       time.Duration
	LookupRetries     int
}

// ProcessSource reads process identity separately from executable metadata.
// A Resolver checks Identity even on a flow-cache hit, so PID reuse invalidates
// a cached result before it is returned.
type ProcessSource interface {
	Identity(context.Context, int) (time.Time, error)
	ExecutablePath(context.Context, int) (string, error)
}

type socketLookup func(sockowner.FlowTuple) (*sockowner.SocketOwner, error)

// Resolver combines socket-table lookup, process enrichment, and bounded LRU
// caches. It is safe for concurrent use.
type Resolver struct {
	lookup    socketLookup
	processes ProcessSource
	now       func() time.Time
	retryable func(error) bool
	config    Config
	flows     *lru[flowKey, flowEntry]
	process   *lru[processKey, processEntry]
}

type flowKey struct {
	proto                 string
	local, remote         netip.Addr
	localPort, remotePort uint16
}

type flowEntry struct {
	result  *Result
	err     error
	expires time.Time
}

type processKey struct {
	pid      int
	creation int64
}

type processEntry struct {
	path    string
	err     error
	expires time.Time
}

// newResolver creates an ownership resolver around injected native boundaries.
func newResolver(config Config, lookup socketLookup, processes ProcessSource, now func() time.Time) (*Resolver, error) {
	if lookup == nil || processes == nil {
		return nil, errors.New("create owner resolver without native boundary")
	}
	if now == nil {
		now = time.Now
	}
	config = normalizeConfig(config)
	return &Resolver{
		lookup: lookup, processes: processes, now: now, retryable: isSizeRace, config: config,
		flows:   newLRU[flowKey, flowEntry](config.MaxFlowEntries),
		process: newLRU[processKey, processEntry](config.MaxProcessEntries),
	}, nil
}

func normalizeConfig(config Config) Config {
	if config.MaxFlowEntries <= 0 {
		config.MaxFlowEntries = defaultCacheEntries
	}
	if config.MaxProcessEntries <= 0 {
		config.MaxProcessEntries = defaultCacheEntries
	}
	if config.PositiveTTL <= 0 {
		config.PositiveTTL = defaultPositiveTTL
	}
	if config.NegativeTTL <= 0 {
		config.NegativeTTL = defaultNegativeTTL
	}
	if config.LookupRetries <= 0 {
		config.LookupRetries = defaultLookupRetries
	}
	return config
}

// Owner resolves and enriches a flow. Context cancellation is checked between
// native calls; Windows table APIs themselves are synchronous.
func (r *Resolver) Owner(ctx context.Context, flow sockowner.FlowTuple) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := makeFlowKey(flow)
	if err != nil {
		return nil, err
	}
	now := r.now()
	if cached, ok := r.flows.Get(key); ok && now.Before(cached.expires) {
		if cached.result == nil || r.identitiesCurrent(ctx, cached.result) {
			return cloneResult(cached.result), cached.err
		}
		r.flows.Delete(key)
	}

	owner, err := r.lookupOwner(ctx, flow)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		err = classifyLookupError(err)
		r.flows.Add(key, flowEntry{err: err, expires: now.Add(r.config.NegativeTTL)})
		return nil, err
	}
	if owner == nil || len(owner.PIDs) == 0 {
		r.flows.Add(key, flowEntry{err: ErrUnknownOwner, expires: now.Add(r.config.NegativeTTL)})
		return nil, ErrUnknownOwner
	}
	pids := slices.Clone(owner.PIDs)
	slices.Sort(pids)
	pids = slices.Compact(pids)
	if len(pids) != 1 {
		r.flows.Add(key, flowEntry{err: ErrAmbiguousOwner, expires: now.Add(r.config.NegativeTTL)})
		return nil, ErrAmbiguousOwner
	}

	result := &Result{Owner: cloneSocketOwner(*owner)}
	for _, pid := range pids {
		result.Processes = append(result.Processes, r.enrich(ctx, pid, now))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ttl := r.config.PositiveTTL
	for _, process := range result.Processes {
		if process.EnrichmentErr != nil {
			ttl = r.config.NegativeTTL
			break
		}
	}
	r.flows.Add(key, flowEntry{result: cloneResult(result), expires: now.Add(ttl)})
	return result, nil
}

func (r *Resolver) lookupOwner(ctx context.Context, flow sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
	var owner *sockowner.SocketOwner
	var err error
	for attempt := 0; attempt < r.config.LookupRetries; attempt++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		owner, err = r.lookup(flow)
		if !r.retryable(err) {
			return owner, err
		}
	}
	return nil, fmt.Errorf("socket owner table remained unstable after %d attempts: %w", r.config.LookupRetries, err)
}

func (r *Resolver) enrich(ctx context.Context, pid int, now time.Time) Process {
	negativeKey := processKey{pid: pid}
	if cached, ok := r.process.Get(negativeKey); ok && now.Before(cached.expires) {
		return Process{PID: pid, EnrichmentErr: cached.err}
	}
	creation, err := r.processes.Identity(ctx, pid)
	result := Process{PID: pid, CreationTime: creation}
	if err != nil {
		r.process.Add(negativeKey, processEntry{err: err, expires: now.Add(r.config.NegativeTTL)})
		result.EnrichmentErr = err
		return result
	}
	r.process.Delete(negativeKey)
	key := processKey{pid: pid, creation: creation.UnixNano()}
	if cached, ok := r.process.Get(key); ok && now.Before(cached.expires) {
		result.ExecutablePath, result.EnrichmentErr = cached.path, cached.err
		return result
	}
	path, err := r.processes.ExecutablePath(ctx, pid)
	ttl := r.config.PositiveTTL
	if err != nil {
		ttl = r.config.NegativeTTL
	}
	r.process.Add(key, processEntry{path: path, err: err, expires: now.Add(ttl)})
	result.ExecutablePath, result.EnrichmentErr = path, err
	return result
}

func (r *Resolver) identitiesCurrent(ctx context.Context, result *Result) bool {
	for _, process := range result.Processes {
		if process.CreationTime.IsZero() && process.EnrichmentErr != nil {
			// Identity failures have the short negative flow-cache lifetime. Do
			// not defeat that cache by repeating the denied query here.
			continue
		}
		creation, err := r.processes.Identity(ctx, process.PID)
		if err != nil || !creation.Equal(process.CreationTime) {
			return false
		}
	}
	return true
}

func makeFlowKey(flow sockowner.FlowTuple) (flowKey, error) {
	if flow.Proto != "tcp" && flow.Proto != "udp" {
		return flowKey{}, fmt.Errorf("%w: %s", sockowner.ErrProtocol, flow.Proto)
	}
	local, ok := netip.AddrFromSlice(flow.LocalIP)
	if !ok {
		return flowKey{}, sockowner.ErrInvIP
	}
	remote, ok := netip.AddrFromSlice(flow.RemoteIP)
	if !ok {
		return flowKey{}, sockowner.ErrInvIP
	}
	local = local.Unmap()
	remote = remote.Unmap()
	if local.Is4() != remote.Is4() {
		return flowKey{}, sockowner.ErrInvIP
	}
	return flowKey{proto: flow.Proto, local: local, remote: remote, localPort: flow.LocalPort, remotePort: flow.RemotePort}, nil
}

func classifyLookupError(err error) error {
	if errors.Is(err, sockowner.ErrAEx) || errors.Is(err, sockowner.ErrAUW) {
		return errors.Join(ErrAmbiguousOwner, err)
	}
	if errors.Is(err, sockowner.ErrNoOwner) {
		return errors.Join(ErrUnknownOwner, err)
	}
	return err
}

func cloneResult(result *Result) *Result {
	if result == nil {
		return nil
	}
	clone := &Result{Owner: cloneSocketOwner(result.Owner), Processes: slices.Clone(result.Processes)}
	return clone
}

func cloneSocketOwner(owner sockowner.SocketOwner) sockowner.SocketOwner {
	owner.PIDs = slices.Clone(owner.PIDs)
	if owner.UID != nil {
		value := *owner.UID
		owner.UID = &value
	}
	if owner.GID != nil {
		value := *owner.GID
		owner.GID = &value
	}
	return owner
}

type lru[K comparable, V any] struct {
	capacity int
	items    map[K]*list.Element
	order    *list.List
	mu       sync.Mutex
}

type lruItem[K comparable, V any] struct {
	key   K
	value V
}

func newLRU[K comparable, V any](capacity int) *lru[K, V] {
	return &lru[K, V]{capacity: capacity, items: make(map[K]*list.Element), order: list.New()}
}

func (c *lru[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(element)
	return element.Value.(lruItem[K, V]).value, true
}

func (c *lru[K, V]) Add(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.items[key]; ok {
		element.Value = lruItem[K, V]{key, value}
		c.order.MoveToFront(element)
		return
	}
	c.items[key] = c.order.PushFront(lruItem[K, V]{key, value})
	if c.order.Len() <= c.capacity {
		return
	}
	oldest := c.order.Back()
	item := oldest.Value.(lruItem[K, V])
	delete(c.items, item.key)
	c.order.Remove(oldest)
}

func (c *lru[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.items[key]; ok {
		delete(c.items, key)
		c.order.Remove(element)
	}
}
