package owner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
)

var errDenied = errors.New("access denied")

func TestResolverCachesAndClonesResult(t *testing.T) {
	now := time.Unix(100, 0)
	lookups := 0
	processes := &fakeProcessSource{creation: map[int]time.Time{42: now}, paths: map[int]string{42: `C:\Program Files\app.exe`}}
	resolver := newTestResolver(t, Config{}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
		lookups++
		return &sockowner.SocketOwner{PIDs: []int{42}}, nil
	}, processes, func() time.Time { return now })
	flow := testFlow(1)
	first, err := resolver.Owner(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	first.Owner.PIDs[0] = 99
	first.Processes[0].ExecutablePath = "changed"
	second, err := resolver.Owner(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 || second.Owner.PIDs[0] != 42 || second.Processes[0].ExecutablePath != `C:\Program Files\app.exe` {
		t.Fatalf("cached result was aliased or missed: lookups=%d result=%+v", lookups, second)
	}
}

func TestResolverInvalidatesFlowOnPIDReuse(t *testing.T) {
	now := time.Unix(100, 0)
	identity := now
	lookups := 0
	processes := &fakeProcessSource{creationFunc: func(int) (time.Time, error) { return identity, nil }, paths: map[int]string{42: "old.exe", 43: "new.exe"}}
	resolver := newTestResolver(t, Config{}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
		lookups++
		pid := 42
		if lookups > 1 {
			pid = 43
		}
		return &sockowner.SocketOwner{PIDs: []int{pid}}, nil
	}, processes, func() time.Time { return now })
	flow := testFlow(1)
	if _, err := resolver.Owner(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	identity = identity.Add(time.Second)
	result, err := resolver.Owner(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 2 || result.Processes[0].PID != 43 {
		t.Fatalf("PID reuse did not invalidate flow: lookups=%d result=%+v", lookups, result)
	}
}

func TestResolverClassifiesAndNegativeCachesMissingOwners(t *testing.T) {
	now := time.Unix(100, 0)
	for _, test := range []struct {
		name            string
		owner           *sockowner.SocketOwner
		sourceErr, want error
	}{
		{name: "nil", want: ErrUnknownOwner},
		{name: "no PID", owner: &sockowner.SocketOwner{}, want: ErrUnknownOwner},
		{name: "no row", sourceErr: sockowner.ErrNoOwner, want: ErrUnknownOwner},
		{name: "wildcard ambiguous", sourceErr: sockowner.ErrAUW, want: ErrAmbiguousOwner},
		{name: "multiple PIDs", owner: &sockowner.SocketOwner{PIDs: []int{4, 5}}, want: ErrAmbiguousOwner},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			resolver := newTestResolver(t, Config{}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) { calls++; return test.owner, test.sourceErr }, &fakeProcessSource{}, func() time.Time { return now })
			for range 2 {
				if _, err := resolver.Owner(context.Background(), testFlow(1)); !errors.Is(err, test.want) {
					t.Fatalf("Owner() error = %v", err)
				}
			}
			if calls != 1 {
				t.Fatalf("lookup calls = %d, want 1", calls)
			}
		})
	}
}

func TestResolverPreservesEnrichmentFailure(t *testing.T) {
	processes := &fakeProcessSource{identityErr: errDenied}
	resolver := newTestResolver(t, Config{}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
		return &sockowner.SocketOwner{PIDs: []int{42}}, nil
	}, processes, time.Now)
	for range 2 {
		result, err := resolver.Owner(context.Background(), testFlow(1))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Processes) != 1 || !errors.Is(result.Processes[0].EnrichmentErr, errDenied) {
			t.Fatalf("Owner() result = %+v", result)
		}
	}
	if processes.identityCalls != 1 {
		t.Fatalf("identity calls = %d, want one negatively cached call", processes.identityCalls)
	}
}

func TestResolverRetriesOnlyBoundedSizeRaces(t *testing.T) {
	retry := errors.New("table grew")
	calls := 0
	resolver := newTestResolver(t, Config{LookupRetries: 3}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
		calls++
		if calls < 3 {
			return nil, retry
		}
		return &sockowner.SocketOwner{PIDs: []int{42}}, nil
	}, &fakeProcessSource{creation: map[int]time.Time{42: time.Unix(1, 0)}, paths: map[int]string{42: "app.exe"}}, time.Now)
	resolver.retryable = func(err error) bool { return errors.Is(err, retry) }
	if _, err := resolver.Owner(context.Background(), testFlow(1)); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("lookup calls = %d", calls)
	}

	calls = 0
	resolver = newTestResolver(t, Config{LookupRetries: 3}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) { calls++; return nil, retry }, &fakeProcessSource{}, time.Now)
	resolver.retryable = func(err error) bool { return errors.Is(err, retry) }
	if _, err := resolver.Owner(context.Background(), testFlow(2)); !errors.Is(err, retry) {
		t.Fatalf("Owner() error = %v", err)
	}
	if calls != 3 {
		t.Fatalf("lookup calls = %d", calls)
	}
}

func TestResolverCachesRemainBoundedDuringChurn(t *testing.T) {
	const limit = 8
	processes := &fakeProcessSource{creationFunc: func(pid int) (time.Time, error) { return time.Unix(int64(pid), 0), nil }, pathFunc: func(pid int) (string, error) { return fmt.Sprintf("%d.exe", pid), nil }}
	resolver := newTestResolver(t, Config{MaxFlowEntries: limit, MaxProcessEntries: limit}, func(flow sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
		return &sockowner.SocketOwner{PIDs: []int{int(flow.LocalPort)}}, nil
	}, processes, time.Now)
	for i := 1; i <= 100; i++ {
		if _, err := resolver.Owner(context.Background(), testFlow(uint16(i))); err != nil {
			t.Fatal(err)
		}
	}
	if resolver.flows.order.Len() != limit || len(resolver.flows.items) != limit {
		t.Fatalf("flow cache size = %d/%d", resolver.flows.order.Len(), len(resolver.flows.items))
	}
	if resolver.process.order.Len() != limit || len(resolver.process.items) != limit {
		t.Fatalf("process cache size = %d/%d", resolver.process.order.Len(), len(resolver.process.items))
	}
}

func TestResolverConcurrentAccess(t *testing.T) {
	processes := &fakeProcessSource{creation: map[int]time.Time{42: time.Unix(1, 0)}, paths: map[int]string{42: "app.exe"}}
	resolver := newTestResolver(t, Config{}, func(sockowner.FlowTuple) (*sockowner.SocketOwner, error) {
		return &sockowner.SocketOwner{PIDs: []int{42}}, nil
	}, processes, time.Now)
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(port uint16) {
			defer group.Done()
			for range 100 {
				_, _ = resolver.Owner(context.Background(), testFlow(port))
			}
		}(uint16(i + 1))
	}
	group.Wait()
}

func newTestResolver(t *testing.T, config Config, lookup socketLookup, processes ProcessSource, now func() time.Time) *Resolver {
	t.Helper()
	resolver, err := newResolver(config, lookup, processes, now)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func testFlow(port uint16) sockowner.FlowTuple {
	return sockowner.FlowTuple{Proto: "tcp", LocalIP: net.ParseIP("192.0.2.1"), LocalPort: port, RemoteIP: net.ParseIP("198.51.100.2"), RemotePort: 443}
}

func TestMakeFlowKeyNormalizesIPv4Representations(t *testing.T) {
	flow := testFlow(80)
	flow.LocalIP = flow.LocalIP.To4()
	key, err := makeFlowKey(flow)
	if err != nil {
		t.Fatalf("makeFlowKey() error = %v", err)
	}
	if !key.local.Is4() || !key.remote.Is4() {
		t.Fatalf("normalized addresses = (%s, %s), want IPv4", key.local, key.remote)
	}
}

type fakeProcessSource struct {
	mu            sync.Mutex
	creation      map[int]time.Time
	paths         map[int]string
	identityErr   error
	creationFunc  func(int) (time.Time, error)
	pathFunc      func(int) (string, error)
	identityCalls int
}

func (s *fakeProcessSource) Identity(_ context.Context, pid int) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityCalls++
	if s.creationFunc != nil {
		return s.creationFunc(pid)
	}
	if s.identityErr != nil {
		return time.Time{}, s.identityErr
	}
	return s.creation[pid], nil
}

func (s *fakeProcessSource) ExecutablePath(_ context.Context, pid int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pathFunc != nil {
		return s.pathFunc(pid)
	}
	return s.paths[pid], nil
}
