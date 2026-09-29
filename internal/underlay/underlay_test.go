package underlay

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestN17N19N20SelectRanksAndFiltersCandidates(t *testing.T) {
	t.Parallel()
	v4 := netip.MustParsePrefix("0.0.0.0/0")
	base := []Candidate{
		candidate("slow-route", 1, false, "192.0.2.1", v4, 20, 1),
		candidate("best-total", 2, false, "192.0.2.2", v4, 5, 5),
		candidate("equal-route", 3, false, "192.0.2.3", v4, 5, 10),
		candidate("down", 4, false, "192.0.2.4", v4, 1, 1),
	}
	base[3].Operational = false

	t.Run("N17 route and interface metrics", func(t *testing.T) {
		got := Select(base, "", nil)
		if got.IPv4 == nil || got.IPv4.InterfaceName != "best-total" {
			t.Fatalf("IPv4 path = %+v, want best-total", got.IPv4)
		}
	})

	t.Run("unusable source and unreachable destination", func(t *testing.T) {
		badSource := candidate("bad-source", 5, false, "169.254.1.1", v4, 0, 0)
		badRoute := candidate("bad-route", 6, false, "192.0.2.6", netip.MustParsePrefix("203.0.113.0/24"), 0, 0)
		got := Select([]Candidate{badSource, badRoute}, "", nil)
		if got.IPv4 != nil {
			t.Fatalf("IPv4 path = %+v, want unavailable", got.IPv4)
		}
	})

	t.Run("N19 owned adapters excluded but other VPN retained", func(t *testing.T) {
		vpn := candidate("other-vpn", 7, false, "198.51.100.7", v4, 1, 1)
		owned := candidate("owned", 8, false, "198.51.100.8", v4, 0, 0)
		got := Select([]Candidate{owned, vpn}, "", func(iface Interface) bool { return iface.LUID == 8 })
		if got.IPv4 == nil || got.IPv4.InterfaceName != "other-vpn" {
			t.Fatalf("IPv4 path = %+v, want other-vpn", got.IPv4)
		}
	})

	t.Run("N20 explicit selector has first priority", func(t *testing.T) {
		got := Select(base, "SLOW-ROUTE", nil)
		if got.IPv4 == nil || got.IPv4.InterfaceName != "slow-route" {
			t.Fatalf("IPv4 path = %+v, want slow-route", got.IPv4)
		}
	})

	t.Run("stable tie breaker", func(t *testing.T) {
		zulu := candidate("zulu", 10, false, "192.0.2.10", v4, 5, 5)
		zulu.GUID = "{bbbbbbbb-0000-0000-0000-000000000000}"
		alpha := candidate("alpha", 11, false, "192.0.2.11", v4, 5, 5)
		alpha.GUID = "{aaaaaaaa-0000-0000-0000-000000000000}"
		for _, input := range [][]Candidate{{zulu, alpha}, {alpha, zulu}} {
			got := Select(input, "", nil)
			if got.IPv4 == nil || got.IPv4.InterfaceName != "alpha" {
				t.Fatalf("IPv4 path = %+v, want alpha", got.IPv4)
			}
		}
	})
}

func TestN18SelectPublishesFamiliesIndependently(t *testing.T) {
	t.Parallel()
	v4 := candidate("v4", 4, false, "192.0.2.4", netip.MustParsePrefix("0.0.0.0/0"), 10, 10)
	v6 := candidate("v6", 6, true, "2001:db8::6", netip.MustParsePrefix("::/0"), 5, 5)

	got := Select([]Candidate{v6, v4}, "", nil)
	if got.IPv4 == nil || got.IPv4.InterfaceIndex != 4 {
		t.Fatalf("IPv4 path = %+v, want index 4", got.IPv4)
	}
	if got.IPv6 == nil || got.IPv6.InterfaceIndex != 6 {
		t.Fatalf("IPv6 path = %+v, want index 6", got.IPv6)
	}
}

func TestN21N24MonitorReconcilesNetworkChanges(t *testing.T) {
	v4Default := netip.MustParsePrefix("0.0.0.0/0")
	v6Default := netip.MustParsePrefix("::/0")
	source := &fakeSource{candidates: []Candidate{
		candidate("v4", 4, false, "192.0.2.4", v4Default, 1, 1),
		candidate("v6", 6, true, "2001:db8::6", v6Default, 1, 1),
	}}
	monitor, err := newMonitor(source, "", nil, time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := monitor.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	t.Run("N21 underlay loss", func(t *testing.T) {
		source.replace([]Candidate{candidate("v6", 6, true, "2001:db8::6", v6Default, 1, 1)})
		source.signal()
		waitSnapshot(t, monitor, func(snapshot Snapshot) bool { return snapshot.IPv4 == nil && snapshot.IPv6 != nil })
	})

	t.Run("N22 DHCP address change", func(t *testing.T) {
		source.replace([]Candidate{candidate("v4", 4, false, "192.0.2.44", v4Default, 1, 1)})
		source.signal()
		waitSnapshot(t, monitor, func(snapshot Snapshot) bool {
			return snapshot.IPv4 != nil && snapshot.IPv4.Source == netip.MustParseAddr("192.0.2.44") && snapshot.IPv6 == nil
		})
	})

	t.Run("N23 interface recreation changes current identifiers", func(t *testing.T) {
		recreated := candidate("v4", 40, false, "192.0.2.44", v4Default, 1, 1)
		recreated.GUID = "stable-guid"
		recreated.Index = 40
		source.replace([]Candidate{recreated})
		source.signal()
		waitSnapshot(t, monitor, func(snapshot Snapshot) bool {
			return snapshot.IPv4 != nil && snapshot.IPv4.InterfaceLUID == 40 && snapshot.IPv4.InterfaceIndex == 40
		})
	})

	t.Run("N24 resume burst uses one replacement read", func(t *testing.T) {
		before := source.readCount()
		source.replace([]Candidate{
			candidate("v4-resumed", 41, false, "192.0.2.45", v4Default, 1, 1),
			candidate("v6-resumed", 61, true, "2001:db8::61", v6Default, 1, 1),
		})
		for range 20 {
			source.signal()
		}
		waitSnapshot(t, monitor, func(snapshot Snapshot) bool {
			return snapshot.IPv4 != nil && snapshot.IPv4.InterfaceIndex == 41 &&
				snapshot.IPv6 != nil && snapshot.IPv6.InterfaceIndex == 61
		})
		if reads := source.readCount() - before; reads != 1 {
			t.Fatalf("burst caused %d reads, want 1", reads)
		}
	})
}

func TestMonitorReadFailureMakesBothFamiliesUnavailable(t *testing.T) {
	source := &fakeSource{candidates: []Candidate{
		candidate("v4", 4, false, "192.0.2.4", netip.MustParsePrefix("0.0.0.0/0"), 1, 1),
	}}
	monitor, err := newMonitor(source, "", nil, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = monitor.Close() })
	wantErr := errors.New("table read failed")
	source.fail(wantErr)
	source.signal()
	waitSnapshot(t, monitor, func(snapshot Snapshot) bool {
		return monitor.LastError() != nil && snapshot.IPv4 == nil && snapshot.IPv6 == nil
	})
	if !errors.Is(monitor.LastError(), wantErr) {
		t.Fatalf("LastError = %v, want %v", monitor.LastError(), wantErr)
	}
}

func TestMonitorObserverRunsAfterReplacementPublication(t *testing.T) {
	source := &fakeSource{}
	monitor, err := newMonitor(source, "", nil, time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = monitor.Close() })
	observed := make(chan Snapshot, 1)
	monitor.SetObserver(func() { observed <- monitor.Snapshot() })
	source.replace([]Candidate{
		candidate("changed", 9, false, "192.0.2.9", netip.MustParsePrefix("0.0.0.0/0"), 1, 1),
	})
	source.signal()
	select {
	case snapshot := <-observed:
		if snapshot.IPv4 == nil || snapshot.IPv4.InterfaceIndex != 9 {
			t.Fatalf("observer snapshot = %+v, want replacement", snapshot)
		}
	case <-time.After(time.Second):
		t.Fatal("observer was not called")
	}
}

func TestMonitorStartupAndCloseFailures(t *testing.T) {
	t.Run("subscribe failure", func(t *testing.T) {
		wantErr := errors.New("subscribe failed")
		_, err := newMonitor(&fakeSource{subscribeErr: wantErr}, "", nil, time.Second, 0)
		if !errors.Is(err, wantErr) {
			t.Fatalf("NewMonitor error = %v, want %v", err, wantErr)
		}
	})
	t.Run("initial read failure unregisters", func(t *testing.T) {
		wantErr := errors.New("read failed")
		closeErr := errors.New("unregister failed")
		source := &fakeSource{err: wantErr, closeErr: closeErr, closeFailures: 1}
		_, err := newMonitor(source, "", nil, time.Second, 0)
		if !errors.Is(err, wantErr) || !errors.Is(err, closeErr) || source.closeCount() != 1 {
			t.Fatalf("NewMonitor error = %v, closes = %d", err, source.closeCount())
		}
	})
	t.Run("close is idempotent", func(t *testing.T) {
		source := &fakeSource{}
		monitor, err := newMonitor(source, "", nil, time.Second, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := monitor.Close(); err != nil {
			t.Fatal(err)
		}
		if err := monitor.Close(); err != nil {
			t.Fatal(err)
		}
		if source.closeCount() != 1 {
			t.Fatalf("subscription closes = %d, want 1", source.closeCount())
		}
	})
	t.Run("failed close can be retried", func(t *testing.T) {
		wantErr := errors.New("unregister failed")
		source := &fakeSource{closeErr: wantErr, closeFailures: 1}
		monitor, err := newMonitor(source, "", nil, time.Second, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := monitor.Close(); !errors.Is(err, wantErr) {
			t.Fatalf("first Close error = %v, want %v", err, wantErr)
		}
		if err := monitor.Close(); err != nil {
			t.Fatalf("second Close error = %v", err)
		}
		if source.closeCount() != 2 {
			t.Fatalf("subscription closes = %d, want 2", source.closeCount())
		}
	})
}

func candidate(name string, id uint64, ipv6 bool, address string, destination netip.Prefix, routeMetric, interfaceMetric uint32) Candidate {
	return Candidate{
		Interface: Interface{LUID: id, Index: uint32(id), Name: name},
		IPv6:      ipv6, Operational: true, InterfaceMetric: interfaceMetric,
		Addresses: []Address{{Address: netip.MustParseAddr(address), Usable: true}},
		Routes:    []Route{{Destination: destination, Metric: routeMetric}},
	}
}

func waitSnapshot(t *testing.T, monitor *Monitor, accept func(Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if accept(monitor.Snapshot()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("snapshot did not converge: %+v; error: %v", monitor.Snapshot(), monitor.LastError())
}

type fakeSource struct {
	mu            sync.Mutex
	candidates    []Candidate
	err           error
	subscribeErr  error
	notify        func()
	reads         int
	closes        int
	closeErr      error
	closeFailures int
}

func (s *fakeSource) ReadCandidates(ctx context.Context) ([]Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]Candidate(nil), s.candidates...), s.err
}

func (s *fakeSource) SubscribeChanges(notify func()) (Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribeErr != nil {
		return nil, s.subscribeErr
	}
	s.notify = notify
	return fakeSubscription{close: func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closes++
		if s.closeFailures > 0 {
			s.closeFailures--
			return s.closeErr
		}
		return nil
	}}, nil
}

func (s *fakeSource) replace(candidates []Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append([]Candidate(nil), candidates...)
	s.err = nil
}

func (s *fakeSource) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *fakeSource) signal() {
	s.mu.Lock()
	notify := s.notify
	s.mu.Unlock()
	notify()
}

func (s *fakeSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *fakeSource) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

type fakeSubscription struct{ close func() error }

func (s fakeSubscription) Close() error {
	return s.close()
}
