package netio

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

var testInterface = Interface{LUID: 41, Index: 7}

type fakeStore struct {
	mu                sync.Mutex
	state             State
	wait              func(context.Context, netip.Addr) error
	noRoute           bool
	tentativeAddress  bool
	failDeleteAddress bool
	deleteAddressErr  error
	createAddressAs   *netip.Prefix
	createAddressErr  error
	createRouteAs     *Route
	createRouteErr    error
	propertiesResult  *Properties
	propertiesError   error
	propertiesHook    func(*fakeStore, Properties) error
	log               []string
	snapshots         int
	beforeSnapshot    func(*fakeStore, int)
}

func (s *fakeStore) Snapshot(ctx context.Context, _ Interface) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots++
	if s.beforeSnapshot != nil {
		s.beforeSnapshot(s, s.snapshots)
	}
	result := s.state
	result.Addresses = append([]Address(nil), s.state.Addresses...)
	result.Routes = append([]Route(nil), s.state.Routes...)
	result.Properties = append([]Properties(nil), s.state.Properties...)
	return result, nil
}

func (s *fakeStore) CreateAddress(_ context.Context, _ Interface, prefix netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, "add-address "+prefix.String())
	if s.createAddressAs != nil {
		prefix = *s.createAddressAs
	}
	s.state.Addresses = append(s.state.Addresses, Address{Prefix: prefix, Usable: !s.tentativeAddress})
	return s.createAddressErr
}

func (s *fakeStore) DeleteAddress(_ context.Context, _ Interface, prefix netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, "delete-address "+prefix.String())
	if s.failDeleteAddress {
		return errors.New("injected address delete failure")
	}
	for index, row := range s.state.Addresses {
		if row.Prefix.Addr() == prefix.Addr() {
			s.state.Addresses = append(s.state.Addresses[:index], s.state.Addresses[index+1:]...)
			return s.deleteAddressErr
		}
	}
	return errors.New("address not found")
}

func (s *fakeStore) WaitAddressUsable(ctx context.Context, _ Interface, address netip.Addr) error {
	if s.wait != nil {
		return s.wait(ctx, address)
	}
	return nil
}

func (s *fakeStore) CreateRoute(_ context.Context, _ Interface, route Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, "add-route "+route.Destination.String())
	if s.createRouteAs != nil {
		route = *s.createRouteAs
	}
	if !s.noRoute {
		s.state.Routes = append(s.state.Routes, route)
	}
	return s.createRouteErr
}

func (s *fakeStore) DeleteRoute(_ context.Context, _ Interface, route Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, "delete-route "+route.Destination.String())
	key := routeKey(route)
	for index, row := range s.state.Routes {
		if routeKey(row) == key {
			s.state.Routes = append(s.state.Routes[:index], s.state.Routes[index+1:]...)
			return nil
		}
	}
	return errors.New("route not found")
}

func (s *fakeStore) SetProperties(_ context.Context, _ Interface, properties Properties) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, "set-properties")
	if s.propertiesHook != nil {
		return s.propertiesHook(s, properties)
	}
	for index, row := range s.state.Properties {
		if row.Family == properties.Family {
			if s.propertiesResult != nil {
				s.state.Properties[index] = *s.propertiesResult
			} else {
				s.state.Properties[index] = properties
			}
			return s.propertiesError
		}
	}
	return errors.New("properties not found")
}

func TestExactManagerRequiresRecoveryAfterUncertainPropertyMutation(t *testing.T) {
	original := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	desired := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 5}
	partial := Properties{Family: FamilyIPv4, MTU: desired.MTU, Metric: original.Metric, AutomaticMetric: true}
	mutationErr := errors.New("native property update failed after mutation")
	store := &fakeStore{
		state:            State{Interface: testInterface, Properties: []Properties{original}},
		propertiesResult: &partial,
		propertiesError:  mutationErr,
	}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Apply(context.Background(), testInterface, Config{Properties: []Properties{desired}})
	if !errors.Is(err, mutationErr) || !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("Apply() error = %v, want mutation and rollback-conflict errors", err)
	}
	if !RequiresRecovery(err) {
		t.Fatalf("Apply() error = %v, want recovery required for changed host properties", err)
	}
	if got := store.state.Properties[0]; got != partial {
		t.Fatalf("properties after failed mutation = %+v, want evidence value %+v", got, partial)
	}
}

func TestExactManagerRequiresRecoveryAfterUncertainRowMutation(t *testing.T) {
	t.Parallel()
	mutationErr := errors.New("native row update failed after mutation")
	tests := []struct {
		name      string
		configure func(*fakeStore)
		config    Config
	}{
		{
			name: "address",
			configure: func(store *fakeStore) {
				partial := netip.MustParsePrefix("10.19.0.1/25")
				store.createAddressAs = &partial
				store.createAddressErr = mutationErr
			},
			config: Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.19.0.1/24")}},
		},
		{
			name: "route",
			configure: func(store *fakeStore) {
				partial := Route{
					Destination: netip.MustParsePrefix("203.0.113.0/24"),
					NextHop:     netip.IPv4Unspecified(),
					Metric:      6,
				}
				store.createRouteAs = &partial
				store.createRouteErr = mutationErr
			},
			config: Config{Routes: []Route{{
				Destination: netip.MustParsePrefix("203.0.113.0/24"),
				NextHop:     netip.IPv4Unspecified(),
				Metric:      5,
			}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{state: State{Interface: testInterface}}
			test.configure(store)
			manager, err := NewManager(store)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}
			err = manager.Apply(context.Background(), testInterface, test.config)
			if !errors.Is(err, mutationErr) || !errors.Is(err, ErrResourceConflict) {
				t.Fatalf("Apply() error = %v, want mutation and rollback-conflict errors", err)
			}
			if !RequiresRecovery(err) {
				t.Fatalf("Apply() error = %v, want recovery required", err)
			}
		})
	}
}

func TestExactManagerAcceptsFailedInverseWithVerifiedCleanup(t *testing.T) {
	inverseErr := errors.New("delete reported failure after mutation")
	store := &fakeStore{
		state:            State{Interface: testInterface},
		noRoute:          true,
		deleteAddressErr: inverseErr,
	}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	prefix := netip.MustParsePrefix("10.19.0.1/24")
	route := Route{
		Destination: netip.MustParsePrefix("203.0.113.0/24"),
		NextHop:     netip.IPv4Unspecified(),
		Metric:      5,
	}
	err = manager.Apply(context.Background(), testInterface, Config{
		Addresses: []netip.Prefix{prefix}, Routes: []Route{route},
	})
	if !errors.Is(err, ErrReadback) || !errors.Is(err, inverseErr) {
		t.Fatalf("Apply() error = %v, want readback and inverse errors", err)
	}
	if RequiresRecovery(err) {
		t.Fatalf("Apply() error = %v, want verified cleanup without recovery", err)
	}
	if len(store.state.Addresses) != 0 {
		t.Fatalf("addresses after rollback = %+v, want empty", store.state.Addresses)
	}
}

func TestExactManagerReplacementRollbackDoesNotRequireRecovery(t *testing.T) {
	originalProperties := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	firstAddress := netip.MustParsePrefix("10.19.0.1/24")
	secondAddress := netip.MustParsePrefix("10.19.0.1/25")
	peerAddress := netip.MustParsePrefix("10.19.1.1/24")
	firstRoute := Route{Destination: netip.MustParsePrefix("10.20.0.0/16"), NextHop: netip.IPv4Unspecified(), Metric: 5}
	secondRoute := firstRoute
	secondRoute.Metric = 8
	peerRoute := Route{Destination: netip.MustParsePrefix("10.21.0.0/16"), NextHop: netip.IPv4Unspecified(), Metric: 6}
	firstProperties := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 3}
	secondProperties := Properties{Family: FamilyIPv4, MTU: 1300, Metric: 4}
	tests := []struct {
		name   string
		first  Config
		second Config
	}{
		{
			name: "address prefix",
			first: Config{
				Addresses: []netip.Prefix{firstAddress}, Properties: []Properties{firstProperties},
			},
			second: Config{
				Addresses: []netip.Prefix{secondAddress}, Properties: []Properties{secondProperties},
			},
		},
		{
			name: "route metric",
			first: Config{
				Routes: []Route{firstRoute}, Properties: []Properties{firstProperties},
			},
			second: Config{
				Routes: []Route{secondRoute}, Properties: []Properties{secondProperties},
			},
		},
		{
			name: "address and route",
			first: Config{
				Addresses: []netip.Prefix{firstAddress}, Routes: []Route{firstRoute},
				Properties: []Properties{firstProperties},
			},
			second: Config{
				Addresses: []netip.Prefix{secondAddress}, Routes: []Route{secondRoute},
				Properties: []Properties{secondProperties},
			},
		},
		{
			name: "replacement and new peer keys",
			first: Config{
				Addresses: []netip.Prefix{firstAddress}, Routes: []Route{firstRoute},
				Properties: []Properties{firstProperties},
			},
			second: Config{
				Addresses: []netip.Prefix{secondAddress, peerAddress}, Routes: []Route{secondRoute, peerRoute},
				Properties: []Properties{secondProperties},
			},
		},
		{
			name: "replacement and removed peer keys",
			first: Config{
				Addresses: []netip.Prefix{firstAddress, peerAddress}, Routes: []Route{firstRoute, peerRoute},
				Properties: []Properties{firstProperties},
			},
			second: Config{
				Addresses: []netip.Prefix{secondAddress}, Routes: []Route{secondRoute},
				Properties: []Properties{secondProperties},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{state: State{Interface: testInterface, Properties: []Properties{originalProperties}}}
			manager, err := NewManager(store)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}
			if err := manager.Apply(context.Background(), testInterface, test.first); err != nil {
				t.Fatalf("initial Apply() error = %v", err)
			}

			store.propertiesError = errors.New("property update failed after mutation")
			err = manager.Apply(context.Background(), testInterface, test.second)
			if err == nil {
				t.Fatal("replacement Apply() error = nil")
			}
			if RequiresRecovery(err) {
				t.Fatalf("replacement Apply() error = %v, want verified rollback without recovery", err)
			}
			assertConfig(t, manager, test.first)

			store.propertiesError = nil
			if err := manager.Apply(context.Background(), testInterface, test.second); err != nil {
				t.Fatalf("replacement retry Apply() error = %v", err)
			}
			assertConfig(t, manager, test.second)
			if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
				t.Fatalf("cleanup Apply() error = %v", err)
			}
			state, err := store.Snapshot(context.Background(), testInterface)
			if err != nil {
				t.Fatalf("Snapshot() error = %v", err)
			}
			if len(state.Addresses) != 0 || len(state.Routes) != 0 || !slices.Equal(state.Properties, []Properties{originalProperties}) {
				t.Fatalf("state after cleanup = %+v, want only original properties %+v", state, originalProperties)
			}
		})
	}
}

func TestExactManagerReplacementRollbackRequiresRecoveryWhenOldValueIsNotRestored(t *testing.T) {
	originalProperties := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	firstProperties := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 3}
	secondProperties := Properties{Family: FamilyIPv4, MTU: 1300, Metric: 4}
	firstAddress := netip.MustParsePrefix("10.19.0.1/24")
	secondAddress := netip.MustParsePrefix("10.19.0.1/25")
	store := &fakeStore{state: State{Interface: testInterface, Properties: []Properties{originalProperties}}}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	first := Config{Addresses: []netip.Prefix{firstAddress}, Properties: []Properties{firstProperties}}
	if err := manager.Apply(context.Background(), testInterface, first); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	propertyCalls := 0
	primaryErr := errors.New("property update failed after mutation")
	store.propertiesHook = func(store *fakeStore, properties Properties) error {
		propertyCalls++
		store.state.Properties[0] = properties
		if propertyCalls == 1 {
			store.failDeleteAddress = true
			return primaryErr
		}
		return nil
	}
	err = manager.Apply(context.Background(), testInterface, Config{
		Addresses: []netip.Prefix{secondAddress}, Properties: []Properties{secondProperties},
	})
	if !errors.Is(err, primaryErr) || !RequiresRecovery(err) {
		t.Fatalf("replacement Apply() error = %v, want primary error with recovery required", err)
	}
	if len(store.state.Addresses) != 1 || store.state.Addresses[0].Prefix != secondAddress {
		t.Fatalf("address after incomplete rollback = %+v, want retained replacement %s", store.state.Addresses, secondAddress)
	}

	store.propertiesHook = nil
	store.failDeleteAddress = false
	if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
		t.Fatalf("cleanup retained replacement error = %v", err)
	}
	state, err := store.Snapshot(context.Background(), testInterface)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(state.Addresses) != 0 || !slices.Equal(state.Properties, []Properties{originalProperties}) {
		t.Fatalf("state after recovery cleanup = %+v, want only original properties %+v", state, originalProperties)
	}
}

func TestT04T06ExactManagerOwnedDeltaPreservesForeignRows(t *testing.T) {
	foreignAddress := Address{Prefix: netip.MustParsePrefix("192.0.2.9/24"), Usable: true}
	foreignRoute := Route{Destination: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("0.0.0.0"), Metric: 90}
	originalProperties := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	store := &fakeStore{state: State{
		Interface: testInterface, Addresses: []Address{foreignAddress}, Routes: []Route{foreignRoute},
		Properties: []Properties{originalProperties},
	}}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	firstAddress := netip.MustParsePrefix("10.19.0.1/24")
	firstRoute := Route{Destination: netip.MustParsePrefix("10.20.0.0/16"), NextHop: netip.MustParseAddr("0.0.0.0"), Metric: 5}
	appliedProperties := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 3}
	first := Config{Addresses: []netip.Prefix{firstAddress}, Routes: []Route{firstRoute}, Properties: []Properties{appliedProperties}}
	if err := manager.Apply(context.Background(), testInterface, first); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	assertConfig(t, manager, first)

	secondAddress := netip.MustParsePrefix("10.19.0.1/25")
	secondRoute := firstRoute
	secondRoute.Metric = 8
	second := Config{Addresses: []netip.Prefix{secondAddress}, Routes: []Route{secondRoute}, Properties: []Properties{{Family: FamilyIPv4, MTU: 1300, Metric: 4}}}
	if err := manager.Apply(context.Background(), testInterface, second); err != nil {
		t.Fatalf("replacement Apply() error = %v", err)
	}
	assertConfig(t, manager, second)
	if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
		t.Fatalf("cleanup Apply() error = %v", err)
	}

	state, _ := store.Snapshot(context.Background(), testInterface)
	if !slices.Equal(state.Addresses, []Address{foreignAddress}) {
		t.Fatalf("addresses after cleanup = %+v, want foreign sentinel %+v", state.Addresses, foreignAddress)
	}
	if !slices.Equal(state.Routes, []Route{foreignRoute}) {
		t.Fatalf("routes after cleanup = %+v, want foreign sentinel %+v", state.Routes, foreignRoute)
	}
	if !slices.Equal(state.Properties, []Properties{originalProperties}) {
		t.Fatalf("properties after cleanup = %+v, want restored %+v", state.Properties, originalProperties)
	}
}

func TestExactManagerCleanupContinuesAfterOwnedStateDisappears(t *testing.T) {
	originalProperties := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	address := netip.MustParsePrefix("10.19.0.1/24")
	route := Route{Destination: netip.MustParsePrefix("10.20.0.0/16"), NextHop: netip.IPv4Unspecified(), Metric: 5}
	appliedProperties := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 3}
	tests := []struct {
		name   string
		remove func(*fakeStore)
	}{
		{name: "address", remove: func(store *fakeStore) { store.state.Addresses = nil }},
		{name: "route", remove: func(store *fakeStore) { store.state.Routes = nil }},
		{name: "properties", remove: func(store *fakeStore) { store.state.Properties = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{state: State{Interface: testInterface, Properties: []Properties{originalProperties}}}
			manager, err := NewManager(store)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}
			config := Config{
				Addresses:  []netip.Prefix{address},
				Routes:     []Route{route},
				Properties: []Properties{appliedProperties},
			}
			if err := manager.Apply(context.Background(), testInterface, config); err != nil {
				t.Fatalf("initial Apply() error = %v", err)
			}
			test.remove(store)
			store.log = nil
			if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
				t.Fatalf("cleanup Apply() error = %v", err)
			}
			if len(store.state.Addresses) != 0 || len(store.state.Routes) != 0 {
				t.Fatalf("state after cleanup = %+v, want no addresses or routes", store.state)
			}
			if test.name == "properties" {
				if len(store.state.Properties) != 0 {
					t.Fatalf("properties after external removal = %+v, want empty", store.state.Properties)
				}
			} else if !slices.Equal(store.state.Properties, []Properties{originalProperties}) {
				t.Fatalf("properties after cleanup = %+v, want restored %+v", store.state.Properties, originalProperties)
			}
			got, err := manager.Read(context.Background(), testInterface)
			if err != nil || len(got.Addresses) != 0 || len(got.Routes) != 0 || len(got.Properties) != 0 {
				t.Fatalf("Read() after cleanup = %+v, %v, want empty", got, err)
			}
		})
	}
}

func TestExactManagerRejectsMissingStateThatIsStillDesired(t *testing.T) {
	originalProperties := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	address := netip.MustParsePrefix("10.19.0.1/24")
	route := Route{Destination: netip.MustParsePrefix("10.20.0.0/16"), NextHop: netip.IPv4Unspecified(), Metric: 5}
	appliedProperties := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 3}
	config := Config{Addresses: []netip.Prefix{address}, Routes: []Route{route}, Properties: []Properties{appliedProperties}}
	tests := []struct {
		name   string
		remove func(*fakeStore)
	}{
		{name: "address", remove: func(store *fakeStore) { store.state.Addresses = nil }},
		{name: "route", remove: func(store *fakeStore) { store.state.Routes = nil }},
		{name: "properties", remove: func(store *fakeStore) { store.state.Properties = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{state: State{Interface: testInterface, Properties: []Properties{originalProperties}}}
			manager, _ := NewManager(store)
			if err := manager.Apply(context.Background(), testInterface, config); err != nil {
				t.Fatalf("initial Apply() error = %v", err)
			}
			test.remove(store)
			if err := manager.Apply(context.Background(), testInterface, config); !errors.Is(err, ErrResourceConflict) {
				t.Fatalf("Apply() error = %v, want ErrResourceConflict", err)
			}
		})
	}
}

func TestExactManagerRejectsOwnedAddressThatBecameUnusable(t *testing.T) {
	prefix := netip.MustParsePrefix("10.19.0.1/24")
	store := &fakeStore{state: State{Interface: testInterface}}
	manager, _ := NewManager(store)
	config := Config{Addresses: []netip.Prefix{prefix}}
	if err := manager.Apply(context.Background(), testInterface, config); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}
	store.state.Addresses[0].Usable = false
	if _, err := manager.Read(context.Background(), testInterface); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("Read() error = %v, want ErrResourceConflict", err)
	}
	if err := manager.Apply(context.Background(), testInterface, config); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("keep Apply() error = %v, want ErrResourceConflict", err)
	}
	if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
		t.Fatalf("cleanup Apply() error = %v", err)
	}
}

func TestT04T06ExactManagerRejectsForeignDuplicateAndChangedOwnedValue(t *testing.T) {
	prefix := netip.MustParsePrefix("10.19.0.1/24")
	store := &fakeStore{state: State{Interface: testInterface, Addresses: []Address{{Prefix: prefix, Usable: true}}}}
	manager, _ := NewManager(store)
	if err := manager.Apply(context.Background(), testInterface, Config{Addresses: []netip.Prefix{prefix}}); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("foreign duplicate error = %v, want ErrResourceConflict", err)
	}

	store.state.Addresses = nil
	if err := manager.Apply(context.Background(), testInterface, Config{Addresses: []netip.Prefix{prefix}}); err != nil {
		t.Fatalf("owned Apply() error = %v", err)
	}
	store.state.Addresses[0].Prefix = netip.MustParsePrefix("10.19.0.1/25")
	if err := manager.Apply(context.Background(), testInterface, Config{}); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("changed owned cleanup error = %v, want ErrResourceConflict", err)
	}
	if store.state.Addresses[0].Prefix.Bits() != 25 {
		t.Fatal("cleanup changed a foreign replacement")
	}
}

func TestT04T06ExactManagerRechecksValueImmediatelyBeforeDelete(t *testing.T) {
	prefix := netip.MustParsePrefix("10.19.0.1/24")
	store := &fakeStore{state: State{Interface: testInterface}}
	manager, _ := NewManager(store)
	if err := manager.Apply(context.Background(), testInterface, Config{Addresses: []netip.Prefix{prefix}}); err != nil {
		t.Fatalf("owned Apply() error = %v", err)
	}
	store.snapshots = 0
	store.beforeSnapshot = func(store *fakeStore, count int) {
		if count == 2 {
			store.state.Addresses[0].Prefix = netip.MustParsePrefix("10.19.0.1/25")
		}
	}
	if err := manager.Apply(context.Background(), testInterface, Config{}); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("cleanup error = %v, want ErrResourceConflict", err)
	}
	if got := store.state.Addresses[0].Prefix; got.Bits() != 25 {
		t.Fatalf("foreign replacement = %s, want preserved /25", got)
	}
}

func TestT04T06ExactManagerWaitDeadlineRollsBackAddress(t *testing.T) {
	store := &fakeStore{state: State{Interface: testInterface}, tentativeAddress: true}
	store.wait = func(ctx context.Context, _ netip.Addr) error {
		<-ctx.Done()
		return ctx.Err()
	}
	manager, _ := NewManager(store)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := manager.Apply(ctx, testInterface, Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.19.0.1/24")}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Apply() error = %v, want deadline exceeded", err)
	}
	state, _ := store.Snapshot(context.Background(), testInterface)
	if len(state.Addresses) != 0 {
		t.Fatalf("addresses after failed usability wait = %+v, want rollback", state.Addresses)
	}
}

func TestT07T09ExactManagerRequiresReadback(t *testing.T) {
	store := &fakeStore{state: State{Interface: testInterface}, noRoute: true}
	manager, _ := NewManager(store)
	route := Route{Destination: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("0.0.0.0"), Metric: 4}
	if err := manager.Apply(context.Background(), testInterface, Config{Routes: []Route{route}}); !errors.Is(err, ErrReadback) {
		t.Fatalf("Apply() error = %v, want ErrReadback", err)
	}
	if got, _ := manager.Read(context.Background(), testInterface); len(got.Routes) != 0 {
		t.Fatalf("inventory committed after failed readback: %+v", got)
	}
}

func TestNormalizeConfigRejectsIPv4MappedIPv6Values(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "address",
			config: Config{Addresses: []netip.Prefix{
				netip.MustParsePrefix("::ffff:192.0.2.1/128"),
			}},
		},
		{
			name: "route destination",
			config: Config{Routes: []Route{{
				Destination: netip.MustParsePrefix("::ffff:192.0.2.0/120"),
				NextHop:     netip.IPv6Unspecified(),
			}}},
		},
		{
			name: "route next hop",
			config: Config{Routes: []Route{{
				Destination: netip.MustParsePrefix("2001:db8::/64"),
				NextHop:     netip.MustParseAddr("::ffff:192.0.2.1"),
			}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeConfig(test.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalizeConfig() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestT07T09ExactManagerReleasesRestoredProperties(t *testing.T) {
	original := Properties{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}
	applied := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 4}
	store := &fakeStore{state: State{Interface: testInterface, Properties: []Properties{original}}}
	manager, _ := NewManager(store)

	if err := manager.Apply(context.Background(), testInterface, Config{Properties: []Properties{applied}}); err != nil {
		t.Fatalf("Apply(changed properties) error = %v", err)
	}
	if err := manager.Apply(context.Background(), testInterface, Config{Properties: []Properties{original}}); err != nil {
		t.Fatalf("Apply(original properties) error = %v", err)
	}
	got, err := manager.Read(context.Background(), testInterface)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(got.Properties) != 0 {
		t.Fatalf("Read().Properties = %+v, want released inventory", got.Properties)
	}

	// The manager no longer owns the restored row. A later host update must not
	// block an empty apply or cause the manager to overwrite the new value.
	hostValue := original
	hostValue.Metric++
	store.state.Properties[0] = hostValue
	if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
		t.Fatalf("Apply(empty) after host update error = %v", err)
	}
	if got := store.state.Properties[0]; got != hostValue {
		t.Fatalf("properties after host update = %+v, want preserved %+v", got, hostValue)
	}
}

func TestExactManagerVerifyAcceptsDesiredUnownedProperties(t *testing.T) {
	t.Parallel()
	original4 := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 5}
	original6 := Properties{Family: FamilyIPv6, MTU: 1400, Metric: 5}
	store := &fakeStore{state: State{
		Interface:  testInterface,
		Properties: []Properties{original4, original6},
	}}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	desired := Config{Properties: []Properties{original4, original6}}
	if err := manager.Apply(context.Background(), testInterface, desired); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	owned, err := manager.Read(context.Background(), testInterface)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(owned.Properties) != 0 {
		t.Fatalf("Read().Properties = %+v, want no ownership of existing values", owned.Properties)
	}
	if err := manager.Verify(context.Background(), testInterface, desired); err != nil {
		t.Fatalf("Verify(desired) error = %v", err)
	}
	if err := manager.Verify(context.Background(), testInterface, Config{}); err != nil {
		t.Fatalf("Verify(empty) error = %v", err)
	}

	store.mu.Lock()
	store.state.Properties[0].Metric++
	store.mu.Unlock()
	if err := manager.Verify(context.Background(), testInterface, desired); !errors.Is(err, ErrReadback) {
		t.Fatalf("Verify(changed properties) error = %v, want ErrReadback", err)
	}
}

func TestExactManagerVerifyRequiresOwnershipOfRows(t *testing.T) {
	t.Parallel()
	address := netip.MustParsePrefix("10.19.0.1/24")
	route := Route{
		Destination: netip.MustParsePrefix("203.0.113.0/24"),
		NextHop:     netip.IPv4Unspecified(),
		Metric:      5,
	}
	desired := Config{Addresses: []netip.Prefix{address}, Routes: []Route{route}}
	store := &fakeStore{state: State{
		Interface: testInterface,
		Addresses: []Address{{Prefix: address, Usable: true}},
		Routes:    []Route{route},
	}}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if err := manager.Verify(context.Background(), testInterface, desired); !errors.Is(err, ErrReadback) {
		t.Fatalf("Verify(foreign rows) error = %v, want ErrReadback", err)
	}
}

func TestExactManagerVerifyRejectsMissingAndExtraOwnedState(t *testing.T) {
	t.Parallel()
	address := netip.MustParsePrefix("10.19.0.1/24")
	properties := Properties{Family: FamilyIPv4, MTU: 1400, Metric: 5}
	store := &fakeStore{state: State{
		Interface:  testInterface,
		Properties: []Properties{{Family: FamilyIPv4, MTU: 1500, Metric: 25, AutomaticMetric: true}},
	}}
	manager, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	desired := Config{Addresses: []netip.Prefix{address}, Properties: []Properties{properties}}
	if err := manager.Apply(context.Background(), testInterface, desired); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := manager.Verify(context.Background(), testInterface, desired); err != nil {
		t.Fatalf("Verify(applied) error = %v", err)
	}
	if err := manager.Verify(context.Background(), testInterface, Config{Properties: []Properties{properties}}); !errors.Is(err, ErrReadback) {
		t.Fatalf("Verify(missing address) error = %v, want ErrReadback", err)
	}
	if err := manager.Verify(context.Background(), testInterface, Config{Addresses: []netip.Prefix{address}}); !errors.Is(err, ErrReadback) {
		t.Fatalf("Verify(missing properties) error = %v, want ErrReadback", err)
	}
}

func TestT04T06ExactManagerRetainsOwnershipAfterFailedRollback(t *testing.T) {
	store := &fakeStore{
		state:             State{Interface: testInterface},
		noRoute:           true,
		failDeleteAddress: true,
	}
	manager, _ := NewManager(store)
	prefix := netip.MustParsePrefix("10.19.0.1/24")
	route := Route{Destination: netip.MustParsePrefix("203.0.113.0/24"), NextHop: netip.MustParseAddr("0.0.0.0"), Metric: 4}
	err := manager.Apply(context.Background(), testInterface, Config{Addresses: []netip.Prefix{prefix}, Routes: []Route{route}})
	if !errors.Is(err, ErrReadback) {
		t.Fatalf("Apply() error = %v, want ErrReadback", err)
	}
	if !RequiresRecovery(err) {
		t.Fatalf("Apply() error = %v, want retained ownership recovery", err)
	}
	store.failDeleteAddress = false
	store.noRoute = false
	if err := manager.Apply(context.Background(), testInterface, Config{}); err != nil {
		t.Fatalf("cleanup retained inventory error = %v", err)
	}
	state, _ := store.Snapshot(context.Background(), testInterface)
	if len(state.Addresses) != 0 {
		t.Fatalf("retained address after cleanup = %+v", state.Addresses)
	}
}

func TestT07T09ExactManagerValidatesIdentityAndMTU(t *testing.T) {
	store := &fakeStore{state: State{Interface: Interface{LUID: testInterface.LUID, Index: testInterface.Index + 1}}}
	manager, _ := NewManager(store)
	if err := manager.Apply(context.Background(), testInterface, Config{}); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("identity error = %v, want ErrIdentityMismatch", err)
	}

	store.state.Interface = testInterface
	store.state.Interface.GUID = "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"
	withGUID := testInterface
	withGUID.GUID = "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}"
	if err := manager.Apply(context.Background(), withGUID, Config{}); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("GUID identity error = %v, want ErrIdentityMismatch", err)
	}
	store.state.Interface = testInterface
	for _, properties := range []Properties{
		{Family: FamilyIPv4, MTU: 0},
		{Family: FamilyIPv4, MTU: 575},
		{Family: FamilyIPv6, MTU: 1279},
	} {
		err := manager.Apply(context.Background(), testInterface, Config{Properties: []Properties{properties}})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("properties %+v error = %v, want ErrInvalidConfig", properties, err)
		}
	}
}

func assertConfig(t *testing.T, manager *ExactManager, want Config) {
	t.Helper()
	got, err := manager.Read(context.Background(), testInterface)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	normalized, err := normalizeConfig(want)
	if err != nil {
		t.Fatalf("normalizeConfig() error = %v", err)
	}
	if !slices.Equal(got.Addresses, normalized.Addresses) || !slices.Equal(got.Routes, normalized.Routes) || !slices.Equal(got.Properties, normalized.Properties) {
		t.Fatalf("Read() = %+v, want %+v", got, normalized)
	}
}

var _ Store = (*fakeStore)(nil)
