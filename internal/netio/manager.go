package netio

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const defaultOperationTimeout = 30 * time.Second

// ExactManager owns only rows that it created and property values that it
// changed. Native state is the authority for every mutation: each call is
// followed by a new snapshot before the inventory is committed.
type ExactManager struct {
	store Store

	mu        sync.Mutex
	inventory map[Interface]*ownedState
}

type ownedState struct {
	addresses map[string]netip.Prefix
	routes    map[string]Route
	props     map[Family]ownedProperties
}

type ownedProperties struct {
	previous Properties
	applied  Properties
}

type mutation struct {
	description  string
	precondition func(State) bool
	apply        func(context.Context) error
	verify       func(State) bool
	inverseSafe  func(State) bool
	inverse      func(context.Context) error
	undone       func(State) bool
}

// NewManager creates an exact-delta manager over store.
func NewManager(store Store) (*ExactManager, error) {
	if store == nil {
		return nil, errors.New("create NetIO manager with nil store")
	}
	return &ExactManager{store: store, inventory: make(map[Interface]*ownedState)}, nil
}

// Apply changes only rows in the manager inventory. It rejects a foreign row
// with the same native key and rolls back verified mutations in reverse order.
func (m *ExactManager) Apply(ctx context.Context, iface Interface, config Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	desired, err := normalizeConfig(config)
	if err != nil {
		return err
	}
	if err := validateInterface(iface); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.snapshot(ctx, iface)
	if err != nil {
		return err
	}
	owned := cloneOwned(m.inventory[iface])
	if owned == nil {
		owned = newOwnedState()
	}
	if err := verifyOwnership(current, owned); err != nil {
		return err
	}
	mutations, next, err := m.plan(iface, current, owned, desired)
	if err != nil {
		return err
	}
	completed := make([]mutation, 0, len(mutations))
	for _, change := range mutations {
		if err := ctx.Err(); err != nil {
			return m.fail(ctx, iface, owned, next, err, completed)
		}
		observed, err := m.snapshot(ctx, iface)
		if err != nil {
			return m.fail(ctx, iface, owned, next, fmt.Errorf("inspect before %s: %w", change.description, err), completed)
		}
		if change.precondition != nil && !change.precondition(observed) {
			return m.fail(ctx, iface, owned, next,
				fmt.Errorf("%w before %s", ErrResourceConflict, change.description), completed)
		}
		// Include the mutation before the call. A native API can change state
		// before it returns an error.
		completed = append(completed, change)
		if err := change.apply(ctx); err != nil {
			return m.fail(ctx, iface, owned, next, fmt.Errorf("%s: %w", change.description, err), completed)
		}
		observed, err = m.snapshot(ctx, iface)
		if err != nil {
			return m.fail(ctx, iface, owned, next, fmt.Errorf("read back %s: %w", change.description, err), completed)
		}
		if !change.verify(observed) {
			return m.fail(ctx, iface, owned, next, fmt.Errorf("%w after %s", ErrReadback, change.description), completed)
		}
	}
	if next.empty() {
		delete(m.inventory, iface)
	} else {
		m.inventory[iface] = next
	}
	return nil
}

func (m *ExactManager) fail(ctx context.Context, iface Interface, before, planned *ownedState, primary error, completed []mutation) error {
	rollbackErr := m.rollback(ctx, iface, completed)
	if rollbackErr == nil {
		return primary
	}
	// A failed inverse can leave any verified part of the old or planned
	// inventory in place. Re-read it and retain only exact matching values so a
	// later cleanup can retry them without claiming a foreign replacement.
	retainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultOperationTimeout)
	defer cancel()
	state, readErr := m.snapshot(retainCtx, iface)
	if readErr == nil {
		retained := retainObservedOwnership(state, before, planned)
		if retained.empty() {
			delete(m.inventory, iface)
		} else {
			m.inventory[iface] = retained
		}
	} else {
		readErr = fmt.Errorf("retain inventory after failed rollback: %w", readErr)
	}
	return errors.Join(primary, rollbackErr, readErr)
}

// Read returns the manager-owned state after it verifies that every recorded
// value still matches the native rows. Foreign rows are not returned.
func (m *ExactManager) Read(ctx context.Context, iface Interface) (Config, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateInterface(iface); err != nil {
		return Config{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.snapshot(ctx, iface)
	if err != nil {
		return Config{}, err
	}
	owned := m.inventory[iface]
	if owned == nil {
		return Config{}, nil
	}
	if err := verifyOwnership(state, owned); err != nil {
		return Config{}, err
	}
	result := Config{}
	for _, prefix := range owned.addresses {
		result.Addresses = append(result.Addresses, prefix)
	}
	for _, route := range owned.routes {
		result.Routes = append(result.Routes, route)
	}
	for _, properties := range owned.props {
		result.Properties = append(result.Properties, properties.applied)
	}
	sortConfig(&result)
	return result, nil
}

func (m *ExactManager) plan(iface Interface, current State, owned *ownedState, desired Config) ([]mutation, *ownedState, error) {
	addresses, routes, properties := indexState(current)
	desiredAddresses, desiredRoutes, desiredProperties := indexConfig(desired)
	changes := make([]mutation, 0)
	next := cloneOwned(owned)

	// Delete dependent routes before addresses.
	for _, key := range sortedStringKeys(owned.routes) {
		old := owned.routes[key]
		want, keep := desiredRoutes[key]
		if keep && want == old {
			continue
		}
		changes = append(changes, m.deleteRoute(iface, old))
		delete(next.routes, key)
	}
	for _, key := range sortedStringKeys(owned.addresses) {
		old := owned.addresses[key]
		want, keep := desiredAddresses[key]
		if keep && want == old {
			continue
		}
		changes = append(changes, m.deleteAddress(iface, old))
		delete(next.addresses, key)
	}

	for _, key := range sortedStringKeys(desiredAddresses) {
		prefix := desiredAddresses[key]
		if old, ok := owned.addresses[key]; ok && old == prefix {
			continue
		}
		if _, exists := addresses[key]; exists {
			if _, wasOwned := owned.addresses[key]; !wasOwned {
				return nil, nil, fmt.Errorf("%w: address %s already exists", ErrResourceConflict, prefix.Addr())
			}
		}
		changes = append(changes, m.createAddress(iface, prefix))
		next.addresses[key] = prefix
	}
	for _, key := range sortedStringKeys(desiredRoutes) {
		route := desiredRoutes[key]
		if old, ok := owned.routes[key]; ok && old == route {
			continue
		}
		if _, exists := routes[key]; exists {
			if _, wasOwned := owned.routes[key]; !wasOwned {
				return nil, nil, fmt.Errorf("%w: route %s via %s already exists", ErrResourceConflict, route.Destination, route.NextHop)
			}
		}
		changes = append(changes, m.createRoute(iface, route))
		next.routes[key] = route
	}

	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		record, exists := owned.props[family]
		if !exists {
			continue
		}
		want, keep := desiredProperties[family]
		if keep {
			if want == record.applied {
				continue
			}
			changes = append(changes, m.setProperties(iface, record.applied, want))
			record.applied = want
			next.props[family] = record
			continue
		}
		changes = append(changes, m.setProperties(iface, record.applied, record.previous))
		delete(next.props, family)
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		want, exists := desiredProperties[family]
		if !exists {
			continue
		}
		if _, ok := owned.props[family]; ok {
			continue
		}
		currentProperties, ok := properties[family]
		if !ok {
			return nil, nil, fmt.Errorf("%w: interface has no IPv%d properties", ErrResourceConflict, family)
		}
		if currentProperties == want {
			// The requested value already belongs to the host. Do not claim it
			// because cleanup must not change a value the manager did not apply.
			continue
		}
		changes = append(changes, m.setProperties(iface, currentProperties, want))
		next.props[family] = ownedProperties{previous: currentProperties, applied: want}
	}
	return changes, next, nil
}

func (m *ExactManager) createAddress(iface Interface, prefix netip.Prefix) mutation {
	key := addressKey(prefix)
	return mutation{
		description: "create address " + prefix.String(),
		precondition: func(state State) bool {
			_, exists := addressMap(state)[key]
			return !exists
		},
		apply: func(ctx context.Context) error {
			if err := m.store.CreateAddress(ctx, iface, prefix); err != nil {
				return err
			}
			return m.store.WaitAddressUsable(ctx, iface, prefix.Addr())
		},
		verify: func(state State) bool {
			value, ok := addressMap(state)[key]
			return ok && value.Prefix == prefix && value.Usable
		},
		inverseSafe: func(state State) bool {
			value, ok := addressMap(state)[key]
			return ok && value.Prefix == prefix
		},
		inverse: func(ctx context.Context) error { return m.store.DeleteAddress(ctx, iface, prefix) },
		undone:  func(state State) bool { _, ok := addressMap(state)[key]; return !ok },
	}
}

func (m *ExactManager) deleteAddress(iface Interface, prefix netip.Prefix) mutation {
	key := addressKey(prefix)
	return mutation{
		description: "delete address " + prefix.String(),
		precondition: func(state State) bool {
			value, ok := addressMap(state)[key]
			return ok && value.Prefix == prefix
		},
		apply:  func(ctx context.Context) error { return m.store.DeleteAddress(ctx, iface, prefix) },
		verify: func(state State) bool { _, ok := addressMap(state)[key]; return !ok },
		inverse: func(ctx context.Context) error {
			if err := m.store.CreateAddress(ctx, iface, prefix); err != nil {
				return err
			}
			return m.store.WaitAddressUsable(ctx, iface, prefix.Addr())
		},
		undone: func(state State) bool {
			value, ok := addressMap(state)[key]
			return ok && value.Prefix == prefix && value.Usable
		},
	}
}

func (m *ExactManager) createRoute(iface Interface, route Route) mutation {
	key := routeKey(route)
	return mutation{
		description: fmt.Sprintf("create route %s via %s", route.Destination, route.NextHop),
		precondition: func(state State) bool {
			_, exists := routeMap(state)[key]
			return !exists
		},
		apply:   func(ctx context.Context) error { return m.store.CreateRoute(ctx, iface, route) },
		verify:  func(state State) bool { value, ok := routeMap(state)[key]; return ok && value == route },
		inverse: func(ctx context.Context) error { return m.store.DeleteRoute(ctx, iface, route) },
		undone:  func(state State) bool { _, ok := routeMap(state)[key]; return !ok },
	}
}

func (m *ExactManager) deleteRoute(iface Interface, route Route) mutation {
	key := routeKey(route)
	return mutation{
		description: fmt.Sprintf("delete route %s via %s", route.Destination, route.NextHop),
		precondition: func(state State) bool {
			value, ok := routeMap(state)[key]
			return ok && value == route
		},
		apply:   func(ctx context.Context) error { return m.store.DeleteRoute(ctx, iface, route) },
		verify:  func(state State) bool { _, ok := routeMap(state)[key]; return !ok },
		inverse: func(ctx context.Context) error { return m.store.CreateRoute(ctx, iface, route) },
		undone:  func(state State) bool { value, ok := routeMap(state)[key]; return ok && value == route },
	}
}

func (m *ExactManager) setProperties(iface Interface, from, to Properties) mutation {
	return mutation{
		description: fmt.Sprintf("set IPv%d interface properties", to.Family),
		precondition: func(state State) bool {
			value, ok := propertiesMap(state)[from.Family]
			return ok && value == from
		},
		apply:   func(ctx context.Context) error { return m.store.SetProperties(ctx, iface, to) },
		verify:  func(state State) bool { value, ok := propertiesMap(state)[to.Family]; return ok && value == to },
		inverse: func(ctx context.Context) error { return m.store.SetProperties(ctx, iface, from) },
		undone:  func(state State) bool { value, ok := propertiesMap(state)[from.Family]; return ok && value == from },
	}
}

func (m *ExactManager) rollback(ctx context.Context, iface Interface, completed []mutation) error {
	// Rollback must still run after request cancellation. Native calls remain
	// bounded by the caller's deadline when it is still active; a canceled
	// request uses a fresh background context and lets the outer lifecycle gate
	// decide its cleanup timeout.
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultOperationTimeout)
	defer cancel()
	var result error
	for index := len(completed) - 1; index >= 0; index-- {
		change := completed[index]
		state, err := m.snapshot(rollbackCtx, iface)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("inspect before rollback of %s: %w", change.description, err))
			continue
		}
		if change.undone(state) {
			continue
		}
		inverseSafe := change.verify
		if change.inverseSafe != nil {
			inverseSafe = change.inverseSafe
		}
		if !inverseSafe(state) {
			result = errors.Join(result, fmt.Errorf("%w during rollback of %s", ErrResourceConflict, change.description))
			continue
		}
		if err := change.inverse(rollbackCtx); err != nil {
			result = errors.Join(result, fmt.Errorf("rollback %s: %w", change.description, err))
			continue
		}
		state, err = m.snapshot(rollbackCtx, iface)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%w after rollback of %s: %w", ErrReadback, change.description, err))
		} else if !change.undone(state) {
			result = errors.Join(result, fmt.Errorf("%w after rollback of %s", ErrReadback, change.description))
		}
	}
	return result
}

func (m *ExactManager) snapshot(ctx context.Context, iface Interface) (State, error) {
	state, err := m.store.Snapshot(ctx, iface)
	if err != nil {
		return State{}, err
	}
	if state.Interface != iface {
		return State{}, fmt.Errorf("%w: got LUID %d index %d, want LUID %d index %d", ErrIdentityMismatch,
			state.Interface.LUID, state.Interface.Index, iface.LUID, iface.Index)
	}
	return state, nil
}

func normalizeConfig(config Config) (Config, error) {
	result := Config{
		Addresses:  append([]netip.Prefix(nil), config.Addresses...),
		Routes:     append([]Route(nil), config.Routes...),
		Properties: append([]Properties(nil), config.Properties...),
	}
	seenAddresses := make(map[string]struct{}, len(result.Addresses))
	for index, prefix := range result.Addresses {
		if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return Config{}, fmt.Errorf("%w: address %d is %s", ErrInvalidConfig, index, prefix)
		}
		key := addressKey(prefix)
		if _, exists := seenAddresses[key]; exists {
			return Config{}, fmt.Errorf("%w: duplicate address %s", ErrInvalidConfig, prefix.Addr())
		}
		seenAddresses[key] = struct{}{}
	}
	seenRoutes := make(map[string]struct{}, len(result.Routes))
	for index := range result.Routes {
		route := &result.Routes[index]
		if !route.Destination.IsValid() || route.Destination != route.Destination.Masked() || route.Destination.Addr().Zone() != "" ||
			!route.NextHop.IsValid() || route.NextHop.Zone() != "" || route.Destination.Addr().Is4() != route.NextHop.Is4() {
			return Config{}, fmt.Errorf("%w: route %d is not canonical", ErrInvalidConfig, index)
		}
		key := routeKey(*route)
		if _, exists := seenRoutes[key]; exists {
			return Config{}, fmt.Errorf("%w: duplicate route %s via %s", ErrInvalidConfig, route.Destination, route.NextHop)
		}
		seenRoutes[key] = struct{}{}
	}
	seenFamilies := make(map[Family]struct{}, len(result.Properties))
	for index, properties := range result.Properties {
		minimum := uint32(1280)
		if properties.Family == FamilyIPv4 {
			minimum = 576
		} else if properties.Family != FamilyIPv6 {
			return Config{}, fmt.Errorf("%w: properties %d has family %d", ErrInvalidConfig, index, properties.Family)
		}
		if properties.MTU < minimum || properties.MTU > 65535 {
			return Config{}, fmt.Errorf("%w: IPv%d MTU %d is outside %d..65535", ErrInvalidConfig, properties.Family, properties.MTU, minimum)
		}
		if _, exists := seenFamilies[properties.Family]; exists {
			return Config{}, fmt.Errorf("%w: duplicate IPv%d properties", ErrInvalidConfig, properties.Family)
		}
		seenFamilies[properties.Family] = struct{}{}
	}
	sortConfig(&result)
	return result, nil
}

func validateInterface(iface Interface) error {
	if iface.LUID == 0 || iface.Index == 0 {
		return fmt.Errorf("%w: invalid interface LUID %d index %d", ErrInvalidConfig, iface.LUID, iface.Index)
	}
	return nil
}

func withDefaultDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultOperationTimeout)
}

func verifyOwnership(state State, owned *ownedState) error {
	addresses, routes, properties := indexState(state)
	for key, want := range owned.addresses {
		got, ok := addresses[key]
		if !ok || got.Prefix != want {
			return fmt.Errorf("%w: owned address %s changed or disappeared", ErrResourceConflict, want)
		}
	}
	for key, want := range owned.routes {
		if got, ok := routes[key]; !ok || got != want {
			return fmt.Errorf("%w: owned route %s via %s changed or disappeared", ErrResourceConflict, want.Destination, want.NextHop)
		}
	}
	for family, want := range owned.props {
		if got, ok := properties[family]; !ok || got != want.applied {
			return fmt.Errorf("%w: owned IPv%d properties changed or disappeared", ErrResourceConflict, family)
		}
	}
	return nil
}

func retainObservedOwnership(state State, states ...*ownedState) *ownedState {
	observedAddresses, observedRoutes, observedProperties := indexState(state)
	result := newOwnedState()
	for _, candidate := range states {
		if candidate == nil {
			continue
		}
		for key, value := range candidate.addresses {
			if observed, ok := observedAddresses[key]; ok && observed.Prefix == value {
				result.addresses[key] = value
			}
		}
		for key, value := range candidate.routes {
			if observed, ok := observedRoutes[key]; ok && observed == value {
				result.routes[key] = value
			}
		}
		for family, value := range candidate.props {
			if observed, ok := observedProperties[family]; ok && observed == value.applied {
				result.props[family] = value
			}
		}
	}
	return result
}

func newOwnedState() *ownedState {
	return &ownedState{addresses: make(map[string]netip.Prefix), routes: make(map[string]Route), props: make(map[Family]ownedProperties)}
}

func cloneOwned(source *ownedState) *ownedState {
	if source == nil {
		return nil
	}
	result := newOwnedState()
	for key, value := range source.addresses {
		result.addresses[key] = value
	}
	for key, value := range source.routes {
		result.routes[key] = value
	}
	for key, value := range source.props {
		result.props[key] = value
	}
	return result
}

func (state *ownedState) empty() bool {
	return len(state.addresses) == 0 && len(state.routes) == 0 && len(state.props) == 0
}

func indexState(state State) (map[string]Address, map[string]Route, map[Family]Properties) {
	return addressMap(state), routeMap(state), propertiesMap(state)
}

func indexConfig(config Config) (map[string]netip.Prefix, map[string]Route, map[Family]Properties) {
	addresses := make(map[string]netip.Prefix, len(config.Addresses))
	for _, value := range config.Addresses {
		addresses[addressKey(value)] = value
	}
	routes := make(map[string]Route, len(config.Routes))
	for _, value := range config.Routes {
		routes[routeKey(value)] = value
	}
	properties := make(map[Family]Properties, len(config.Properties))
	for _, value := range config.Properties {
		properties[value.Family] = value
	}
	return addresses, routes, properties
}

func addressMap(state State) map[string]Address {
	result := make(map[string]Address, len(state.Addresses))
	for _, value := range state.Addresses {
		result[addressKey(value.Prefix)] = value
	}
	return result
}

func routeMap(state State) map[string]Route {
	result := make(map[string]Route, len(state.Routes))
	for _, value := range state.Routes {
		result[routeKey(value)] = value
	}
	return result
}

func propertiesMap(state State) map[Family]Properties {
	result := make(map[Family]Properties, len(state.Properties))
	for _, value := range state.Properties {
		result[value.Family] = value
	}
	return result
}

func addressKey(prefix netip.Prefix) string { return prefix.Addr().String() }
func routeKey(route Route) string           { return route.Destination.String() + "|" + route.NextHop.String() }

func sortedStringKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func sortConfig(config *Config) {
	slices.SortFunc(config.Addresses, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	slices.SortFunc(config.Routes, func(a, b Route) int {
		if compared := a.Destination.Addr().Compare(b.Destination.Addr()); compared != 0 {
			return compared
		}
		if a.Destination.Bits() != b.Destination.Bits() {
			return a.Destination.Bits() - b.Destination.Bits()
		}
		return a.NextHop.Compare(b.NextHop)
	})
	slices.SortFunc(config.Properties, func(a, b Properties) int { return int(a.Family) - int(b.Family) })
}

var _ Manager = (*ExactManager)(nil)
