package split

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sublayers identifies the committed WFP sublayers passed to the driver.
type Sublayers struct {
	Baseline string
	DNS      string
}

// Process is one initial process-tree entry. An empty ImagePath is valid and
// preserves a process whose executable metadata could not be read.
type Process struct {
	PID          uint32
	ParentPID    uint32
	ImagePath    string
	CreationTime uint64
}

// ProcessWarning retains partial process-snapshot diagnostics.
type ProcessWarning struct {
	PID       uint32
	Operation string
	Err       error
}

// ProcessSnapshot is the complete bootstrap view and its non-fatal warnings.
type ProcessSnapshot struct {
	Processes []Process
	Warnings  []ProcessWarning
}

// ProcessSnapshotter reads processes after Initialize has enabled the driver's
// process-change buffer. It must retain entries with partial metadata.
type ProcessSnapshotter interface {
	Snapshot(context.Context) (ProcessSnapshot, error)
}

// PathResolver converts one accepted drive-letter path to its NT device path.
// Bootstrap resolves every path before it sends any policy mutation.
type PathResolver interface {
	Resolve(context.Context, string) (string, error)
}

// Addresses is one coherent generation of tunnel and local-underlay roles.
// An invalid address means that the family is unavailable.
type Addresses struct {
	TunnelIPv4   netip.Addr
	InternetIPv4 netip.Addr
	TunnelIPv6   netip.Addr
	InternetIPv6 netip.Addr
}

// Event is one ordered driver process event. Raw is owned by the caller.
type Event struct {
	ID        uint32
	PID       uint32
	Reason    uint32
	ImagePath string
	NTStatus  uint32
	Message   string
	Raw       []byte
}

const (
	EventErrorStartSplitting uint32 = 0x80000001
	EventErrorStopSplitting  uint32 = 0x80000002
	EventErrorMessage        uint32 = 0x80000003
)

// IsSplittingError reports an event for which the pinned driver could not
// change a process classification. The event ID does not reliably identify
// the attempted direction, so callers must read back policy instead.
func (e Event) IsSplittingError() bool {
	return e.ID == EventErrorStartSplitting || e.ID == EventErrorStopSplitting
}

// EventError reports a driver event which makes process policy uncertain until
// a readback reconciliation completes.
type EventError struct{ Event Event }

func (e *EventError) Error() string {
	return fmt.Sprintf("split-driver process policy error for PID %d (event %#x, status %#x)",
		e.Event.PID, e.Event.ID, e.Event.NTStatus)
}

// BootstrapConfig is one fully compiled exclusion-policy generation.
type BootstrapConfig struct {
	Generation uint64
	Addresses  Addresses
	Paths      []string
	// OnEvent must return quickly. The System uses it only to enqueue work on
	// its serialized reconciler; it must not perform native mutation itself.
	OnEvent func(Event)
	OnError func(error)
}

// Policy owns the event-reader lifetime for an initialized split session.
type Policy struct {
	session  *Session
	resolver PathResolver
	timeout  time.Duration
	cancel   context.CancelFunc
	done     chan struct{}

	generation atomic.Uint64
	mu         sync.RWMutex
	warnings   []ProcessWarning
	addresses  Addresses
	paths      []string
	closeOnce  sync.Once
	closed     bool
	closeErr   error
}

// Bootstrap initializes the driver in its required order, registers the full
// process snapshot, and applies addresses and exclusions from one generation.
func Bootstrap(ctx context.Context, session *Session, dependencies Dependencies, config BootstrapConfig) (*Policy, error) {
	if ctx == nil {
		return nil, errors.New("bootstrap split policy: nil context")
	}
	if session == nil || session.controller == nil {
		return nil, errors.New("bootstrap split policy: session is not configured")
	}
	if dependencies.Snapshot == nil || dependencies.Resolver == nil {
		return nil, errors.New("bootstrap split policy: process snapshotter or path resolver is not configured")
	}
	if config.Generation == 0 {
		return nil, errors.New("bootstrap split policy: generation must be nonzero")
	}
	if err := validateAddresses(config.Addresses); err != nil {
		return nil, fmt.Errorf("bootstrap split policy: %w", err)
	}
	paths, err := resolvePaths(ctx, dependencies.Resolver, config.Paths)
	if err != nil {
		return nil, fmt.Errorf("bootstrap split policy: %w", err)
	}

	resources := session.Resources()
	sublayers := Sublayers{Baseline: resources.Baseline.Key, DNS: resources.DNS.Key}
	session.MarkDriverReferences()
	if err := session.controller.Initialize(ctx, sublayers); err != nil {
		return nil, fmt.Errorf("bootstrap split policy: initialize: %w", err)
	}
	// Snapshot only after Initialize. The driver buffers births in this window,
	// so RegisterProcesses merges them without a bootstrap hole.
	snapshot, err := dependencies.Snapshot.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap split policy: snapshot processes: %w", err)
	}
	if len(snapshot.Processes) == 0 {
		return nil, errors.New("bootstrap split policy: process snapshot is empty")
	}
	if err := session.controller.RegisterProcesses(ctx, cloneProcesses(snapshot.Processes)); err != nil {
		return nil, fmt.Errorf("bootstrap split policy: register processes: %w", err)
	}
	eventCtx, cancel := context.WithCancel(context.Background())
	policy := &Policy{
		session: session, resolver: dependencies.Resolver, timeout: session.cleanupTimeout,
		cancel: cancel, done: make(chan struct{}), warnings: cloneWarnings(snapshot.Warnings),
	}
	if err := policy.applyGeneration(ctx, config.Generation, config.Addresses, paths); err != nil {
		cancel()
		return nil, fmt.Errorf("bootstrap split policy: %w", err)
	}
	go policy.readEvents(eventCtx, config.OnEvent, config.OnError)
	return policy, nil
}

func resolvePaths(ctx context.Context, resolver PathResolver, input []string) ([]string, error) {
	result := make([]string, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, path := range input {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolved, err := resolver.Resolve(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("resolve exclusion %d: %w", index, err)
		}
		resolved = strings.TrimSpace(resolved)
		if resolved == "" {
			return nil, fmt.Errorf("resolve exclusion %d: empty device path", index)
		}
		key := strings.ToLower(resolved)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result[index] = resolved
	}
	return slices.DeleteFunc(result, func(path string) bool { return path == "" }), nil
}

func validateAddresses(addresses Addresses) error {
	pairs := []struct {
		name             string
		tunnel, internet netip.Addr
		want4            bool
	}{
		{name: "IPv4", tunnel: addresses.TunnelIPv4, internet: addresses.InternetIPv4, want4: true},
		{name: "IPv6", tunnel: addresses.TunnelIPv6, internet: addresses.InternetIPv6},
	}
	available := false
	for _, pair := range pairs {
		if pair.tunnel.IsValid() != pair.internet.IsValid() {
			return fmt.Errorf("%s tunnel and Internet roles must be available together", pair.name)
		}
		if !pair.tunnel.IsValid() {
			continue
		}
		available = true
		for role, address := range map[string]netip.Addr{"tunnel": pair.tunnel, "Internet": pair.internet} {
			if address.Is4() != pair.want4 || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() {
				return fmt.Errorf("%s %s address %q is not usable", pair.name, role, address)
			}
		}
	}
	if !available {
		return errors.New("no complete address family is available")
	}
	return nil
}

// Update replaces the complete exclusion set and all four address roles as one
// policy generation. It resolves every path before native mutation. The driver
// can reclassify processes after this call, but established TCP and UDP flows
// are not guaranteed to move to the newly selected path.
func (p *Policy) Update(ctx context.Context, config BootstrapConfig) error {
	if p == nil || p.session == nil {
		return errors.New("update split policy: policy is not configured")
	}
	if ctx == nil {
		return errors.New("update split policy: nil context")
	}
	if config.Generation == 0 {
		return errors.New("update split policy: generation must be nonzero")
	}
	if err := validateAddresses(config.Addresses); err != nil {
		return fmt.Errorf("update split policy: %w", err)
	}
	paths, err := resolvePaths(ctx, p.resolver, config.Paths)
	if err != nil {
		return fmt.Errorf("update split policy: %w", err)
	}
	if err := p.applyGeneration(ctx, config.Generation, config.Addresses, paths); err != nil {
		return fmt.Errorf("update split policy: %w", err)
	}
	return nil
}

// ReconcileAddresses publishes a new generation with a coherent replacement
// of the tunnel and Internet address roles. It also reads back the complete
// exclusion set, so a prior splitting error cannot be treated as success from
// its event ID alone.
func (p *Policy) ReconcileAddresses(ctx context.Context, generation uint64, addresses Addresses) error {
	if p == nil {
		return errors.New("reconcile split policy: policy is not configured")
	}
	p.mu.RLock()
	paths := append([]string(nil), p.paths...)
	p.mu.RUnlock()
	if err := validateAddresses(addresses); err != nil {
		return fmt.Errorf("reconcile split policy: %w", err)
	}
	if err := p.applyGeneration(ctx, generation, addresses, paths); err != nil {
		return fmt.Errorf("reconcile split policy: %w", err)
	}
	return nil
}

func (p *Policy) applyGeneration(ctx context.Context, generation uint64, addresses Addresses, paths []string) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if generation == 0 {
		return errors.New("generation must be nonzero")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("split policy is closed")
	}
	if current := p.generation.Load(); current != 0 && generation <= current {
		return fmt.Errorf("generation %d must be greater than applied generation %d", generation, current)
	}

	priorAddresses, priorPaths, err := p.readPolicy(ctx)
	if err != nil {
		return fmt.Errorf("read current driver policy: %w", err)
	}
	rollback := func(primary error) error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), p.readbackTimeout())
		defer cancel()
		currentAddresses, currentPaths, readErr := p.readPolicy(cleanupCtx)
		if readErr != nil {
			return errors.Join(primary, ErrRecoveryRequired, fmt.Errorf("read policy before restore: %w", readErr))
		}
		var addressErr, pathErr error
		if currentAddresses != priorAddresses {
			addressErr = p.setAddressesVerified(cleanupCtx, priorAddresses)
		}
		if !equalPaths(currentPaths, priorPaths) {
			pathErr = p.setPathsVerified(cleanupCtx, priorPaths)
		}
		cleanupErr := errors.Join(addressErr, pathErr)
		if cleanupErr != nil {
			return errors.Join(primary, ErrRecoveryRequired, fmt.Errorf("restore prior split policy: %w", cleanupErr))
		}
		return primary
	}

	if addresses != priorAddresses {
		if err := p.setAddressesVerified(ctx, addresses); err != nil {
			return rollback(fmt.Errorf("set addresses: %w", err))
		}
	}
	if !equalPaths(paths, priorPaths) {
		if err := p.setPathsVerified(ctx, paths); err != nil {
			return rollback(fmt.Errorf("set exclusions: %w", err))
		}
	}
	// A final combined read prevents publication if an external or delayed
	// driver change raced either individual verification.
	observedAddresses, observedPaths, err := p.readPolicyFresh()
	if err != nil {
		return rollback(fmt.Errorf("read back complete policy: %w", err))
	}
	if observedAddresses != addresses || !equalPaths(observedPaths, paths) {
		return rollback(fmt.Errorf("complete policy readback differs from generation %d", generation))
	}
	p.addresses = addresses
	p.paths = append([]string(nil), observedPaths...)
	p.generation.Store(generation)
	return nil
}

func (p *Policy) setAddressesVerified(ctx context.Context, want Addresses) error {
	mutationErr := p.session.controller.SetAddresses(ctx, want)
	got, readErr := p.readAddressesFresh()
	if readErr != nil {
		return errors.Join(mutationErr, ErrRecoveryRequired, fmt.Errorf("read addresses after mutation: %w", readErr))
	}
	if got == want {
		return nil
	}
	return errors.Join(mutationErr, fmt.Errorf("address readback = %+v, want %+v", got, want))
}

func (p *Policy) setPathsVerified(ctx context.Context, want []string) error {
	mutationErr := p.session.controller.SetExcludedDevicePaths(ctx, append([]string(nil), want...))
	got, readErr := p.readPathsFresh()
	if readErr != nil {
		return errors.Join(mutationErr, ErrRecoveryRequired, fmt.Errorf("read exclusions after mutation: %w", readErr))
	}
	if equalPaths(got, want) {
		return nil
	}
	return errors.Join(mutationErr, fmt.Errorf("exclusion readback differs from complete desired set"))
}

func (p *Policy) readPolicy(ctx context.Context) (Addresses, []string, error) {
	addresses, err := p.session.controller.Addresses(ctx)
	if err != nil {
		return Addresses{}, nil, err
	}
	paths, err := p.session.controller.ExcludedDevicePaths(ctx)
	return addresses, paths, err
}

func (p *Policy) readPolicyFresh() (Addresses, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.readbackTimeout())
	defer cancel()
	return p.readPolicy(ctx)
}

func (p *Policy) readAddressesFresh() (Addresses, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.readbackTimeout())
	defer cancel()
	return p.session.controller.Addresses(ctx)
}

func (p *Policy) readPathsFresh() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.readbackTimeout())
	defer cancel()
	return p.session.controller.ExcludedDevicePaths(ctx)
}

func (p *Policy) readbackTimeout() time.Duration {
	if p.timeout > 0 {
		return p.timeout
	}
	return 30 * time.Second
}

func equalPaths(left, right []string) bool {
	canonical := func(input []string) []string {
		result := make([]string, len(input))
		for index, path := range input {
			result[index] = strings.ToLower(strings.TrimSpace(path))
		}
		slices.Sort(result)
		return slices.Compact(result)
	}
	return slices.Equal(canonical(left), canonical(right))
}

func (p *Policy) readEvents(ctx context.Context, onEvent func(Event), onError func(error)) {
	defer close(p.done)
	for {
		event, err := p.session.controller.ReadEvent(ctx)
		if err != nil {
			if ctx.Err() == nil && onError != nil {
				onError(fmt.Errorf("read split-driver event: %w", err))
			}
			return
		}
		event.Raw = append([]byte(nil), event.Raw...)
		if event.IsSplittingError() && onError != nil {
			onError(&EventError{Event: event})
		}
		if onEvent != nil {
			onEvent(event)
		}
	}
}

// AppliedGeneration returns the generation published after all initial driver
// mutations completed successfully.
func (p *Policy) AppliedGeneration() uint64 {
	if p == nil {
		return 0
	}
	return p.generation.Load()
}

// AppliedAddresses returns the four roles from the last completely verified
// generation.
func (p *Policy) AppliedAddresses() Addresses {
	if p == nil {
		return Addresses{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.addresses
}

// Warnings returns a copy of non-fatal process snapshot diagnostics.
func (p *Policy) Warnings() []ProcessWarning {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneWarnings(p.warnings)
}

// StopEvents cancels and joins the sole event reader. It is idempotent.
func (p *Policy) StopEvents() {
	if p == nil {
		return
	}
	p.closeOnce.Do(p.cancel)
	<-p.done
}

func (p *Policy) stopEvents(ctx context.Context) error {
	p.closeOnce.Do(p.cancel)
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops event intake, resets the driver with a fresh bounded context,
// verifies the clean state, and then releases the session and its WFP objects.
// A failed reset deliberately leaves the session journal recovery-required.
func (p *Policy) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed && p.session.Cleaned() {
		return p.closeErr
	}
	p.closed = true
	stopCtx, cancel := context.WithTimeout(context.Background(), p.readbackTimeout())
	stopErr := p.stopEvents(stopCtx)
	cancel()
	if stopErr != nil {
		p.closeErr = errors.Join(ErrRecoveryRequired, fmt.Errorf("stop split event reader: %w", stopErr))
		return p.closeErr
	}
	// Session.Close creates its own context. It must not inherit cancellation
	// from a policy update or from the event-reader stop attempt.
	p.closeErr = p.session.Close()
	return p.closeErr
}

// Cleaned is used by the owning resource journal for independent
// verification after an inverse operation. It intentionally does not infer
// cleanup from the error returned by Reset or Close.
func (p *Policy) Cleaned() bool {
	return p == nil || p.session == nil || p.session.Cleaned()
}

func cloneProcesses(input []Process) []Process { return append([]Process(nil), input...) }

func cloneWarnings(input []ProcessWarning) []ProcessWarning {
	return append([]ProcessWarning(nil), input...)
}
