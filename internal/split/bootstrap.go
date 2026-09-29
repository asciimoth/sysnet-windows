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
	session *Session
	cancel  context.CancelFunc
	done    chan struct{}

	generation atomic.Uint64
	mu         sync.RWMutex
	warnings   []ProcessWarning
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
	if err := session.controller.SetAddresses(ctx, config.Addresses); err != nil {
		return nil, fmt.Errorf("bootstrap split policy: set addresses: %w", err)
	}
	if err := session.controller.SetExcludedDevicePaths(ctx, paths); err != nil {
		return nil, fmt.Errorf("bootstrap split policy: set exclusions: %w", err)
	}

	eventCtx, cancel := context.WithCancel(context.Background())
	policy := &Policy{session: session, cancel: cancel, done: make(chan struct{}), warnings: cloneWarnings(snapshot.Warnings)}
	policy.generation.Store(config.Generation)
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
	p.closeOnce.Do(func() {
		p.cancel()
		<-p.done
	})
}

// Close stops event intake, resets the driver with a fresh bounded context,
// verifies the clean state, and then releases the session and its WFP objects.
// A failed reset deliberately leaves the session journal recovery-required.
func (p *Policy) Close() error {
	if p == nil {
		return nil
	}
	p.StopEvents()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	timeout := p.session.cleanupTimeout
	cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
	resetErr := p.session.controller.Reset(cleanupCtx)
	var verifyErr error
	if resetErr == nil {
		var state State
		state, verifyErr = p.session.controller.State(cleanupCtx)
		if verifyErr == nil && state != StateStarted {
			verifyErr = fmt.Errorf("state after reset is %s, want started", state)
		}
		if verifyErr == nil {
			p.session.MarkResetConfirmed()
		}
	}
	cancel()
	p.closeErr = errors.Join(resetErr, verifyErr, p.session.Close())
	return p.closeErr
}

func cloneProcesses(input []Process) []Process { return append([]Process(nil), input...) }

func cloneWarnings(input []ProcessWarning) []ProcessWarning {
	return append([]ProcessWarning(nil), input...)
}
