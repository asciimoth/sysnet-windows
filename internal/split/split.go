// Package split acquires and records the exclusive split-driver session.
package split

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/asciimoth/sysnet-windows/internal/wfp"
)

// State is the driver lifecycle state observed through its pinned ABI.
type State uint64

const (
	StateNone State = iota
	StateStarted
	StateInitialized
	StateReady
	StateEngaged
	StateZombie
)

func (s State) String() string {
	names := [...]string{"none", "started", "initialized", "ready", "engaged", "zombie"}
	if uint64(s) < uint64(len(names)) {
		return names[s]
	}
	return fmt.Sprintf("unknown(%d)", s)
}

var (
	// ErrUnavailable means that the verified driver dependency is absent.
	ErrUnavailable = errors.New("split driver is unavailable")
	// ErrBusy means that another process owns the exclusive device.
	ErrBusy = errors.New("split driver is owned by another process")
	// ErrIncompatible means that provenance or ABI verification failed.
	ErrIncompatible = errors.New("split driver is incompatible")
	// ErrDirty means that the driver contains policy this process does not own.
	ErrDirty = errors.New("split driver has unowned state")
	// ErrRecoveryRequired means that referenced objects must be preserved.
	ErrRecoveryRequired = errors.New("split driver recovery is required")
)

// Deployment is verified, immutable evidence for the opened driver package.
// The verifier must validate service identity, binary path, signature, digest,
// and version before returning it.
type Deployment struct {
	ServiceName string
	BinaryPath  string
	Signer      string
	SHA256      string
	Version     string
	ABI         string
}

// Verifier verifies package provenance without opening or changing the driver.
type Verifier interface {
	Verify(context.Context) (Deployment, error)
}

// Controller is the part of the pinned controller used during acquisition.
type Controller interface {
	State(context.Context) (State, error)
	Initialize(context.Context, Sublayers) error
	RegisterProcesses(context.Context, []Process) error
	SetAddresses(context.Context, Addresses) error
	Addresses(context.Context) (Addresses, error)
	SetExcludedDevicePaths(context.Context, []string) error
	ExcludedDevicePaths(context.Context) ([]string, error)
	ReadEvent(context.Context) (Event, error)
	Reset(context.Context) error
	Close() error
}

// Opener opens the global device exclusively and does not change driver state.
type Opener interface {
	Open() (Controller, error)
}

// Dependencies contains the three independently testable native boundaries.
type Dependencies struct {
	Verifier Verifier
	Opener   Opener
	WFP      wfp.Factory
	Snapshot ProcessSnapshotter
	Resolver PathResolver
	// CleanupTimeout bounds rollback and close cleanup. Zero uses 30 seconds.
	CleanupTimeout time.Duration
}

// AcquisitionError identifies the acquisition phase while preserving both a
// stable classification and the native cause.
type AcquisitionError struct {
	Phase         string
	Kind          error
	State         State
	ObservedState bool
	Err           error
}

// RecoveryError retains the exact ownership journal when acquisition cleanup
// cannot prove that created WFP objects were removed.
type RecoveryError struct {
	Resources wfp.Resources
	Err       error
}

func (e *RecoveryError) Error() string { return "split session recovery is required: " + e.Err.Error() }
func (e *RecoveryError) Unwrap() []error {
	return []error{ErrRecoveryRequired, e.Err}
}

func (e *AcquisitionError) Error() string {
	detail := e.Phase
	if e.ObservedState {
		detail += ": state is " + e.State.String()
	}
	if e.Err != nil {
		detail += ": " + e.Err.Error()
	}
	return "acquire split session: " + detail
}

func (e *AcquisitionError) Unwrap() []error {
	result := []error{e.Kind}
	if e.Err != nil {
		result = append(result, e.Err)
	}
	return result
}

// Session owns the exclusive controller and the exact committed WFP objects.
// A later initialization step must call MarkDriverReferences before it sends
// the first initialization IOCTL, because cancellation can hide a committed
// driver change.
type Session struct {
	mu             sync.Mutex
	controller     Controller
	wfp            wfp.Manager
	deployment     Deployment
	resources      wfp.Resources
	references     bool
	closed         bool
	closeErr       error
	closeDone      chan struct{}
	cleanupTimeout time.Duration
}

// Acquire verifies deployment provenance, opens the device, rejects all state
// except Started, and then creates committed non-dynamic WFP resources. It does
// not initialize or reset the driver.
func Acquire(ctx context.Context, dependencies Dependencies) (*Session, error) {
	if ctx == nil {
		return nil, &AcquisitionError{Phase: "validate context", Kind: ErrUnavailable, Err: errors.New("nil context")}
	}
	if dependencies.Verifier == nil || dependencies.Opener == nil || dependencies.WFP == nil {
		return nil, &AcquisitionError{Phase: "validate dependencies", Kind: ErrUnavailable, Err: errors.New("split dependency is not configured")}
	}
	cleanupTimeout := dependencies.CleanupTimeout
	if cleanupTimeout <= 0 {
		cleanupTimeout = 30 * time.Second
	}
	if err := ctx.Err(); err != nil {
		return nil, &AcquisitionError{Phase: "verify deployment", Kind: ErrUnavailable, Err: err}
	}
	deployment, err := dependencies.Verifier.Verify(ctx)
	if err != nil {
		return nil, &AcquisitionError{Phase: "verify deployment", Kind: ErrIncompatible, Err: err}
	}
	if err := validateDeployment(deployment); err != nil {
		return nil, &AcquisitionError{Phase: "verify deployment", Kind: ErrIncompatible, Err: err}
	}
	controller, err := dependencies.Opener.Open()
	if err != nil {
		kind := ErrUnavailable
		if errors.Is(err, ErrBusy) {
			kind = ErrBusy
		}
		return nil, &AcquisitionError{Phase: "open exclusive device", Kind: kind, Err: err}
	}
	state, stateErr := controller.State(ctx)
	if stateErr != nil {
		return nil, errors.Join(
			&AcquisitionError{Phase: "read driver state", Kind: ErrIncompatible, Err: stateErr},
			controller.Close(),
		)
	}
	if state != StateStarted {
		return nil, errors.Join(
			&AcquisitionError{Phase: "verify clean driver state", Kind: ErrDirty, State: state, ObservedState: true},
			controller.Close(),
		)
	}
	manager, managerErr := dependencies.WFP.Open(ctx)
	if managerErr != nil {
		return nil, errors.Join(
			&AcquisitionError{Phase: "open non-dynamic WFP session", Kind: ErrUnavailable, Err: managerErr},
			controller.Close(),
		)
	}
	resources, createErr := manager.CreateSplitResources(ctx)
	if createErr == nil {
		createErr = resources.Validate()
	}
	if createErr != nil {
		return nil, errors.Join(
			&AcquisitionError{Phase: "create committed WFP resources", Kind: ErrIncompatible, Err: createErr},
			controller.Close(), manager.Close(),
		)
	}
	if err := manager.VerifySplitResources(ctx, resources); err != nil {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		cleanupErr := manager.DeleteSplitResources(cleanupCtx, resources)
		cancelCleanup()
		var recoveryErr error
		if cleanupErr != nil {
			recoveryErr = &RecoveryError{Resources: cloneResources(resources), Err: cleanupErr}
		}
		return nil, errors.Join(
			&AcquisitionError{Phase: "verify committed WFP resources", Kind: ErrIncompatible, Err: err},
			recoveryErr, controller.Close(), manager.Close(),
		)
	}
	return &Session{
		controller: controller, wfp: manager, deployment: deployment,
		resources: cloneResources(resources), closeDone: make(chan struct{}), cleanupTimeout: cleanupTimeout,
	}, nil
}

func validateDeployment(deployment Deployment) error {
	if deployment.ServiceName == "" || deployment.BinaryPath == "" || deployment.Signer == "" ||
		deployment.SHA256 == "" || deployment.Version == "" || deployment.ABI == "" {
		return errors.New("driver deployment evidence is incomplete")
	}
	if deployment.Version != deployment.ABI {
		return fmt.Errorf("driver version %q does not match controller ABI %q", deployment.Version, deployment.ABI)
	}
	return nil
}

// Deployment returns a copy of the verified deployment evidence.
func (s *Session) Deployment() Deployment {
	if s == nil {
		return Deployment{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deployment
}

// Resources returns a deep copy of the exact WFP ownership journal.
func (s *Session) Resources() wfp.Resources {
	if s == nil {
		return wfp.Resources{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneResources(s.resources)
}

// MarkDriverReferences records that an initialization IOCTL can reference the
// WFP objects. From this point, Close preserves them until reset is confirmed.
func (s *Session) MarkDriverReferences() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.references = true
	s.mu.Unlock()
}

// MarkResetConfirmed records independent readback that the driver is Started
// and no longer references the caller-owned WFP objects.
func (s *Session) MarkResetConfirmed() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.references = false
	s.mu.Unlock()
}

// Close releases a clean pre-initialization session. If initialization could
// have reached the driver, it closes the handle but preserves the WFP journal
// and reports recovery-required. Close is idempotent.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		if done != nil {
			<-done
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	}
	s.closed = true
	controller, manager := s.controller, s.wfp
	resources, references := cloneResources(s.resources), s.references
	s.mu.Unlock()

	controllerErr := controller.Close()
	var result error
	if references {
		result = errors.Join(ErrRecoveryRequired, controllerErr, manager.Close())
	} else {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), s.cleanupTimeout)
		deleteErr := manager.DeleteSplitResources(cleanupCtx, resources)
		cancelCleanup()
		result = errors.Join(controllerErr, deleteErr, manager.Close())
	}
	s.mu.Lock()
	s.closeErr = result
	if s.closeDone != nil {
		close(s.closeDone)
	}
	s.mu.Unlock()
	return result
}

func cloneResources(resources wfp.Resources) wfp.Resources {
	resources.Filters = append([]wfp.Object(nil), resources.Filters...)
	return resources
}
