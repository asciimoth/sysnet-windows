package network

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"

	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

// Family identifies the address family of a socket policy.
type Family uint8

const (
	FamilyIPv4 Family = 4
	FamilyIPv6 Family = 6
)

var (
	// ErrUnderlayUnavailable reports that the requested family has no current
	// selected path. A caller must not retry the operation without its binding
	// policy because that can send traffic through an owned tunnel.
	ErrUnderlayUnavailable = errors.New("underlay is unavailable")
	// ErrUnderlayChanged reports that the selected path changed while the
	// mandatory socket policy was being applied. The caller must start a new
	// operation with the replacement path.
	ErrUnderlayChanged = errors.New("underlay changed during socket binding")
	// ErrLocalAddressConflict reports that an explicit local address does not
	// belong to the selected underlay.
	ErrLocalAddressConflict = errors.New("local address conflicts with underlay")
	// ErrSocketPolicyConflict reports that a caller control installed a
	// different interface policy before the mandatory control ran.
	ErrSocketPolicyConflict = errors.New("socket interface policy conflicts with underlay")
	// ErrSocketPolicyReadback reports that Winsock did not retain the mandatory
	// interface option.
	ErrSocketPolicyReadback = errors.New("socket interface policy readback failed")
)

// ControlFunc has the same contract as net.Dialer.Control and
// net.ListenConfig.Control.
type ControlFunc func(network, address string, connection syscall.RawConn) error

// PathSource supplies one coherent, current underlay snapshot.
type PathSource interface {
	Snapshot() underlay.Snapshot
}

// BindError adds stable socket-policy context while retaining the native
// Winsock or RawConn error for errors.Is and errors.As.
type BindError struct {
	Operation      string
	Family         Family
	InterfaceIndex uint32
	InterfaceName  string
	Action         string
	Err            error
}

func (e *BindError) Error() string {
	iface := "unavailable interface"
	if e.InterfaceIndex != 0 {
		iface = fmt.Sprintf("interface %d", e.InterfaceIndex)
		if e.InterfaceName != "" {
			iface += " (" + e.InterfaceName + ")"
		}
	}
	return fmt.Sprintf("%s %s on IPv%d %s: %v", e.Operation, e.Action, e.Family, iface, e.Err)
}

func (e *BindError) Unwrap() error { return e.Err }

// Binder creates pre-bind and pre-connect controls which enforce the selected
// Windows underlay. It reads PathSource inside each control so an interface
// recreation cannot leave a prepared operation with a cached index.
type Binder struct {
	paths   PathSource
	options socketOptions
}

// NewBinder creates a binder which uses native Windows socket options.
// Constructing a Binder does not create a socket or change host state.
func NewBinder(paths PathSource) (*Binder, error) {
	if paths == nil {
		return nil, errors.New("create socket binder with nil underlay source")
	}
	return &Binder{paths: paths, options: nativeSocketOptions{}}, nil
}

// Control validates fixed policy and returns a control suitable for a dialer
// or listener. local can be invalid or unspecified when the caller does not
// request a source address. An explicit local address must exactly match the
// source in the current selected path.
//
// The returned function runs caller first. It then rejects a caller-installed
// conflicting interface option, sets the mandatory option, and reads the value
// back. It never retries an operation without that option.
func (b *Binder) Control(operation string, family Family, local netip.Addr, caller ControlFunc) (ControlFunc, error) {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return nil, errors.New("socket binding operation is empty")
	}
	if family != FamilyIPv4 && family != FamilyIPv6 {
		return nil, fmt.Errorf("%s: unsupported socket family %d", operation, family)
	}
	if err := validateLocal(family, local); err != nil {
		return nil, &BindError{Operation: operation, Family: family, Action: "validate local address", Err: err}
	}
	return func(network, address string, connection syscall.RawConn) error {
		// Reject a known unavailable or conflicting path before the caller can
		// mutate the socket. Read it again after caller returns because a network
		// callback can replace the selection while caller is running.
		initialPath, err := b.currentPath(operation, family, local)
		if err != nil {
			return err
		}
		if caller != nil {
			if err := caller(network, address, connection); err != nil {
				return bindError(operation, family, initialPath, "run caller control", err)
			}
		}
		path, err := b.currentPath(operation, family, local)
		if err != nil {
			return err
		}
		var controlErr error
		err = connection.Control(func(descriptor uintptr) {
			current, optionErr := b.options.get(descriptor, family)
			if optionErr != nil {
				controlErr = optionErr
				return
			}
			if current != 0 && current != path.InterfaceIndex {
				controlErr = fmt.Errorf("%w: caller selected interface %d", ErrSocketPolicyConflict, current)
				return
			}
			if optionErr = b.options.set(descriptor, family, path.InterfaceIndex); optionErr != nil {
				controlErr = optionErr
				return
			}
			current, optionErr = b.options.get(descriptor, family)
			if optionErr != nil {
				controlErr = optionErr
				return
			}
			if current != path.InterfaceIndex {
				controlErr = fmt.Errorf("%w: got interface %d, want %d", ErrSocketPolicyReadback, current, path.InterfaceIndex)
			}
		})
		if err != nil {
			return bindError(operation, family, path, "access raw socket", err)
		}
		if controlErr != nil {
			return bindError(operation, family, path, "apply interface option", controlErr)
		}
		currentPath, err := b.currentPath(operation, family, local)
		if err != nil {
			return err
		}
		if !sameBindingPath(path, currentPath) {
			return bindError(operation, family, path, "verify selected path", ErrUnderlayChanged)
		}
		return nil
	}, nil
}

func sameBindingPath(left, right *underlay.Path) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.InterfaceIndex == right.InterfaceIndex &&
		left.InterfaceLUID == right.InterfaceLUID &&
		strings.EqualFold(left.InterfaceGUID, right.InterfaceGUID) &&
		left.Source == right.Source
}

func (b *Binder) currentPath(operation string, family Family, local netip.Addr) (*underlay.Path, error) {
	snapshot := b.paths.Snapshot()
	path := snapshot.IPv4
	if family == FamilyIPv6 {
		path = snapshot.IPv6
	}
	if path == nil {
		return nil, &BindError{Operation: operation, Family: family, Action: "select path", Err: ErrUnderlayUnavailable}
	}
	if path.InterfaceIndex == 0 || !path.Source.IsValid() || path.Source.Is4() != (family == FamilyIPv4) {
		return nil, bindError(operation, family, path, "validate path", ErrUnderlayUnavailable)
	}
	if local.IsValid() && !local.IsUnspecified() && local != path.Source {
		return nil, bindError(operation, family, path, "validate local address", ErrLocalAddressConflict)
	}
	return path, nil
}

func validateLocal(family Family, local netip.Addr) error {
	if !local.IsValid() {
		return nil
	}
	if local.Is4In6() || local.Zone() != "" {
		return ErrLocalAddressConflict
	}
	if local.Is4() != (family == FamilyIPv4) {
		return ErrLocalAddressConflict
	}
	return nil
}

func bindError(operation string, family Family, path *underlay.Path, action string, err error) error {
	result := &BindError{Operation: operation, Family: family, Action: action, Err: err}
	if path != nil {
		result.InterfaceIndex = path.InterfaceIndex
		result.InterfaceName = path.InterfaceName
	}
	return result
}

type socketOptions interface {
	get(uintptr, Family) (uint32, error)
	set(uintptr, Family, uint32) error
}
