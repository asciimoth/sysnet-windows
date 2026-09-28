// Package tun contains the Wintun construction and lifecycle boundary.
package tun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf16"

	gtun "github.com/asciimoth/gonnect/tun"
)

const (
	// DefaultNamePrefix is used when a caller does not request an adapter name.
	DefaultNamePrefix = "gonnect"
	maxAdapterNameLen = 128
)

var (
	// ErrNameCollision reports that an adapter already uses the requested name.
	// The factory does not reuse an adapter that it cannot prove it owns.
	ErrNameCollision = errors.New("wintun adapter name is already in use")
	// ErrIdentityMismatch reports that the created or opened adapter does not
	// have the GUID requested by the caller.
	ErrIdentityMismatch = errors.New("wintun adapter identity does not match")
)

// Config is the normalized device configuration used at creation time. GUID
// is empty for a newly generated stable identity or is a canonical Windows
// GUID. MTU initializes the packet-facing MTU report only. Applying the native
// Windows interface MTU is a separate NetIO transaction.
type Config struct {
	Name string
	GUID string
	MTU  int
}

// Metadata separates durable adapter identity from identifiers that are valid
// only for the current Windows interface instance.
type Metadata struct {
	GUID  string
	LUID  uint64
	Index uint32
}

// ManagedTun is a Wintun device with the identity needed by later NetIO work.
// UpdateReportedMTU does not change Windows interface state. A caller must use
// it only after the native MTU transaction succeeds and is read back.
type ManagedTun interface {
	gtun.Tun
	Metadata() Metadata
	UpdateReportedMTU(int) error
}

// Factory creates one Wintun device. System construction and read-only probes
// must not call it because Wintun can acquire driver resources during explicit
// adapter creation. Implementations must not reuse an adapter whose ownership
// is unknown.
type Factory interface {
	Create(context.Context, Config) (ManagedTun, error)
}

type mtuReporter interface {
	ForceMTU(int)
}

// Adapter preserves the packet contract of its native TUN. It permits one
// active Read and one active Write at the same time and serializes additional
// calls in the same direction. This matches Wintun's documented single-reader
// and single-writer use without holding a lock that can prevent Close.
type Adapter struct {
	native   gtun.Tun
	metadata Metadata
	batch    int
	mro      int
	mwo      int
	events   chan gtun.Event
	stop     chan struct{}
	done     chan struct{}

	readMu    sync.Mutex
	writeMu   sync.Mutex
	controlMu sync.RWMutex
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

// Wrap creates a transparent lifecycle wrapper around a native Wintun TUN.
// The fixed packet layout is captured once because the Tun contract forbids it
// from changing over the device lifetime.
func Wrap(native gtun.Tun, metadata Metadata) (*Adapter, error) {
	if native == nil {
		return nil, errors.New("wrap nil TUN")
	}
	if metadata.GUID == "" || metadata.LUID == 0 || metadata.Index == 0 {
		return nil, fmt.Errorf("invalid Wintun metadata: %+v", metadata)
	}
	batch, mro, mwo := native.BatchSize(), native.MRO(), native.MWO()
	if batch < 1 || mro < 0 || mwo < 0 {
		return nil, fmt.Errorf("invalid Wintun packet contract: batch=%d mro=%d mwo=%d", batch, mro, mwo)
	}
	adapter := &Adapter{
		native: native, metadata: metadata,
		batch: batch, mro: mro, mwo: mwo,
		events: make(chan gtun.Event, 10),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go adapter.forwardEvents(native.Events())
	return adapter, nil
}

// Metadata returns a copy of the immutable creation metadata.
func (a *Adapter) Metadata() Metadata { return a.metadata }

// File returns the native file when one exists. Wintun returns nil because it
// has no Unix-style packet file descriptor.
func (a *Adapter) File() *os.File { return a.native.File() }

// IsNative reports the underlying device status. Adapter does not intercept or
// transform packet data, so bypassing its methods does not bypass packet policy.
func (a *Adapter) IsNative() bool { return a.native.IsNative() }

// Read delegates one batch without changing the buffers, sizes, or offset.
func (a *Adapter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	for {
		if a.closed.Load() {
			return 0, os.ErrClosed
		}
		n, err := a.native.Read(bufs, sizes, offset)
		if err != nil || batchHasPacketData(n, sizes) {
			return n, a.ioError(err)
		}
		// Wintun can return a successful batch with no packet bytes while its
		// session is stopping. Retry so Read keeps its blocking contract and
		// observes a concurrent Close.
	}
}

func batchHasPacketData(n int, sizes []int) bool {
	if n > len(sizes) {
		return true
	}
	for _, size := range sizes[:max(n, 0)] {
		if size > 0 {
			return true
		}
	}
	return false
}

// Write delegates one batch without changing the buffers or offset.
func (a *Adapter) Write(bufs [][]byte, offset int) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.closed.Load() {
		return 0, os.ErrClosed
	}
	n, err := a.native.Write(bufs, offset)
	return n, a.ioError(err)
}

func (a *Adapter) ioError(err error) error {
	if !a.closed.Load() || errors.Is(err, os.ErrClosed) {
		return err
	}
	return errors.Join(os.ErrClosed, err)
}

// MWO returns the native minimum write offset captured at creation.
func (a *Adapter) MWO() int { return a.mwo }

// MRO returns the native minimum read offset captured at creation.
func (a *Adapter) MRO() int { return a.mro }

// BatchSize returns the native batch size captured at creation.
func (a *Adapter) BatchSize() int { return a.batch }

// MTU returns the packet-facing MTU report. It does not read the Windows
// IP-interface MTU and must not be used as native apply verification.
func (a *Adapter) MTU() (int, error) {
	a.controlMu.RLock()
	defer a.controlMu.RUnlock()
	return a.native.MTU()
}

// Name returns the current native adapter name.
func (a *Adapter) Name() (string, error) { return a.native.Name() }

// Events returns the wrapper event stream. Repeated pending event bits can be
// coalesced, as permitted by the TUN event contract. The channel closes when
// the adapter closes even if a consumer does not drain it.
func (a *Adapter) Events() <-chan gtun.Event { return a.events }

// UpdateReportedMTU updates only the packet-facing report and event stream.
// Native NetIO code must apply and verify the Windows interface MTU first.
func (a *Adapter) UpdateReportedMTU(mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("reported MTU must be positive: %d", mtu)
	}
	a.controlMu.Lock()
	defer a.controlMu.Unlock()
	if a.closed.Load() {
		return os.ErrClosed
	}
	reporter, ok := a.native.(mtuReporter)
	if !ok {
		return errors.New("native TUN cannot update its MTU report")
	}
	reporter.ForceMTU(mtu)
	return nil
}

// Close permanently closes the adapter. The native Wintun implementation
// wakes its read wait handle before it waits for active I/O, so pending calls
// return and later calls are rejected with os.ErrClosed.
func (a *Adapter) Close() error {
	a.closeOnce.Do(func() {
		a.closed.Store(true)
		a.controlMu.Lock()
		a.closeErr = a.native.Close()
		a.controlMu.Unlock()
		close(a.stop)
		<-a.done
	})
	return a.closeErr
}

func (a *Adapter) forwardEvents(source <-chan gtun.Event) {
	defer close(a.done)
	defer close(a.events)
	var pending gtun.Event
	for {
		var output chan gtun.Event
		if pending != 0 {
			output = a.events
		}
		select {
		case <-a.stop:
			return
		case event, ok := <-source:
			if !ok {
				return
			}
			pending |= event
		case output <- pending:
			pending = 0
		}
	}
}

// NormalizeGUID validates a Windows GUID without requiring Windows APIs. It
// returns the canonical lowercase form with braces.
func NormalizeGUID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) == 38 && value[0] == '{' && value[len(value)-1] == '}' {
		value = value[1 : len(value)-1]
	}
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", fmt.Errorf("GUID %q does not use the 8-4-4-4-12 form", value)
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !isHexDigit(char) {
			return "", fmt.Errorf("GUID %q contains a non-hexadecimal character", value)
		}
	}
	return "{" + strings.ToLower(value) + "}", nil
}

func isHexDigit(char rune) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F'
}

// ValidateName checks the limits applied by the Wintun API.
func ValidateName(name string) error {
	if name == "" {
		return nil
	}
	if strings.IndexByte(name, 0) >= 0 {
		return errors.New("adapter name contains NUL")
	}
	if len(utf16.Encode([]rune(name))) > maxAdapterNameLen {
		return fmt.Errorf("adapter name exceeds %d UTF-16 code units", maxAdapterNameLen)
	}
	return nil
}
