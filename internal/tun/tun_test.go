package tun

import (
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gtun "github.com/asciimoth/gonnect/tun"
)

var testMetadata = Metadata{
	GUID:  "{01234567-89ab-cdef-0123-456789abcdef}",
	LUID:  42,
	Index: 7,
}

func TestT10T12AdapterPreservesPacketContract(t *testing.T) {
	t.Parallel()
	packets := [][]byte{
		// IPv4 with an ICMP payload. Adapter must not require a TCP/UDP tuple.
		{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 8, 0, 0, 0, 1, 2, 3, 4},
		// IPv6 with a hop-by-hop extension header and an ICMPv6 payload.
		{0x60, 0, 0, 0, 0, 16, 0, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 58, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 5, 6, 7, 8},
	}
	for _, packet := range packets {
		packet := packet
		t.Run("packet", func(t *testing.T) {
			t.Parallel()
			native := newFakeTun()
			native.batch, native.mro, native.mwo = 3, 11, 13
			native.read = func(bufs [][]byte, sizes []int, offset int) (int, error) {
				if offset != 17 {
					t.Fatalf("native Read offset = %d, want 17", offset)
				}
				copy(bufs[0][offset:], packet)
				sizes[0] = len(packet)
				return 1, nil
			}
			native.write = func(bufs [][]byte, offset int) (int, error) {
				if offset != 19 {
					t.Fatalf("native Write offset = %d, want 19", offset)
				}
				if got := bufs[0][offset:]; !reflect.DeepEqual(got, packet) {
					t.Fatalf("native Write packet = %x, want %x", got, packet)
				}
				return len(bufs), nil
			}
			adapter := mustWrap(t, native)
			t.Cleanup(func() { closeAdapter(t, adapter) })
			if adapter.BatchSize() != 3 || adapter.MRO() != 11 || adapter.MWO() != 13 {
				t.Fatalf("packet contract = batch %d, MRO %d, MWO %d", adapter.BatchSize(), adapter.MRO(), adapter.MWO())
			}
			if adapter.File() != nil || !adapter.IsNative() {
				t.Fatalf("native status = file %v, IsNative %t", adapter.File(), adapter.IsNative())
			}
			if got := adapter.Metadata(); got != testMetadata {
				t.Fatalf("Metadata() = %+v, want %+v", got, testMetadata)
			}

			readBuffer := make([]byte, 17+len(packet))
			sizes := make([]int, 1)
			if n, err := adapter.Read([][]byte{readBuffer}, sizes, 17); err != nil || n != 1 {
				t.Fatalf("Read() = %d, %v", n, err)
			}
			if sizes[0] != len(packet) || !reflect.DeepEqual(readBuffer[17:], packet) {
				t.Fatalf("Read packet = %x size %d, want %x", readBuffer[17:], sizes[0], packet)
			}
			writeBuffer := append(make([]byte, 19), packet...)
			if n, err := adapter.Write([][]byte{writeBuffer}, 19); err != nil || n != 1 {
				t.Fatalf("Write() = %d, %v", n, err)
			}
		})
	}
}

func TestT10AdapterReturnsNativeCapacityError(t *testing.T) {
	t.Parallel()
	native := newFakeTun()
	native.read = func([][]byte, []int, int) (int, error) { return 0, io.ErrShortBuffer }
	adapter := mustWrap(t, native)
	t.Cleanup(func() { closeAdapter(t, adapter) })
	if _, err := adapter.Read([][]byte{{0}}, []int{0}, 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() error = %v, want io.ErrShortBuffer", err)
	}
}

func TestAdapterAllowsOneReaderAndWriterTogether(t *testing.T) {
	t.Parallel()
	native := newFakeTun()
	started := make(chan string, 2)
	release := make(chan struct{})
	native.read = func(_ [][]byte, sizes []int, _ int) (int, error) {
		started <- "read"
		<-release
		sizes[0] = 1
		return 1, nil
	}
	native.write = func([][]byte, int) (int, error) {
		started <- "write"
		<-release
		return 0, nil
	}
	adapter := mustWrap(t, native)
	results := make(chan error, 2)
	go func() {
		_, err := adapter.Read([][]byte{{0}}, []int{0}, 0)
		results <- err
	}()
	go func() {
		_, err := adapter.Write([][]byte{{0}}, 0)
		results <- err
	}()
	waitForValues(t, started, 2)
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("I/O error = %v", err)
		}
	}
	closeAdapter(t, adapter)
}

func TestAdapterMTUReportDoesNotApplyNativeMTU(t *testing.T) {
	t.Parallel()
	native := newFakeTun()
	native.mtu = 1420
	native.nativeMTU = 1500
	adapter := mustWrap(t, native)
	t.Cleanup(func() { closeAdapter(t, adapter) })

	if err := adapter.UpdateReportedMTU(1280); err != nil {
		t.Fatalf("UpdateReportedMTU() error = %v", err)
	}
	if got, err := adapter.MTU(); err != nil || got != 1280 {
		t.Fatalf("MTU() = %d, %v, want 1280", got, err)
	}
	if native.nativeMTU != 1500 {
		t.Fatalf("native MTU = %d, want unchanged 1500", native.nativeMTU)
	}
	select {
	case event := <-adapter.Events():
		if event&gtun.EventMTUUpdate == 0 {
			t.Fatalf("event = %v, want EventMTUUpdate", event)
		}
	case <-time.After(time.Second):
		t.Fatal("MTU event was not delivered")
	}
}

func TestT13T15CloseUnblocksIOAndNormalizesErrors(t *testing.T) {
	t.Parallel()
	native := newFakeTun()
	blocked := make(chan struct{})
	var started sync.WaitGroup
	var readCalls atomic.Int32
	started.Add(2)
	native.read = func(_ [][]byte, sizes []int, _ int) (int, error) {
		if readCalls.Add(1) == 1 {
			sizes[0] = 0
			return 1, nil
		}
		started.Done()
		<-blocked
		return 0, errors.New("native read stopped")
	}
	native.write = func([][]byte, int) (int, error) {
		started.Done()
		<-blocked
		return 0, errors.New("native write stopped")
	}
	native.close = func() error {
		close(blocked)
		return nil
	}
	adapter := mustWrap(t, native)
	readResult := make(chan error, 1)
	writeResult := make(chan error, 1)
	go func() {
		_, err := adapter.Read([][]byte{{0}}, []int{0}, 0)
		readResult <- err
	}()
	go func() {
		_, err := adapter.Write([][]byte{{0}}, 0)
		writeResult <- err
	}()
	waitForWaitGroup(t, &started)

	closeResults := make(chan error, 16)
	for range cap(closeResults) {
		go func() { closeResults <- adapter.Close() }()
	}
	for range cap(closeResults) {
		if err := <-closeResults; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if got := native.closeCalls.Load(); got != 1 {
		t.Fatalf("native Close calls = %d, want 1", got)
	}
	if got := readCalls.Load(); got != 2 {
		t.Fatalf("native Read calls = %d, want 2 after an empty batch", got)
	}
	for operation, result := range map[string]<-chan error{"Read": readResult, "Write": writeResult} {
		select {
		case err := <-result:
			if !errors.Is(err, os.ErrClosed) {
				t.Fatalf("blocked %s error = %v, want os.ErrClosed", operation, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("blocked %s did not return", operation)
		}
	}
	if _, err := adapter.Read([][]byte{{0}}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read() after Close error = %v, want os.ErrClosed", err)
	}
	if _, err := adapter.Write([][]byte{{0}}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write() after Close error = %v, want os.ErrClosed", err)
	}
	if err := adapter.UpdateReportedMTU(1400); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("UpdateReportedMTU() after Close error = %v, want os.ErrClosed", err)
	}
	select {
	case _, ok := <-adapter.Events():
		if ok {
			t.Fatal("Events channel remained open after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Events channel did not close")
	}
}

func TestGUIDAndNameValidation(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"01234567-89AB-CDEF-0123-456789ABCDEF",
		"{01234567-89ab-cdef-0123-456789abcdef}",
	} {
		got, err := NormalizeGUID(input)
		if err != nil || got != testMetadata.GUID {
			t.Fatalf("NormalizeGUID(%q) = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"bad", "{01234567-89ab-cdef-0123-456789abcdeg}", "0123456789ab-cdef-0123-456789abcdef"} {
		if _, err := NormalizeGUID(input); err == nil {
			t.Fatalf("NormalizeGUID(%q) error = nil", input)
		}
	}
	if err := ValidateName("name\x00suffix"); err == nil {
		t.Fatal("ValidateName() accepted NUL")
	}
	if err := ValidateName(strings.Repeat("x", maxAdapterNameLen+1)); err == nil {
		t.Fatal("ValidateName() accepted an oversized name")
	}
}

func TestWrapRejectsInvalidContractAndIdentity(t *testing.T) {
	t.Parallel()
	native := newFakeTun()
	native.batch = 0
	if _, err := Wrap(native, testMetadata); err == nil {
		t.Fatal("Wrap() accepted a zero batch size")
	}
	native.batch = 1
	if _, err := Wrap(native, Metadata{}); err == nil {
		t.Fatal("Wrap() accepted empty metadata")
	}
}

type fakeTun struct {
	batch int
	mro   int
	mwo   int
	mtu   int

	nativeMTU  int
	events     chan gtun.Event
	read       func([][]byte, []int, int) (int, error)
	write      func([][]byte, int) (int, error)
	close      func() error
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newFakeTun() *fakeTun {
	return &fakeTun{batch: 1, mro: 16, mwo: 16, mtu: 1420, nativeMTU: 1500, events: make(chan gtun.Event, 10)}
}

func (*fakeTun) File() *os.File                { return nil }
func (*fakeTun) IsNative() bool                { return true }
func (tun *fakeTun) MWO() int                  { return tun.mwo }
func (tun *fakeTun) MRO() int                  { return tun.mro }
func (tun *fakeTun) BatchSize() int            { return tun.batch }
func (tun *fakeTun) MTU() (int, error)         { return tun.mtu, nil }
func (*fakeTun) Name() (string, error)         { return "test", nil }
func (tun *fakeTun) Events() <-chan gtun.Event { return tun.events }

func (tun *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if tun.read == nil {
		return 0, nil
	}
	return tun.read(bufs, sizes, offset)
}

func (tun *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	if tun.write == nil {
		return len(bufs), nil
	}
	return tun.write(bufs, offset)
}

func (tun *fakeTun) ForceMTU(mtu int) {
	if tun.mtu == mtu {
		return
	}
	tun.mtu = mtu
	tun.events <- gtun.EventMTUUpdate
}

func (tun *fakeTun) Close() (err error) {
	tun.closeOnce.Do(func() {
		tun.closeCalls.Add(1)
		if tun.close != nil {
			err = tun.close()
		}
		close(tun.events)
	})
	return err
}

func mustWrap(t *testing.T, native gtun.Tun) *Adapter {
	t.Helper()
	adapter, err := Wrap(native, testMetadata)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}
	return adapter
}

func closeAdapter(t *testing.T, adapter *Adapter) {
	t.Helper()
	if err := adapter.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func waitForValues(t *testing.T, values <-chan string, count int) {
	t.Helper()
	for range count {
		select {
		case <-values:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for concurrent I/O")
		}
	}
}

func waitForWaitGroup(t *testing.T, group *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blocked I/O")
	}
}
