package network

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

func TestSocketBinderAppliesAndReadsBackEachFamily(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		family Family
		local  netip.Addr
		path   underlay.Path
	}{
		{name: "IPv4", family: FamilyIPv4, local: netip.MustParseAddr("192.0.2.10"), path: testPath(4, 41)},
		{name: "IPv6", family: FamilyIPv6, local: netip.MustParseAddr("2001:db8::10"), path: testPath(6, 61)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			paths := &fakePaths{snapshot: snapshotFor(test.family, test.path)}
			options := &fakeOptions{}
			binder := &Binder{paths: paths, options: options}
			callerRan := false
			control, err := binder.Control("dial UDP", test.family, test.local, func(network, address string, _ syscall.RawConn) error {
				callerRan = true
				if network != "udp" || address != "example.test:53" {
					t.Fatalf("caller arguments = %q, %q", network, address)
				}
				options.record("caller")
				return nil
			})
			if err != nil {
				t.Fatalf("Control: %v", err)
			}
			if err := control("udp", "example.test:53", &fakeRawConn{descriptor: 7}); err != nil {
				t.Fatalf("control callback: %v", err)
			}
			if !callerRan {
				t.Fatal("caller control did not run")
			}
			if got := options.calls(); strings.Join(got, ",") != "caller,get,set:41,get" && strings.Join(got, ",") != "caller,get,set:61,get" {
				t.Fatalf("option calls = %v", got)
			}
		})
	}
}

func TestSocketBinderRejectsLocalAddressBeforeSocketMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		family Family
		local  netip.Addr
	}{
		{name: "other source", family: FamilyIPv4, local: netip.MustParseAddr("192.0.2.11")},
		{name: "wrong family", family: FamilyIPv4, local: netip.MustParseAddr("2001:db8::10")},
		{name: "mapped IPv4", family: FamilyIPv6, local: netip.MustParseAddr("::ffff:192.0.2.10")},
		{name: "zoned IPv6", family: FamilyIPv6, local: netip.MustParseAddr("2001:db8::10%ethernet")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			paths := &fakePaths{snapshot: underlay.Snapshot{IPv4: pathPointer(testPath(4, 41)), IPv6: pathPointer(testPath(6, 61))}}
			options := &fakeOptions{}
			binder := &Binder{paths: paths, options: options}
			callerRan := false
			control, err := binder.Control("dial TCP", test.family, test.local, func(string, string, syscall.RawConn) error {
				callerRan = true
				return nil
			})
			if err == nil {
				err = control("tcp", "example.test:443", &fakeRawConn{descriptor: 8})
			}
			if !errors.Is(err, ErrLocalAddressConflict) {
				t.Fatalf("error = %v, want ErrLocalAddressConflict", err)
			}
			if callerRan || len(options.calls()) != 0 {
				t.Fatalf("rejected operation mutated socket: caller=%t calls=%v", callerRan, options.calls())
			}
		})
	}
}

func TestSocketBinderCallerRunsBeforeMandatoryConflictCheck(t *testing.T) {
	t.Parallel()
	options := &fakeOptions{}
	binder := &Binder{paths: &fakePaths{snapshot: snapshotFor(FamilyIPv4, testPath(4, 41))}, options: options}
	control, err := binder.Control("dial TCP", FamilyIPv4, netip.Addr{}, func(string, string, syscall.RawConn) error {
		options.record("caller")
		options.value = 99
		return nil
	})
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	err = control("tcp4", "192.0.2.1:443", &fakeRawConn{descriptor: 9})
	if !errors.Is(err, ErrSocketPolicyConflict) {
		t.Fatalf("error = %v, want ErrSocketPolicyConflict", err)
	}
	if got := strings.Join(options.calls(), ","); got != "caller,get" {
		t.Fatalf("option calls = %s, want caller,get", got)
	}
}

func TestSocketBinderUsesReplacementSnapshotAfterCallerControl(t *testing.T) {
	t.Parallel()
	paths := &fakePaths{snapshot: snapshotFor(FamilyIPv4, testPath(4, 41))}
	options := &fakeOptions{}
	binder := &Binder{paths: paths, options: options}
	control, err := binder.Control("dial TCP", FamilyIPv4, netip.Addr{}, func(string, string, syscall.RawConn) error {
		paths.set(snapshotFor(FamilyIPv4, testPath(4, 42)))
		return nil
	})
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if err := control("tcp4", "192.0.2.1:443", &fakeRawConn{descriptor: 10}); err != nil {
		t.Fatalf("control callback: %v", err)
	}
	if got := strings.Join(options.calls(), ","); got != "get,set:42,get" {
		t.Fatalf("option calls = %s, want replacement index 42", got)
	}
}

func TestSocketBinderExposesAllFailuresWithContext(t *testing.T) {
	t.Parallel()
	nativeErr := syscall.Errno(10013)
	tests := []struct {
		name       string
		paths      underlay.Snapshot
		options    *fakeOptions
		rawErr     error
		callerErr  error
		want       error
		wantAction string
	}{
		{name: "underlay loss", want: ErrUnderlayUnavailable, wantAction: "select path"},
		{name: "caller permission", paths: snapshotFor(FamilyIPv4, testPath(4, 41)), callerErr: nativeErr, want: nativeErr, wantAction: "run caller control"},
		{name: "raw connection", paths: snapshotFor(FamilyIPv4, testPath(4, 41)), rawErr: syscall.EINVAL, want: syscall.EINVAL, wantAction: "access raw socket"},
		{name: "get permission", paths: snapshotFor(FamilyIPv4, testPath(4, 41)), options: &fakeOptions{getErr: nativeErr}, want: nativeErr, wantAction: "apply interface option"},
		{name: "set stale index", paths: snapshotFor(FamilyIPv4, testPath(4, 41)), options: &fakeOptions{setErr: syscall.ENODEV}, want: syscall.ENODEV, wantAction: "apply interface option"},
		{name: "readback mismatch", paths: snapshotFor(FamilyIPv4, testPath(4, 41)), options: &fakeOptions{discardSet: true}, want: ErrSocketPolicyReadback, wantAction: "apply interface option"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := test.options
			if options == nil {
				options = &fakeOptions{}
			}
			binder := &Binder{paths: &fakePaths{snapshot: test.paths}, options: options}
			control, err := binder.Control("dial TCP", FamilyIPv4, netip.Addr{}, func(string, string, syscall.RawConn) error {
				return test.callerErr
			})
			if err != nil {
				t.Fatalf("Control: %v", err)
			}
			err = control("tcp4", "192.0.2.1:443", &fakeRawConn{descriptor: 11, controlErr: test.rawErr})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want cause %v", err, test.want)
			}
			var bindErr *BindError
			if !errors.As(err, &bindErr) || bindErr.Operation != "dial TCP" || bindErr.Family != FamilyIPv4 || bindErr.Action != test.wantAction {
				t.Fatalf("context = %#v", bindErr)
			}
		})
	}
}

func TestNewSocketBinderValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewBinder(nil); err == nil {
		t.Fatal("NewBinder(nil) succeeded")
	}
	binder, err := NewBinder(&fakePaths{})
	if err != nil {
		t.Fatalf("NewBinder: %v", err)
	}
	if _, err := binder.Control("", FamilyIPv4, netip.Addr{}, nil); err == nil {
		t.Fatal("empty operation succeeded")
	}
	if _, err := binder.Control("dial", Family(5), netip.Addr{}, nil); err == nil {
		t.Fatal("unknown family succeeded")
	}
}

type fakePaths struct {
	mu       sync.Mutex
	snapshot underlay.Snapshot
}

func (f *fakePaths) Snapshot() underlay.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

func (f *fakePaths) set(snapshot underlay.Snapshot) {
	f.mu.Lock()
	f.snapshot = snapshot
	f.mu.Unlock()
}

type fakeOptions struct {
	mu         sync.Mutex
	value      uint32
	log        []string
	getErr     error
	setErr     error
	discardSet bool
}

func (f *fakeOptions) get(uintptr, Family) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "get")
	if f.getErr != nil {
		return 0, f.getErr
	}
	return f.value, nil
}

func (f *fakeOptions) set(_ uintptr, _ Family, value uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "set:"+strconv.FormatUint(uint64(value), 10))
	if f.setErr != nil {
		return f.setErr
	}
	if !f.discardSet {
		f.value = value
	}
	return nil
}

func (f *fakeOptions) record(value string) {
	f.mu.Lock()
	f.log = append(f.log, value)
	f.mu.Unlock()
}

func (f *fakeOptions) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

type fakeRawConn struct {
	descriptor uintptr
	controlErr error
}

func (f *fakeRawConn) Control(callback func(uintptr)) error {
	if f.controlErr != nil {
		return f.controlErr
	}
	callback(f.descriptor)
	return nil
}

func (*fakeRawConn) Read(func(uintptr) bool) error  { return errors.ErrUnsupported }
func (*fakeRawConn) Write(func(uintptr) bool) error { return errors.ErrUnsupported }

func testPath(family int, index uint32) underlay.Path {
	if family == 4 {
		return underlay.Path{InterfaceIndex: index, InterfaceName: "Ethernet", Source: netip.MustParseAddr("192.0.2.10")}
	}
	return underlay.Path{InterfaceIndex: index, InterfaceName: "Ethernet 2", Source: netip.MustParseAddr("2001:db8::10")}
}

func pathPointer(path underlay.Path) *underlay.Path { return &path }

func snapshotFor(family Family, path underlay.Path) underlay.Snapshot {
	if family == FamilyIPv4 {
		return underlay.Snapshot{IPv4: pathPointer(path)}
	}
	return underlay.Snapshot{IPv6: pathPointer(path)}
}
