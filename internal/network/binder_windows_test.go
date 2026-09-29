//go:build windows

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

// TestNativeSocketBinderTCPAndUDP proves that the control can create TCP and
// UDP flows whose observed source is the selected interface address. The test
// uses only a host-local flow and does not change routes or interface state.
func TestNativeSocketBinderTCPAndUDP(t *testing.T) {
	snapshot := nativeUnderlaySnapshot(t)
	tests := []struct {
		name   string
		family Family
		path   *underlay.Path
	}{
		{name: "IPv4", family: FamilyIPv4, path: snapshot.IPv4},
		{name: "IPv6", family: FamilyIPv6, path: snapshot.IPv6},
	}
	tested := 0
	for _, test := range tests {
		if test.path == nil {
			t.Logf("host has no selected %s underlay", test.name)
			continue
		}
		tested++
		t.Run(test.name, func(t *testing.T) {
			paths := staticPaths{snapshot: snapshotFor(test.family, *test.path)}
			binder, err := NewBinder(paths)
			if err != nil {
				t.Fatalf("NewBinder: %v", err)
			}
			t.Run("TCP", func(t *testing.T) { testNativeTCPSource(t, binder, test.family, test.path.Source) })
			t.Run("UDP", func(t *testing.T) { testNativeUDPSource(t, binder, test.family, test.path.Source) })
		})
	}
	if tested == 0 {
		t.Fatal("host has no selected underlay")
	}
}

// TestNativeSocketBinderFamilyFailure verifies that a Winsock family mismatch
// is returned with its native cause and socket-policy context. There is no
// unbound retry.
func TestNativeSocketBinderFamilyFailure(t *testing.T) {
	snapshot := nativeUnderlaySnapshot(t)
	if snapshot.IPv4 == nil {
		t.Skip("host has no selected IPv4 underlay")
	}
	binder, err := NewBinder(staticPaths{snapshot: underlay.Snapshot{IPv4: snapshot.IPv4}})
	if err != nil {
		t.Fatalf("NewBinder: %v", err)
	}
	control, err := binder.Control("test family mismatch", FamilyIPv4, netip.Addr{}, nil)
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	listener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 socket is unavailable: %v", err)
	}
	defer listener.Close()
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	err = control("udp6", listener.LocalAddr().String(), raw)
	if err == nil {
		t.Fatal("IPv4 interface option on IPv6-only socket succeeded")
	}
	var bindErr *BindError
	if !errors.As(err, &bindErr) || bindErr.InterfaceIndex != snapshot.IPv4.InterfaceIndex {
		t.Fatalf("error context = %#v, error = %v", bindErr, err)
	}
}

// TestNativeSocketBinderUnderlayLoss verifies that a prepared control uses the
// latest snapshot and does not touch a socket after its selected path is lost.
func TestNativeSocketBinderUnderlayLoss(t *testing.T) {
	paths := &fakePaths{snapshot: snapshotFor(FamilyIPv4, testPath(4, 41))}
	binder, err := NewBinder(paths)
	if err != nil {
		t.Fatalf("NewBinder: %v", err)
	}
	control, err := binder.Control("test stale selection", FamilyIPv4, netip.Addr{}, nil)
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	paths.set(underlay.Snapshot{})
	err = control("tcp4", "192.0.2.1:443", &fakeRawConn{descriptor: 12})
	if !errors.Is(err, ErrUnderlayUnavailable) {
		t.Fatalf("error = %v, want ErrUnderlayUnavailable", err)
	}
}

// TestN05N08NativeUnconnectedUDPRetainsUnderlayPolicy verifies the operation
// which cannot fall back to an unbound socket: one unconnected UDP socket sends
// to multiple remote endpoints while retaining the selected interface source.
func TestN05N08NativeUnconnectedUDPRetainsUnderlayPolicy(t *testing.T) {
	snapshot := nativeUnderlaySnapshot(t)
	tests := []struct {
		name    string
		network string
		path    *underlay.Path
	}{
		{name: "IPv4", network: "udp4", path: snapshot.IPv4},
		{name: "IPv6", network: "udp6", path: snapshot.IPv6},
	}
	tested := 0
	for _, test := range tests {
		if test.path == nil {
			t.Logf("host has no selected %s underlay", test.name)
			continue
		}
		tested++
		t.Run(test.name, func(t *testing.T) {
			paths := staticPaths{snapshot: snapshot}
			binder, err := NewBinder(paths)
			if err != nil {
				t.Fatal(err)
			}
			network, err := NewBoundNetwork(binder, paths, Families{IPv4: true, IPv6: true})
			if err != nil {
				t.Fatal(err)
			}
			local := net.JoinHostPort(test.path.Source.String(), "0")
			first := listenNativeUDP(t, test.network, test.path.Source)
			defer first.Close()
			second := listenNativeUDP(t, test.network, test.path.Source)
			defer second.Close()
			client, err := network.ListenUDP(context.Background(), test.network, local)
			if err != nil {
				t.Fatalf("create unconnected UDP socket: %v", err)
			}
			defer client.Close()
			for index, destination := range []*net.UDPConn{first, second} {
				address := destination.LocalAddr().(*net.UDPAddr).AddrPort()
				if _, err := client.WriteToUDPAddrPort([]byte{byte(index)}, address); err != nil {
					t.Fatalf("write to endpoint %d: %v", index, err)
				}
				if err := destination.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1)
				_, source, err := destination.ReadFromUDPAddrPort(buffer)
				if err != nil {
					t.Fatalf("read endpoint %d: %v", index, err)
				}
				if source.Addr().WithZone("").Unmap() != test.path.Source.WithZone("").Unmap() {
					t.Fatalf("endpoint %d source = %s, want %s", index, source.Addr(), test.path.Source)
				}
			}
		})
	}
	if tested == 0 {
		t.Fatal("host has no selected underlay")
	}
}

func listenNativeUDP(t *testing.T, network string, source netip.Addr) *net.UDPConn {
	t.Helper()
	listener, err := net.ListenUDP(network, &net.UDPAddr{IP: source.AsSlice()})
	if err != nil {
		t.Fatalf("listen on selected source: %v", err)
	}
	return listener
}

type staticPaths struct{ snapshot underlay.Snapshot }

func (s staticPaths) Snapshot() underlay.Snapshot { return s.snapshot }

func nativeUnderlaySnapshot(t *testing.T) underlay.Snapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	candidates, err := (underlay.NativeSource{}).ReadCandidates(ctx)
	if err != nil {
		t.Fatalf("read native underlays: %v", err)
	}
	return underlay.Select(candidates, "", nil)
}

func testNativeTCPSource(t *testing.T, binder *Binder, family Family, source netip.Addr) {
	t.Helper()
	network := familyNetwork("tcp", family)
	listener, err := net.ListenTCP(network, &net.TCPAddr{IP: source.AsSlice()})
	if err != nil {
		t.Fatalf("listen on selected source: %v", err)
	}
	defer listener.Close()
	control, err := binder.Control("native TCP dial", family, source, nil)
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: source.AsSlice()}, Control: control}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := dialer.DialContext(ctx, network, listener.Addr().String())
	if err != nil {
		t.Fatalf("dial selected source: %v", err)
	}
	defer connection.Close()
	assertNativeSource(t, connection.LocalAddr(), source)
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept selected source: %v", err)
	}
	defer accepted.Close()
	assertNativeSource(t, accepted.RemoteAddr(), source)
}

func testNativeUDPSource(t *testing.T, binder *Binder, family Family, source netip.Addr) {
	t.Helper()
	network := familyNetwork("udp", family)
	listener, err := net.ListenUDP(network, &net.UDPAddr{IP: source.AsSlice()})
	if err != nil {
		t.Fatalf("listen on selected source: %v", err)
	}
	defer listener.Close()
	control, err := binder.Control("native UDP dial", family, source, nil)
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: source.AsSlice()}, Control: control}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := dialer.DialContext(ctx, network, listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial selected source: %v", err)
	}
	defer connection.Close()
	assertNativeSource(t, connection.LocalAddr(), source)
	if _, err := connection.Write([]byte("source-check")); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 32)
	_, remote, err := listener.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if remote.Addr().WithZone("").Unmap() != source {
		t.Fatalf("observed UDP source = %s, want %s", remote.Addr(), source)
	}
}

func assertNativeSource(t *testing.T, address net.Addr, source netip.Addr) {
	t.Helper()
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatalf("split address %q: %v", address, err)
	}
	got, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("parse source %q: %v", host, err)
	}
	if got.WithZone("").Unmap() != source {
		t.Fatalf("observed source = %s, want %s", got, source)
	}
}

func familyNetwork(base string, family Family) string {
	if family == FamilyIPv4 {
		return base + "4"
	}
	if family == FamilyIPv6 {
		return base + "6"
	}
	panic(fmt.Sprintf("unsupported test family %d", family))
}

var _ ControlFunc = func(string, string, syscall.RawConn) error { return nil }
