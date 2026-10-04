//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	sysnetwindows "github.com/asciimoth/sysnet-windows"
	internalnetwork "github.com/asciimoth/sysnet-windows/internal/network"
)

// TestNativeOutNetListenPacketUDPContract verifies the public ownership
// wrapper, all UDP write methods, generic addresses, full-duplex traffic, and
// lifecycle behavior for fixed-port wildcard packet listeners.
func TestNativeOutNetListenPacketUDPContract(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	outNet := system.OutNet()
	addresses, err := outNet.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs() error = %v", err)
	}

	families := []struct {
		name     string
		network  string
		wildcard netip.Addr
		loopback netip.Addr
		ipv4     bool
	}{
		{name: "IPv4", network: "udp4", wildcard: netip.IPv4Unspecified(), loopback: netip.MustParseAddr("127.0.0.1"), ipv4: true},
		{name: "IPv6", network: "udp6", wildcard: netip.IPv6Unspecified(), loopback: netip.IPv6Loopback()},
	}
	tested := 0
	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			selected := selectedAddress(addresses, family.ipv4)
			if !selected.IsValid() {
				t.Skipf("host has no selected %s underlay", family.name)
			}
			firstPort := reserveE2EWildcardUDPPort(t, family.network, family.wildcard)
			secondPort := reserveE2EWildcardUDPPort(t, family.network, family.wildcard)
			if firstPort == secondPort {
				secondPort = reserveDistinctE2EWildcardUDPPort(t, family.network, family.wildcard, firstPort)
			}
			first := listenOwnedPacketUDP(t, outNet, nil, family.network, netip.AddrPortFrom(family.wildcard, uint16(firstPort)).String())
			second := listenOwnedPacketUDP(t, outNet, &gonnect.ListenConfig{}, family.network, netip.AddrPortFrom(family.wildcard, uint16(secondPort)).String())
			t.Cleanup(func() { _ = first.Close() })
			t.Cleanup(func() { _ = second.Close() })

			t.Run("method-set-and-wrapper-chain", func(t *testing.T) {
				assertWrapperChainTerminates(t, first)
				assertWrapperChainTerminates(t, second)
			})

			t.Run("all-write-methods-and-replies", func(t *testing.T) {
				destination := netip.AddrPortFrom(family.loopback, uint16(secondPort))
				writes := []struct {
					name string
					run  func([]byte) error
				}{
					{name: "WriteTo", run: func(payload []byte) error {
						_, writeErr := first.WriteTo(payload, net.UDPAddrFromAddrPort(destination))
						return writeErr
					}},
					{name: "WriteToUDP", run: func(payload []byte) error {
						_, writeErr := first.WriteToUDP(payload, net.UDPAddrFromAddrPort(destination))
						return writeErr
					}},
					{name: "WriteToUDPAddrPort", run: func(payload []byte) error {
						_, writeErr := first.WriteToUDPAddrPort(payload, destination)
						return writeErr
					}},
					{name: "WriteMsgUDP", run: func(payload []byte) error {
						_, _, writeErr := first.WriteMsgUDP(payload, nil, net.UDPAddrFromAddrPort(destination))
						return writeErr
					}},
					{name: "WriteMsgUDPAddrPort", run: func(payload []byte) error {
						_, _, writeErr := first.WriteMsgUDPAddrPort(payload, nil, destination)
						return writeErr
					}},
					{name: "generic WriteTo", run: func(payload []byte) error {
						_, writeErr := first.WriteTo(payload, &gonnect.NetAddr{Net: family.network, Addr: destination.String()})
						return writeErr
					}},
				}
				for index, write := range writes {
					payload := []byte(fmt.Sprintf("%s-%d", write.name, index))
					if writeErr := write.run(payload); writeErr != nil {
						t.Fatalf("%s() error = %v", write.name, writeErr)
					}
					source := readPacketUDP(t, second, payload)
					if int(source.Port()) != firstPort || !source.Addr().IsLoopback() {
						t.Fatalf("%s source = %s, want loopback port %d", write.name, source, firstPort)
					}
					reply := append([]byte("reply-"), payload...)
					if _, writeErr := second.WriteToUDPAddrPort(reply, source); writeErr != nil {
						t.Fatalf("%s reply error = %v", write.name, writeErr)
					}
					replySource := readPacketUDP(t, first, reply)
					if int(replySource.Port()) != secondPort {
						t.Fatalf("%s reply source port = %d, want %d", write.name, replySource.Port(), secondPort)
					}
				}
			})

			t.Run("mixed-loopback-and-underlay", func(t *testing.T) {
				receiver, listenErr := net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(selected, 0)))
				if listenErr != nil {
					t.Fatalf("listen on selected underlay: %v", listenErr)
				}
				defer receiver.Close()
				loopbackDestination := netip.AddrPortFrom(family.loopback, uint16(secondPort))
				for index := range 3 {
					if index != 1 {
						payload := []byte(fmt.Sprintf("loopback-%d", index))
						if _, writeErr := first.WriteToUDPAddrPort(payload, loopbackDestination); writeErr != nil {
							t.Fatalf("loopback write %d: %v", index, writeErr)
						}
						readPacketUDP(t, second, payload)
						continue
					}
					payload := []byte("underlay")
					destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
					if _, writeErr := first.WriteToUDPAddrPort(payload, destination); writeErr != nil {
						t.Fatalf("underlay write: %v", writeErr)
					}
					if deadlineErr := receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
						t.Fatal(deadlineErr)
					}
					buffer := make([]byte, 32)
					n, source, readErr := receiver.ReadFromUDPAddrPort(buffer)
					if readErr != nil || string(buffer[:n]) != string(payload) || source.Addr().WithZone("").Unmap() != selected.WithZone("").Unmap() || int(source.Port()) != firstPort {
						t.Fatalf("underlay read = %q from %s, error %v; want source %s:%d", buffer[:n], source, readErr, selected, firstPort)
					}
				}
			})

			t.Run("concurrent-full-duplex", func(t *testing.T) {
				const datagrams = 64
				firstDestination := netip.AddrPortFrom(family.loopback, uint16(firstPort))
				secondDestination := netip.AddrPortFrom(family.loopback, uint16(secondPort))
				var group sync.WaitGroup
				group.Add(2)
				go sendPacketSeries(t, &group, first, secondDestination, "first", datagrams)
				go sendPacketSeries(t, &group, second, firstDestination, "second", datagrams)
				for range datagrams {
					readAnyPacketUDP(t, first)
					readAnyPacketUDP(t, second)
				}
				group.Wait()
			})

			t.Run("deadline-close-and-rebind", func(t *testing.T) {
				if deadlineErr := first.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); deadlineErr != nil {
					t.Fatal(deadlineErr)
				}
				started := time.Now()
				if _, _, readErr := first.ReadFromUDPAddrPort(make([]byte, 1)); !errors.Is(readErr, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline read error = %v, want deadline exceeded", readErr)
				}
				if elapsed := time.Since(started); elapsed < 50*time.Millisecond || elapsed > 5*time.Second {
					t.Fatalf("deadline elapsed = %v, want 50ms..5s", elapsed)
				}
				if deadlineErr := first.SetReadDeadline(time.Time{}); deadlineErr != nil {
					t.Fatal(deadlineErr)
				}
				readResult := make(chan error, 1)
				go func() {
					_, _, readErr := first.ReadFromUDPAddrPort(make([]byte, 1))
					readResult <- readErr
				}()
				time.Sleep(20 * time.Millisecond)
				if closeErr := first.Close(); closeErr != nil {
					t.Fatalf("Close() error = %v", closeErr)
				}
				select {
				case readErr := <-readResult:
					if !errors.Is(readErr, net.ErrClosed) {
						t.Fatalf("blocked read error = %v, want closed", readErr)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("Close() did not unblock ReadFromUDPAddrPort()")
				}
				if closeErr := first.Close(); closeErr != nil {
					t.Fatalf("second Close() error = %v", closeErr)
				}
				rebound := listenOwnedPacketUDP(t, outNet, nil, family.network, netip.AddrPortFrom(family.wildcard, uint16(firstPort)).String())
				if closeErr := rebound.Close(); closeErr != nil {
					t.Fatalf("rebound Close() error = %v", closeErr)
				}
			})

			if closeErr := second.Close(); closeErr != nil {
				t.Fatalf("second endpoint Close() error = %v", closeErr)
			}
			tested++
		})
	}
	if tested == 0 {
		t.Fatal("host has no usable UDP family")
	}
}

// TestNativeOutNetPacketDialPreservesUDPConn verifies the connected packet
// operation because it uses the same ownership path as ListenPacket.
func TestNativeOutNetPacketDialPreservesUDPConn(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen loopback UDP: %v", err)
	}
	defer receiver.Close()
	packet, err := system.OutNet().PacketDial(context.Background(), "udp4", receiver.LocalAddr().String())
	if errors.Is(err, internalnetwork.ErrUnderlayUnavailable) {
		t.Skip("host has no selected IPv4 underlay")
	}
	if err != nil {
		t.Fatalf("PacketDial() error = %v", err)
	}
	defer func() { _ = packet.Close() }()
	udp, ok := packet.(gonnect.UDPConn)
	if !ok {
		t.Fatalf("PacketDial() type = %T, want gonnect.UDPConn", packet)
	}
	assertWrapperChainTerminates(t, packet)
	if _, err := udp.Write([]byte("packet-dial")); err != nil {
		t.Fatalf("PacketDial() Write() error = %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := receiver.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "packet-dial" {
		t.Fatalf("PacketDial() peer read = %q from %s, error %v", buffer[:n], source, err)
	}
	if _, err := receiver.WriteToUDPAddrPort([]byte("packet-reply"), source); err != nil {
		t.Fatalf("PacketDial() peer reply error = %v", err)
	}
	if err := udp.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err = udp.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "packet-reply" {
		t.Fatalf("PacketDial() reply = %q, error %v", buffer[:n], err)
	}
}

func listenOwnedPacketUDP(t *testing.T, network gonnect.Network, config *gonnect.ListenConfig, protocol, address string) gonnect.UDPConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var packet gonnect.PacketConn
	var err error
	if config == nil {
		packet, err = network.ListenPacket(ctx, protocol, address)
	} else {
		packet, err = network.ListenPacketConfig(ctx, config, protocol, address)
	}
	if errors.Is(err, internalnetwork.ErrUnderlayUnavailable) {
		t.Skipf("selected underlay became unavailable for %s", protocol)
	}
	if err != nil {
		t.Fatalf("ListenPacket(%q) error = %v", address, err)
	}
	udp, ok := packet.(gonnect.UDPConn)
	if !ok {
		_ = packet.Close()
		t.Fatalf("ListenPacket(%q) type = %T, want gonnect.UDPConn", address, packet)
	}
	if got := udp.LocalAddr().(*net.UDPAddr).Port; got != int(netip.MustParseAddrPort(address).Port()) {
		_ = udp.Close()
		t.Fatalf("ListenPacket(%q) local port = %d", address, got)
	}
	return udp
}

func assertWrapperChainTerminates(t *testing.T, value any) {
	t.Helper()
	seen := make(map[any]struct{})
	for depth := 0; depth < 16; depth++ {
		wrapper, ok := value.(gonnect.Wrapper)
		if !ok {
			return
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("wrapper chain contains a cycle at %T", value)
		}
		seen[value] = struct{}{}
		next := wrapper.GetWrapped()
		if next == nil || next == value {
			t.Fatalf("wrapper %T returned invalid wrapped value %T", value, next)
		}
		value = next
	}
	t.Fatal("wrapper traversal did not terminate")
}

func readPacketUDP(t *testing.T, connection gonnect.UDPConn, want []byte) netip.AddrPort {
	t.Helper()
	buffer, source := readAnyPacketUDP(t, connection)
	if string(buffer) != string(want) {
		t.Fatalf("received payload = %q, want %q", buffer, want)
	}
	return source
}

func readAnyPacketUDP(t *testing.T, connection gonnect.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, source, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
	}
	return buffer[:n], source
}

func sendPacketSeries(t *testing.T, group *sync.WaitGroup, connection gonnect.UDPConn, destination netip.AddrPort, prefix string, count int) {
	t.Helper()
	defer group.Done()
	for index := range count {
		if _, err := connection.WriteToUDPAddrPort([]byte(fmt.Sprintf("%s-%d", prefix, index)), destination); err != nil {
			t.Errorf("%s write %d error = %v", prefix, index, err)
			return
		}
	}
}

func reserveDistinctE2EWildcardUDPPort(t *testing.T, network string, wildcard netip.Addr, excluded int) int {
	t.Helper()
	for range 10 {
		port := reserveE2EWildcardUDPPort(t, network, wildcard)
		if port != excluded {
			return port
		}
	}
	t.Fatalf("could not reserve a port other than %d", excluded)
	return 0
}
