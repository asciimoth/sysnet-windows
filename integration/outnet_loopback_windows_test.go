//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	sysnetwindows "github.com/asciimoth/sysnet-windows"
	internalnetwork "github.com/asciimoth/sysnet-windows/internal/network"
)

// TestNativeOutNetWildcardUDPExchangesWithLoopback verifies that each UDP
// write API selects the loopback component and keeps the logical source port.
// It also verifies the reply path through the same logical connection.
func TestNativeOutNetWildcardUDPExchangesWithLoopback(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	outNet := system.OutNet()

	families := []struct {
		name, network, wildcard string
		loopback                netip.Addr
	}{
		{name: "IPv4", network: "udp4", wildcard: "0.0.0.0:0", loopback: netip.MustParseAddr("127.0.0.1")},
		{name: "IPv6", network: "udp6", wildcard: "[::]:0", loopback: netip.IPv6Loopback()},
	}
	tested := 0
	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			receiver, listenErr := net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.loopback, 0)))
			if listenErr != nil {
				t.Skipf("%s loopback is unavailable: %v", family.name, listenErr)
			}
			defer receiver.Close()
			destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
			writes := []struct {
				name string
				run  func(connection gonnect.UDPConn, payload []byte) error
			}{
				{name: "WriteTo", run: func(c gonnect.UDPConn, payload []byte) error {
					_, err := c.WriteTo(payload, net.UDPAddrFromAddrPort(destination))
					return err
				}},
				{name: "WriteToUDP", run: func(c gonnect.UDPConn, payload []byte) error {
					_, err := c.WriteToUDP(payload, net.UDPAddrFromAddrPort(destination))
					return err
				}},
				{name: "WriteToUDPAddrPort", run: func(c gonnect.UDPConn, payload []byte) error {
					_, err := c.WriteToUDPAddrPort(payload, destination)
					return err
				}},
				{name: "WriteMsgUDP", run: func(c gonnect.UDPConn, payload []byte) error {
					_, _, err := c.WriteMsgUDP(payload, nil, net.UDPAddrFromAddrPort(destination))
					return err
				}},
				{name: "WriteMsgUDPAddrPort", run: func(c gonnect.UDPConn, payload []byte) error {
					_, _, err := c.WriteMsgUDPAddrPort(payload, nil, destination)
					return err
				}},
			}

			for index, write := range writes {
				t.Run(write.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					connection, connectionErr := outNet.ListenUDP(ctx, family.network, family.wildcard)
					if errors.Is(connectionErr, internalnetwork.ErrUnderlayUnavailable) {
						t.Skipf("host has no selected %s underlay", family.name)
					}
					if connectionErr != nil {
						t.Fatalf("ListenUDP() error = %v", connectionErr)
					}
					defer func() { _ = connection.Close() }()
					logicalPort := connection.LocalAddr().(*net.UDPAddr).Port
					payload := []byte(fmt.Sprintf("%s-%d", write.name, index))
					if err := write.run(connection, payload); err != nil {
						t.Fatalf("%s() error = %v", write.name, err)
					}
					if err := receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
						t.Fatal(err)
					}
					buffer := make([]byte, 64)
					n, source, readErr := receiver.ReadFromUDPAddrPort(buffer)
					if readErr != nil {
						t.Fatalf("receiver read error = %v", readErr)
					}
					if string(buffer[:n]) != string(payload) {
						t.Fatalf("receiver payload = %q, want %q", buffer[:n], payload)
					}
					if int(source.Port()) != logicalPort {
						t.Fatalf("source port = %d, logical port = %d", source.Port(), logicalPort)
					}
					reply := append([]byte("reply-"), payload...)
					if _, writeErr := receiver.WriteToUDPAddrPort(reply, source); writeErr != nil {
						t.Fatalf("reply write error = %v", writeErr)
					}
					if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
						t.Fatal(err)
					}
					n, replySource, readErr := connection.ReadFromUDPAddrPort(buffer)
					if readErr != nil {
						t.Fatalf("reply read error = %v", readErr)
					}
					if string(buffer[:n]) != string(reply) || replySource != destination {
						t.Fatalf("reply = %q from %s, want %q from %s", buffer[:n], replySource, reply, destination)
					}
				})
			}
			tested++
		})
	}
	if tested == 0 {
		t.Fatal("host has no usable UDP family")
	}
}

// TestNativeOutNetDirectUDPLoopback verifies the destination-known paths do
// not apply a physical-interface option to a loopback socket.
func TestNativeOutNetDirectUDPLoopback(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := system.OutNet().DialUDP(ctx, "udp4", "", receiver.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write([]byte("direct")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "direct" {
		t.Fatalf("received %q with error %v", buffer[:n], err)
	}

	listener, err := system.OutNet().ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	sender, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("native loopback dial error = %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("listen")); err != nil {
		t.Fatalf("native loopback write error = %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err = listener.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "listen" {
		t.Fatalf("listener received %q with error %v", buffer[:n], err)
	}
}

// TestNativeOutNetWildcardUDPExternalUsesSelectedUnderlay verifies that the
// composite endpoint does not weaken the existing external path policy.
func TestNativeOutNetWildcardUDPExternalUsesSelectedUnderlay(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = system.Close() })
	outNet := system.OutNet()
	addresses, err := outNet.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs() error = %v", err)
	}
	for _, family := range []struct {
		name, network, wildcard string
		ipv4                    bool
	}{
		{name: "IPv4", network: "udp4", wildcard: "0.0.0.0:0", ipv4: true},
		{name: "IPv6", network: "udp6", wildcard: "[::]:0"},
	} {
		t.Run(family.name, func(t *testing.T) {
			var selected netip.Addr
			for _, raw := range addresses {
				ipNet, ok := raw.(*net.IPNet)
				if !ok {
					continue
				}
				address, ok := netip.AddrFromSlice(ipNet.IP)
				if ok && address.Is4() == family.ipv4 {
					selected = address.Unmap()
					break
				}
			}
			if !selected.IsValid() {
				t.Skipf("host has no selected %s underlay", family.name)
			}
			receiver, err := net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(selected, 0)))
			if err != nil {
				t.Fatalf("listen on selected source: %v", err)
			}
			defer receiver.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			connection, err := outNet.ListenUDP(ctx, family.network, family.wildcard)
			if err != nil {
				t.Fatalf("ListenUDP() error = %v", err)
			}
			defer func() { _ = connection.Close() }()
			destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
			if _, err := connection.WriteToUDPAddrPort([]byte("underlay"), destination); err != nil {
				t.Fatalf("WriteToUDPAddrPort() error = %v", err)
			}
			if err := receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 16)
			n, source, err := receiver.ReadFromUDPAddrPort(buffer)
			if err != nil {
				t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
			}
			logicalPort := connection.LocalAddr().(*net.UDPAddr).Port
			observedSource := source.Addr().WithZone("").Unmap()
			if string(buffer[:n]) != "underlay" || observedSource != selected.WithZone("").Unmap() || int(source.Port()) != logicalPort {
				t.Fatalf("received %q from %s, want underlay source %s and port %d", buffer[:n], source, selected, logicalPort)
			}
		})
	}
}
