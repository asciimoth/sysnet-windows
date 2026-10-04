//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	sysnetwindows "github.com/asciimoth/sysnet-windows"
	internalnetwork "github.com/asciimoth/sysnet-windows/internal/network"
)

// TestNativeOutNetWildcardUDPPortContract verifies the complete wildcard UDP
// port contract through the public OutNet API. The Windows VM runs this test
// as part of the live-driver end-to-end gate.
func TestNativeOutNetWildcardUDPPortContract(t *testing.T) {
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

	tests := []struct {
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected := selectedAddress(addresses, test.ipv4)
			if !selected.IsValid() {
				t.Skipf("host has no selected %s underlay", test.name)
			}
			tested++
			for _, fixed := range []bool{false, true} {
				name := "port-zero"
				requestedPort := 0
				if fixed {
					name = "fixed-port"
					requestedPort = reserveE2EWildcardUDPPort(t, test.network, test.wildcard)
				}
				t.Run(name, func(t *testing.T) {
					endpoint := netip.AddrPortFrom(test.wildcard, uint16(requestedPort)).String()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					connection, listenErr := outNet.ListenUDP(ctx, test.network, endpoint)
					if errors.Is(listenErr, internalnetwork.ErrUnderlayUnavailable) {
						t.Skipf("host lost its selected %s underlay", test.name)
					}
					if listenErr != nil {
						t.Fatalf("ListenUDP(%q) error = %v", endpoint, listenErr)
					}
					defer func() { _ = connection.Close() }()
					effectivePort := connection.LocalAddr().(*net.UDPAddr).Port
					if effectivePort == 0 {
						t.Fatal("port-zero listen returned port 0")
					}
					if fixed && effectivePort != requestedPort {
						t.Fatalf("LocalAddr().Port = %d, want requested port %d", effectivePort, requestedPort)
					}

					testWildcardUDPExchange(t, connection, test.network, test.loopback, effectivePort, "loopback")
					testWildcardUDPExchange(t, connection, test.network, selected, effectivePort, "underlay")
				})
			}

			t.Run("bind-conflict", func(t *testing.T) {
				blocker, listenErr := net.ListenUDP(test.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(selected, 0)))
				if listenErr != nil {
					t.Fatalf("create selected-underlay conflict: %v", listenErr)
				}
				defer blocker.Close()
				port := blocker.LocalAddr().(*net.UDPAddr).Port
				endpoint := netip.AddrPortFrom(test.wildcard, uint16(port)).String()
				connection, conflictErr := outNet.ListenUDP(context.Background(), test.network, endpoint)
				if connection != nil {
					_ = connection.Close()
					t.Fatalf("ListenUDP(%q) returned a connection during a bind conflict", endpoint)
				}
				if conflictErr == nil {
					t.Fatalf("ListenUDP(%q) selected another port during a bind conflict", endpoint)
				}
			})
		})
	}
	if tested == 0 {
		t.Fatal("host has no usable UDP family")
	}
}

func testWildcardUDPExchange(t *testing.T, connection gonnect.UDPConn, network string, destinationIP netip.Addr, effectivePort int, path string) {
	t.Helper()
	receiver, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(destinationIP, 0)))
	if err != nil {
		t.Fatalf("listen on %s destination %s: %v", path, destinationIP, err)
	}
	defer receiver.Close()
	destination := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte("request-" + path)
	if _, err := connection.WriteToUDPAddrPort(payload, destination); err != nil {
		t.Fatalf("write to %s destination: %v", path, err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, source, err := receiver.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatalf("read from %s destination: %v", path, err)
	}
	if string(buffer[:n]) != string(payload) {
		t.Fatalf("%s request = %q, want %q", path, buffer[:n], payload)
	}
	if int(source.Port()) != effectivePort {
		t.Fatalf("%s source port = %d, want effective port %d", path, source.Port(), effectivePort)
	}
	if path == "underlay" && source.Addr().WithZone("").Unmap() != destinationIP.WithZone("").Unmap() {
		t.Fatalf("underlay source address = %s, want %s", source.Addr(), destinationIP)
	}
	reply := []byte("reply-" + path)
	if _, err := receiver.WriteToUDPAddrPort(reply, source); err != nil {
		t.Fatalf("reply from %s destination: %v", path, err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, replySource, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatalf("read %s reply: %v", path, err)
	}
	if string(buffer[:n]) != string(reply) || replySource != destination {
		t.Fatalf("%s reply = %q from %s, want %q from %s", path, buffer[:n], replySource, reply, destination)
	}
}

func reserveE2EWildcardUDPPort(t *testing.T, network string, wildcard netip.Addr) int {
	t.Helper()
	reservation, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(wildcard, 0)))
	if err != nil {
		t.Fatalf("reserve wildcard UDP port: %v", err)
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatalf("release wildcard UDP port %d: %v", port, err)
	}
	return port
}

func selectedAddress(addresses []net.Addr, ipv4 bool) netip.Addr {
	for _, raw := range addresses {
		ipNet, ok := raw.(*net.IPNet)
		if !ok {
			continue
		}
		address, ok := netip.AddrFromSlice(ipNet.IP)
		if ok && address.Is4() == ipv4 {
			return address.Unmap()
		}
	}
	return netip.Addr{}
}
