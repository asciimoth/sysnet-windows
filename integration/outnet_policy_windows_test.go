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
)

// TestNativeOutNetRejectsMulticastDestinations verifies the public Windows
// path before and after creation of an unconnected UDP socket. No multicast
// packet can reach the native socket boundary.
func TestNativeOutNetRejectsMulticastDestinations(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	outNet := system.OutNet()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, test := range []struct {
		name, network, endpoint string
	}{
		{name: "IPv4 dial", network: "udp4", endpoint: "239.1.2.3:1234"},
		{name: "IPv6 dial", network: "udp6", endpoint: "[ff0e::1234]:1234"},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, dialErr := outNet.PacketDial(ctx, test.network, test.endpoint)
			if connection != nil {
				_ = connection.Close()
			}
			if !errors.Is(dialErr, gonnect.ErrUnsupported) {
				t.Fatalf("PacketDial() error = %v, want gonnect.ErrUnsupported", dialErr)
			}
		})
	}

	for _, test := range []struct {
		name, network, local string
		destination          netip.AddrPort
	}{
		{name: "IPv4 write", network: "udp4", local: "0.0.0.0:0", destination: netip.MustParseAddrPort("239.1.2.3:1234")},
		{name: "IPv6 write", network: "udp6", local: "[::]:0", destination: netip.MustParseAddrPort("[ff0e::1234]:1234")},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, listenErr := outNet.ListenUDP(ctx, test.network, test.local)
			if listenErr != nil {
				t.Fatalf("ListenUDP() error = %v", listenErr)
			}
			defer func() { _ = connection.Close() }()
			if _, writeErr := connection.WriteToUDPAddrPort(nil, test.destination); !errors.Is(writeErr, gonnect.ErrUnsupported) {
				t.Fatalf("WriteToUDPAddrPort() error = %v, want gonnect.ErrUnsupported", writeErr)
			}
			udpAddress := &net.UDPAddr{IP: test.destination.Addr().AsSlice(), Port: int(test.destination.Port())}
			if _, writeErr := connection.WriteTo(nil, udpAddress); !errors.Is(writeErr, gonnect.ErrUnsupported) {
				t.Fatalf("WriteTo() error = %v, want gonnect.ErrUnsupported", writeErr)
			}
		})
	}
}
