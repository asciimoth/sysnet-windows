//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	sysnetwindows "github.com/asciimoth/sysnet-windows"
	internaldns "github.com/asciimoth/sysnet-windows/internal/dns"
	internalnetwork "github.com/asciimoth/sysnet-windows/internal/network"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

func TestNativeLocalNetRejectsEveryNonLoopbackUDPWrite(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	local := system.LocalNet()

	packet, err := local.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = packet.Close() }()
	nonlocalUDP := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53}
	if _, err := packet.WriteTo(nil, nonlocalUDP); !errors.Is(err, internalnetwork.ErrNonLoopbackAddress) {
		t.Fatalf("PacketConn.WriteTo() error = %v, want non-loopback rejection", err)
	}

	udp, err := local.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = udp.Close() }()
	nonlocalAddrPort := netip.MustParseAddrPort("192.0.2.1:53")
	writes := []struct {
		name string
		run  func() error
	}{
		{name: "WriteTo", run: func() error { _, err := udp.WriteTo(nil, nonlocalUDP); return err }},
		{name: "WriteToUDP", run: func() error { _, err := udp.WriteToUDP(nil, nonlocalUDP); return err }},
		{name: "WriteToUDPAddrPort", run: func() error { _, err := udp.WriteToUDPAddrPort(nil, nonlocalAddrPort); return err }},
		{name: "WriteMsgUDP", run: func() error { _, _, err := udp.WriteMsgUDP(nil, nil, nonlocalUDP); return err }},
		{name: "WriteMsgUDPAddrPort", run: func() error { _, _, err := udp.WriteMsgUDPAddrPort(nil, nil, nonlocalAddrPort); return err }},
	}
	for _, test := range writes {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, internalnetwork.ErrNonLoopbackAddress) {
				t.Fatalf("error = %v, want non-loopback rejection", err)
			}
		})
	}
}

func TestNativeDNSProxyRejectsIdleTCPConnectionsAboveLimit(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	proxy := internaldns.NewProxy(packet, listener, 30*time.Second)
	t.Cleanup(func() { _ = proxy.Close() })
	connections := make([]net.Conn, 0, 256)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for index := 0; index < 256; index++ {
		connection, dialErr := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
		if dialErr != nil {
			t.Fatalf("idle connection %d: %v", index, dialErr)
		}
		connections = append(connections, connection)
	}
	time.Sleep(250 * time.Millisecond)
	overflow, err := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = overflow.Close() }()
	_ = overflow.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := overflow.Read(make([]byte, 1)); err == nil {
		t.Fatal("257th idle TCP connection remained open")
	} else if networkErr := (net.Error)(nil); errors.As(err, &networkErr) && networkErr.Timeout() {
		t.Fatalf("257th idle TCP connection was not rejected promptly: %v", err)
	}
}

func TestNativeDefaultTunPropertiesRequireRebuild(t *testing.T) {
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{TunAddrs: []string{"198.18.231.1/32"}})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	operations := []struct {
		name string
		run  func() error
	}{
		{name: "GetTunAddrs", run: func() error { _, err := system.GetTunAddrs(device); return err }},
		{name: "SetTunMTU", run: func() error { return system.SetTunMTU(device, 1400) }},
		{name: "SetTunName", run: func() error { return system.SetTunName(device, "replacement") }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.run()
			if !errors.Is(err, sysnet.ErrNotSupported) || errors.Is(err, sysnet.ErrUnknownTun) {
				t.Fatalf("error = %v, want only ErrNotSupported", err)
			}
		})
	}
}

func TestNativeConcurrentSocketAndSystemCloseCleansAdapter(t *testing.T) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID() error = %v", err)
	}
	name := testAdapterName("close-race", guid)
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{StableGUID: guid.String()})
	if err != nil {
		t.Fatalf("windows.New() error = %v", err)
	}
	if _, err := system.BuildTun(sysnet.TunOpts{Name: name, TunAddrs: []string{"198.18.232.1/32"}}); err != nil {
		_ = system.Close()
		t.Fatalf("BuildTun() error = %v", err)
	}
	connection, err := system.LocalNet().ListenUDP(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		_ = system.Close()
		t.Fatalf("ListenUDP() error = %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		<-start
		results <- connection.Close()
	}()
	go func() {
		defer group.Done()
		<-start
		results <- system.Close()
	}()
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent close error = %v", err)
		}
	}
	assertReviewAdapterAbsent(t, name)
}

func assertReviewAdapterAbsent(t *testing.T, name string) {
	t.Helper()
	adapter, err := wintun.OpenAdapter(name)
	if err == nil {
		_ = adapter.Close()
		t.Fatalf("owned adapter %q remains after cleanup", name)
	}
}
