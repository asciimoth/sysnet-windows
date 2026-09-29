package windows

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
)

func TestN25N28SystemLocalNetOwnsResourcesAndRejectsWorkAfterClose(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	local := system.LocalNet()
	if local.IsNative() {
		t.Fatal("LocalNet reports native")
	}
	listener, err := local.Listen(context.Background(), "tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() || address.IsUnspecified() {
		t.Fatalf("listener address = %q, want concrete loopback", listener.Addr())
	}
	if err = system.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = listener.Accept(); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("Accept after System.Close error = %v, want unavailable", err)
	}
	if _, err = local.Listen(context.Background(), "tcp4", ":0"); !errors.Is(err, sysnet.ErrUnavailable) {
		t.Fatalf("Listen after System.Close error = %v, want unavailable", err)
	}
}
