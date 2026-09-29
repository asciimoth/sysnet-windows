//go:build windows

package owner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect/sockowner"
)

func TestNativeResolverTCPAndProcessMetadata(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Skipf("%s loopback is unavailable: %v", network, err)
			}
			defer listener.Close()
			client, err := net.Dial(network, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			flow, err := LocalPeerFlow(server)
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := NewNative(Config{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver.Owner(context.Background(), flow)
			if err != nil {
				t.Fatal(err)
			}
			assertCurrentProcess(t, result)
		})
	}
}

func TestNativeResolverUDPExactAndWildcard(t *testing.T) {
	resolver, err := NewNative(Config{})
	if err != nil {
		t.Fatal(err)
	}
	loopback := net.IPv4(127, 0, 0, 1)
	exact, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer exact.Close()
	address := exact.LocalAddr().(*net.UDPAddr)
	flow := sockowner.FlowTuple{Proto: "udp", LocalIP: loopback, LocalPort: uint16(address.Port), RemoteIP: net.IPv4(192, 0, 2, 1), RemotePort: 53} //nolint:gosec
	result, err := resolver.Owner(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	assertCurrentProcess(t, result)

	wildcard, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer wildcard.Close()
	wildcardAddress := wildcard.LocalAddr().(*net.UDPAddr)
	flow.LocalIP = loopback
	flow.LocalPort = uint16(wildcardAddress.Port) //nolint:gosec
	if _, err := resolver.Owner(context.Background(), flow); !errors.Is(err, ErrUnknownOwner) {
		t.Fatalf("wildcard UDP Owner() error = %v, want unknown", err)
	}
}

func TestNativeResolverLocalPeerIsChild(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	command := exec.Command(os.Args[0], "-test.run=TestOwnerHelperProcess", "--", listener.Addr().String())
	command.Env = append(os.Environ(), "GO_WANT_OWNER_HELPER=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		_ = command.Wait()
	}()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper readiness = %q, %v", line, err)
	}

	flow, err := LocalPeerFlow(accepted)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewNative(Config{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Owner(context.Background(), flow)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Processes[0].PID; got != command.Process.Pid {
		t.Fatalf("peer PID = %d, want child %d (listener PID %d)", got, command.Process.Pid, os.Getpid())
	}
}

func TestOwnerHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_OWNER_HELPER") != "1" {
		return
	}
	separator := 0
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator == 0 || separator+1 >= len(os.Args) {
		os.Exit(2)
	}
	connection, err := net.Dial("tcp4", os.Args[separator+1])
	if err != nil {
		os.Exit(3)
	}
	defer connection.Close()
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
	os.Exit(0)
}

func assertCurrentProcess(t *testing.T, result *Result) {
	t.Helper()
	if result == nil || len(result.Processes) != 1 {
		t.Fatalf("Owner() result = %+v", result)
	}
	process := result.Processes[0]
	if process.PID != os.Getpid() {
		t.Fatalf("PID = %d, want %d", process.PID, os.Getpid())
	}
	if process.EnrichmentErr != nil {
		t.Fatalf("process enrichment error = %v", process.EnrichmentErr)
	}
	if process.CreationTime.IsZero() {
		t.Fatal("process creation time is zero")
	}
	if !filepath.IsAbs(process.ExecutablePath) || !strings.EqualFold(filepath.Base(process.ExecutablePath), filepath.Base(os.Args[0])) {
		t.Fatalf("executable path = %q, test executable = %q", process.ExecutablePath, os.Args[0])
	}
	if len(result.Owner.PIDs) != 1 || result.Owner.PIDs[0] != process.PID {
		t.Fatalf("socket owner PIDs = %v, process = %d", result.Owner.PIDs, process.PID)
	}
}
