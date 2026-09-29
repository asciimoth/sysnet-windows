//go:build windows

// Command sysnetflow exercises the public OutNet API in the isolated Windows
// packet-flow topology. It is a test helper, not a general-purpose client.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
	windows "github.com/asciimoth/sysnet-windows"
	"github.com/asciimoth/sysnet-windows/internal/testtunnel"
)

const (
	underlayIPv4 = "198.18.1.2"
	tunnelIPv4   = "198.18.0.2"
	remoteIPv4   = "203.0.113.1:47823"
	remoteIPv6   = "[2001:db8:ffff::1]:47823"
	controlIPv4  = "203.0.113.1:47824"
	controlIPv6  = "[2001:db8:ffff::1]:47824"
)

type observation struct {
	Case         string `json:"case"`
	Token        string `json:"token"`
	ExpectedPath string `json:"expectedPath"`
	Operation    string `json:"operation"`
	Phase        string `json:"phase"`
}

func main() {
	output := flag.String("output", "", "JSON-lines observation output")
	flag.Parse()
	if *output == "" {
		fatal(errors.New("output path is required"))
	}
	if err := run(*output); err != nil {
		fatal(err)
	}
}

func run(output string) (result error) {
	selector, underlayIndex, err := interfaceWithAddress(net.ParseIP(underlayIPv4))
	if err != nil {
		return err
	}
	system, err := windows.New(windows.SystemConfig{UnderlaySelector: selector})
	if err != nil {
		return fmt.Errorf("create System: %w", err)
	}
	defer func() { result = errors.Join(result, system.Close()) }()
	pump, err := startTestTunnel(system)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, pump.Close()) }()
	file, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create observations: %w", err)
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	writer := bufio.NewWriter(file)
	for _, current := range flowCases() {
		if err := runObserved(writer, current, system.OutNet()); err != nil {
			return err
		}
	}

	active, err := openActiveConnections(system.OutNet())
	if err != nil {
		return err
	}
	defer closeConnections(active)
	for _, current := range activeBeforeLossCases(active) {
		if err := runObserved(writer, current, system.OutNet()); err != nil {
			return err
		}
	}
	link := underlayLink{interfaceIndex: underlayIndex}
	linkDisabled := true
	defer func() {
		if linkDisabled {
			result = errors.Join(result, link.Enable())
		}
	}()
	if err := link.Disable(); err != nil {
		return err
	}
	for _, current := range activeAfterLossCases(active) {
		if err := runObservedAllowError(writer, current, system.OutNet()); err != nil {
			return err
		}
	}
	for _, current := range unavailableCases() {
		if err := runExpectedFailure(writer, current, system.OutNet()); err != nil {
			return err
		}
	}
	if err := link.Enable(); err != nil {
		return err
	}
	linkDisabled = false
	if err := runUntilAvailable(writer, recoveryCase(), system.OutNet(), 15*time.Second); err != nil {
		return err
	}
	closeProbe, err := openConnection(system.OutNet(), "tcp4", remoteIPv4)
	if err != nil {
		return fmt.Errorf("open close probe: %w", err)
	}
	active["close-probe"] = closeProbe
	closeObservation := observation{Case: "N29-system-close-resources", Token: "SNW_CLOSE_PROBE", ExpectedPath: "underlay", Operation: "tracked socket before close", Phase: "underlay-restored"}
	if err := writeObservation(writer, closeObservation); err != nil {
		return err
	}
	if err := echoConnected(closeProbe, []byte(closeObservation.Token)); err != nil {
		return fmt.Errorf("close probe: %w", err)
	}

	if err := system.Close(); err != nil {
		return fmt.Errorf("close System: %w", err)
	}
	for name, connection := range active {
		_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte("CLOSED_" + name)); err == nil {
			return fmt.Errorf("tracked %s connection remained writable after System.Close", name)
		}
	}
	if _, err := system.OutNet().Dial(context.Background(), "tcp4", remoteIPv4); err == nil {
		return errors.New("OutNet accepted work after System.Close")
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("finish observations: %w", err)
	}
	return nil
}

func runObserved(writer *bufio.Writer, current flowCase, out gonnect.Network) error {
	if err := writeObservation(writer, current.observation); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := current.run(ctx, out, []byte(current.observation.Token)); err != nil {
		return fmt.Errorf("%s: %w", current.observation.Operation, err)
	}
	return nil
}

func runObservedAllowError(writer *bufio.Writer, current flowCase, out gonnect.Network) error {
	if err := writeObservation(writer, current.observation); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = current.run(ctx, out, []byte(current.observation.Token))
	return nil
}

func runExpectedFailure(writer *bufio.Writer, current flowCase, out gonnect.Network) error {
	if err := writeObservation(writer, current.observation); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := current.run(ctx, out, []byte(current.observation.Token))
		cancel()
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s kept succeeding without an underlay", current.observation.Operation)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func runUntilAvailable(writer *bufio.Writer, current flowCase, out gonnect.Network, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := current.run(ctx, out, []byte(current.observation.Token))
		cancel()
		if err == nil {
			return writeObservation(writer, current.observation)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("underlay did not recover: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func writeObservation(writer *bufio.Writer, value observation) error {
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return fmt.Errorf("write observation: %w", err)
	}
	return writer.Flush()
}

type flowCase struct {
	observation observation
	run         func(context.Context, gonnect.Network, []byte) error
}

func flowCases() []flowCase {
	var cases []flowCase
	for _, family := range []struct {
		network, remote, local, control, suffix, tcpCase, udpCase string
	}{
		{"4", remoteIPv4, "0.0.0.0:0", controlIPv4, "4", "N01", "N03"},
		{"6", remoteIPv6, "[::]:0", controlIPv6, "6", "N02", "N04"},
	} {
		phase := "default-route-bypass"
		add := func(caseID, token, operation string, run func(context.Context, gonnect.Network, []byte) error) {
			cases = append(cases, flowCase{observation: observation{
				Case: caseID, Token: token, ExpectedPath: "underlay", Operation: operation, Phase: phase,
			}, run: run})
		}
		add(family.tcpCase+"-outnet-tcp"+family.suffix+"-underlay", "SNW_"+family.tcpCase+"_GENERIC_TCP"+family.suffix, "Dial tcp"+family.network, dial("tcp"+family.network, family.remote))
		add(family.tcpCase+"-outnet-tcp"+family.suffix+"-underlay", "SNW_"+family.tcpCase+"_TYPED_TCP"+family.suffix, "DialTCP tcp"+family.network, dialTCP("tcp"+family.network, family.remote))
		add(family.udpCase+"-outnet-udp"+family.suffix+"-underlay", "SNW_"+family.udpCase+"_GENERIC_UDP"+family.suffix, "Dial udp"+family.network, dial("udp"+family.network, family.remote))
		add(family.udpCase+"-outnet-udp"+family.suffix+"-underlay", "SNW_"+family.udpCase+"_TYPED_UDP"+family.suffix, "DialUDP udp"+family.network, dialUDP("udp"+family.network, family.remote))
		add("N05-outnet-packet-dial"+family.suffix, "SNW_N05_PACKET_DIAL"+family.suffix, "PacketDial udp"+family.network, packetDial("udp"+family.network, family.remote))
		add("N05-outnet-listen"+family.suffix, "SNW_N05_LISTEN"+family.suffix, "Listen tcp"+family.network, listenTCPCallback("tcp"+family.network, family.local, family.control, false))
		add("N05-outnet-listen-tcp"+family.suffix, "SNW_N05_LISTEN_TCP"+family.suffix, "ListenTCP tcp"+family.network, listenTCPCallback("tcp"+family.network, family.local, family.control, true))
		add("N06-outnet-listen-packet"+family.suffix, "SNW_N06_LISTEN_PACKET"+family.suffix, "ListenPacket udp"+family.network, listenPacket("udp"+family.network, family.local, family.remote, false))
		add("N07-outnet-listen-udp"+family.suffix, "SNW_N07_LISTEN_UDP"+family.suffix, "ListenUDP udp"+family.network, listenPacket("udp"+family.network, family.local, family.remote, true))
		add("N08-outnet-configured-packet"+family.suffix, "SNW_N08_CONFIG_PACKET"+family.suffix, "ListenPacketConfig udp"+family.network, listenConfiguredPacket("udp"+family.network, family.local, family.remote))
		add("N08-outnet-configured-udp"+family.suffix, "SNW_N08_CONFIG_UDP"+family.suffix, "ListenUDPConfig udp"+family.network, listenConfiguredUDP("udp"+family.network, family.local, family.remote))
	}
	return cases
}

func dial(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.Dial(ctx, network, address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func dialTCP(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.DialTCP(ctx, network, "", address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func dialUDP(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.DialUDP(ctx, network, "", address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func packetDial(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.PacketDial(ctx, network, address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func listenPacket(network, local, remote string, typed bool) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		var connection gonnect.PacketConn
		var err error
		if typed {
			var udp gonnect.UDPConn
			udp, err = out.ListenUDP(ctx, network, local)
			connection = udp
		} else {
			connection, err = out.ListenPacket(ctx, network, local)
		}
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoPacket(connection, remote, token)
	}
}

func listenConfiguredUDP(network, local, remote string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.ListenUDPConfig(ctx, &gonnect.ListenConfig{}, network, local)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoPacket(connection, remote, token)
	}
}

func listenConfiguredPacket(network, local, remote string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.ListenPacketConfig(ctx, &gonnect.ListenConfig{}, network, local)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoPacket(connection, remote, token)
	}
}

func listenTCPCallback(network, local, control string, typed bool) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		var listener net.Listener
		var err error
		if typed {
			listener, err = out.ListenTCP(ctx, network, local)
		} else {
			listener, err = out.Listen(ctx, network, local)
		}
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		request := callbackRequest{
			Network: network, Address: listenerAddress(listener.Addr(), network),
			Token: base64.StdEncoding.EncodeToString(token),
		}
		controlConnection, err := out.Dial(ctx, network, control)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(controlConnection).Encode(request); err != nil {
			_ = controlConnection.Close()
			return err
		}
		_ = controlConnection.Close()
		accepted, err := acceptCallback(ctx, listener, typed)
		if err != nil {
			return err
		}
		defer func() { _ = accepted.Close() }()
		return readToken(accepted, token)
	}
}

type acceptResult struct {
	connection net.Conn
	err        error
}

func acceptCallback(ctx context.Context, listener net.Listener, typed bool) (net.Conn, error) {
	var tcpListener gonnect.TCPListener
	if typed {
		var ok bool
		tcpListener, ok = listener.(gonnect.TCPListener)
		if !ok {
			return nil, fmt.Errorf("typed listener returned %T", listener)
		}
	}
	result := make(chan acceptResult, 1)
	go func() {
		if typed {
			connection, err := tcpListener.AcceptTCP()
			result <- acceptResult{connection: connection, err: err}
			return
		}
		connection, err := listener.Accept()
		result <- acceptResult{connection: connection, err: err}
	}()
	select {
	case accepted := <-result:
		return accepted.connection, accepted.err
	case <-ctx.Done():
		_ = listener.Close()
		<-result
		return nil, ctx.Err()
	}
}

type callbackRequest struct {
	Network string `json:"network"`
	Address string `json:"address"`
	Token   string `json:"token"`
}

func listenerAddress(address net.Addr, network string) string {
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	if strings.HasSuffix(network, "6") {
		return net.JoinHostPort("fd00:18:1::2", port)
	}
	return net.JoinHostPort(underlayIPv4, port)
}

func readToken(connection net.Conn, token []byte) error {
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	got := make([]byte, len(token))
	if _, err := io.ReadFull(connection, got); err != nil {
		return err
	}
	if string(got) != string(token) {
		return errors.New("callback does not match token")
	}
	return nil
}

func echoConnected(connection net.Conn, token []byte) error {
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.Write(token); err != nil {
		return err
	}
	reply := make([]byte, len(token))
	if _, err := io.ReadFull(connection, reply); err != nil {
		return err
	}
	if string(reply) != string(token) {
		return errors.New("echo reply does not match token")
	}
	return nil
}

func echoPacket(connection net.PacketConn, remote string, token []byte) error {
	destination, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return err
	}
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.WriteTo(token, destination); err != nil {
		return err
	}
	reply := make([]byte, len(token))
	length, _, err := connection.ReadFrom(reply)
	if err != nil {
		return err
	}
	if string(reply[:length]) != string(token) {
		return errors.New("echo reply does not match token")
	}
	return nil
}

func openActiveConnections(out gonnect.Network) (map[string]net.Conn, error) {
	result := make(map[string]net.Conn, 4)
	for _, item := range []struct{ name, network, remote string }{
		{"tcp4", "tcp4", remoteIPv4}, {"tcp6", "tcp6", remoteIPv6},
		{"udp4", "udp4", remoteIPv4}, {"udp6", "udp6", remoteIPv6},
	} {
		connection, err := openConnection(out, item.network, item.remote)
		if err != nil {
			closeConnections(result)
			return nil, fmt.Errorf("open active %s connection: %w", item.name, err)
		}
		result[item.name] = connection
	}
	return result, nil
}

func openConnection(out gonnect.Network, network, remote string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return out.Dial(ctx, network, remote)
}

func closeConnections(connections map[string]net.Conn) {
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func activeBeforeLossCases(connections map[string]net.Conn) []flowCase {
	return connectionCases(connections, "before-loss", "underlay", "ACTIVE_BEFORE")
}

func activeAfterLossCases(connections map[string]net.Conn) []flowCase {
	return connectionCases(connections, "underlay-lost", "underlay-or-none-stopped", "ACTIVE_AFTER")
}

func connectionCases(connections map[string]net.Conn, phase, expected, prefix string) []flowCase {
	result := make([]flowCase, 0, len(connections))
	for _, name := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		connection := connections[name]
		token := "SNW_" + prefix + "_" + strings.ToUpper(name)
		result = append(result, flowCase{
			observation: observation{Case: "N21-active-" + name, Token: token, ExpectedPath: expected, Operation: "active " + name, Phase: phase},
			run:         func(context.Context, gonnect.Network, []byte) error { return echoConnected(connection, []byte(token)) },
		})
	}
	return result
}

func unavailableCases() []flowCase {
	return []flowCase{
		{observation{Case: "N21-new-tcp4-fails", Token: "SNW_LOST_NEW_TCP4", ExpectedPath: "none", Operation: "new Dial tcp4", Phase: "underlay-lost"}, dialCreation("tcp4", remoteIPv4)},
		{observation{Case: "N21-new-tcp6-fails", Token: "SNW_LOST_NEW_TCP6", ExpectedPath: "none", Operation: "new Dial tcp6", Phase: "underlay-lost"}, dialCreation("tcp6", remoteIPv6)},
		// UDP Dial can create a connected socket without proving that its path is
		// usable. Require the complete request/reply operation to fail instead.
		{observation{Case: "N21-new-udp4-fails", Token: "SNW_LOST_NEW_UDP4", ExpectedPath: "none", Operation: "new Dial udp4", Phase: "underlay-lost"}, dial("udp4", remoteIPv4)},
		{observation{Case: "N21-new-udp6-fails", Token: "SNW_LOST_NEW_UDP6", ExpectedPath: "none", Operation: "new Dial udp6", Phase: "underlay-lost"}, dial("udp6", remoteIPv6)},
	}
}

func dialCreation(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, _ []byte) error {
		connection, err := out.Dial(ctx, network, address)
		if err != nil {
			return err
		}
		_ = connection.Close()
		return nil
	}
}

func recoveryCase() flowCase {
	return flowCase{
		observation: observation{Case: "N24-underlay-recovery", Token: "SNW_UNDERLAY_RECOVERED", ExpectedPath: "underlay", Operation: "Dial tcp4 after recovery", Phase: "underlay-restored"},
		run:         dial("tcp4", remoteIPv4),
	}
}

func interfaceWithAddress(want net.IP) (string, int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", 0, err
	}
	for _, iface := range interfaces {
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			return "", 0, addrErr
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.Equal(want) {
				return iface.Name, iface.Index, nil
			}
		}
	}
	return "", 0, fmt.Errorf("interface with address %s not found", want)
}

// testTunnel pumps packets from a System-owned Wintun over the isolated
// physical tunnel link. The deliberately insecure protocol exists only for
// independent packet-path tests.
type testTunnel struct {
	device    tun.Tun
	transport *net.UDPConn
	wg        sync.WaitGroup
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
}

func startTestTunnel(system *windows.System) (*testTunnel, error) {
	local, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(tunnelIPv4, "0"))
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp4", "198.18.0.1:51900")
	if err != nil {
		return nil, err
	}
	transport, err := net.DialUDP("udp4", local, remote)
	if err != nil {
		return nil, fmt.Errorf("open test tunnel transport: %w", err)
	}
	device, err := system.BuildTun(sysnet.TunOpts{
		TunAddrs: []string{"10.77.0.2/24", "fd77::2/64"},
		TunRoutes: []string{
			"0.0.0.0/0", "::/0", "203.0.113.1/32", "2001:db8:ffff::1/128",
		},
	})
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("create test TUN: %w", err)
	}
	pump := &testTunnel{device: device, transport: transport}
	pump.wg.Add(2)
	go pump.readTun()
	go pump.readTransport()
	return pump, nil
}

func (p *testTunnel) readTun() {
	defer p.wg.Done()
	offset := p.device.MRO()
	batch := p.device.BatchSize()
	buffers := make([][]byte, batch)
	sizes := make([]int, batch)
	for index := range buffers {
		buffers[index] = make([]byte, offset+65535)
	}
	for {
		count, err := p.device.Read(buffers, sizes, offset)
		if err != nil {
			p.recordPumpError("read test TUN", err)
			return
		}
		for index := range count {
			if sizes[index] <= 0 || offset+sizes[index] > len(buffers[index]) {
				p.recordPumpError("read test TUN", fmt.Errorf("invalid packet size %d", sizes[index]))
				return
			}
			packet := buffers[index][offset : offset+sizes[index]]
			if _, err := p.transport.Write(testtunnel.Encode(packet)); err != nil {
				p.recordPumpError("write test tunnel transport", err)
				return
			}
		}
	}
}

func (p *testTunnel) readTransport() {
	defer p.wg.Done()
	buffer := make([]byte, 65535+testtunnel.HeaderSize)
	for {
		length, err := p.transport.Read(buffer)
		if err != nil {
			p.recordPumpError("read test tunnel transport", err)
			return
		}
		packet, err := testtunnel.Decode(buffer[:length])
		if err != nil {
			continue
		}
		offset := p.device.MWO()
		writeBuffer := make([]byte, offset+len(packet))
		copy(writeBuffer[offset:], packet)
		if count, err := p.device.Write([][]byte{writeBuffer}, offset); err != nil {
			p.recordPumpError("write test TUN", err)
			return
		} else if count != 1 {
			p.recordPumpError("write test TUN", fmt.Errorf("wrote %d packets, want 1", count))
			return
		}
	}
}

func (p *testTunnel) recordPumpError(operation string, err error) {
	if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
		return
	}
	p.errMu.Lock()
	p.err = errors.Join(p.err, fmt.Errorf("%s: %w", operation, err))
	p.errMu.Unlock()
}

func (p *testTunnel) Close() error {
	p.closeOnce.Do(func() {
		transportErr := p.transport.Close()
		deviceErr := p.device.Close()
		p.wg.Wait()
		p.errMu.Lock()
		p.err = errors.Join(p.err, transportErr, deviceErr)
		p.errMu.Unlock()
	})
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

type underlayLink struct{ interfaceIndex int }

func (l underlayLink) Disable() error {
	script := `
param([int]$Index)
$ErrorActionPreference='Stop'
$routes=@(
    @{Family='IPv4'; Prefix='0.0.0.0/0'; Hop='198.18.1.1'},
    @{Family='IPv6'; Prefix='::/0'; Hop='fd00:18:1::1'}
)
foreach($route in $routes) {
    $owned=@(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex $Index -AddressFamily $route.Family -DestinationPrefix $route.Prefix -ErrorAction SilentlyContinue | Where-Object NextHop -eq $route.Hop)
    if($owned.Count -ne 1) { throw "Expected one fixture route $($route.Prefix)" }
    $owned[0] | Remove-NetRoute -Confirm:$false
}
$adapter=@(Get-NetAdapter | Where-Object ifIndex -eq $Index)
if($adapter.Count -ne 1) { throw "Expected one interface with index $Index" }
$adapter[0] | Disable-NetAdapter -Confirm:$false
$deadline=(Get-Date).AddSeconds(10)
do {
    if((Get-NetAdapter | Where-Object ifIndex -eq $Index).Status -ne 'Up') { return }
    Start-Sleep -Milliseconds 100
} while((Get-Date) -lt $deadline)
throw "Interface $Index did not leave the Up state"
`
	return runPowerShell("disable selected underlay", script, strconv.Itoa(l.interfaceIndex))
}

func (l underlayLink) Enable() error {
	script := `
param([int]$Index)
$ErrorActionPreference='Stop'
$adapter=@(Get-NetAdapter | Where-Object ifIndex -eq $Index)
if($adapter.Count -ne 1) { throw "Expected one interface with index $Index" }
$adapter[0] | Enable-NetAdapter -Confirm:$false
$deadline=(Get-Date).AddSeconds(15)
do {
    if((Get-NetAdapter | Where-Object ifIndex -eq $Index).Status -eq 'Up') { return }
    Start-Sleep -Milliseconds 100
} while((Get-Date) -lt $deadline)
throw "Interface $Index did not return to the Up state"
`
	if err := runPowerShell("enable selected underlay", script, strconv.Itoa(l.interfaceIndex)); err != nil {
		return err
	}
	routes := `
param([int]$Index)
$ErrorActionPreference='Stop'
$routes=@(
    @{Family='IPv4'; Prefix='0.0.0.0/0'; Hop='198.18.1.1'},
    @{Family='IPv6'; Prefix='::/0'; Hop='fd00:18:1::1'}
)
foreach($route in $routes) {
    $existing=@(Get-NetRoute -PolicyStore ActiveStore -InterfaceIndex $Index -AddressFamily $route.Family -DestinationPrefix $route.Prefix -ErrorAction SilentlyContinue | Where-Object NextHop -eq $route.Hop)
    if($existing.Count -eq 0) {
        New-NetRoute -PolicyStore ActiveStore -InterfaceIndex $Index -AddressFamily $route.Family -DestinationPrefix $route.Prefix -NextHop $route.Hop -RouteMetric 5000 | Out-Null
    } elseif($existing.Count -ne 1 -or $existing[0].RouteMetric -ne 5000) {
        throw "Fixture route $($route.Prefix) has unexpected state"
    }
}
`
	return runPowerShell("restore selected underlay routes", routes, strconv.Itoa(l.interfaceIndex))
}

func runPowerShell(operation, script string, arguments ...string) error {
	command, err := powerShellCommand(script, arguments...)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	commandArguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command}
	output, err := exec.Command("powershell.exe", commandArguments...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", operation, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func powerShellCommand(script string, arguments ...string) (string, error) {
	for _, argument := range arguments {
		if _, err := strconv.Atoi(argument); err != nil {
			return "", fmt.Errorf("invalid numeric PowerShell argument %q", argument)
		}
	}
	// -Command does not bind trailing process arguments to a top-level param
	// block consistently across Windows PowerShell versions. Invoke an explicit
	// script block so the numeric interface index is a positional parameter.
	command := "& {\n" + script + "\n} " + strings.Join(arguments, " ")
	return command, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
