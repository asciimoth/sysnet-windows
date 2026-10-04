package network

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestWildcardUDPConnRoutesEveryWriteByDestination(t *testing.T) {
	t.Parallel()
	underlay := newRecordingUDPConn()
	loopback := newRecordingUDPConn()
	validationErr := errors.New("stale underlay")
	validateCalls := 0
	connection := newWildcardUDPConn(underlay, loopback, &net.UDPAddr{IP: net.IPv4zero, Port: 1234}, func() error {
		validateCalls++
		return nil
	})
	t.Cleanup(func() { _ = connection.Close() })

	loopbackUDP := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}
	externalUDP := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9002}
	loopbackAddrPort := netip.MustParseAddrPort("127.0.0.1:9003")
	externalAddrPort := netip.MustParseAddrPort("192.0.2.2:9004")
	tests := []struct {
		name string
		run  func(*net.UDPAddr, netip.AddrPort) error
	}{
		{name: "WriteTo", run: func(address *net.UDPAddr, _ netip.AddrPort) error {
			_, err := connection.WriteTo([]byte("a"), address)
			return err
		}},
		{name: "WriteToUDP", run: func(address *net.UDPAddr, _ netip.AddrPort) error {
			_, err := connection.WriteToUDP([]byte("b"), address)
			return err
		}},
		{name: "WriteToUDPAddrPort", run: func(_ *net.UDPAddr, address netip.AddrPort) error {
			_, err := connection.WriteToUDPAddrPort([]byte("c"), address)
			return err
		}},
		{name: "WriteMsgUDP", run: func(address *net.UDPAddr, _ netip.AddrPort) error {
			_, _, err := connection.WriteMsgUDP([]byte("d"), nil, address)
			return err
		}},
		{name: "WriteMsgUDPAddrPort", run: func(_ *net.UDPAddr, address netip.AddrPort) error {
			_, _, err := connection.WriteMsgUDPAddrPort([]byte("e"), nil, address)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(loopbackUDP, loopbackAddrPort); err != nil {
				t.Fatalf("loopback write error = %v", err)
			}
			if err := test.run(externalUDP, externalAddrPort); err != nil {
				t.Fatalf("external write error = %v", err)
			}
		})
	}
	if got := loopback.writeCount(); got != len(tests) {
		t.Fatalf("loopback writes = %d, want %d", got, len(tests))
	}
	if got := underlay.writeCount(); got != len(tests) {
		t.Fatalf("underlay writes = %d, want %d", got, len(tests))
	}
	if validateCalls != len(tests) {
		t.Fatalf("underlay validations = %d, want %d", validateCalls, len(tests))
	}

	connection.validate = func() error { return validationErr }
	for _, test := range tests {
		if err := test.run(externalUDP, externalAddrPort); !errors.Is(err, validationErr) {
			t.Errorf("%s stale-path error = %v, want %v", test.name, err, validationErr)
		}
		if err := test.run(loopbackUDP, loopbackAddrPort); err != nil {
			t.Errorf("%s loopback write after underlay loss = %v", test.name, err)
		}
	}
	if got := underlay.writeCount(); got != len(tests) {
		t.Fatalf("stale external write reached socket: writes = %d", got)
	}
	if got := loopback.writeCount(); got != 2*len(tests) {
		t.Fatalf("loopback writes after underlay loss = %d, want %d", got, 2*len(tests))
	}
	beforeUnderlay, beforeLoopback := underlay.writeCount(), loopback.writeCount()
	if _, err := connection.WriteToUDPAddrPort(nil, netip.MustParseAddrPort("239.1.2.3:9")); err == nil {
		t.Fatal("multicast write succeeded")
	}
	if underlay.writeCount() != beforeUnderlay || loopback.writeCount() != beforeLoopback {
		t.Fatal("multicast write reached a component socket")
	}
}

func TestWildcardUDPConnMultiplexesReadsAndPreservesLogicalAddress(t *testing.T) {
	t.Parallel()
	underlay := newRecordingUDPConn()
	loopback := newRecordingUDPConn()
	logical := &net.UDPAddr{IP: net.IPv4zero, Port: 4321}
	connection := newWildcardUDPConn(underlay, loopback, logical, nil)
	t.Cleanup(func() { _ = connection.Close() })

	underlay.reads <- recordedDatagram{packet: []byte("outside"), from: netip.MustParseAddrPort("192.0.2.8:80")}
	loopback.reads <- recordedDatagram{packet: []byte("inside"), oob: []byte{1, 2}, flags: 7, from: netip.MustParseAddrPort("127.0.0.1:81")}
	seen := make(map[netip.AddrPort]string)
	for range 2 {
		packet := make([]byte, 16)
		oob := make([]byte, 8)
		n, oobn, flags, from, err := connection.ReadMsgUDPAddrPort(packet, oob)
		if err != nil {
			t.Fatalf("ReadMsgUDPAddrPort() error = %v", err)
		}
		seen[from] = string(packet[:n])
		if from.Addr().IsLoopback() && (oobn != 2 || flags != 7) {
			t.Fatalf("loopback metadata = oob %d flags %d, want 2 and 7", oobn, flags)
		}
	}
	if seen[netip.MustParseAddrPort("192.0.2.8:80")] != "outside" ||
		seen[netip.MustParseAddrPort("127.0.0.1:81")] != "inside" {
		t.Fatalf("multiplexed datagrams = %v", seen)
	}
	if got := connection.LocalAddr().String(); got != logical.String() {
		t.Fatalf("LocalAddr() = %s, want %s", got, logical)
	}
}

func TestWildcardUDPConnDeadlinesAndCloseApplyToBothSockets(t *testing.T) {
	t.Parallel()
	underlay := newRecordingUDPConn()
	loopback := newRecordingUDPConn()
	connection := newWildcardUDPConn(underlay, loopback, &net.UDPAddr{}, nil)

	if err := connection.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, _, err := connection.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired read error = %v, want deadline exceeded", err)
	}
	deadline := time.Now().Add(time.Minute)
	if err := connection.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if underlay.writeDeadlines != 1 || loopback.writeDeadlines != 1 {
		t.Fatalf("write deadline calls = underlay %d, loopback %d", underlay.writeDeadlines, loopback.writeDeadlines)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if underlay.closeCalls != 1 || loopback.closeCalls != 1 {
		t.Fatalf("close calls = underlay %d, loopback %d", underlay.closeCalls, loopback.closeCalls)
	}
	if _, _, err := connection.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close error = %v, want net.ErrClosed", err)
	}
}

type recordedDatagram struct {
	packet []byte
	oob    []byte
	flags  int
	from   netip.AddrPort
}

type recordingUDPConn struct {
	mu             sync.Mutex
	writes         int
	writeDeadlines int
	closeCalls     int
	reads          chan recordedDatagram
	closed         chan struct{}
}

func newRecordingUDPConn() *recordingUDPConn {
	return &recordingUDPConn{reads: make(chan recordedDatagram, 4), closed: make(chan struct{})}
}

func (c *recordingUDPConn) recordWrite(packet []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return len(packet), nil
}

func (c *recordingUDPConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *recordingUDPConn) Read(packet []byte) (int, error) {
	n, _, err := c.ReadFromUDPAddrPort(packet)
	return n, err
}
func (c *recordingUDPConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, address, err := c.ReadFromUDP(packet)
	return n, address, err
}
func (c *recordingUDPConn) ReadFromUDP(packet []byte) (int, *net.UDPAddr, error) {
	n, address, err := c.ReadFromUDPAddrPort(packet)
	return n, net.UDPAddrFromAddrPort(address), err
}
func (c *recordingUDPConn) ReadFromUDPAddrPort(packet []byte) (int, netip.AddrPort, error) {
	n, _, _, address, err := c.ReadMsgUDPAddrPort(packet, nil)
	return n, address, err
}
func (c *recordingUDPConn) ReadMsgUDP(packet, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, address, err := c.ReadMsgUDPAddrPort(packet, oob)
	return n, oobn, flags, net.UDPAddrFromAddrPort(address), err
}
func (c *recordingUDPConn) ReadMsgUDPAddrPort(packet, oob []byte) (int, int, int, netip.AddrPort, error) {
	select {
	case datagram := <-c.reads:
		return copy(packet, datagram.packet), copy(oob, datagram.oob), datagram.flags, datagram.from, nil
	case <-c.closed:
		return 0, 0, 0, netip.AddrPort{}, net.ErrClosed
	}
}
func (c *recordingUDPConn) Write(packet []byte) (int, error) { return c.recordWrite(packet) }
func (c *recordingUDPConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return c.recordWrite(packet)
}
func (c *recordingUDPConn) WriteToUDP(packet []byte, _ *net.UDPAddr) (int, error) {
	return c.recordWrite(packet)
}
func (c *recordingUDPConn) WriteToUDPAddrPort(packet []byte, _ netip.AddrPort) (int, error) {
	return c.recordWrite(packet)
}
func (c *recordingUDPConn) WriteMsgUDP(packet, _ []byte, _ *net.UDPAddr) (int, int, error) {
	n, err := c.recordWrite(packet)
	return n, 0, err
}
func (c *recordingUDPConn) WriteMsgUDPAddrPort(packet, _ []byte, _ netip.AddrPort) (int, int, error) {
	n, err := c.recordWrite(packet)
	return n, 0, err
}
func (c *recordingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCalls++
	if c.closeCalls == 1 {
		close(c.closed)
	}
	return nil
}
func (*recordingUDPConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (*recordingUDPConn) RemoteAddr() net.Addr               { return nil }
func (*recordingUDPConn) SetDeadline(time.Time) error        { return nil }
func (*recordingUDPConn) SetReadDeadline(time.Time) error    { return nil }
func (c *recordingUDPConn) SetWriteDeadline(time.Time) error { c.writeDeadlines++; return nil }

var _ interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
} = (*recordingUDPConn)(nil)
