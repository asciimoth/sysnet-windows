package owner

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
)

func TestOutgoingPacketFlow(t *testing.T) {
	tests := []struct {
		name       string
		packet     []byte
		proto      string
		localPort  uint16
		remotePort uint16
		err        error
	}{
		{name: "IPv4 TCP with options", packet: ipv4Packet(6, tcpHeader(1234, 443), 24), proto: "tcp", localPort: 1234, remotePort: 443},
		{name: "IPv4 UDP", packet: ipv4Packet(17, udpHeader(5353, 53), 20), proto: "udp", localPort: 5353, remotePort: 53},
		{name: "IPv6 UDP after hop-by-hop", packet: ipv6Packet(0, append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, udpHeader(6000, 6001)...)), proto: "udp", localPort: 6000, remotePort: 6001},
		{name: "ICMP", packet: ipv4Packet(1, make([]byte, 8), 20), err: sockowner.ErrProtocol},
		{name: "IPv4 non-first fragment", packet: ipv4Fragment(), err: sockowner.ErrNonFirstFragment},
		{name: "IPv6 non-first fragment", packet: ipv6Fragment(), err: sockowner.ErrNonFirstFragment},
		{name: "invalid version", packet: []byte{0x70}, err: sockowner.ErrNotIPPacket},
		{name: "short IPv4", packet: []byte{0x45}, err: sockowner.ErrShortPacket},
		{name: "bad IPv4 header length", packet: append([]byte{0x44}, make([]byte, 19)...), err: sockowner.ErrMalformedPacket},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flow, err := OutgoingPacketFlow(test.packet)
			if !errors.Is(err, test.err) {
				t.Fatalf("OutgoingPacketFlow() error = %v, want %v", err, test.err)
			}
			if test.err == nil && (flow.Proto != test.proto || flow.LocalPort != test.localPort || flow.RemotePort != test.remotePort) {
				t.Fatalf("OutgoingPacketFlow() = %+v", flow)
			}
		})
	}
}

func TestOutgoingPacketFlowDoesNotAliasPacket(t *testing.T) {
	packet := ipv4Packet(17, udpHeader(1, 2), 20)
	flow, err := OutgoingPacketFlow(packet)
	if err != nil {
		t.Fatal(err)
	}
	clear(packet)
	if got := flow.LocalIP.String(); got != "192.0.2.1" {
		t.Fatalf("LocalIP after packet mutation = %s", got)
	}
}

func TestLocalPeerFlowReversesAcceptedConnection(t *testing.T) {
	connection := addressConn{
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49152},
	}
	flow, err := LocalPeerFlow(connection)
	if err != nil {
		t.Fatal(err)
	}
	if flow.LocalPort != 49152 || flow.RemotePort != 8080 {
		t.Fatalf("LocalPeerFlow() = %+v", flow)
	}
}

func FuzzOutgoingPacketFlow(f *testing.F) {
	f.Add(ipv4Packet(6, tcpHeader(1234, 443), 20))
	f.Add(ipv6Packet(17, udpHeader(1234, 53)))
	f.Add(ipv6Fragment())
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, packet []byte) {
		flow, err := OutgoingPacketFlow(packet)
		if err == nil {
			if _, familyErr := flow.FlowFamily(); familyErr != nil {
				t.Fatalf("successful parse returned invalid flow: %+v: %v", flow, familyErr)
			}
			if flow.Proto != "tcp" && flow.Proto != "udp" {
				t.Fatalf("successful parse returned protocol %q", flow.Proto)
			}
		}
	})
}

func ipv4Packet(protocol byte, payload []byte, headerLength int) []byte {
	packet := make([]byte, headerLength+len(payload))
	packet[0] = 0x40 | byte(headerLength/4)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[9] = protocol
	copy(packet[12:16], net.ParseIP("192.0.2.1").To4())
	copy(packet[16:20], net.ParseIP("198.51.100.2").To4())
	copy(packet[headerLength:], payload)
	return packet
}

func ipv6Packet(nextHeader byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = nextHeader
	copy(packet[8:24], net.ParseIP("2001:db8::1").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::2").To16())
	copy(packet[40:], payload)
	return packet
}

func tcpHeader(source, destination uint16) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], source)
	binary.BigEndian.PutUint16(header[2:4], destination)
	header[12] = 5 << 4
	return header
}

func udpHeader(source, destination uint16) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:2], source)
	binary.BigEndian.PutUint16(header[2:4], destination)
	binary.BigEndian.PutUint16(header[4:6], 8)
	return header
}

func ipv4Fragment() []byte {
	packet := ipv4Packet(17, udpHeader(1, 2), 20)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	return packet
}

func ipv6Fragment() []byte {
	header := []byte{17, 0, 0, 8, 0, 0, 0, 1}
	return ipv6Packet(44, append(header, udpHeader(1, 2)...))
}

type addressConn struct{ local, remote net.Addr }

func (c addressConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c addressConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c addressConn) Close() error                     { return nil }
func (c addressConn) LocalAddr() net.Addr              { return c.local }
func (c addressConn) RemoteAddr() net.Addr             { return c.remote }
func (c addressConn) SetDeadline(time.Time) error      { return nil }
func (c addressConn) SetReadDeadline(time.Time) error  { return nil }
func (c addressConn) SetWriteDeadline(time.Time) error { return nil }
