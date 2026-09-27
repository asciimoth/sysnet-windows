package testtunnel

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func ipv4Packet(protocol byte, transport []byte) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 32, protocol
	copy(packet[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 1})
	copy(packet[20:], transport)
	return packet
}

func ipv6Packet(protocol byte, transport []byte) []byte {
	packet := make([]byte, 40+len(transport))
	packet[0], packet[6], packet[7] = 0x60, protocol, 32
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(transport)))
	packet[23], packet[39] = 2, 1
	copy(packet[40:], transport)
	return packet
}

func udpSegment(payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], 1234)
	binary.BigEndian.PutUint16(segment[2:4], 47823)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	copy(segment[8:], payload)
	return segment
}

func tcpSegment(flags byte, payload []byte, headerLength int) []byte {
	segment := make([]byte, headerLength+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], 1234)
	binary.BigEndian.PutUint16(segment[2:4], 47823)
	binary.BigEndian.PutUint32(segment[4:8], 50)
	binary.BigEndian.PutUint32(segment[8:12], 0x10203041)
	segment[12], segment[13] = byte(headerLength/4)<<4, flags
	copy(segment[headerLength:], payload)
	return segment
}

func TestEncodeDecode(t *testing.T) {
	want := []byte{0x45, 0, 0, 20}
	datagram := Encode(want)
	got, err := Decode(datagram)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("decoded packet = %x; want %x", got, want)
	}
	if _, err := Decode([]byte("invalid")); err == nil {
		t.Fatal("invalid datagram was accepted")
	}
	if _, err := Decode(header[:]); err == nil {
		t.Fatal("header without a packet was accepted")
	}
	corrupt := Encode(want)
	corrupt[4]++
	if _, err := Decode(corrupt); err == nil {
		t.Fatal("unknown protocol version was accepted")
	}
}

func TestUDPReplyIPv4(t *testing.T) {
	packet := make([]byte, 20+8+4)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[20:24], 1234)
	binary.BigEndian.PutUint16(packet[22:24], 47823)
	binary.BigEndian.PutUint16(packet[24:26], 12)
	copy(packet[28:], "demo")
	reply, ok := Reply(packet)
	if !ok {
		t.Fatal("packet did not produce a reply")
	}
	if got := string(reply[28:]); got != "demo" {
		t.Fatalf("payload = %q; want demo", got)
	}
	if got := binary.BigEndian.Uint16(reply[20:22]); got != 47823 {
		t.Fatalf("source port = %d; want 47823", got)
	}
	if got := binary.BigEndian.Uint16(reply[22:24]); got != 1234 {
		t.Fatalf("destination port = %d; want 1234", got)
	}
}

func TestTCPReplyLifecycleIPv6(t *testing.T) {
	packet := make([]byte, 60)
	packet[0], packet[6], packet[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[23], packet[39] = 2, 1
	binary.BigEndian.PutUint16(packet[40:44], 1234)
	binary.BigEndian.PutUint16(packet[42:44], 47823)
	binary.BigEndian.PutUint32(packet[44:48], 50)
	packet[52], packet[53] = 5<<4, 0x02
	synAck, ok := Reply(packet)
	if !ok || synAck[53] != 0x12 {
		t.Fatalf("SYN reply = %x, %t", synAck, ok)
	}
	if got := binary.BigEndian.Uint32(synAck[48:52]); got != 51 {
		t.Fatalf("SYN acknowledgment = %d; want 51", got)
	}

	data := append(append([]byte(nil), packet...), []byte("token")...)
	binary.BigEndian.PutUint16(data[4:6], 25)
	binary.BigEndian.PutUint32(data[44:48], 51)
	binary.BigEndian.PutUint32(data[48:52], 0x10203041)
	data[53] = 0x18
	reply, ok := Reply(data)
	if !ok || string(reply[60:]) != "token" {
		t.Fatalf("data reply = %x, %t", reply, ok)
	}
	if got := binary.BigEndian.Uint32(reply[48:52]); got != 56 {
		t.Fatalf("data acknowledgment = %d; want 56", got)
	}

	finish := ipv6Packet(6, tcpSegment(0x11, nil, 20))
	finAck, ok := Reply(finish)
	if !ok || finAck[53] != 0x11 {
		t.Fatalf("FIN reply = %x, %t", finAck, ok)
	}
	if got := binary.BigEndian.Uint32(finAck[48:52]); got != 51 {
		t.Fatalf("FIN acknowledgment = %d; want 51", got)
	}
}

func TestTCPReplySequenceAccounting(t *testing.T) {
	tests := []struct {
		name      string
		ipv6      bool
		flags     byte
		sequence  uint32
		payload   string
		wantAck   uint32
		wantFlags byte
	}{
		{name: "IPv4 data", flags: 0x18, sequence: 50, payload: "data", wantAck: 54, wantFlags: 0x18},
		{name: "IPv6 FIN", ipv6: true, flags: 0x11, sequence: 50, wantAck: 51, wantFlags: 0x11},
		{name: "IPv4 data and FIN", flags: 0x19, sequence: 50, payload: "last", wantAck: 55, wantFlags: 0x19},
		{name: "IPv6 data and FIN", ipv6: true, flags: 0x19, sequence: 50, payload: "last", wantAck: 55, wantFlags: 0x19},
		{name: "IPv6 odd data and FIN", ipv6: true, flags: 0x19, sequence: 50, payload: "end", wantAck: 54, wantFlags: 0x19},
		{name: "sequence wrap", flags: 0x19, sequence: ^uint32(0) - 2, payload: "data", wantAck: 2, wantFlags: 0x19},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			segment := tcpSegment(test.flags, []byte(test.payload), 20)
			binary.BigEndian.PutUint32(segment[4:8], test.sequence)
			packet := ipv4Packet(6, segment)
			transportOffset := 20
			if test.ipv6 {
				packet = ipv6Packet(6, segment)
				transportOffset = 40
			}
			reply, ok := Reply(packet)
			if !ok {
				t.Fatal("TCP packet did not produce a reply")
			}
			transport := reply[transportOffset:]
			if got := binary.BigEndian.Uint32(transport[8:12]); got != test.wantAck {
				t.Errorf("acknowledgment = %d; want %d", got, test.wantAck)
			}
			if got := transport[13]; got != test.wantFlags {
				t.Errorf("flags = %#x; want %#x", got, test.wantFlags)
			}
			if got := binary.BigEndian.Uint32(transport[4:8]); got != 0x10203041 {
				t.Errorf("sequence = %#x; want input acknowledgment %#x", got, uint32(0x10203041))
			}
			if got := binary.BigEndian.Uint16(transport[0:2]); got != 47823 {
				t.Errorf("source port = %d; want 47823", got)
			}
			if got := binary.BigEndian.Uint16(transport[2:4]); got != 1234 {
				t.Errorf("destination port = %d; want 1234", got)
			}
			if got := string(transport[20:]); got != test.payload {
				t.Errorf("payload = %q; want %q", got, test.payload)
			}
			assertReplyChecksums(t, reply)
		})
	}
}

func TestTCPReplyDisablesOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   byte
		payload string
	}{
		{name: "SYN", flags: 0x02},
		{name: "data", flags: 0x18, payload: "echo"},
		{name: "data and FIN", flags: 0x19, payload: "last"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			segment := tcpSegment(test.flags, []byte(test.payload), 24)
			copy(segment[20:24], []byte{2, 4, 5, 0xb4})
			reply, ok := Reply(ipv4Packet(6, segment))
			if !ok {
				t.Fatal("TCP packet with options did not produce a reply")
			}
			if !bytes.Equal(reply[40:44], []byte{1, 1, 1, 1}) {
				t.Errorf("TCP options were not disabled: %x", reply[40:44])
			}
			if got := string(reply[44:]); got != test.payload {
				t.Errorf("payload = %q; want %q", got, test.payload)
			}
			assertReplyChecksums(t, reply)
		})
	}
}

func TestTCPReplySYNSequenceWrap(t *testing.T) {
	segment := tcpSegment(0x02, nil, 20)
	binary.BigEndian.PutUint32(segment[4:8], ^uint32(0))
	reply, ok := Reply(ipv6Packet(6, segment))
	if !ok {
		t.Fatal("TCP SYN did not produce a reply")
	}
	if got := binary.BigEndian.Uint32(reply[48:52]); got != 0 {
		t.Errorf("acknowledgment = %d; want wrapped value 0", got)
	}
	if got := binary.BigEndian.Uint32(reply[44:48]); got != 0x10203040 {
		t.Errorf("sequence = %#x; want %#x", got, uint32(0x10203040))
	}
	if got := reply[53]; got != 0x12 {
		t.Errorf("flags = %#x; want SYN-ACK", got)
	}
	assertReplyChecksums(t, reply)
}

func TestIPv4ReplyDisablesOptions(t *testing.T) {
	transport := udpSegment([]byte("echo"))
	packet := make([]byte, 24+len(transport))
	packet[0] = 0x46
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 32, 17
	copy(packet[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 1})
	copy(packet[20:24], []byte{7, 4, 0, 0})
	copy(packet[24:], transport)

	reply, ok := Reply(packet)
	if !ok {
		t.Fatal("IPv4 packet with options did not produce a reply")
	}
	if !bytes.Equal(reply[20:24], []byte{1, 1, 1, 1}) {
		t.Errorf("IPv4 options were not disabled: %x", reply[20:24])
	}
	if got := string(reply[32:]); got != "echo" {
		t.Errorf("payload = %q; want echo", got)
	}
	assertReplyChecksums(t, reply)
}

func TestReplyRejectsUnsupportedPackets(t *testing.T) {
	validIPv4UDP := ipv4Packet(17, udpSegment([]byte("x")))
	validIPv6UDP := ipv6Packet(17, udpSegment([]byte("x")))
	cases := map[string][]byte{
		"empty":                nil,
		"unknown IP version":   {0x70},
		"short IPv4":           {0x45},
		"short IPv6":           {0x60},
		"short IPv4 header":    append([]byte{0x44}, validIPv4UDP[1:]...),
		"IPv4 length mismatch": append([]byte(nil), validIPv4UDP...),
		"IPv4 fragment":        append([]byte(nil), validIPv4UDP...),
		"IPv6 length mismatch": append([]byte(nil), validIPv6UDP...),
		"unknown protocol":     ipv4Packet(1, make([]byte, 8)),
		"short UDP":            ipv4Packet(17, make([]byte, 7)),
		"bad UDP length":       ipv4Packet(17, make([]byte, 8)),
		"short TCP":            ipv4Packet(6, make([]byte, 19)),
		"short TCP header":     ipv4Packet(6, tcpSegment(0x02, nil, 16)),
		"long TCP header":      ipv4Packet(6, tcpSegment(0x02, nil, 20)),
		"TCP reset":            ipv4Packet(6, tcpSegment(0x04, nil, 20)),
		"TCP SYN with ACK":     ipv4Packet(6, tcpSegment(0x12, nil, 20)),
		"TCP SYN with FIN":     ipv4Packet(6, tcpSegment(0x03, nil, 20)),
		"TCP SYN with payload": ipv4Packet(6, tcpSegment(0x02, []byte("fast-open"), 20)),
		"TCP ACK only":         ipv4Packet(6, tcpSegment(0x10, nil, 20)),
	}
	binary.BigEndian.PutUint16(cases["IPv4 length mismatch"][2:4], uint16(len(validIPv4UDP)-1))
	binary.BigEndian.PutUint16(cases["IPv4 fragment"][6:8], 1)
	binary.BigEndian.PutUint16(cases["IPv6 length mismatch"][4:6], uint16(len(validIPv6UDP)-41))
	binary.BigEndian.PutUint16(cases["bad UDP length"][24:26], 9)
	cases["short TCP header"][32] = 4 << 4
	cases["long TCP header"][32] = 6 << 4
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(packet)
			if reply, ok := Reply(packet); ok || reply != nil {
				t.Fatalf("unsupported packet produced a reply: %x", reply)
			}
			if !bytes.Equal(packet, original) {
				t.Fatal("Reply changed caller-owned packet memory")
			}
		})
	}
}

func assertReplyChecksums(t *testing.T, packet []byte) {
	t.Helper()
	switch packet[0] >> 4 {
	case 4:
		headerLength := int(packet[0]&0x0f) * 4
		if got := checksum(packet[:headerLength]); got != 0 {
			t.Errorf("IPv4 header checksum = %#x; want 0", got)
		}
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], packet[12:16])
		copy(pseudo[4:8], packet[16:20])
		pseudo[9] = packet[9]
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-headerLength))
		if got := checksum(pseudo, packet[headerLength:]); got != 0 {
			t.Errorf("IPv4 transport checksum = %#x; want 0", got)
		}
	case 6:
		pseudo := make([]byte, 40)
		copy(pseudo[0:16], packet[8:24])
		copy(pseudo[16:32], packet[24:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)-40))
		pseudo[39] = packet[6]
		if got := checksum(pseudo, packet[40:]); got != 0 {
			t.Errorf("IPv6 transport checksum = %#x; want 0", got)
		}
	default:
		t.Fatalf("unexpected IP version %#x", packet[0]>>4)
	}
}

func TestUDPReplyIPv6WithOddPayload(t *testing.T) {
	packet := ipv6Packet(17, udpSegment([]byte("odd")))
	reply, ok := Reply(packet)
	if !ok || string(reply[48:]) != "odd" {
		t.Fatalf("UDP reply = %x, %t", reply, ok)
	}
	if binary.BigEndian.Uint16(reply[46:48]) == 0 {
		t.Fatal("UDP reply checksum is zero")
	}
}

func FuzzDemoTunnelProtocol(f *testing.F) {
	f.Add(ipv4Packet(17, udpSegment([]byte("seed"))))
	f.Add(ipv6Packet(6, tcpSegment(0x02, nil, 20)))
	f.Add(ipv4Packet(6, tcpSegment(0x19, []byte("last"), 20)))
	f.Add(ipv6Packet(6, tcpSegment(0x02, []byte("fast-open"), 20)))
	f.Add(ipv4Packet(6, tcpSegment(0x03, nil, 20)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		encoded := Encode(packet)
		decoded, err := Decode(encoded)
		if len(packet) == 0 {
			if err == nil {
				t.Fatal("empty packet was accepted")
			}
			return
		}
		if err != nil || !bytes.Equal(decoded, packet) {
			t.Fatalf("Encode/Decode round trip failed: %x, %v", decoded, err)
		}
		original := bytes.Clone(packet)
		reply, ok := Reply(packet)
		if !bytes.Equal(packet, original) {
			t.Fatal("Reply changed caller-owned packet memory")
		}
		if ok && (len(reply) != len(packet) || bytes.Equal(reply, packet)) {
			t.Fatalf("invalid successful reply: input=%x reply=%x", packet, reply)
		}
	})
}
