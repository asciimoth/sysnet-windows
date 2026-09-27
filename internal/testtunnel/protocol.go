// Package testtunnel implements the deliberately insecure wire protocol used
// by cmd/test tunnel and cmd/tunnelpeer.
package testtunnel

import (
	"encoding/binary"
	"errors"
)

const HeaderSize = 8

var header = [HeaderSize]byte{'M', 'S', 'T', 'D', 1, 0, 0, 0}

// Encode adds the demo protocol header to one IP packet.
func Encode(packet []byte) []byte {
	datagram := make([]byte, HeaderSize+len(packet))
	copy(datagram, header[:])
	copy(datagram[HeaderSize:], packet)
	return datagram
}

// Decode validates a demo datagram and returns its IP packet.
func Decode(datagram []byte) ([]byte, error) {
	if len(datagram) <= HeaderSize || string(datagram[:HeaderSize]) != string(header[:]) {
		return nil, errors.New("invalid demo tunnel datagram")
	}
	return datagram[HeaderSize:], nil
}

// Reply creates the controlled peer's reply to a TCP or UDP IP packet.
// It supports standard TCP handshake, data, and close packets. It does not
// support TCP Fast Open, simultaneous open, IP fragmentation, or IPv6
// extension headers.
func Reply(packet []byte) ([]byte, bool) {
	result := append([]byte(nil), packet...)
	transport, protocol, pseudo, ok := prepareIPReply(result)
	if !ok {
		return nil, false
	}
	switch protocol {
	case 6:
		if !replyTCP(transport) {
			return nil, false
		}
		transport[16], transport[17] = 0, 0
		binary.BigEndian.PutUint16(transport[16:18], checksum(pseudo, transport))
	case 17:
		if !replyUDP(transport) {
			return nil, false
		}
		transport[6], transport[7] = 0, 0
		value := checksum(pseudo, transport)
		if value == 0 {
			value = 0xffff
		}
		binary.BigEndian.PutUint16(transport[6:8], value)
	default:
		return nil, false
	}
	return result, true
}

func prepareIPReply(packet []byte) ([]byte, byte, []byte, bool) {
	if len(packet) < 1 {
		return nil, 0, nil, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return nil, 0, nil, false
		}
		headerLength := int(packet[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if headerLength < 20 || totalLength < headerLength || totalLength != len(packet) || fragment&0x3fff != 0 {
			return nil, 0, nil, false
		}
		packet = packet[:totalLength]
		protocol := packet[9]
		packet[12], packet[16] = packet[16], packet[12]
		packet[13], packet[17] = packet[17], packet[13]
		packet[14], packet[18] = packet[18], packet[14]
		packet[15], packet[19] = packet[19], packet[15]
		packet[8] = 64
		packet[10], packet[11] = 0, 0
		for index := 20; index < headerLength; index++ {
			packet[index] = 1 // NOP disables untrusted IPv4 options.
		}
		binary.BigEndian.PutUint16(packet[10:12], checksum(nil, packet[:headerLength]))
		transport := packet[headerLength:]
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], packet[12:16])
		copy(pseudo[4:8], packet[16:20])
		pseudo[9] = protocol
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(transport)))
		return transport, protocol, pseudo, true
	case 6:
		if len(packet) < 40 {
			return nil, 0, nil, false
		}
		payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
		if payloadLength != len(packet)-40 {
			return nil, 0, nil, false
		}
		packet = packet[:40+payloadLength]
		protocol := packet[6]
		for i := range 16 {
			packet[8+i], packet[24+i] = packet[24+i], packet[8+i]
		}
		packet[7] = 64
		transport := packet[40:]
		pseudo := make([]byte, 40)
		copy(pseudo[0:16], packet[8:24])
		copy(pseudo[16:32], packet[24:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(transport)))
		pseudo[39] = protocol
		return transport, protocol, pseudo, true
	default:
		return nil, 0, nil, false
	}
}

func replyUDP(packet []byte) bool {
	if len(packet) < 8 || int(binary.BigEndian.Uint16(packet[4:6])) != len(packet) {
		return false
	}
	packet[0], packet[2] = packet[2], packet[0]
	packet[1], packet[3] = packet[3], packet[1]
	return true
}

func replyTCP(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	headerLength := int(packet[12]>>4) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return false
	}
	flags := packet[13]
	payload := append([]byte(nil), packet[headerLength:]...)
	hasSYN := flags&0x02 != 0
	hasFIN := flags&0x01 != 0
	// The controlled peer does not implement simultaneous open or TCP Fast
	// Open. Reject those packets instead of returning a SYN reply with invalid
	// sequence accounting or unintended payload.
	if flags&0x04 != 0 || hasSYN && (flags&0x10 != 0 || hasFIN || len(payload) != 0) {
		return false
	}
	sequence := binary.BigEndian.Uint32(packet[4:8])
	acknowledgment := binary.BigEndian.Uint32(packet[8:12])
	packet[0], packet[2] = packet[2], packet[0]
	packet[1], packet[3] = packet[3], packet[1]
	packet[12] = byte(headerLength/4) << 4
	binary.BigEndian.PutUint16(packet[14:16], 0xffff)
	for index := 20; index < headerLength; index++ {
		packet[index] = 1 // NOP disables untrusted client options.
	}
	switch {
	case hasSYN:
		binary.BigEndian.PutUint32(packet[4:8], 0x10203040)
		binary.BigEndian.PutUint32(packet[8:12], sequence+1)
		packet[13] = 0x12
	case len(payload) != 0 || hasFIN:
		sequenceAdvance := uint32(len(payload))
		if hasFIN {
			sequenceAdvance++
		}
		binary.BigEndian.PutUint32(packet[4:8], acknowledgment)
		binary.BigEndian.PutUint32(packet[8:12], sequence+sequenceAdvance)
		packet[13] = 0x10
		if len(payload) != 0 {
			packet[13] |= 0x08
		}
		if hasFIN {
			packet[13] |= 0x01
		}
		copy(packet[headerLength:], payload)
	default:
		return false
	}
	return true
}

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd byte
	haveOdd := false
	for _, part := range parts {
		for _, value := range part {
			if haveOdd {
				sum += uint32(odd)<<8 | uint32(value)
				haveOdd = false
			} else {
				odd = value
				haveOdd = true
			}
		}
	}
	if haveOdd {
		sum += uint32(odd) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
