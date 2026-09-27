package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/sysnet-windows/internal/testtunnel"
)

func demoUDPPacket(payload string) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[20:22], 1234)
	binary.BigEndian.PutUint16(packet[22:24], 47823)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func TestServePacketRepliesAndIgnoresInvalidDatagrams(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- servePacket(server) }()
	client, err := net.Dial("udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("invalid")); err != nil {
		t.Fatal(err)
	}
	packet := demoUDPPacket("peer-echo")
	if _, err := client.Write(testtunnel.Encode(packet)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	length, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := testtunnel.Decode(buffer[:length])
	if err != nil || string(reply[28:]) != "peer-echo" {
		t.Fatalf("reply = %x, %v", reply, err)
	}
	_ = server.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("closed connection error = %v", err)
	}
}

func TestServeRejectsInvalidAddress(t *testing.T) {
	if err := serve("invalid address"); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("serve: %v", err)
	}
}
