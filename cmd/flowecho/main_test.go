package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPAndUDPEcho(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- serveTCPListener(listener, listener.Addr().String()) }()
		connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte("tcp-echo")
		if _, err := connection.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(connection, reply); err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		_ = listener.Close()
		if err := <-done; err == nil || !strings.Contains(err.Error(), "accept TCP") {
			t.Fatalf("closed listener error = %v", err)
		}
		if !bytes.Equal(reply, payload) {
			t.Fatalf("reply = %q; want %q", reply, payload)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- serveUDPPacket(server, server.LocalAddr().String()) }()
		client, err := net.Dial("udp4", server.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		payload := []byte("udp-echo")
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(client, reply); err != nil {
			t.Fatal(err)
		}
		_ = server.Close()
		if err := <-done; err == nil || !strings.Contains(err.Error(), "read UDP") {
			t.Fatalf("closed packet connection error = %v", err)
		}
		if !bytes.Equal(reply, payload) {
			t.Fatalf("reply = %q; want %q", reply, payload)
		}
	})
}

func TestEchoRejectsInvalidListenAddress(t *testing.T) {
	if err := serveTCP("invalid address"); err == nil || !strings.Contains(err.Error(), "listen TCP") {
		t.Fatalf("serveTCP: %v", err)
	}
	if err := serveUDP("invalid address"); err == nil || !strings.Contains(err.Error(), "listen UDP") {
		t.Fatalf("serveUDP: %v", err)
	}
}
