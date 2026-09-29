package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

func TestCallbackControlDecodesTokenAndConnects(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleCallbackControl(server)
		close(done)
	}()
	token := []byte("callback-token")
	request := callbackRequest{
		Network: "tcp4", Address: listener.Addr().String(),
		Token: base64.StdEncoding.EncodeToString(token),
	}
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(token))
	if _, err := io.ReadFull(connection, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("callback = %q, want %q", got, token)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback control did not finish")
	}
}

func TestEchoRejectsInvalidListenAddress(t *testing.T) {
	if err := serveTCP("invalid address"); err == nil || !strings.Contains(err.Error(), "listen TCP") {
		t.Fatalf("serveTCP: %v", err)
	}
	if err := serveUDP("invalid address"); err == nil || !strings.Contains(err.Error(), "listen UDP") {
		t.Fatalf("serveUDP: %v", err)
	}
}

func TestDNSResponsePreservesQuestionMarkerAndAnswersEachFamily(t *testing.T) {
	for _, test := range []struct {
		name      string
		queryType uint16
		wantSize  uint16
	}{
		{name: "A", queryType: 1, wantSize: 4},
		{name: "AAAA", queryType: 28, wantSize: 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := []byte{0x73, 0x57, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
				6, 'M', 'A', 'R', 'K', 'E', 'R', 4, 't', 'e', 's', 't', 0,
				byte(test.queryType >> 8), byte(test.queryType), 0, 1}
			response, err := dnsResponse(query)
			if err != nil {
				t.Fatal(err)
			}
			if response[2]&0x80 == 0 || binary.BigEndian.Uint16(response[6:8]) != 1 {
				t.Fatalf("DNS response header = %x", response[:12])
			}
			if !bytes.Contains(response, []byte("MARKER")) {
				t.Fatal("DNS response lost the capture marker")
			}
			if got := binary.BigEndian.Uint16(response[len(response)-int(test.wantSize)-2:]); got != test.wantSize {
				t.Fatalf("RDLENGTH = %d, want %d", got, test.wantSize)
			}
		})
	}
}

func TestDNSResponseRejectsMalformedQueries(t *testing.T) {
	for _, query := range [][]byte{
		nil,
		make([]byte, 12),
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64},
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a'},
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
	} {
		if response, err := dnsResponse(query); err == nil {
			t.Fatalf("dnsResponse(%x) = %x, nil", query, response)
		}
	}
}

func TestDNSPortTCPAlsoSupportsDependencyConformanceMarker(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleDNSTCP(server)
		close(done)
	}()
	token := []byte("FLOW_00000001")
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(token)
		writeDone <- err
	}()
	reply := make([]byte, len(token))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, token) {
		t.Fatalf("dependency marker reply = %q, want %q", reply, token)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DNS TCP marker handler did not stop")
	}
}
