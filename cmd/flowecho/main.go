// Command flowecho provides the isolated echo endpoint for the Windows packet
// flow tests. It is not a general-purpose network service.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	defaultIPv4 = "203.0.113.1"
	defaultIPv6 = "2001:db8:ffff::1"
	defaultPort = 47823
	controlPort = 47824
	dnsPort     = 53
)

func main() {
	ipv4 := flag.String("ipv4", defaultIPv4, "IPv4 service address")
	ipv6 := flag.String("ipv6", defaultIPv6, "IPv6 service address")
	port := flag.Int("port", defaultPort, "TCP and UDP service port")
	flag.Parse()

	addresses := []string{
		net.JoinHostPort(*ipv4, fmt.Sprint(*port)),
		net.JoinHostPort(*ipv6, fmt.Sprint(*port)),
		net.JoinHostPort(*ipv4, fmt.Sprint(dnsPort)),
		net.JoinHostPort(*ipv6, fmt.Sprint(dnsPort)),
	}
	controlAddresses := []string{
		net.JoinHostPort(*ipv4, fmt.Sprint(controlPort)),
		net.JoinHostPort(*ipv6, fmt.Sprint(controlPort)),
	}
	serveErrors := make(chan error, len(addresses)*2+len(controlAddresses))
	for _, address := range addresses {
		address := address
		go func() {
			serveErrors <- serveTCP(address)
		}()
		go func() {
			serveErrors <- serveUDP(address)
		}()
	}
	for _, address := range controlAddresses {
		address := address
		go func() {
			serveErrors <- serveCallbackControl(address)
		}()
	}
	fmt.Fprintf(os.Stderr, "flowecho listening on %v\n", addresses)
	if err := <-serveErrors; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// callbackRequest asks the controlled endpoint to connect to a listener in the
// client guest. Token is base64 encoded so the packet validator observes the
// plain marker only on the callback connection, not in this control request.
type callbackRequest struct {
	Network string `json:"network"`
	Address string `json:"address"`
	Token   string `json:"token"`
}

func serveCallbackControl(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen callback control on %s: %w", address, err)
	}
	defer func() { _ = listener.Close() }()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept callback control on %s: %w", address, err)
		}
		go handleCallbackControl(connection)
	}
}

func handleCallbackControl(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	var request callbackRequest
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&request); err != nil {
		return
	}
	if request.Network != "tcp4" && request.Network != "tcp6" {
		return
	}
	token, err := base64.StdEncoding.DecodeString(request.Token)
	if err != nil || len(token) == 0 {
		return
	}
	callback, err := net.DialTimeout(request.Network, request.Address, 10*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = callback.Close() }()
	_ = callback.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = callback.Write(token)
}

func serveTCP(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen TCP on %s: %w", address, err)
	}
	defer func() { _ = listener.Close() }()
	return serveTCPListener(listener, address)
}

func serveTCPListener(listener net.Listener, address string) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept TCP on %s: %w", address, err)
		}
		go func() {
			defer func() { _ = connection.Close() }()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func serveUDP(address string) error {
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("listen UDP on %s: %w", address, err)
	}
	defer func() { _ = connection.Close() }()
	return serveUDPPacket(connection, address)
}

func serveUDPPacket(connection net.PacketConn, address string) error {
	buffer := make([]byte, 2048)
	for {
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return fmt.Errorf("read UDP on %s: %w", address, err)
		}
		if _, err := connection.WriteTo(buffer[:length], peer); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("write UDP on %s: %w", address, err)
		}
	}
}
