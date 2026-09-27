// Command flowecho provides the isolated echo endpoint for the Windows packet
// flow tests. It is not a general-purpose network service.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	defaultIPv4 = "203.0.113.1"
	defaultIPv6 = "2001:db8:ffff::1"
	defaultPort = 47823
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
	serveErrors := make(chan error, len(addresses)*2)
	for _, address := range addresses {
		address := address
		go func() {
			serveErrors <- serveTCP(address)
		}()
		go func() {
			serveErrors <- serveUDP(address)
		}()
	}
	fmt.Fprintf(os.Stderr, "flowecho listening on %v\n", addresses)
	if err := <-serveErrors; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
