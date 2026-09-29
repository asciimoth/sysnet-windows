// Command flowecho provides the isolated echo endpoint for the Windows packet
// flow tests. It is not a general-purpose network service.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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
			if portOf(address) == dnsPort {
				serveErrors <- serveDNSTCP(address)
			} else {
				serveErrors <- serveTCP(address)
			}
		}()
		go func() {
			if portOf(address) == dnsPort {
				serveErrors <- serveDNSUDP(address)
			} else {
				serveErrors <- serveUDP(address)
			}
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

func portOf(address string) int {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return value
}

// dnsResponse returns a minimal authoritative address response. It preserves
// the complete question so packet captures contain the caller's unique marker.
func dnsResponse(query []byte) ([]byte, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("invalid DNS query header")
	}
	offset := 12
	for {
		if offset >= len(query) {
			return nil, errors.New("truncated DNS question")
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(query) {
			return nil, errors.New("invalid DNS question name")
		}
		offset += length
	}
	if offset+4 > len(query) {
		return nil, errors.New("truncated DNS question type")
	}
	questionEnd := offset + 4
	response := append([]byte(nil), query[:questionEnd]...)
	response[2] = 0x81
	response[3] = 0x80
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	queryType := binary.BigEndian.Uint16(query[offset : offset+2])
	// Use the requested family so LookupIP("ip4") and LookupIP("ip6") each
	// receive an unambiguous controlled answer.
	switch queryType {
	case 1:
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 1)
	case 28:
		response = append(response, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16,
			0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	default:
		binary.BigEndian.PutUint16(response[6:8], 0)
	}
	return response, nil
}

func serveDNSUDP(address string) error {
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("listen DNS UDP on %s: %w", address, err)
	}
	defer func() { _ = connection.Close() }()
	buffer := make([]byte, 4096)
	for {
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return fmt.Errorf("read DNS UDP on %s: %w", address, err)
		}
		response, responseErr := dnsResponse(buffer[:length])
		if responseErr != nil {
			// The pinned split-controller conformance suite uses port 53 to
			// test its DNS WFP sublayer with an opaque echo marker. Supporting
			// both forms lets it run before the public managed-DNS test.
			response = append([]byte(nil), buffer[:length]...)
		}
		if _, err := connection.WriteTo(response, peer); err != nil {
			return fmt.Errorf("write DNS UDP on %s: %w", address, err)
		}
	}
}

func serveDNSTCP(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen DNS TCP on %s: %w", address, err)
	}
	defer func() { _ = listener.Close() }()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept DNS TCP on %s: %w", address, err)
		}
		go handleDNSTCP(connection)
	}
}

func handleDNSTCP(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length == 0 || length > 4096 {
		// An opaque conformance marker has no DNS length prefix. Echo the
		// bytes already consumed, then stream the rest of the marker.
		if _, err := connection.Write(prefix[:]); err == nil {
			_, _ = io.Copy(connection, connection)
		}
		return
	}
	query := make([]byte, length)
	if _, err := io.ReadFull(connection, query); err != nil {
		return
	}
	response, err := dnsResponse(query)
	if err != nil || len(response) > 65535 {
		return
	}
	binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
	_, _ = connection.Write(append(prefix[:], response...))
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
