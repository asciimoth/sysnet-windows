// Command tunnelpeer is a controlled endpoint for packet-flow tests.
// It is not a general-purpose network service.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/asciimoth/sysnet-windows/internal/testtunnel"
)

func main() {
	listen := flag.String("listen", ":51900", "UDP listen address")
	flag.Parse()
	if err := serve(*listen); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(address string) error {
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = connection.Close() }()
	fmt.Fprintf(os.Stderr, "tunnelpeer listening on %s\n", connection.LocalAddr())
	return servePacket(connection)
}

func servePacket(connection net.PacketConn) error {
	buffer := make([]byte, 65535)
	for {
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		packet, err := testtunnel.Decode(buffer[:length])
		if err != nil {
			continue
		}
		reply, ok := testtunnel.Reply(packet)
		if !ok {
			continue
		}
		if _, err := connection.WriteTo(testtunnel.Encode(reply), peer); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
}
