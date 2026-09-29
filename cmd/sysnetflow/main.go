//go:build windows

// Command sysnetflow exercises the public OutNet API in the isolated Windows
// packet-flow topology. It is a test helper, not a general-purpose client.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/asciimoth/gonnect"
	windows "github.com/asciimoth/sysnet-windows"
)

const (
	underlayIPv4 = "198.18.1.2"
	remoteIPv4   = "203.0.113.1:47823"
	remoteIPv6   = "[2001:db8:ffff::1]:47823"
)

type observation struct {
	Case         string `json:"case"`
	Token        string `json:"token"`
	ExpectedPath string `json:"expectedPath"`
	Operation    string `json:"operation"`
}

func main() {
	output := flag.String("output", "", "JSON-lines observation output")
	flag.Parse()
	if *output == "" {
		fatal(errors.New("output path is required"))
	}
	selector, err := interfaceWithAddress(net.ParseIP(underlayIPv4))
	if err != nil {
		fatal(err)
	}
	system, err := windows.New(windows.SystemConfig{UnderlaySelector: selector})
	if err != nil {
		fatal(fmt.Errorf("create System: %w", err))
	}
	defer func() {
		if err := system.Close(); err != nil {
			fatal(fmt.Errorf("close System: %w", err))
		}
	}()
	file, err := os.Create(*output)
	if err != nil {
		fatal(fmt.Errorf("create observations: %w", err))
	}
	writer := bufio.NewWriter(file)
	for _, current := range flowCases() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := current.run(ctx, system.OutNet(), []byte(current.observation.Token))
		cancel()
		if err != nil {
			_ = file.Close()
			fatal(fmt.Errorf("%s: %w", current.observation.Operation, err))
		}
		if err := json.NewEncoder(writer).Encode(current.observation); err != nil {
			_ = file.Close()
			fatal(fmt.Errorf("write observation: %w", err))
		}
	}
	if err := errors.Join(writer.Flush(), file.Close()); err != nil {
		fatal(fmt.Errorf("finish observations: %w", err))
	}
}

type flowCase struct {
	observation observation
	run         func(context.Context, gonnect.Network, []byte) error
}

func flowCases() []flowCase {
	return []flowCase{
		{observation{"N01-outnet-tcp4-underlay", "SNW_N01_GENERIC_TCP4", "underlay", "Dial tcp4"}, dial("tcp4", remoteIPv4)},
		{observation{"N01-outnet-tcp4-underlay", "SNW_N01_TYPED_TCP4", "underlay", "DialTCP tcp4"}, dialTCP("tcp4", remoteIPv4)},
		{observation{"N02-outnet-tcp6-underlay", "SNW_N02_GENERIC_TCP6", "underlay", "Dial tcp6"}, dial("tcp6", remoteIPv6)},
		{observation{"N02-outnet-tcp6-underlay", "SNW_N02_TYPED_TCP6", "underlay", "DialTCP tcp6"}, dialTCP("tcp6", remoteIPv6)},
		{observation{"N03-outnet-udp4-underlay", "SNW_N03_GENERIC_UDP4", "underlay", "Dial udp4"}, dial("udp4", remoteIPv4)},
		{observation{"N03-outnet-udp4-underlay", "SNW_N03_TYPED_UDP4", "underlay", "DialUDP udp4"}, dialUDP("udp4", remoteIPv4)},
		{observation{"N04-outnet-udp6-underlay", "SNW_N04_GENERIC_UDP6", "underlay", "Dial udp6"}, dial("udp6", remoteIPv6)},
		{observation{"N04-outnet-udp6-underlay", "SNW_N04_TYPED_UDP6", "underlay", "DialUDP udp6"}, dialUDP("udp6", remoteIPv6)},
		{observation{"N05-outnet-packet-dial", "SNW_N05_PACKET_DIAL4", "underlay", "PacketDial udp4"}, packetDial("udp4", remoteIPv4)},
		{observation{"N06-outnet-listen-packet", "SNW_N06_LISTEN_PACKET4", "underlay", "ListenPacket udp4"}, listenPacket("udp4", "0.0.0.0:0", remoteIPv4, false)},
		{observation{"N07-outnet-listen-udp", "SNW_N07_LISTEN_UDP6", "underlay", "ListenUDP udp6"}, listenPacket("udp6", "[::]:0", remoteIPv6, true)},
		{observation{"N08-outnet-configured-udp", "SNW_N08_CONFIG_UDP4", "underlay", "ListenUDPConfig udp4"}, listenConfiguredUDP("udp4", "0.0.0.0:0", remoteIPv4)},
	}
}

func dial(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.Dial(ctx, network, address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func dialTCP(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.DialTCP(ctx, network, "", address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func dialUDP(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.DialUDP(ctx, network, "", address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func packetDial(network, address string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.PacketDial(ctx, network, address)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoConnected(connection, token)
	}
}

func listenPacket(network, local, remote string, typed bool) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		var connection gonnect.PacketConn
		var err error
		if typed {
			var udp gonnect.UDPConn
			udp, err = out.ListenUDP(ctx, network, local)
			connection = udp
		} else {
			connection, err = out.ListenPacket(ctx, network, local)
		}
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoPacket(connection, remote, token)
	}
}

func listenConfiguredUDP(network, local, remote string) func(context.Context, gonnect.Network, []byte) error {
	return func(ctx context.Context, out gonnect.Network, token []byte) error {
		connection, err := out.ListenUDPConfig(ctx, &gonnect.ListenConfig{}, network, local)
		if err != nil {
			return err
		}
		defer func() { _ = connection.Close() }()
		return echoPacket(connection, remote, token)
	}
}

func echoConnected(connection net.Conn, token []byte) error {
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.Write(token); err != nil {
		return err
	}
	reply := make([]byte, len(token))
	if _, err := io.ReadFull(connection, reply); err != nil {
		return err
	}
	if string(reply) != string(token) {
		return errors.New("echo reply does not match token")
	}
	return nil
}

func echoPacket(connection net.PacketConn, remote string, token []byte) error {
	destination, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return err
	}
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.WriteTo(token, destination); err != nil {
		return err
	}
	reply := make([]byte, len(token))
	length, _, err := connection.ReadFrom(reply)
	if err != nil {
		return err
	}
	if string(reply[:length]) != string(token) {
		return errors.New("echo reply does not match token")
	}
	return nil
}

func interfaceWithAddress(want net.IP) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		addresses, addrErr := iface.Addrs()
		if addrErr != nil {
			return "", addrErr
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.Equal(want) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("interface with address %s not found", want)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
