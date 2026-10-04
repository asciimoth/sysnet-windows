package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

const (
	maxUDPDatagram = 65535
	maxUDPOOB      = 4096
)

// listenWildcardUDP creates two concrete sockets with one logical port. The
// underlay socket is always pinned. The loopback socket is used only for a
// loopback destination, so it cannot become an external fallback.
func (n *BoundNetwork) listenWildcardUDP(ctx context.Context, caller ControlFunc, family Family, requestedPort int) (gonnect.UDPConn, error) {
	path, err := n.binder.currentPath("listen UDP", family, netip.Addr{})
	if err != nil {
		return nil, err
	}
	control, err := n.binder.Control("listen UDP", family, path.Source, caller)
	if err != nil {
		return nil, err
	}
	underlayLocal := net.JoinHostPort(path.Source.String(), strconv.Itoa(requestedPort))
	underlayPacket, err := (&net.ListenConfig{Control: control}).ListenPacket(ctx, familyNetworkName("udp", family), underlayLocal)
	if err != nil {
		return nil, err
	}
	underlayConn, ok := underlayPacket.(*net.UDPConn)
	if !ok {
		_ = underlayPacket.Close()
		return nil, errors.Join(gonnect.ErrUnsupported, errors.New("listen UDP did not return a UDP connection"))
	}
	port := underlayConn.LocalAddr().(*net.UDPAddr).Port
	loopback := netip.IPv6Loopback()
	unspecified := netip.IPv6Unspecified()
	if family == FamilyIPv4 {
		loopback = netip.MustParseAddr("127.0.0.1")
		unspecified = netip.IPv4Unspecified()
	}
	loopbackLocal := net.JoinHostPort(loopback.String(), strconv.Itoa(port))
	loopbackPacket, err := (&net.ListenConfig{Control: caller}).ListenPacket(ctx, familyNetworkName("udp", family), loopbackLocal)
	if err != nil {
		_ = underlayConn.Close()
		return nil, err
	}
	loopbackConn, ok := loopbackPacket.(*net.UDPConn)
	if !ok {
		_ = loopbackPacket.Close()
		_ = underlayConn.Close()
		return nil, errors.Join(gonnect.ErrUnsupported, errors.New("listen loopback UDP did not return a UDP connection"))
	}
	current, err := n.binder.currentPath("listen UDP", family, netip.Addr{})
	if err != nil || !sameBindingPath(path, current) {
		_ = loopbackConn.Close()
		_ = underlayConn.Close()
		if err != nil {
			return nil, err
		}
		return nil, bindError("listen UDP", family, path, "verify selected path", ErrUnderlayChanged)
	}
	logicalAddr := &net.UDPAddr{IP: unspecified.AsSlice(), Port: port}
	return newWildcardUDPConn(underlayConn, loopbackConn, logicalAddr, func() error {
		currentPath, currentErr := n.binder.currentPath("write UDP", family, netip.Addr{})
		if currentErr != nil {
			return currentErr
		}
		if !sameBindingPath(path, currentPath) {
			return bindError("write UDP", family, path, "verify selected path", ErrUnderlayChanged)
		}
		return nil
	}), nil
}

type udpDatagram struct {
	packet []byte
	oob    []byte
	flags  int
	from   netip.AddrPort
	err    error
}

type wildcardUDPConn struct {
	underlay gonnect.UDPConn
	loopback gonnect.UDPConn
	local    net.Addr
	validate func() error

	startOnce sync.Once
	closeOnce sync.Once
	events    chan udpDatagram
	closed    chan struct{}

	deadlineMu   sync.Mutex
	readDeadline time.Time
	deadlineWake chan struct{}
	closeErr     error
}

func newWildcardUDPConn(underlayConn, loopbackConn gonnect.UDPConn, local net.Addr, validate func() error) *wildcardUDPConn {
	return &wildcardUDPConn{
		underlay: underlayConn, loopback: loopbackConn, local: local, validate: validate,
		events: make(chan udpDatagram, 2), closed: make(chan struct{}), deadlineWake: make(chan struct{}),
	}
}

func (c *wildcardUDPConn) startReaders() {
	c.startOnce.Do(func() {
		go c.pump(c.underlay)
		go c.pump(c.loopback)
	})
}

func (c *wildcardUDPConn) pump(connection gonnect.UDPConn) {
	for {
		packet := make([]byte, maxUDPDatagram)
		oob := make([]byte, maxUDPOOB)
		n, oobn, flags, from, err := connection.ReadMsgUDPAddrPort(packet, oob)
		event := udpDatagram{packet: packet[:n], oob: oob[:oobn], flags: flags, from: from, err: err}
		select {
		case c.events <- event:
		case <-c.closed:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *wildcardUDPConn) readDatagram() (udpDatagram, error) {
	c.startReaders()
	for {
		c.deadlineMu.Lock()
		deadline, wake := c.readDeadline, c.deadlineWake
		c.deadlineMu.Unlock()
		var clock *time.Timer
		var timer <-chan time.Time
		if !deadline.IsZero() {
			duration := time.Until(deadline)
			if duration <= 0 {
				return udpDatagram{}, os.ErrDeadlineExceeded
			}
			clock = time.NewTimer(duration)
			timer = clock.C
		}
		select {
		case event := <-c.events:
			if clock != nil {
				clock.Stop()
			}
			return event, event.err
		case <-timer:
			return udpDatagram{}, os.ErrDeadlineExceeded
		case <-wake:
			if clock != nil {
				clock.Stop()
			}
			continue
		case <-c.closed:
			if clock != nil {
				clock.Stop()
			}
			return udpDatagram{}, net.ErrClosed
		}
	}
}

func (c *wildcardUDPConn) Read(packet []byte) (int, error) {
	event, err := c.readDatagram()
	return copy(packet, event.packet), err
}

func (c *wildcardUDPConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, address, err := c.ReadFromUDP(packet)
	return n, address, err
}

func (c *wildcardUDPConn) ReadFromUDP(packet []byte) (int, *net.UDPAddr, error) {
	event, err := c.readDatagram()
	return copy(packet, event.packet), net.UDPAddrFromAddrPort(event.from), err
}

func (c *wildcardUDPConn) ReadFromUDPAddrPort(packet []byte) (int, netip.AddrPort, error) {
	event, err := c.readDatagram()
	return copy(packet, event.packet), event.from, err
}

func (c *wildcardUDPConn) ReadMsgUDP(packet, oob []byte) (int, int, int, *net.UDPAddr, error) {
	event, err := c.readDatagram()
	return copy(packet, event.packet), copy(oob, event.oob), event.flags, net.UDPAddrFromAddrPort(event.from), err
}

func (c *wildcardUDPConn) ReadMsgUDPAddrPort(packet, oob []byte) (int, int, int, netip.AddrPort, error) {
	event, err := c.readDatagram()
	return copy(packet, event.packet), copy(oob, event.oob), event.flags, event.from, err
}

func (c *wildcardUDPConn) Write(packet []byte) (int, error) { return c.underlay.Write(packet) }

func (c *wildcardUDPConn) WriteTo(packet []byte, destination net.Addr) (int, error) {
	if err := validatePacketDestination(destination); err != nil {
		return 0, err
	}
	if udp, ok := destination.(*net.UDPAddr); ok && udp != nil && udp.IP.IsLoopback() {
		return c.loopback.WriteTo(packet, destination)
	}
	if err := c.validateExternal(); err != nil {
		return 0, err
	}
	return c.underlay.WriteTo(packet, destination)
}

func (c *wildcardUDPConn) WriteToUDP(packet []byte, destination *net.UDPAddr) (int, error) {
	if err := validatePacketDestination(destination); err != nil {
		return 0, err
	}
	if destination != nil && destination.IP.IsLoopback() {
		return c.loopback.WriteToUDP(packet, destination)
	}
	if err := c.validateExternal(); err != nil {
		return 0, err
	}
	return c.underlay.WriteToUDP(packet, destination)
}

func (c *wildcardUDPConn) WriteToUDPAddrPort(packet []byte, destination netip.AddrPort) (int, error) {
	if err := validatePacketAddrPort(destination); err != nil {
		return 0, err
	}
	if destination.Addr().IsLoopback() {
		return c.loopback.WriteToUDPAddrPort(packet, destination)
	}
	if err := c.validateExternal(); err != nil {
		return 0, err
	}
	return c.underlay.WriteToUDPAddrPort(packet, destination)
}

func (c *wildcardUDPConn) WriteMsgUDP(packet, oob []byte, destination *net.UDPAddr) (int, int, error) {
	if err := validatePacketDestination(destination); err != nil {
		return 0, 0, err
	}
	if destination != nil && destination.IP.IsLoopback() {
		return c.loopback.WriteMsgUDP(packet, oob, destination)
	}
	if err := c.validateExternal(); err != nil {
		return 0, 0, err
	}
	return c.underlay.WriteMsgUDP(packet, oob, destination)
}

func (c *wildcardUDPConn) WriteMsgUDPAddrPort(packet, oob []byte, destination netip.AddrPort) (int, int, error) {
	if err := validatePacketAddrPort(destination); err != nil {
		return 0, 0, err
	}
	if destination.Addr().IsLoopback() {
		return c.loopback.WriteMsgUDPAddrPort(packet, oob, destination)
	}
	if err := c.validateExternal(); err != nil {
		return 0, 0, err
	}
	return c.underlay.WriteMsgUDPAddrPort(packet, oob, destination)
}

func (c *wildcardUDPConn) validateExternal() error {
	if c.validate == nil {
		return nil
	}
	return c.validate()
}

func (c *wildcardUDPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.closeErr = errors.Join(c.underlay.Close(), c.loopback.Close())
		c.signalDeadlineChange()
	})
	return c.closeErr
}

func (c *wildcardUDPConn) LocalAddr() net.Addr  { return c.local }
func (c *wildcardUDPConn) RemoteAddr() net.Addr { return nil }

func (c *wildcardUDPConn) SetDeadline(deadline time.Time) error {
	c.setReadDeadline(deadline)
	return errors.Join(c.underlay.SetWriteDeadline(deadline), c.loopback.SetWriteDeadline(deadline))
}

func (c *wildcardUDPConn) SetReadDeadline(deadline time.Time) error {
	c.setReadDeadline(deadline)
	return nil
}

func (c *wildcardUDPConn) setReadDeadline(deadline time.Time) {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	close(c.deadlineWake)
	c.deadlineWake = make(chan struct{})
	c.deadlineMu.Unlock()
}

func (c *wildcardUDPConn) signalDeadlineChange() {
	c.deadlineMu.Lock()
	close(c.deadlineWake)
	c.deadlineWake = make(chan struct{})
	c.deadlineMu.Unlock()
}

func (c *wildcardUDPConn) SetWriteDeadline(deadline time.Time) error {
	return errors.Join(c.underlay.SetWriteDeadline(deadline), c.loopback.SetWriteDeadline(deadline))
}

var _ gonnect.UDPConn = (*wildcardUDPConn)(nil)
