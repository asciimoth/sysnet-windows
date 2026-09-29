// Package dns defines the Windows resolver-configuration boundary.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	gonnectdns "github.com/asciimoth/gonnect/dns"
)

// State records resolver mode and server values for exact restoration.
type State struct {
	DHCP    bool
	Servers []netip.Addr
}

// Configurator changes resolver state for one interface.
type Configurator interface {
	Read(context.Context, uint64) (State, error)
	Apply(context.Context, uint64, State) error
}

const (
	defaultRequestTimeout = 5 * time.Second
	maxDNSMessageSize     = 1<<16 - 1
	maxConcurrentRequests = 256
)

// ProxyFactory binds the private UDP and TCP listeners for a managed DNS
// proxy. Keeping this boundary injectable lets portable tests verify the DNS
// lifecycle without assigning the requested TUN address to the test host.
type ProxyFactory interface {
	Create(netip.Addr, time.Duration) (ManagedProxy, error)
}

// ManagedProxy is the part of Proxy used by the default-TUN transaction.
// Providers are caller-owned: Attach never closes the old or new provider.
type ManagedProxy interface {
	Attach(gonnectdns.Interface)
	Close() error
	Closed() bool
}

// NativeProxyFactory binds UDP and TCP port 53 on one numeric address.
type NativeProxyFactory struct{}

func (NativeProxyFactory) Create(address netip.Addr, timeout time.Duration) (ManagedProxy, error) {
	if !address.IsValid() || address.IsUnspecified() {
		return nil, errors.New("dns proxy address is not valid")
	}
	endpoint := net.JoinHostPort(address.String(), "53")
	packet, err := net.ListenPacket("udp", endpoint)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		return nil, errors.Join(err, packet.Close())
	}
	return NewProxy(packet, listener, timeout), nil
}

// Proxy serves DNS wire requests on pre-bound UDP and TCP listeners. Attach
// changes the provider generation atomically and cancels requests that still
// use the prior generation. A nil provider intentionally drops requests.
type Proxy struct {
	packet   net.PacketConn
	listener net.Listener
	timeout  time.Duration
	root     context.Context
	cancel   context.CancelFunc
	limit    chan struct{}

	providerMu sync.RWMutex
	provider   gonnectdns.Interface
	generation chan struct{}

	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	workers       sync.WaitGroup
	closeOnce     sync.Once
	closed        chan struct{}
	closeErr      error
}

// NewProxy starts a proxy on packet and listener. Both listeners must already
// be bound to the same address and port. A nonpositive timeout selects five
// seconds.
func NewProxy(packet net.PacketConn, listener net.Listener, timeout time.Duration) *Proxy {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	root, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		packet: packet, listener: listener, timeout: timeout, root: root, cancel: cancel,
		limit: make(chan struct{}, maxConcurrentRequests), generation: make(chan struct{}),
		connections: make(map[net.Conn]struct{}), closed: make(chan struct{}),
	}
	p.workers.Add(2)
	go p.serveUDP()
	go p.serveTCP()
	return p
}

// Attach installs provider for new requests. It also cancels requests that
// took their provider snapshot before this call.
func (p *Proxy) Attach(provider gonnectdns.Interface) {
	if p == nil {
		return
	}
	p.providerMu.Lock()
	select {
	case <-p.root.Done():
		p.providerMu.Unlock()
		return
	default:
	}
	close(p.generation)
	p.provider = provider
	p.generation = make(chan struct{})
	p.providerMu.Unlock()
}

// Closed reports whether shutdown has completed.
func (p *Proxy) Closed() bool {
	if p == nil {
		return true
	}
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

// Close stops intake, interrupts active connections and requests, and waits
// until no proxy worker can access its provider state.
func (p *Proxy) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.cancel()
		p.closeErr = errors.Join(p.packet.Close(), p.listener.Close())
		p.connectionsMu.Lock()
		for connection := range p.connections {
			// Closing accepted connections is the cancellation mechanism. A peer
			// can close concurrently, so its close result is not a proxy cleanup
			// failure.
			_ = connection.Close()
		}
		p.connectionsMu.Unlock()
		p.providerMu.Lock()
		close(p.generation)
		p.provider = nil
		p.providerMu.Unlock()
		p.workers.Wait()
		close(p.closed)
	})
	if !p.Closed() {
		<-p.closed
	}
	return p.closeErr
}

func (p *Proxy) serveUDP() {
	defer p.workers.Done()
	buffer := make([]byte, maxDNSMessageSize)
	for {
		count, address, err := p.packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		request := append([]byte(nil), buffer[:count]...)
		if !p.acquire() {
			return
		}
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			defer p.release()
			response, generation, ok := p.forward(request)
			if ok {
				p.writeCurrent(generation, func() error {
					_, err := p.packet.WriteTo(response, address)
					return err
				})
			}
		}()
	}
}

func (p *Proxy) serveTCP() {
	defer p.workers.Done()
	for {
		connection, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.connectionsMu.Lock()
		select {
		case <-p.root.Done():
			p.connectionsMu.Unlock()
			_ = connection.Close()
			return
		default:
		}
		p.connections[connection] = struct{}{}
		p.connectionsMu.Unlock()
		p.workers.Add(1)
		go p.serveTCPConnection(connection)
	}
}

func (p *Proxy) serveTCPConnection(connection net.Conn) {
	defer p.workers.Done()
	defer func() {
		_ = connection.Close()
		p.connectionsMu.Lock()
		delete(p.connections, connection)
		p.connectionsMu.Unlock()
	}()
	var sizeBytes [2]byte
	for {
		_ = connection.SetDeadline(time.Now().Add(p.timeout))
		if _, err := io.ReadFull(connection, sizeBytes[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(sizeBytes[:]))
		if size == 0 {
			return
		}
		request := make([]byte, size)
		if _, err := io.ReadFull(connection, request); err != nil {
			return
		}
		if !p.acquire() {
			return
		}
		response, generation, ok := p.forward(request)
		p.release()
		if !ok {
			return
		}
		if !p.writeCurrent(generation, func() error {
			binary.BigEndian.PutUint16(sizeBytes[:], uint16(len(response)))
			if _, err := connection.Write(sizeBytes[:]); err != nil {
				return err
			}
			_, err := connection.Write(response)
			return err
		}) {
			return
		}
	}
}

func (p *Proxy) acquire() bool {
	select {
	case p.limit <- struct{}{}:
		return true
	case <-p.root.Done():
		return false
	}
}

func (p *Proxy) release() { <-p.limit }

func (p *Proxy) current() (gonnectdns.Interface, <-chan struct{}) {
	p.providerMu.RLock()
	defer p.providerMu.RUnlock()
	return p.provider, p.generation
}

func (p *Proxy) writeCurrent(generation <-chan struct{}, write func() error) bool {
	p.providerMu.RLock()
	defer p.providerMu.RUnlock()
	if generation != p.generation || p.provider == nil {
		return false
	}
	select {
	case <-p.root.Done():
		return false
	default:
	}
	return write() == nil
}

func (p *Proxy) forward(packet []byte) ([]byte, <-chan struct{}, bool) {
	request, err := gonnectdns.Unpack(packet)
	if err != nil {
		return nil, nil, false
	}
	provider, generation := p.current()
	if provider == nil {
		return nil, nil, false
	}
	clientID := request.ID
	request.ID = gonnectdns.NextID()
	ctx, cancel := context.WithTimeout(p.root, p.timeout)
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-generation:
			cancel()
		case <-watchDone:
		}
	}()
	response, queryErr := gonnectdns.Query(ctx, provider, request)
	close(watchDone)
	cancel()
	if queryErr != nil {
		if errors.Is(queryErr, context.Canceled) || errors.Is(queryErr, net.ErrClosed) {
			return nil, nil, false
		}
		response = &gonnectdns.Message{
			ID: clientID, Response: true, Opcode: request.Opcode,
			RCode: gonnectdns.RCodeServerFailure, Questions: append([]gonnectdns.Question(nil), request.Questions...),
		}
	} else if response == nil {
		return nil, nil, false
	}
	response = response.Copy()
	response.ID = clientID
	wire, err := gonnectdns.Pack(response)
	return wire, generation, err == nil
}

var _ ManagedProxy = (*Proxy)(nil)
