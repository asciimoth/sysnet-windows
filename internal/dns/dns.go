// Package dns defines the Windows resolver-configuration boundary.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	gonnectdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
)

// State records resolver mode and server values for exact restoration.
type State struct {
	AutomaticIPv4 bool
	AutomaticIPv6 bool
	Servers       []netip.Addr
}

// Configurator changes resolver state for one interface.
type Configurator interface {
	Read(context.Context, uint64) (State, error)
	Apply(context.Context, uint64, State) error
}

// CloneState returns a state value which does not share its server slice with
// the input. DNS state is retained in a recovery journal and must stay stable
// when a native reader reuses its storage.
func CloneState(state State) State {
	state.Servers = append([]netip.Addr(nil), state.Servers...)
	return state
}

// EqualState reports semantic equality. Server order is significant because
// Windows uses it as resolver preference order.
func EqualState(left, right State) bool {
	return left.AutomaticIPv4 == right.AutomaticIPv4 &&
		left.AutomaticIPv6 == right.AutomaticIPv6 &&
		slices.Equal(familyServers(left.Servers, true), familyServers(right.Servers, true)) &&
		slices.Equal(familyServers(left.Servers, false), familyServers(right.Servers, false))
}

func familyServers(servers []netip.Addr, ipv4 bool) []netip.Addr {
	result := make([]netip.Addr, 0, len(servers))
	for _, server := range servers {
		if server.Is4() == ipv4 {
			result = append(result, server)
		}
	}
	return result
}

// ValidateState rejects values which cannot be restored without changing
// their meaning. Automatic state carries observed effective servers for
// upstream discovery, but Apply restores the automatic mode instead of those
// values.
func ValidateState(state State) error {
	for _, server := range state.Servers {
		if !server.IsValid() || server.IsUnspecified() || server.Zone() != "" || server.Is4In6() {
			return errors.New("DNS state contains an invalid server address")
		}
	}
	if !state.AutomaticIPv4 && !hasServerFamily(state.Servers, true) {
		return errors.New("static IPv4 DNS state has no IPv4 server")
	}
	if !state.AutomaticIPv6 && !hasServerFamily(state.Servers, false) {
		return errors.New("static IPv6 DNS state has no IPv6 server")
	}
	return nil
}

func hasServerFamily(servers []netip.Addr, ipv4 bool) bool {
	for _, server := range servers {
		if server.Is4() == ipv4 {
			return true
		}
	}
	return false
}

// WithProxy returns the full interface state which keeps the other address
// family's DNS mode and values and makes proxy the only static server for its
// own family.
func WithProxy(prior State, proxy netip.Addr) State {
	result := CloneState(prior)
	result.Servers = slices.DeleteFunc(result.Servers, func(server netip.Addr) bool {
		return server.Is4() == proxy.Is4()
	})
	result.Servers = append(result.Servers, proxy)
	if proxy.Is4() {
		result.AutomaticIPv4 = false
	} else {
		result.AutomaticIPv6 = false
	}
	return result
}

// UpstreamProvider discovers numeric DNS endpoints from the currently selected
// underlays for every request. It never uses the host resolver, which prevents
// recursion after the managed proxy becomes the Windows resolver.
type UpstreamProvider struct {
	paths        interface{ Snapshot() underlay.Snapshot }
	configurator Configurator
	dial         gonnect.Dial
	timeout      time.Duration
	requests     chan gonnectdns.Request
	done         chan struct{}
	limit        chan struct{}

	mu       sync.RWMutex
	excluded map[netip.Addr]struct{}
	close    sync.Once
	workers  sync.WaitGroup
}

// NewUpstreamProvider creates an ownership-aware outbound DNS transport. A nil
// configurator is accepted so systems without the native API fail individual
// queries with a useful error instead of using an unrestricted resolver.
func NewUpstreamProvider(
	paths interface{ Snapshot() underlay.Snapshot },
	configurator Configurator,
	dial gonnect.Dial,
	timeout time.Duration,
) (*UpstreamProvider, error) {
	if paths == nil || dial == nil {
		return nil, errors.New("create outbound DNS without underlay policy")
	}
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	p := &UpstreamProvider{
		paths: paths, configurator: configurator, dial: dial, timeout: timeout,
		requests: make(chan gonnectdns.Request), done: make(chan struct{}),
		limit:    make(chan struct{}, maxConcurrentRequests),
		excluded: make(map[netip.Addr]struct{}),
	}
	p.workers.Add(1)
	go p.run()
	return p, nil
}

func (p *UpstreamProvider) Requests() chan<- gonnectdns.Request { return p.requests }

// SetExcluded replaces the managed proxy addresses which must not become
// upstreams. It is safe to call while queries are active.
func (p *UpstreamProvider) SetExcluded(addresses ...netip.Addr) {
	next := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if address.IsValid() {
			next[address.Unmap()] = struct{}{}
		}
	}
	p.mu.Lock()
	p.excluded = next
	p.mu.Unlock()
}

func (p *UpstreamProvider) Close() error {
	p.close.Do(func() { close(p.done) })
	p.workers.Wait()
	return nil
}

func (p *UpstreamProvider) run() {
	defer p.workers.Done()
	for {
		select {
		case <-p.done:
			return
		case request := <-p.requests:
			select {
			case p.limit <- struct{}{}:
			case <-p.done:
				return
			}
			p.workers.Add(1)
			go p.query(request)
		}
	}
}

func (p *UpstreamProvider) query(request gonnectdns.Request) {
	defer p.workers.Done()
	defer func() { <-p.limit }()
	ctx := request.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	servers, err := p.upstreams(ctx)
	if err != nil {
		replyDNS(request, nil, err)
		return
	}
	client := gonnectdns.NewClientWithOptions(p.dial, nil, nil,
		gonnectdns.ClientOptions{RequestTimeout: p.timeout}, serverURLs(servers)...)
	response, err := gonnectdns.Query(ctx, client, request.Message)
	closeErr := client.Close()
	replyDNS(request, response, errors.Join(err, closeErr))
}

func (p *UpstreamProvider) upstreams(ctx context.Context) ([]netip.Addr, error) {
	if p.configurator == nil {
		return nil, errors.New("windows DNS configurator is not available")
	}
	snapshot := p.paths.Snapshot()
	luidSeen := make(map[uint64]struct{}, 2)
	result := make([]netip.Addr, 0, 4)
	for _, path := range []*underlay.Path{snapshot.IPv4, snapshot.IPv6} {
		if path == nil {
			continue
		}
		if _, found := luidSeen[path.InterfaceLUID]; found {
			continue
		}
		luidSeen[path.InterfaceLUID] = struct{}{}
		state, err := p.configurator.Read(ctx, path.InterfaceLUID)
		if err != nil {
			return nil, errors.Join(errors.New("read underlay DNS state"), err)
		}
		for _, server := range state.Servers {
			server = server.Unmap()
			if !p.allowed(server) || slices.Contains(result, server) {
				continue
			}
			result = append(result, server)
		}
	}
	if len(result) == 0 {
		return nil, gonnectdns.ErrNoUpstream
	}
	return result, nil
}

func (p *UpstreamProvider) allowed(server netip.Addr) bool {
	if !server.IsValid() || server.IsUnspecified() || server.Zone() != "" || server.Is4In6() {
		return false
	}
	p.mu.RLock()
	_, excluded := p.excluded[server]
	p.mu.RUnlock()
	return !excluded
}

func serverURLs(servers []netip.Addr) []string {
	result := make([]string, 0, len(servers))
	for _, server := range servers {
		result = append(result, "udp://"+net.JoinHostPort(server.String(), "53"))
	}
	return result
}

func replyDNS(request gonnectdns.Request, message *gonnectdns.Message, err error) {
	ctx := request.Context
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case request.Reply <- gonnectdns.Response{Message: message, Err: err}:
	case <-ctx.Done():
	}
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
