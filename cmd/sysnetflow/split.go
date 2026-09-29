//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
	windows "github.com/asciimoth/sysnet-windows"
)

type processRequest struct {
	Operation string `json:"operation"`
	Network   string `json:"network,omitempty"`
	Address   string `json:"address,omitempty"`
	Token     string `json:"token,omitempty"`
}

type processResponse struct {
	PID       int    `json:"pid"`
	LocalAddr string `json:"localAddr,omitempty"`
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
}

type flowProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

func runProcessHelper(mode, child string) error {
	if mode == "descendant" {
		if child == "" {
			return errors.New("descendant helper executable is required")
		}
		command := exec.Command(child, "-helper", "client")
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		return command.Run()
	}
	if mode != "client" {
		return fmt.Errorf("unknown helper mode %q", mode)
	}
	return serveProcessRequests(os.Stdin, os.Stdout)
}

func serveProcessRequests(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(input)
	encoder := json.NewEncoder(output)
	var ipc net.Listener
	defer func() {
		if ipc != nil {
			_ = ipc.Close()
		}
	}()
	for {
		var request processRequest
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode helper request: %w", err)
		}
		response := processResponse{PID: os.Getpid()}
		var err error
		switch request.Operation {
		case "pid":
		case "once":
			response.LocalAddr, err = processExchange(request.Network, request.Address, request.Token)
		case "dns":
			response.LocalAddr, err = dnsExchange(request.Network, request.Address, request.Token)
		case "lookup":
			var addresses []net.IP
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			addresses, err = net.DefaultResolver.LookupIP(ctx, request.Network, request.Token+".sysnet-flow.test")
			cancel()
			values := make([]string, 0, len(addresses))
			for _, address := range addresses {
				values = append(values, address.String())
			}
			response.Value = strings.Join(values, ",")
		case "serve-ipc":
			ipc, err = net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				response.Value = ipc.Addr().String()
				go serveIPC(ipc)
			}
		case "ipc":
			response.LocalAddr, err = ipcExchange(request.Address, request.Network, request.Token)
		default:
			err = fmt.Errorf("unknown helper operation %q", request.Operation)
		}
		if err != nil {
			response.Error = err.Error()
		}
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("encode helper response: %w", err)
		}
	}
}

func processExchange(network, address, token string) (string, error) {
	connection, err := net.DialTimeout(network, address, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = connection.Close() }()
	if err := echoConnected(connection, []byte(token)); err != nil {
		return "", err
	}
	return connection.LocalAddr().String(), nil
}

func dnsExchange(network, address, token string) (string, error) {
	query, err := dnsQuery(token + ".sysnet-flow.test")
	if err != nil {
		return "", err
	}
	connection, err := net.DialTimeout(network, address, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", err
	}
	if _, err := connection.Write(query); err != nil {
		return "", err
	}
	response := make([]byte, 2048)
	length, err := connection.Read(response)
	if err != nil {
		return "", err
	}
	if length < 12 || binary.BigEndian.Uint16(response[:2]) != binary.BigEndian.Uint16(query[:2]) || response[2]&0x80 == 0 {
		return "", errors.New("DNS endpoint returned an invalid response")
	}
	return connection.LocalAddr().String(), nil
}

func dnsQuery(name string) ([]byte, error) {
	result := make([]byte, 12)
	binary.BigEndian.PutUint16(result[:2], 0x7357)
	binary.BigEndian.PutUint16(result[2:4], 0x0100)
	binary.BigEndian.PutUint16(result[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, errors.New("DNS label is invalid")
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	result = append(result, 0, 0, 1, 0, 1)
	return result, nil
}

func serveIPC(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = connection.Close() }()
			var request processRequest
			response := processResponse{PID: os.Getpid()}
			if err := json.NewDecoder(connection).Decode(&request); err == nil {
				response.LocalAddr, err = processExchange(request.Network, request.Address, request.Token)
				if err != nil {
					response.Error = err.Error()
				}
			} else {
				response.Error = err.Error()
			}
			_ = json.NewEncoder(connection).Encode(response)
		}()
	}
}

func ipcExchange(address, network, token string) (string, error) {
	connection, err := net.DialTimeout("tcp4", address, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", err
	}
	if err := json.NewEncoder(connection).Encode(processRequest{
		Operation: "once", Network: network, Address: flowRemote(network), Token: token,
	}); err != nil {
		return "", err
	}
	var response processResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return "", err
	}
	if response.Error != "" {
		return "", errors.New(response.Error)
	}
	return response.LocalAddr, nil
}

func flowRemote(network string) string {
	if strings.HasSuffix(network, "4") {
		return remoteIPv4
	}
	return remoteIPv6
}

func startFlowProcess(executable, mode, child string) (*flowProcess, error) {
	arguments := []string{"-helper", mode}
	if child != "" {
		arguments = append(arguments, "-child", child)
	}
	command := exec.Command(executable, arguments...)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &flowProcess{command: command, input: input, output: bufio.NewScanner(output)}
	response, err := process.request(processRequest{Operation: "pid"})
	if err != nil || response.PID == 0 {
		process.close()
		return nil, errors.Join(errors.New("flow helper did not report its PID"), err)
	}
	return process, nil
}

func (p *flowProcess) request(request processRequest) (processResponse, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return processResponse{}, err
	}
	if _, err := p.input.Write(append(data, '\n')); err != nil {
		return processResponse{}, err
	}
	if !p.output.Scan() {
		return processResponse{}, errors.Join(errors.New("flow helper exited without a response"), p.output.Err())
	}
	var response processResponse
	if err := json.Unmarshal(p.output.Bytes(), &response); err != nil {
		return processResponse{}, err
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func (p *flowProcess) close() {
	if p == nil {
		return
	}
	_ = p.input.Close()
	_ = p.command.Process.Kill()
	_ = p.command.Wait()
}

type splitFlow struct {
	file      *os.File
	writer    *bufio.Writer
	sequence  atomic.Uint64
	processes map[string]*flowProcess
	ipcAddr   string
	profile   string
}

func runSplit(output string) (result error) {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "sysnet-split-flow-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	paths := make(map[string]string)
	for _, role := range []string{"included", "excluded", "parent", "descendant", "ipc-target"} {
		roleDirectory := filepath.Join(directory, role)
		if err := os.Mkdir(roleDirectory, 0o700); err != nil {
			return err
		}
		path := filepath.Join(roleDirectory, role+".exe")
		if err := copyExecutable(executable, path); err != nil {
			return err
		}
		paths[role] = path
	}

	file, err := os.Create(output)
	if err != nil {
		return err
	}
	h := &splitFlow{file: file, writer: bufio.NewWriter(file)}
	defer h.close()
	for _, profile := range []struct {
		name      string
		addresses []string
		dnsIP     string
		networks  []string
	}{
		{name: "ipv4", addresses: []string{"10.77.0.2/24"}, dnsIP: "10.77.0.2", networks: []string{"tcp4", "udp4"}},
		{name: "ipv6", addresses: []string{"fd77::2/64"}, dnsIP: "fd77::2", networks: []string{"tcp6", "udp6"}},
		{name: "dual", addresses: []string{"10.77.0.2/24", "fd77::2/64"}, dnsIP: "10.77.0.2", networks: []string{"tcp4", "udp4", "tcp6", "udp6"}},
	} {
		if err := h.runProfile(paths, profile.name, profile.addresses, profile.dnsIP, profile.networks); err != nil {
			return err
		}
	}
	return h.flush()
}

func (h *splitFlow) runProfile(paths map[string]string, profile string, addresses []string, dnsIP string, networks []string) (result error) {
	h.profile = profile
	h.processes = make(map[string]*flowProcess)
	defer h.closeProcesses()

	// Start the IPC target before System construction and split-driver process
	// registration. It must keep its own included classification when an
	// excluded process later asks it to create a connection.
	var err error
	h.processes["ipc-target"], err = startFlowProcess(paths["ipc-target"], "client", "")
	if err != nil {
		return err
	}
	ipcResponse, err := h.processes["ipc-target"].request(processRequest{Operation: "serve-ipc"})
	if err != nil || ipcResponse.Value == "" {
		return errors.Join(errors.New("start pre-existing IPC target"), err)
	}
	h.ipcAddr = ipcResponse.Value

	selector, _, err := interfaceWithAddress(net.ParseIP(underlayIPv4))
	if err != nil {
		return err
	}
	system, err := windows.New(windows.SystemConfig{UnderlaySelector: selector})
	if err != nil {
		return fmt.Errorf("create System for %s profile: %w", profile, err)
	}
	defer func() { result = errors.Join(result, system.Close()) }()
	var defaultDevice sysnet.DefaultTun
	pump, err := startTestTunnelWith(system, func() (tun.Tun, error) {
		// Add an exact service route for each advertised family. The Wintun
		// route is preferred for included processes. The split driver moves an
		// excluded flow to the equal-prefix route on the underlay interface.
		// This is also the route model used by the pinned controller's packet
		// conformance fixture.
		var routes []string
		for _, address := range addresses {
			if strings.Contains(address, ":") {
				routes = append(routes, "2001:db8:ffff::1/128")
			} else {
				routes = append(routes, "203.0.113.1/32")
			}
		}
		device, buildErr := system.BuildDefaultTun(sysnet.DefaultTunOpts{
			TunAddrs:  addresses,
			TunRoutes: routes,
			DnsIP:     dnsIP,
			Exclude: []sysnet.Rule{
				{Type: "win-exe-tree", Rule: paths["excluded"]},
				{Type: "win-exe-tree", Rule: paths["parent"]},
			},
		})
		defaultDevice = device
		return device, buildErr
	})
	if err != nil {
		return fmt.Errorf("build public default TUN for %s profile: %w", profile, err)
	}
	defer func() { result = errors.Join(result, pump.Close()) }()
	if err := defaultDevice.SetDNS(system.OutDNS()); err != nil {
		return fmt.Errorf("attach public OutDNS provider for %s profile: %w", profile, err)
	}

	for role, spec := range map[string]struct{ executable, mode, child string }{
		"included":   {paths["included"], "client", ""},
		"excluded":   {paths["excluded"], "client", ""},
		"descendant": {paths["parent"], "descendant", paths["descendant"]},
	} {
		h.processes[role], err = startFlowProcess(spec.executable, spec.mode, spec.child)
		if err != nil {
			return fmt.Errorf("start %s process for %s profile: %w", role, profile, err)
		}
	}
	warmupNetwork := "tcp4"
	if profile == "ipv6" {
		warmupNetwork = "tcp6"
	}
	for role, path := range map[string]string{
		"included": "tunnel", "excluded": "underlay", "descendant": "underlay", "ipc-target": "tunnel",
	} {
		if err := h.waitProcessPath(role, path, warmupNetwork); err != nil {
			return err
		}
	}
	for _, network := range networks {
		if err := h.assertPath("included", network, "tunnel", "included process", ""); err != nil {
			return err
		}
		if err := h.assertPath("excluded", network, "underlay", "excluded process", ""); err != nil {
			return err
		}
		if err := h.assertPath("descendant", network, "underlay", "new excluded descendant", ""); err != nil {
			return err
		}
		if err := h.assertPath("ipc", network, "tunnel", "pre-existing IPC target", h.ipcAddr); err != nil {
			return err
		}
	}
	for _, network := range networks {
		if strings.HasPrefix(network, "udp") {
			if err := h.assertDNSPath(network, false); err != nil {
				return err
			}
		}
	}
	for _, network := range networks {
		if strings.HasPrefix(network, "tcp") {
			if err := h.assertDNSPath(strings.Replace(network, "tcp", "ip", 1), true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *splitFlow) waitProcessPath(role, expected, network string) error {
	deadline := time.Now().Add(15 * time.Second)
	lastResult := "no response"
	for attempt := 1; ; attempt++ {
		token := fmt.Sprintf("SNW_WARMUP_%s_%s_%08d", strings.ToUpper(h.profile), strings.ToUpper(strings.ReplaceAll(role, "-", "_")), attempt)
		response, err := h.processes[role].request(processRequest{
			Operation: "once", Network: network, Address: flowRemote(network), Token: token,
		})
		if err == nil {
			host, _, splitErr := net.SplitHostPort(response.LocalAddr)
			lastResult = fmt.Sprintf("local address %q", response.LocalAddr)
			want := "10.77.0.2"
			if strings.HasSuffix(network, "6") {
				want = "fd77::2"
			}
			if expected == "underlay" {
				want = underlayIPv4
				if strings.HasSuffix(network, "6") {
					want = "fd00:18:1::2"
				}
			}
			if splitErr == nil && host == want {
				return nil
			}
		} else {
			lastResult = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s process did not converge to %s path for %s profile: %s", role, expected, h.profile, lastResult)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *splitFlow) closeProcesses() {
	for _, process := range h.processes {
		process.close()
	}
	h.processes = nil
}

func copyExecutable(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	return errors.Join(copyErr, output.Close())
}

func (h *splitFlow) token(prefix string) string {
	return fmt.Sprintf("SNW_%s_%08d", prefix, h.sequence.Add(1))
}

func (h *splitFlow) assertPath(role, network, expected, description, ipcAddress string) error {
	controlRole, controlPath := "included", "tunnel"
	if expected == "tunnel" {
		controlRole, controlPath = "excluded", "underlay"
	}
	control := h.token("CONTROL")
	if _, err := h.processes[controlRole].request(processRequest{
		Operation: "once", Network: network, Address: flowRemote(network), Token: control,
	}); err != nil {
		return fmt.Errorf("%s positive control: %w", description, err)
	}
	if err := h.observe(observation{Case: "CTRL-" + role + "-" + network, Token: control, ExpectedPath: controlPath, Operation: "opposite-link positive control", Phase: "public-api"}, map[string]any{
		"role": controlRole, "network": network, "positiveControl": true,
	}); err != nil {
		return err
	}
	token := h.token(strings.ToUpper(role))
	request := processRequest{Operation: "once", Network: network, Address: flowRemote(network), Token: token}
	process := h.processes[role]
	if role == "ipc" {
		process = h.processes["excluded"]
		request.Operation, request.Address = "ipc", ipcAddress
	}
	response, err := process.request(request)
	if err != nil {
		return fmt.Errorf("%s %s: %w", description, network, err)
	}
	caseID := map[string]string{"included": "E01-included-process-tunnel", "excluded": "E02-excluded-process-underlay", "descendant": "E03-excluded-descendant-underlay", "ipc": "E04-pre-existing-ipc-target-tunnel"}[role]
	metadata := map[string]any{
		"role": role, "network": network, "localAddr": response.LocalAddr, "controlToken": control,
	}
	if role == "ipc" {
		metadata["preExistingTarget"] = true
		metadata["requestingRole"] = "excluded"
	}
	return h.observe(observation{Case: caseID, Token: token, ExpectedPath: expected, Operation: description, Phase: "public-api"}, metadata)
}

func (h *splitFlow) assertDNSPath(network string, shared bool) error {
	control := h.token("DNS_CONTROL")
	if _, err := h.processes["included"].request(processRequest{
		Operation: "once", Network: strings.Replace(network, "ip", "tcp", 1), Address: flowRemote(strings.Replace(network, "ip", "tcp", 1)), Token: control,
	}); err != nil {
		return fmt.Errorf("DNS tunnel positive control: %w", err)
	}
	if err := h.observe(observation{Case: "CTRL-dns-" + network, Token: control, ExpectedPath: "tunnel", Operation: "DNS opposite-link positive control", Phase: "public-api"}, map[string]any{
		"role": "included", "network": network, "positiveControl": true,
	}); err != nil {
		return err
	}
	// Windows DNS components can normalize the case of query names. Use a
	// digit-only marker so the capture validator is independent of that valid
	// DNS transformation.
	token := fmt.Sprintf("7357%08d", h.sequence.Add(1))
	request := processRequest{Operation: "dns", Network: network, Address: flowDNSRemote(network), Token: token}
	caseID, role := "E05-explicit-application-dns-underlay", "excluded"
	metadata := map[string]any{"role": role, "network": network, "controlToken": control, "attribution": "requesting executable"}
	if shared {
		request = processRequest{Operation: "lookup", Network: network, Token: token}
		caseID, role = "E06-shared-windows-dns-client", "shared-client"
		metadata["role"] = role
		metadata["attribution"] = "Windows DNS Client and the managed proxy, not the requesting executable"
		metadata["limitation"] = "shared resolver traffic cannot prove per-requesting-process attribution"
	}
	response, err := h.processes["excluded"].request(request)
	if err != nil {
		return fmt.Errorf("%s: %w", caseID, err)
	}
	metadata["localAddr"] = response.LocalAddr
	metadata["answer"] = response.Value
	return h.observe(observation{Case: caseID, Token: token, ExpectedPath: "underlay", Operation: "DNS request", Phase: "public-api"}, metadata)
}

func flowDNSRemote(network string) string {
	if strings.HasSuffix(network, "4") {
		return "203.0.113.1:53"
	}
	return "[2001:db8:ffff::1]:53"
}

func (h *splitFlow) observe(base observation, extra map[string]any) error {
	value := map[string]any{
		"case": base.Case, "token": base.Token, "expectedPath": base.ExpectedPath,
		"operation": base.Operation, "phase": base.Phase, "profile": h.profile,
	}
	for key, item := range extra {
		value[key] = item
	}
	if err := json.NewEncoder(h.writer).Encode(value); err != nil {
		return err
	}
	return h.writer.Flush()
}

func (h *splitFlow) flush() error {
	if h.writer != nil {
		if err := h.writer.Flush(); err != nil {
			return err
		}
	}
	if h.file != nil {
		return h.file.Close()
	}
	return nil
}

func (h *splitFlow) close() {
	h.closeProcesses()
	_ = h.flush()
}
