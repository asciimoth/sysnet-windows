//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFlowCasesHaveUniqueCaptureMarkersAndRequiredPaths(t *testing.T) {
	required := map[string]bool{
		"N01-outnet-tcp4-underlay": false,
		"N02-outnet-tcp6-underlay": false,
		"N03-outnet-udp4-underlay": false,
		"N04-outnet-udp6-underlay": false,
	}
	tokens := make(map[string]struct{})
	for _, current := range flowCases() {
		if current.run == nil || current.observation.ExpectedPath != "underlay" {
			t.Fatalf("invalid flow case: %+v", current.observation)
		}
		token := current.observation.Token
		if token == "" {
			t.Fatal("flow case has an empty capture token")
		}
		if _, exists := tokens[token]; exists {
			t.Fatalf("duplicate capture token %q", token)
		}
		for existing := range tokens {
			if strings.Contains(token, existing) || strings.Contains(existing, token) {
				t.Fatalf("overlapping capture tokens %q and %q", token, existing)
			}
		}
		tokens[token] = struct{}{}
		if _, exists := required[current.observation.Case]; exists {
			required[current.observation.Case] = true
		}
	}
	for name, observed := range required {
		if !observed {
			t.Fatalf("required packet case %s is absent", name)
		}
	}
	for _, family := range []string{"4", "6"} {
		for _, operation := range []string{
			"Dial tcp", "DialTCP tcp", "Dial udp", "DialUDP udp", "PacketDial udp",
			"Listen tcp", "ListenTCP tcp", "ListenPacket udp", "ListenUDP udp",
			"ListenPacketConfig udp", "ListenUDPConfig udp",
		} {
			want := operation + family
			found := false
			for _, current := range flowCases() {
				found = found || current.observation.Operation == want
			}
			if !found {
				t.Errorf("supported operation %q is absent", want)
			}
		}
	}
}

func TestSplitCaptureTokensAreFixedWidthAndNonoverlapping(t *testing.T) {
	h := &splitFlow{}
	tokens := make([]string, 0, 20)
	for range 20 {
		tokens = append(tokens, h.token("CONTROL"))
	}
	for index, token := range tokens {
		if len(token) != len("SNW_CONTROL_00000000") {
			t.Fatalf("token %d length = %d", index, len(token))
		}
		for otherIndex, other := range tokens {
			if index != otherIndex && (strings.Contains(token, other) || strings.Contains(other, token)) {
				t.Fatalf("tokens overlap: %q and %q", token, other)
			}
		}
	}
}

func TestDNSQueryContainsStableMarkerAndRejectsInvalidLabels(t *testing.T) {
	query, err := dnsQuery("735700000001.sysnet-flow.test")
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(query[:2]) != 0x7357 || !bytes.Contains(query, []byte("735700000001")) {
		t.Fatalf("DNS query = %x", query)
	}
	for _, name := range []string{"", ".invalid", strings.Repeat("x", 64) + ".test"} {
		if _, err := dnsQuery(name); err == nil {
			t.Fatalf("dnsQuery(%q) succeeded", name)
		}
	}
}

func TestProcessHelperReportsUnknownOperationWithoutLosingProtocol(t *testing.T) {
	var input, output bytes.Buffer
	if err := json.NewEncoder(&input).Encode(processRequest{Operation: "invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := serveProcessRequests(&input, &output); err != nil {
		t.Fatal(err)
	}
	var response processResponse
	if err := json.NewDecoder(&output).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Error, "unknown helper operation") || response.PID == 0 {
		t.Fatalf("helper response = %+v", response)
	}
}

func TestUnderlayLossCasesRequireNoTunnelFallback(t *testing.T) {
	for _, current := range activeAfterLossCases(map[string]net.Conn{
		"tcp4": &testConnection{}, "tcp6": &testConnection{},
		"udp4": &testConnection{}, "udp6": &testConnection{},
	}) {
		if current.observation.ExpectedPath != "underlay-or-none-stopped" {
			t.Fatalf("active-loss path = %q", current.observation.ExpectedPath)
		}
	}
	for _, current := range unavailableCases() {
		if current.observation.ExpectedPath != "none" || current.observation.Phase != "underlay-lost" {
			t.Fatalf("unavailable case = %+v", current.observation)
		}
	}
}

func TestPowerShellCommandBindsNumericInterfaceIndex(t *testing.T) {
	command, err := powerShellCommand("param([int]$Index) $Index", "41")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(command, "& {\nparam([int]$Index)") || !strings.HasSuffix(command, "} 41") {
		t.Fatalf("PowerShell command = %q", command)
	}
	if _, err := powerShellCommand("param($Index)", "not-an-index"); err == nil {
		t.Fatal("nonnumeric interface index succeeded")
	}
}

type testConnection struct{ net.Conn }

func (*testConnection) SetWriteDeadline(time.Time) error { return nil }

func (*testConnection) Write(payload []byte) (int, error) { return len(payload), nil }
