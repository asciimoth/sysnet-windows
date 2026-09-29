package windows

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/owner"
)

type ownerLookupFunc func(context.Context, sockowner.FlowTuple) (*owner.Result, error)

func (function ownerLookupFunc) Owner(ctx context.Context, flow sockowner.FlowTuple) (*owner.Result, error) {
	return function(ctx, flow)
}

func TestCanonicalWindowsExecutablePath(t *testing.T) {
	t.Parallel()
	longComponent := strings.Repeat("長", 300)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "case slashes spaces and Unicode", input: `c:/Program Files/例/App.EXE`, want: `C:\Program Files\例\App.EXE`},
		{name: "dot components", input: `D:\one\.\two\..\app.exe`, want: `D:\one\app.exe`},
		{name: "long path", input: `E:\` + longComponent + `\app.exe`, want: `E:\` + longComponent + `\app.exe`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, issue := canonicalWindowsExecutablePath(test.input)
			if issue != nil {
				t.Fatalf("canonicalWindowsExecutablePath() issue = %+v", issue)
			}
			if got != test.want {
				t.Fatalf("canonicalWindowsExecutablePath() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCanonicalWindowsExecutablePathRejectsUnsupportedForms(t *testing.T) {
	t.Parallel()
	tests := []string{
		`\\server\share\app.exe`,
		`\\?\C:\long\app.exe`,
		`\\.\C:\app.exe`,
		`relative\app.exe`,
		`C:\*.exe`,
		`C:\app.exe:stream`,
		"C:\\bad\x00name.exe",
		`C:\directory\`,
		`C:\trailing.\app.exe`,
		`C:\app.exe `,
	}
	for _, value := range tests {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, issue := canonicalWindowsExecutablePath(value); issue == nil {
				t.Fatalf("canonicalWindowsExecutablePath(%q) succeeded", value)
			}
		})
	}
}

func TestMatcherPIDDoesNotRequireExecutableEnrichment(t *testing.T) {
	t.Parallel()
	denied := errors.New("process access denied")
	lookup := ownerLookupFunc(func(context.Context, sockowner.FlowTuple) (*owner.Result, error) {
		return &owner.Result{
			Owner:     sockowner.SocketOwner{PIDs: []int{42}},
			Processes: []owner.Process{{PID: 42, EnrichmentErr: denied}},
		}, nil
	})
	match := &matcher{lookup: lookup, timeout: defaultNormalizedSystemConfig().operationTimeout, rule: normalizedRule{typeName: rulePID, value: "42"}}
	matched, err := match.Match(testFlow())
	if err != nil || !matched {
		t.Fatalf("Match() = %v, %v; want true, nil", matched, err)
	}
}

func TestMatcherExecutablePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		configured string
		observed   string
		processErr error
		lookupErr  error
		want       bool
		wantErr    error
	}{
		{name: "case and Unicode", configured: `C:\Program Files\例\APP.exe`, observed: `c:/program files/例/app.EXE`, want: true},
		{name: "hard link alternate path", configured: `C:\bin\app.exe`, observed: `C:\links\app.exe`},
		{name: "renamed path", configured: `C:\bin\old.exe`, observed: `C:\bin\new.exe`},
		{name: "inaccessible process", configured: `C:\bin\app.exe`, observed: `C:\bin\app.exe`, processErr: os.ErrPermission, wantErr: os.ErrPermission},
		{name: "unknown owner", configured: `C:\bin\app.exe`, lookupErr: owner.ErrUnknownOwner, wantErr: owner.ErrUnknownOwner},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configured, issue := canonicalWindowsExecutablePath(test.configured)
			if issue != nil {
				t.Fatalf("configured path issue = %+v", issue)
			}
			lookup := ownerLookupFunc(func(context.Context, sockowner.FlowTuple) (*owner.Result, error) {
				if test.lookupErr != nil {
					return nil, test.lookupErr
				}
				return &owner.Result{
					Owner:     sockowner.SocketOwner{PIDs: []int{42}},
					Processes: []owner.Process{{PID: 42, ExecutablePath: test.observed, EnrichmentErr: test.processErr}},
				}, nil
			})
			match := &matcher{lookup: lookup, timeout: defaultNormalizedSystemConfig().operationTimeout, rule: normalizedRule{typeName: ruleExecutablePath, value: configured}}
			got, err := match.Match(testFlow())
			if got != test.want || !errors.Is(err, test.wantErr) || test.wantErr == nil && err != nil {
				t.Fatalf("Match() = %v, %v; want %v, %v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestMatcherDefensivelyRejectsInvalidOwnerResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		result  *owner.Result
		wantErr error
	}{
		{name: "nil", wantErr: owner.ErrUnknownOwner},
		{name: "no PID", result: &owner.Result{}, wantErr: owner.ErrUnknownOwner},
		{name: "ambiguous", result: &owner.Result{Owner: sockowner.SocketOwner{PIDs: []int{1, 2}}}, wantErr: owner.ErrAmbiguousOwner},
		{name: "missing process", result: &owner.Result{Owner: sockowner.SocketOwner{PIDs: []int{1}}}, wantErr: owner.ErrUnknownOwner},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			match := &matcher{
				lookup:  ownerLookupFunc(func(context.Context, sockowner.FlowTuple) (*owner.Result, error) { return test.result, nil }),
				timeout: defaultNormalizedSystemConfig().operationTimeout,
				rule:    normalizedRule{typeName: ruleExecutablePath, value: `C:\app.exe`},
			}
			if got, err := match.Match(testFlow()); got || !errors.Is(err, test.wantErr) {
				t.Fatalf("Match() = %v, %v; want false, %v", got, err, test.wantErr)
			}
		})
	}
}

func TestMatcherCloseCancelsActiveLookup(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	lookup := ownerLookupFunc(func(ctx context.Context, _ sockowner.FlowTuple) (*owner.Result, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	match := newMatcher(lookup, defaultNormalizedSystemConfig().operationTimeout, normalizedRule{typeName: rulePID, value: "42"})
	result := make(chan error, 1)
	go func() {
		_, err := match.Match(testFlow())
		result <- err
	}()
	<-started
	if err := match.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Match() error = %v, want context.Canceled", err)
	}
}

func TestBuildMatcherCompletionAndLifecycle(t *testing.T) {
	t.Parallel()
	lookup := ownerLookupFunc(func(context.Context, sockowner.FlowTuple) (*owner.Result, error) {
		return &owner.Result{Owner: sockowner.SocketOwner{PIDs: []int{42}}}, nil
	})
	system, err := newSystem(SystemConfig{}, systemDependencies{ownerLookup: lookup})
	if err != nil {
		t.Fatal(err)
	}
	context := sysnet.RuleContext{Matcher: &sysnet.MatcherProfileKey{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP}}
	completed, err := system.CompleteRule(sysnet.Rule{Type: rulePID, Rule: "00042"}, context)
	if err != nil || len(completed) != 1 || completed[0] != "42" {
		t.Fatalf("CompleteRule() = %v, %v; want [42], nil", completed, err)
	}
	built, err := system.BuildMatcher(sysnet.Rule{Type: rulePID, Rule: "42"})
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := built.Match(testFlow()); err != nil || !matched {
		t.Fatalf("Match() = %v, %v; want true, nil", matched, err)
	}
	if err := system.Close(); err != nil {
		t.Fatal(err)
	}
	if matched, err := built.Match(testFlow()); matched || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Match() after System.Close = %v, %v; want false, os.ErrClosed", matched, err)
	}
	if err := built.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestMatcherCapabilityRequiresOwnerLookup(t *testing.T) {
	t.Parallel()
	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	profile := matcherProfile(system.Capabilities().Rule(rulePID), sysnet.MatcherProfileKey{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP})
	if profile.State != sysnet.CapabilityUnavailable || !containsReason(profile.Reasons, sysnet.ReasonMissingDependency) {
		t.Fatalf("matcher capability = %+v, want unavailable missing dependency", profile.Capability)
	}
}

func testFlow() sockowner.FlowTuple {
	return sockowner.FlowTuple{
		Proto: "tcp", LocalIP: net.IPv4(127, 0, 0, 1), LocalPort: 1234,
		RemoteIP: net.IPv4(127, 0, 0, 1), RemotePort: 4321,
	}
}
