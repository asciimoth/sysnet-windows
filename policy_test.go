package windows

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	gtun "github.com/asciimoth/gonnect/tun"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
)

func TestNormalizeTunOptions(t *testing.T) {
	t.Parallel()

	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	opts := sysnet.TunOpts{
		Name:      " test ",
		TunAddrs:  []string{"127.0.0.1/8", "10.0.0.2/24", "10.0.0.2/24"},
		TunRoutes: []string{"127.0.0.0/8", "10.20.1.4/16"},
		MTU:       100,
	}
	desired, report := normalizeTunOpts(system.policyConfig(), opts)
	if err := report.Err(); err != nil {
		t.Fatal(err)
	}
	if desired.name != "test" || desired.mtu != defaultTunMTU {
		t.Fatalf("desired = %+v", desired)
	}
	wantAddress := netip.MustParsePrefix("10.0.0.2/24")
	if len(desired.addresses) != 1 || desired.addresses[0] != wantAddress {
		t.Fatalf("addresses = %v, want [%v]", desired.addresses, wantAddress)
	}
	wantRoute := netip.MustParsePrefix("10.20.0.0/16")
	if len(desired.routes) != 1 || desired.routes[0] != wantRoute {
		t.Fatalf("routes = %v, want [%v]", desired.routes, wantRoute)
	}
}

func TestDefaultTunDNSNormalization(t *testing.T) {
	t.Parallel()

	config := defaultNormalizedSystemConfig()
	tests := []struct {
		name string
		raw  string
		want netip.Addr
	}{
		{name: "owned", raw: "10.0.0.3", want: netip.MustParseAddr("10.0.0.3")},
		{name: "unowned is ignored", raw: "192.0.2.1", want: netip.MustParseAddr("10.0.0.2")},
		{name: "unassigned subnet address is ignored", raw: "10.0.0.99", want: netip.MustParseAddr("10.0.0.2")},
		{name: "empty selects first", want: netip.MustParseAddr("10.0.0.2")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			desired, report := normalizeDefaultTunOpts(config, sysnet.DefaultTunOpts{
				TunAddrs: []string{"10.0.0.2/24", "10.0.0.3/24"},
				DnsIP:    test.raw,
			})
			if err := report.Err(); err != nil {
				t.Fatal(err)
			}
			if desired.dnsIP != test.want {
				t.Fatalf("dnsIP = %v, want %v", desired.dnsIP, test.want)
			}
		})
	}
}

func TestValidationRejectsBeforeConstruction(t *testing.T) {
	t.Parallel()

	factory := &countingTUNFactory{}
	system, err := newSystem(SystemConfig{}, systemDependencies{tunFactory: factory})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		opts sysnet.DefaultTunOpts
		path string
	}{
		{name: "include", opts: sysnet.DefaultTunOpts{Include: []sysnet.Rule{{Type: "win-exe-tree", Rule: `C:\app.exe`}}}, path: "DefaultTun.Include"},
		{name: "strict", opts: sysnet.DefaultTunOpts{Strict: true}, path: "DefaultTun.Strict"},
		{name: "source routes", opts: sysnet.DefaultTunOpts{SourceRoutes: []sysnet.TunSourceRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Source: netip.MustParseAddr("10.0.0.2")}}}, path: "DefaultTun.SourceRoutes"},
		{name: "bad address", opts: sysnet.DefaultTunOpts{TunAddrs: []string{"bad"}}, path: "DefaultTun.TunAddrs[0]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := system.CheckDefaultTunOpts(test.opts)
			if len(report.Issues) == 0 || report.Issues[0].Path != test.path {
				t.Fatalf("issues = %+v, want first path %q", report.Issues, test.path)
			}
			_, buildErr := system.BuildDefaultTun(test.opts)
			if buildErr == nil {
				t.Fatal("BuildDefaultTun() error = nil")
			}
			if errors.Is(buildErr, sysnet.ErrNotSupported) != (report.Issues[0].State == sysnet.CapabilityUnsupported) {
				t.Fatalf("BuildDefaultTun() error = %v, issue = %+v", buildErr, report.Issues[0])
			}
		})
	}
	if factory.calls != 0 {
		t.Fatalf("TUN factory calls = %d, want 0", factory.calls)
	}
}

func TestOneFamilyValidation(t *testing.T) {
	t.Parallel()

	system, err := newSystem(SystemConfig{Features: FeatureConfig{DisableIPv6: true}}, systemDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	_, report := normalizeTunOpts(system.policyConfig(), sysnet.TunOpts{TunAddrs: []string{"2001:db8::2/64"}})
	if len(report.Issues) != 1 || report.Issues[0].Reason != sysnet.ReasonAddressFamilyUnavailable {
		t.Fatalf("issues = %+v", report.Issues)
	}
}

func TestDisabledFamilyStillIgnoresLoopback(t *testing.T) {
	t.Parallel()
	config, err := normalizeSystemConfig(SystemConfig{Features: FeatureConfig{DisableIPv4: true}})
	if err != nil {
		t.Fatalf("normalizeSystemConfig() error = %v", err)
	}
	desired, report := normalizeTunOpts(config, sysnet.TunOpts{
		TunAddrs:  []string{"127.0.0.1/8"},
		TunRoutes: []string{"127.0.0.0/8"},
	})
	if err := report.Err(); err != nil {
		t.Fatalf("normalizeTunOpts() error = %v", err)
	}
	if len(desired.addresses) != 0 || len(desired.routes) != 0 {
		t.Fatalf("loopback options were not ignored: %+v", desired)
	}
}

func TestDefaultTunRejectsAllFamiliesDisabled(t *testing.T) {
	t.Parallel()
	config, err := normalizeSystemConfig(SystemConfig{Features: FeatureConfig{
		DisableIPv4: true,
		DisableIPv6: true,
	}})
	if err != nil {
		t.Fatalf("normalizeSystemConfig() error = %v", err)
	}
	_, report := normalizeDefaultTunOpts(config, sysnet.DefaultTunOpts{})
	if len(report.Issues) != 1 || report.Issues[0].Reason != sysnet.ReasonAddressFamilyUnavailable {
		t.Fatalf("issues = %+v", report.Issues)
	}
}

func TestRuleContexts(t *testing.T) {
	t.Parallel()

	system, err := newSystem(SystemConfig{}, systemDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	exclude := sysnet.RoutingProfileKey{Family: sysnet.FamilyDual, Mode: sysnet.RoutingExclude}
	matcher := sysnet.MatcherProfileKey{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP}
	tests := []struct {
		name    string
		rule    sysnet.Rule
		context sysnet.RuleContext
		valid   bool
	}{
		{name: "exe tree exclusion", rule: sysnet.Rule{Type: "win-exe-tree", Rule: `C:\app.exe`}, context: sysnet.RuleContext{Routing: &exclude}, valid: true},
		{name: "PID matcher", rule: sysnet.Rule{Type: "win-pid", Rule: "42"}, context: sysnet.RuleContext{Matcher: &matcher}, valid: true},
		{name: "wrong PID context", rule: sysnet.Rule{Type: "win-pid", Rule: "42"}, context: sysnet.RuleContext{Routing: &exclude}},
		{name: "missing context", rule: sysnet.Rule{Type: "win-pid", Rule: "42"}},
		{name: "two contexts", rule: sysnet.Rule{Type: "win-pid", Rule: "42"}, context: sysnet.RuleContext{Routing: &exclude, Matcher: &matcher}},
		{name: "UNC unsupported", rule: sysnet.Rule{Type: "win-exe-tree", Rule: `\\server\app.exe`}, context: sysnet.RuleContext{Routing: &exclude}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, report := normalizeRule(system.policyConfig(), test.rule, test.context)
			err := report.Err()
			if (err == nil) != test.valid {
				t.Fatalf("CheckRule() error = %v, valid = %v", err, test.valid)
			}
		})
	}
}

func TestNewUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	system, err := New(SystemConfig{})
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if closeErr := system.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
		return
	}
	if err == nil || !errors.Is(err, sysnet.ErrNotSupported) {
		t.Fatalf("New() error = %v, want ErrNotSupported", err)
	}
}

func TestNewValidatesConfigBeforePlatform(t *testing.T) {
	t.Parallel()

	_, err := New(SystemConfig{OperationTimeout: -1})
	if err == nil || !errors.Is(err, sysnet.ErrInvalidOptions) {
		t.Fatalf("New() error = %v, want ErrInvalidOptions", err)
	}
}

type countingTUNFactory struct {
	calls int
}

func (f *countingTUNFactory) Create(context.Context, internaltun.Config) (gtun.Tun, error) {
	f.calls++
	return nil, errors.New("unexpected TUN creation")
}
