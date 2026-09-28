package windows

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
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

func TestNormalizeTunOptionsRejectsInvalidName(t *testing.T) {
	t.Parallel()
	_, report := normalizeTunOpts(defaultNormalizedSystemConfig(), sysnet.TunOpts{
		Name: strings.Repeat("x", 129),
	})
	if err := report.Err(); err == nil || !errors.Is(err, sysnet.ErrInvalidOptions) ||
		len(report.Issues) != 1 || report.Issues[0].Path != "Tun.Name" {
		t.Fatalf("normalizeTunOpts() report = %+v, want invalid Tun.Name", report)
	}
}

func TestNormalizeTunOptionsRejectsOneAddressWithDifferentPrefixLengths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		addresses []string
	}{
		{name: "IPv4", addresses: []string{"10.0.0.2/24", "10.0.0.2/16"}},
		{name: "IPv6", addresses: []string{"fd00::2/64", "fd00::2/48"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, report := normalizeTunOpts(defaultNormalizedSystemConfig(), sysnet.TunOpts{
				TunAddrs: test.addresses,
			})
			if err := report.Err(); err == nil || !errors.Is(err, sysnet.ErrInvalidOptions) ||
				len(report.Issues) != 1 || report.Issues[0].Path != "Tun.TunAddrs[1]" {
				t.Fatalf("normalizeTunOpts() report = %+v, want invalid duplicate address", report)
			}
		})
	}
}

func TestTunAddressValidationRejectsNonUnicastAndMappedAddresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
	}{
		{name: "unspecified IPv4", value: "0.0.0.0/32"},
		{name: "unspecified IPv6", value: "::/128"},
		{name: "multicast IPv4", value: "224.0.0.1/32"},
		{name: "multicast IPv6", value: "ff02::1/128"},
		{name: "IPv4-mapped IPv6", value: "::ffff:192.0.2.1/128"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			factory := &countingTUNFactory{}
			system, err := newSystem(SystemConfig{}, systemDependencies{tunFactory: factory})
			if err != nil {
				t.Fatalf("newSystem() error = %v", err)
			}
			opts := sysnet.TunOpts{TunAddrs: []string{test.value}}
			report := system.CheckTunOpts(opts)
			if err := report.Err(); !errors.Is(err, sysnet.ErrInvalidOptions) || len(report.Issues) == 0 || report.Issues[0].Path != "Tun.TunAddrs[0]" {
				t.Fatalf("CheckTunOpts() report = %+v, want invalid Tun.TunAddrs[0]", report)
			}
			if _, err := system.BuildTun(opts); !errors.Is(err, sysnet.ErrInvalidOptions) {
				t.Fatalf("BuildTun() error = %v, want ErrInvalidOptions", err)
			}
			if factory.calls != 0 {
				t.Fatalf("TUN factory calls = %d, want 0", factory.calls)
			}
		})
	}
}

func TestTunPrefixValidationRejectsIPv4MappedIPv6Routes(t *testing.T) {
	t.Parallel()
	_, report := normalizeTunOpts(defaultNormalizedSystemConfig(), sysnet.TunOpts{
		TunRoutes: []string{"::ffff:192.0.2.0/120"},
	})
	if err := report.Err(); !errors.Is(err, sysnet.ErrInvalidOptions) || len(report.Issues) != 1 || report.Issues[0].Path != "Tun.TunRoutes[0]" {
		t.Fatalf("normalizeTunOpts() report = %+v, want invalid Tun.TunRoutes[0]", report)
	}
	_, report = normalizeDefaultTunOpts(defaultNormalizedSystemConfig(), sysnet.DefaultTunOpts{
		TunAddrs: []string{"0.0.0.0/32"},
	})
	if len(report.Issues) != 1 || report.Issues[0].Path != "DefaultTun.TunAddrs[0]" {
		t.Fatalf("normalizeDefaultTunOpts() report = %+v, want repathed address issue", report)
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

func TestRouteLoopbackFilteringUsesNormalizedNetwork(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want []netip.Prefix
	}{
		{
			name: "IPv4 default with loopback host bits",
			raw:  "127.0.0.1/0",
			want: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
		{
			name: "IPv4 wider than loopback block",
			raw:  "127.0.0.1/7",
			want: []netip.Prefix{netip.MustParsePrefix("126.0.0.0/7")},
		},
		{name: "IPv4 loopback block", raw: "127.0.0.1/8"},
		{name: "IPv4 loopback subnet", raw: "127.20.30.40/24"},
		{
			name: "IPv6 default with loopback host bits",
			raw:  "::1/0",
			want: []netip.Prefix{netip.MustParsePrefix("::/0")},
		},
		{
			name: "IPv6 network containing loopback",
			raw:  "::1/64",
			want: []netip.Prefix{netip.MustParsePrefix("::/64")},
		},
		{name: "IPv6 loopback host route", raw: "::1/128"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			routes, report := normalizePrefixes(
				defaultNormalizedSystemConfig(),
				[]string{test.raw},
				"Tun.TunRoutes",
				prefixRoute,
			)
			if err := report.Err(); err != nil {
				t.Fatalf("normalizePrefixes() error = %v", err)
			}
			if len(routes) != len(test.want) {
				t.Fatalf("routes = %v, want %v", routes, test.want)
			}
			for index := range routes {
				if routes[index] != test.want[index] {
					t.Fatalf("routes = %v, want %v", routes, test.want)
				}
			}
		})
	}
}

func TestAddressLoopbackFilteringStillUsesAssignedAddress(t *testing.T) {
	t.Parallel()
	addresses, report := normalizePrefixes(
		defaultNormalizedSystemConfig(),
		[]string{"127.0.0.1/0", "::1/0"},
		"Tun.TunAddrs",
		prefixAddress,
	)
	if err := report.Err(); err != nil {
		t.Fatalf("normalizePrefixes() error = %v", err)
	}
	if len(addresses) != 0 {
		t.Fatalf("loopback addresses were not ignored: %v", addresses)
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

func TestValidateMatcherRuleReturnsNormalizedPolicy(t *testing.T) {
	t.Parallel()
	normalized, report := validateMatcherRule(defaultNormalizedSystemConfig(), sysnet.Rule{
		Type: " win-pid ", Rule: "00042",
	})
	if err := report.Err(); err != nil {
		t.Fatalf("validateMatcherRule() error = %v", err)
	}
	if normalized.typeName != "win-pid" || normalized.value != "42" {
		t.Fatalf("normalized rule = %+v, want win-pid 42", normalized)
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

func TestNormalizeSystemConfigAdapterIdentity(t *testing.T) {
	t.Parallel()

	normalized, err := normalizeSystemConfig(SystemConfig{
		AdapterNamePrefix: "  private-tunnel  ",
		StableGUID:        "01234567-89AB-CDEF-0123-456789ABCDEF",
	})
	if err != nil {
		t.Fatalf("normalizeSystemConfig() error = %v", err)
	}
	if normalized.adapterNamePrefix != "private-tunnel" {
		t.Fatalf("adapter name prefix = %q, want private-tunnel", normalized.adapterNamePrefix)
	}
	if normalized.stableGUID != "{01234567-89ab-cdef-0123-456789abcdef}" {
		t.Fatalf("stable GUID = %q", normalized.stableGUID)
	}

	for _, test := range []struct {
		name   string
		config SystemConfig
		path   string
	}{
		{name: "invalid GUID", config: SystemConfig{StableGUID: "not-a-guid"}, path: "SystemConfig.StableGUID"},
		{name: "NUL in prefix", config: SystemConfig{AdapterNamePrefix: "bad\x00name"}, path: "SystemConfig.AdapterNamePrefix"},
		{name: "long prefix", config: SystemConfig{AdapterNamePrefix: strings.Repeat("x", 128)}, path: "SystemConfig.AdapterNamePrefix"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := normalizeSystemConfig(test.config)
			if err == nil || !errors.Is(err, sysnet.ErrInvalidOptions) || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("normalizeSystemConfig() error = %v, want invalid options at %s", err, test.path)
			}
		})
	}
}

type countingTUNFactory struct {
	calls int
}

func (f *countingTUNFactory) Create(context.Context, internaltun.Config) (internaltun.ManagedTun, error) {
	f.calls++
	return nil, errors.New("unexpected TUN creation")
}
