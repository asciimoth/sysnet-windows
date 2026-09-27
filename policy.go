package windows

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect/sysnet"
)

const (
	defaultTunMTU = 1420
	minIPv4MTU    = 576
	minIPv6MTU    = 1280
	maxTunMTU     = 65535
)

type prefixKind uint8

const (
	prefixAddress prefixKind = iota
	prefixRoute
)

type desiredTun struct {
	name      string
	addresses []netip.Prefix
	routes    []netip.Prefix
	mtu       int
}

type desiredDefaultTun struct {
	tun      desiredTun
	dnsIP    netip.Addr
	excludes []normalizedRule
	family   sysnet.AddressFamily
}

type normalizedRule struct {
	typeName string
	value    string
}

func normalizeTunOpts(config normalizedSystemConfig, opts sysnet.TunOpts) (desiredTun, sysnet.ValidationReport) {
	addresses, addressReport := normalizePrefixes(config, opts.TunAddrs, "Tun.TunAddrs", prefixAddress)
	routes, routeReport := normalizePrefixes(config, opts.TunRoutes, "Tun.TunRoutes", prefixRoute)
	hasIPv6 := prefixesContainIPv6(addresses) || prefixesContainIPv6(routes)
	mtu, mtuReport := normalizeMTU(config, opts.MTU, "Tun.MTU", hasIPv6)
	return desiredTun{
		name:      strings.TrimSpace(opts.Name),
		addresses: addresses,
		routes:    routes,
		mtu:       mtu,
	}, joinReports(addressReport, routeReport, mtuReport)
}

func normalizeDefaultTunOpts(config normalizedSystemConfig, opts sysnet.DefaultTunOpts) (desiredDefaultTun, sysnet.ValidationReport) {
	tunState, report := normalizeTunOpts(config, sysnet.TunOpts{
		Name:      opts.Name,
		TunAddrs:  opts.TunAddrs,
		TunRoutes: opts.TunRoutes,
		MTU:       opts.MTU,
	})
	report = repathReport(report, "Tun.", "DefaultTun.")

	if len(opts.Include) > 0 && len(opts.Exclude) > 0 {
		report.Issues = append(report.Issues, validationIssue(
			"DefaultTun.Include",
			sysnet.CapabilityUnsupported,
			sysnet.ReasonUnsupportedCombination,
			"include and exclude rules are mutually exclusive",
			nil,
		))
	}
	if len(opts.Include) > 0 {
		report.Issues = append(report.Issues, validationIssue(
			"DefaultTun.Include",
			sysnet.CapabilityUnsupported,
			sysnet.ReasonNotImplemented,
			"include routing is not supported",
			nil,
		))
	}
	if opts.Strict {
		report.Issues = append(report.Issues, validationIssue(
			"DefaultTun.Strict",
			sysnet.CapabilityUnsupported,
			sysnet.ReasonNotImplemented,
			"strict routing is not supported",
			nil,
		))
	}
	if len(opts.SourceRoutes) > 0 {
		report.Issues = append(report.Issues, validationIssue(
			"DefaultTun.SourceRoutes",
			sysnet.CapabilityUnsupported,
			sysnet.ReasonNotImplemented,
			"preferred-source routes are not supported",
			nil,
		))
	}

	family := familyForPrefixes(tunState.addresses, tunState.routes)
	if family == sysnet.FamilyNone {
		family = defaultTunFamily(config)
		if family == sysnet.FamilyNone {
			report.Issues = append(report.Issues, validationIssue(
				"DefaultTun.TunAddrs",
				sysnet.CapabilityUnsupported,
				sysnet.ReasonAddressFamilyUnavailable,
				"no address family is enabled",
				nil,
			))
		}
	}
	routingKey := sysnet.RoutingProfileKey{Family: family, Mode: sysnet.RoutingExclude}
	excludes := make([]normalizedRule, 0, len(opts.Exclude))
	for index, rule := range opts.Exclude {
		normalized, ruleReport := normalizeRule(config, rule, sysnet.RuleContext{Routing: &routingKey})
		ruleReport = repathReport(ruleReport, "Rule", fmt.Sprintf("DefaultTun.Exclude[%d]", index))
		report = joinReports(report, ruleReport)
		if len(ruleReport.Issues) == 0 {
			excludes = append(excludes, normalized)
		}
	}

	dnsIP, dnsReport := normalizeDNSIP(opts.DnsIP, tunState.addresses)
	report = joinReports(report, dnsReport)
	return desiredDefaultTun{
		tun:      tunState,
		dnsIP:    dnsIP,
		excludes: excludes,
		family:   family,
	}, report
}

func normalizePrefixes(config normalizedSystemConfig, raw []string, path string, kind prefixKind) ([]netip.Prefix, sysnet.ValidationReport) {
	result := make([]netip.Prefix, 0, len(raw))
	seen := make(map[netip.Prefix]struct{}, len(raw))
	report := sysnet.ValidationReport{}
	for index, value := range raw {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			report.Issues = append(report.Issues, validationIssue(
				itemPath, 0, "", "address prefix is not valid", invalidCause(err),
			))
			continue
		}
		if prefix.Addr().Zone() != "" {
			report.Issues = append(report.Issues, validationIssue(
				itemPath, 0, "", "scoped addresses are not valid TUN configuration", sysnet.ErrInvalidOptions,
			))
			continue
		}
		if prefix.Addr().IsLoopback() {
			continue
		}
		if issue := validateFamily(config, prefix.Addr(), itemPath); issue != nil {
			report.Issues = append(report.Issues, *issue)
			continue
		}
		if kind == prefixRoute {
			prefix = prefix.Masked()
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result, report
}

func normalizeMTU(_ normalizedSystemConfig, raw int, path string, ipv6 bool) (int, sysnet.ValidationReport) {
	minimum := minIPv4MTU
	if ipv6 {
		minimum = minIPv6MTU
	}
	if raw == 0 || raw < minimum {
		return defaultTunMTU, sysnet.ValidationReport{}
	}
	if raw > maxTunMTU {
		return 0, sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{validationIssue(
			path, 0, "", fmt.Sprintf("MTU must not exceed %d", maxTunMTU), sysnet.ErrInvalidOptions,
		)}}
	}
	return raw, sysnet.ValidationReport{}
}

func normalizeDNSIP(raw string, addresses []netip.Prefix) (netip.Addr, sysnet.ValidationReport) {
	if raw != "" {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err == nil {
			for _, prefix := range addresses {
				if prefix.Addr() == address {
					return address, sysnet.ValidationReport{}
				}
			}
		}
	}
	if len(addresses) > 0 {
		return addresses[0].Addr(), sysnet.ValidationReport{}
	}
	return netip.Addr{}, sysnet.ValidationReport{}
}

func defaultTunFamily(config normalizedSystemConfig) sysnet.AddressFamily {
	if config.ipv4 {
		return sysnet.FamilyIPv4
	}
	if config.ipv6 {
		return sysnet.FamilyIPv6
	}
	return sysnet.FamilyNone
}

func normalizeRule(config normalizedSystemConfig, rule sysnet.Rule, context sysnet.RuleContext) (normalizedRule, sysnet.ValidationReport) {
	contextIssue := validateRuleContext(config, context)
	if contextIssue != nil {
		return normalizedRule{}, sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{*contextIssue}}
	}

	typeName := strings.TrimSpace(rule.Type)
	value := strings.TrimSpace(rule.Rule)
	if value == "" {
		return normalizedRule{}, invalidReport("Rule.Rule", "rule value must not be empty", nil)
	}

	switch typeName {
	case "win-exe-tree":
		if context.Routing == nil || context.Routing.Mode != sysnet.RoutingExclude || context.Routing.Strict {
			return normalizedRule{}, unsupportedReport(
				"Rule.Context", sysnet.ReasonUnsupportedCombination,
				"win-exe-tree is supported only for non-strict exclude routing",
			)
		}
		if !config.exclusions {
			return normalizedRule{}, unsupportedReport("Rule.Type", sysnet.ReasonDisabledByConfig, "executable exclusions are disabled")
		}
		if issue := validateWindowsExecutablePath(value); issue != nil {
			return normalizedRule{}, sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{*issue}}
		}
	case "win-pid":
		if context.Matcher == nil {
			return normalizedRule{}, unsupportedReport("Rule.Context", sysnet.ReasonUnsupportedCombination, "win-pid is a matcher rule")
		}
		if !config.matchers {
			return normalizedRule{}, unsupportedReport("Rule.Type", sysnet.ReasonDisabledByConfig, "matchers are disabled")
		}
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil || pid == 0 {
			return normalizedRule{}, invalidReport("Rule.Rule", "PID must be an integer from 1 through 4294967295", err)
		}
		value = strconv.FormatUint(pid, 10)
	case "win-exe-path":
		if context.Matcher == nil {
			return normalizedRule{}, unsupportedReport("Rule.Context", sysnet.ReasonUnsupportedCombination, "win-exe-path is a matcher rule")
		}
		if !config.matchers {
			return normalizedRule{}, unsupportedReport("Rule.Type", sysnet.ReasonDisabledByConfig, "matchers are disabled")
		}
		if issue := validateWindowsExecutablePath(value); issue != nil {
			return normalizedRule{}, sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{*issue}}
		}
	default:
		return normalizedRule{}, unsupportedReport("Rule.Type", sysnet.ReasonNotImplemented, "rule type is not supported")
	}
	return normalizedRule{typeName: typeName, value: value}, sysnet.ValidationReport{}
}

func validateMatcherRule(config normalizedSystemConfig, rule sysnet.Rule) sysnet.ValidationReport {
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		if (family == sysnet.FamilyIPv4 && !config.ipv4) || (family == sysnet.FamilyIPv6 && !config.ipv6) {
			continue
		}
		key := sysnet.MatcherProfileKey{Family: family, Transport: sysnet.TransportTCP}
		_, report := normalizeRule(config, rule, sysnet.RuleContext{Matcher: &key})
		return report
	}
	return unsupportedReport("Rule.Context.Matcher.Family", sysnet.ReasonAddressFamilyUnavailable, "no address family is enabled")
}

func validateRuleContext(config normalizedSystemConfig, context sysnet.RuleContext) *sysnet.ValidationIssue {
	if (context.Routing == nil) == (context.Matcher == nil) {
		issue := validationIssue("Rule.Context", 0, "", "exactly one rule context must be set", sysnet.ErrInvalidOptions)
		return &issue
	}
	if context.Routing != nil {
		key := *context.Routing
		if key.Family != sysnet.FamilyIPv4 && key.Family != sysnet.FamilyIPv6 && key.Family != sysnet.FamilyDual {
			issue := validationIssue("Rule.Context.Routing.Family", 0, "", "routing family is not valid", sysnet.ErrInvalidOptions)
			return &issue
		}
		if issue := validateCapabilityFamily(config, key.Family, "Rule.Context.Routing.Family"); issue != nil {
			return issue
		}
		if key.Mode != sysnet.RoutingFull && key.Mode != sysnet.RoutingExclude && key.Mode != sysnet.RoutingInclude {
			issue := validationIssue("Rule.Context.Routing.Mode", 0, "", "routing mode is not valid", sysnet.ErrInvalidOptions)
			return &issue
		}
		return nil
	}
	key := *context.Matcher
	if key.Family != sysnet.FamilyIPv4 && key.Family != sysnet.FamilyIPv6 {
		issue := validationIssue("Rule.Context.Matcher.Family", 0, "", "matcher family must be IPv4 or IPv6", sysnet.ErrInvalidOptions)
		return &issue
	}
	if issue := validateCapabilityFamily(config, key.Family, "Rule.Context.Matcher.Family"); issue != nil {
		return issue
	}
	if key.Transport != sysnet.TransportTCP && key.Transport != sysnet.TransportUDP {
		issue := validationIssue("Rule.Context.Matcher.Transport", 0, "", "matcher transport must be TCP or UDP", sysnet.ErrInvalidOptions)
		return &issue
	}
	return nil
}

func validateWindowsExecutablePath(value string) *sysnet.ValidationIssue {
	if strings.HasPrefix(value, `\\`) {
		issue := validationIssue("Rule.Rule", sysnet.CapabilityUnsupported, sysnet.ReasonUnsupportedCombination, "UNC executable paths are not supported", nil)
		return &issue
	}
	if strings.ContainsAny(value, "*?[]") {
		issue := validationIssue("Rule.Rule", 0, "", "executable path must not contain a pattern", sysnet.ErrInvalidOptions)
		return &issue
	}
	if len(value) < 4 || !isASCIILetter(value[0]) || value[1] != ':' || (value[2] != '\\' && value[2] != '/') {
		issue := validationIssue("Rule.Rule", 0, "", "executable path must be an absolute local drive path", sysnet.ErrInvalidOptions)
		return &issue
	}
	return nil
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func validateFamily(config normalizedSystemConfig, address netip.Addr, path string) *sysnet.ValidationIssue {
	family := sysnet.FamilyIPv6
	if address.Is4() {
		family = sysnet.FamilyIPv4
	}
	return validateCapabilityFamily(config, family, path)
}

func validateCapabilityFamily(config normalizedSystemConfig, family sysnet.AddressFamily, path string) *sysnet.ValidationIssue {
	available := family == sysnet.FamilyIPv4 && config.ipv4 ||
		family == sysnet.FamilyIPv6 && config.ipv6 ||
		family == sysnet.FamilyDual && config.ipv4 && config.ipv6
	if available {
		return nil
	}
	issue := validationIssue(path, sysnet.CapabilityUnsupported, sysnet.ReasonAddressFamilyUnavailable, "address family is disabled", nil)
	return &issue
}

func familyForPrefixes(groups ...[]netip.Prefix) sysnet.AddressFamily {
	hasIPv4 := false
	hasIPv6 := false
	for _, prefixes := range groups {
		for _, prefix := range prefixes {
			hasIPv4 = hasIPv4 || prefix.Addr().Is4()
			hasIPv6 = hasIPv6 || prefix.Addr().Is6()
		}
	}
	switch {
	case hasIPv4 && hasIPv6:
		return sysnet.FamilyDual
	case hasIPv4:
		return sysnet.FamilyIPv4
	case hasIPv6:
		return sysnet.FamilyIPv6
	default:
		return sysnet.FamilyNone
	}
}

func prefixesContainIPv6(prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

func validationIssue(path string, state sysnet.CapabilityState, reason sysnet.CapabilityReason, detail string, err error) sysnet.ValidationIssue {
	return sysnet.ValidationIssue{Path: path, State: state, Reason: reason, Detail: detail, Err: err}
}

func invalidReport(path, detail string, cause error) sysnet.ValidationReport {
	return sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{validationIssue(path, 0, "", detail, invalidCause(cause))}}
}

func unsupportedReport(path string, reason sysnet.CapabilityReason, detail string) sysnet.ValidationReport {
	return sysnet.ValidationReport{Issues: []sysnet.ValidationIssue{validationIssue(path, sysnet.CapabilityUnsupported, reason, detail, nil)}}
}

func joinReports(reports ...sysnet.ValidationReport) sysnet.ValidationReport {
	result := sysnet.ValidationReport{}
	for _, report := range reports {
		if report.CapabilityRevision > result.CapabilityRevision {
			result.CapabilityRevision = report.CapabilityRevision
		}
		result.Issues = append(result.Issues, report.Issues...)
	}
	return result
}

func repathReport(report sysnet.ValidationReport, oldPrefix, newPrefix string) sysnet.ValidationReport {
	for index := range report.Issues {
		report.Issues[index].Path = strings.Replace(report.Issues[index].Path, oldPrefix, newPrefix, 1)
	}
	return report
}
