# Integration guide

## Deployment inputs

The Go module does not install drivers. Deploy an architecture-matched Wintun
DLL before an application creates a TUN. Executable-tree exclusions also require
the compatible signed split-driver package recorded in
`dev/winvm/native-driver-lock.json`.

TUN, route, DNS, WFP, and driver-service operations can require an elevated
service identity. Treat the split driver as a global exclusive resource. Two
independent controllers cannot safely own the stock driver at the same time.

## Create and close a System

The zero configuration enables IPv4 and IPv6:

```go
package main

import (
    "log"

    windows "github.com/asciimoth/sysnet-windows"
)

func main() {
    system, err := windows.New(windows.SystemConfig{})
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        if err := system.Close(); err != nil {
            log.Printf("close Windows network system: %v", err)
        }
    }()

    report := system.Capabilities()
    _ = report
}
```

Construction performs validation and read-only probes. It registers network
change monitoring, but it does not install a driver or create a TUN. Native
resources are acquired by later operations.

Call `Close` and check its error. Close stops workers, closes tracked sockets
and TUNs, and restores owned networking state. A cleanup error can put the
System in the recovery-required state. A later `Close` call retries bounded
in-process cleanup after ownership checks.

## Configuration and capabilities

`SystemConfig` controls the adapter-name prefix, optional stable adapter GUID,
preferred underlay, enabled address families, optional exclusions and matchers,
operation timeout, recovery policy, and logger.

Read `Capabilities` before offering optional operations. Use `CheckTunOpts`,
`CheckDefaultTunOpts`, and `CheckRule` before a build. Build operations validate
again immediately before native mutation because host state can change between
validation and application.

A missing or busy split driver affects executable exclusions. It does not make
regular TUNs, ordinary default routing, OutNet, LocalNet, or ownership matchers
unavailable.

## Regular and default TUNs

`BuildTun` creates a System-owned regular Wintun device. Regular TUN address,
destination-route, and MTU getters and setters reconcile exact owned state.
Foreign adapter resources are not flushed or adopted.

`BuildDefaultTun` creates full routing, the managed DNS proxy, Windows DNS
configuration, and optional executable exclusions. Building a replacement
default TUN can close the previous one after validation. If replacement fails
after retirement, no active default TUN can remain.

Default-TUN address, route, DNS-address, and MTU changes require a rebuild. The
regular-TUN setters reject a default-TUN handle instead of applying a partial
policy update. `SetDNS` is different: it atomically replaces the managed DNS
provider, and `SetDNS(nil)` drops managed requests.

Only pass TUN objects returned by the same System. Foreign, stale, and retired
objects return `sysnet.ErrUnknownTun` and do not cause host mutation.

## OutNet and OutDNS

Use `OutNet` for transport that must bypass the default TUN. It binds TCP and
UDP sockets to the selected family-specific underlay before bind or connect.
There is no unrestricted fallback. New operations fail when the selected
underlay is unavailable.

Use an explicit `tcp4`, `tcp6`, `udp4`, or `udp6` network with a wildcard local
address. Explicit local addresses must match the selected underlay source.
OutNet rejects raw sockets, multicast, ambiguous generic wildcards, and
IPv4-mapped IPv6 addresses.

OutNet hostname operations use `OutDNS`. OutDNS discovers numeric DNS servers
from the current underlay and sends DNS traffic through bound OutNet sockets. It
does not call the Windows host resolver, which prevents recursion after managed
DNS takeover.

## LocalNet

`LocalNet` supports TCP and UDP on IPv4 and IPv6 loopback. It resolves names
before socket creation and rejects the complete result if any address is not
loopback. Wildcard listeners become an explicit loopback bind.

Sockets, listeners, and accepted connections returned by OutNet and LocalNet
belong to the System. They close during `System.Close`, and new operations fail
after close starts.

## Rules and matchers

Default-TUN exclusions accept `win-exe-tree` rules only in non-strict exclude
mode. Paths are absolute local drive-letter paths. The controller applies exact
executable identity and descendant inheritance. Each default-TUN build applies
the complete exclusion policy.

`BuildMatcher` supports `win-pid` and `win-exe-path` for TCP and UDP ownership.
Matching is best effort. Short-lived sockets, PID reuse, wildcard or shared UDP
sockets, protected processes, and exited processes can return unknown or
ambiguous ownership errors.

## DNS ownership

The managed proxy listens on the effective default-TUN DNS address on UDP and
TCP port 53. A port conflict makes the build fail before default routes are
published.

The System saves and verifies the DNS state that it changes. Close restores the
previous DHCP mode or static values only when the current state still matches
the System's applied value. It does not overwrite an external edit made while
the TUN is active.

Check `DefaultTunWarnings`. The `default_tun_dns_route_not_exclusive` warning
states that interface DNS configuration is not a system-wide DNS enforcement
boundary.

## Threading and errors

Public network operations and independent socket operations can run
concurrently. Policy mutations are serialized. Do not call a System or its
network wrappers after close starts except to retry `Close` for recovery.

Preserve returned errors. Validation errors identify the rejected field and
retain `sysnet.ErrInvalidOptions` or `sysnet.ErrNotSupported`. Cleanup can
return joined errors when both the primary operation and rollback fail.
