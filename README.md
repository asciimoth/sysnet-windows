# sysnet-windows

Windows network integration backend for `github.com/asciimoth/gonnect`.\
[sysnet-linux](https://github.com/asciimoth/sysnet-linux) provides a linux
backend for same interface.

> [!WARNING]
> This project is experimental. APIs and behavior can change without notice. Do
> not use it for production systems without your own review and tests.

The root package implements host-aware allocation, regular and default Wintun
ownership, underlay selection, the outbound network bypass, confined local
networking, Windows DNS ownership, the local managed-DNS proxy, and executable
tree exclusions. The repository also contains the locked development environment
and Windows test harness for the work in
[`docs/sysnet-windows-implementation-testing-plan.md`](docs/sysnet-windows-implementation-testing-plan.md).

## Support status

The initial release scope is implemented and qualified on these matrix entries:

| Platform            | Architecture | Status    |
| ------------------- | ------------ | --------- |
| Windows Server 2022 | amd64        | Qualified |
| Windows 11          | amd64        | Qualified |
| Windows 11          | arm64        | Qualified |

Regular and default TUNs, IPv4 and IPv6 destination routing, OutNet, LocalNet,
managed DNS, non-strict executable-tree exclusions, and best-effort ownership
matchers are supported. Include-only routing, strict routing, preferred-source
routes, multicast bypass, and adapter rename are not supported.

See the [integration guide](docs/integration.md),
[limitations](docs/limitations.md), [validation status](VALIDATION.md), and
[remaining optional work](docs/sysnet-windows-implementation-testing-plan.md)
for the detailed contract.

## Installation

Add the Go module to the application and deploy an architecture-matched
`wintun.dll`. The module does not install drivers. Applications that use
executable-tree exclusions must also deploy the compatible signed split-driver
package recorded in `dev/winvm/native-driver-lock.json`. Native networking and
driver operations can require an elevated service identity.

## Basic use

The zero configuration enables IPv4 and IPv6. Inspect capabilities before the
application offers optional operations:

```go
system, err := windows.New(windows.SystemConfig{})
if err != nil {
    return err
}

capabilities := system.Capabilities()
_ = capabilities

if err := system.Close(); err != nil {
    return err
}
return nil
```

Always check the `Close` error in production code. It reports cleanup failures
and recovery-required state. See the integration guide for complete lifecycle,
TUN, DNS, and error-handling requirements.

## Ownership matchers

`System.BuildMatcher` supports `win-pid` and `win-exe-path` for IPv4 and IPv6
TCP and UDP flows. These matchers use best-effort Windows socket ownership.
Lookup failure, ambiguous ownership, and inaccessible executable metadata are
errors, not confirmed nonmatches. PID rules do not require executable metadata.

Executable paths use exact, Unicode case-insensitive matching after lexical
drive-letter path normalization. Hard links remain distinct paths. UNC,
extended/device, relative, glob, alternate-stream, and ambiguous Win32 path
forms are rejected during validation. This feature identifies an observed flow;
it is not a routing enforcement boundary.

## Outbound network

`System.OutNet` binds TCP sockets and non-loopback UDP sockets to the selected
IPv4 or IPv6 underlay before bind or connect. A UDP loopback destination stays
on the host loopback path. A wildcard UDP endpoint uses one logical port for its
loopback and selected-underlay paths. It does not use the loopback socket as an
external fallback. It supports the generic and typed dial, listener, and packet
methods in `gonnect.Network`. Returned sockets, listeners, and accepted TCP
connections belong to the System and close during `System.Close`. New operations
fail after close starts. `IsNative` is false so a caller cannot bypass binding,
DNS routing, or resource tracking.

Use an explicit `tcp4`, `tcp6`, `udp4`, or `udp6` network for a wildcard local
address. OutNet rejects ambiguous generic wildcards, IPv4-mapped IPv6 addresses,
raw sockets, and multicast. An explicit non-loopback local address must equal
the selected underlay source. A direct UDP loopback operation can use a loopback
local address. Loss or replacement of the selected underlay makes new operations
and external writes from wildcard UDP endpoints fail. There is no unbound
external retry.

OutNet resolves names through `System.OutDNS`. OutDNS reads numeric servers from
the currently selected underlay interfaces for each request, excludes the
managed proxy address, and sends UDP and TCP DNS traffic through bound OutNet
sockets. It does not use the Windows host resolver and cannot loop back through
the managed proxy after DNS takeover.

## Managed DNS proxy

A default TUN binds a private DNS proxy to its effective `DnsIP` on UDP and TCP
port 53 before it publishes default routes. `DefaultTun.SetDNS` atomically
replaces the caller-owned provider. `SetDNS(nil)` drops managed requests and
does not use the host resolver as a fallback. Closing the default TUN cancels
active requests, closes both listeners, and waits for proxy workers.

Before default routes are published, the System records the adapter's DNS mode
and server values, configures its effective `DnsIP`, and verifies the result.
Close restores static values or DHCP mode only if the current state still
matches the System's write. An administrator, DHCP, or another VPN change made
while the TUN is active is not overwritten.

This configuration is not a system-wide DNS enforcement boundary. The System
changes only the name-server field on its own adapter. It does not change DNS
settings on other interfaces, the suffix search list, NRPT, encrypted-DNS
policy, or application-owned DoH/DoT. Windows can use those paths, and a
more-specific route can take priority over a default route. No per-application
behavior is claimed for requests sent through the shared Windows DNS Client
service. A process which sends DNS itself can use a separate path.

The proxy must own UDP and TCP port 53 on its TUN address. A port conflict makes
the build fail before default routes are published. OutDNS returns an observable
no-upstream error if the selected underlays provide no usable numeric server; it
does not fall back to the host resolver. Graceful close and retryable in-process
recovery are tested. The disposable Windows gate also exits a child process
without Go cleanup, then opens Wintun again and requires its recovery scan to
remove the abandoned adapter identity before the name can be reused with a new
GUID. The route and DNS state is interface-scoped to that abandoned identity.

## Executable exclusions and recovery

A default TUN can apply non-strict `win-exe-tree` exclusions through the pinned
split driver. The driver is global and exclusive. The System verifies the
installed package and clean driver state before it creates caller-owned WFP
objects. It does not reset state that belongs to an unknown owner.

Close first stops the split event reader. It then resets the driver with a new,
bounded context and reads the driver state before it removes the exact WFP
objects in its journal. A failed reset, Zombie state, changed driver package, or
unverified WFP deletion keeps that journal and changes the System state to
recovery-required. Routes, DNS, sockets, and TUN state still use their own
cleanup rules and are not kept only because split cleanup failed.

Call `System.Close` again to request in-process recovery. Before a retry changes
native state, it verifies the recorded WFP objects, driver package and service
identity, and current driver state. Recovery is bounded and does not loop on a
Zombie driver. Each call returns all observed cleanup errors.

The packet-flow release gate first runs the pinned controller's nine address
mode conformance suite. It then creates the default TUN only through `New` and
`BuildDefaultTun` and tests the IPv4-only, IPv6-only, and dual-stack exclusion
profiles. Each profile covers included, excluded, newly created descendant, and
pre-existing IPC-target processes. Each absence assertion has an immediately
preceding positive control on the opposite captured link. The independent
validator rejects missing profiles, roles, families, controls, and markers on
the wrong link. Direct application DNS and the shared Windows DNS Client path
are separate evidence cases. Shared resolver traffic is attributed to the DNS
Client and managed proxy path, not to the process that requested the lookup.

## Local network

`System.LocalNet` supports native TCP and UDP sockets only on IPv4 and IPv6
loopback. It resolves names before socket creation and rejects the complete
result if any address is outside loopback. Listener wildcard addresses become an
explicit `127.0.0.1` or `::1` bind, so they do not expose a service on a
physical or TUN interface.

LocalNet tracks listeners, accepted TCP connections, and UDP sockets as System
resources. `System.Close` closes them, and new operations fail after close
starts. LocalNet is separate from the private managed-DNS listener on the
TUN-owned DNS address.

## Development

Enter the pinned shell, then run the portable gate:

```console
nix develop
just check-fast
```

The shell pins Go 1.25.14, installs the Go, documentation, Nix, shell, and CI
tools, and exposes verified split-driver and Wintun inputs for both supported
architectures. `just check-fast` does not start a guest or change networking.
Use `just` to list all commands.

Windows cross-builds include production packages and each package that has Go
tests. Native Windows tests use `dev/winvm/test.ps1` and do not need Nix.

## Disposable Windows tests

The QEMU/KVM harness needs a Linux amd64 host and developer-supplied Windows
Server and VirtIO media. See [`dev/winvm/README.md`](dev/winvm/README.md) for
setup and safety requirements.

```console
cp dev/winvm/env.example dev/winvm/env
just winvm-input-hashes
just winvm-doctor
just winvm-image
just test-windows-vm
```

The live-driver gate is part of `just check`. `just test-windows-flow` runs the
M2 packet-flow gate. It creates a System-owned Wintun with disposable IPv4 and
IPv6 default routes, pumps its packets over the isolated tunnel link, and proves
that each OutNet socket operation uses the underlay link. It also removes the
selected underlay during live traffic and rejects a run if new traffic falls
back to the tunnel. A missing required test is not reported as a successful
qualification.

`just check` is the routine gate and intentionally omits the slow resource and
packet-flow suites. Run `just check-release` for release qualification. The
privileged and long-running gates run manually on disposable systems; they are
not part of routine GitHub Actions CI.
