# sysnet-windows

Windows network integration for `github.com/asciimoth/gonnect`.

The root package implements host-aware allocation, regular and default Wintun
ownership, underlay selection, the outbound network bypass, confined local
networking, Windows DNS ownership, the local managed-DNS proxy, and executable
tree exclusions. The repository also contains the locked development environment
and Windows test harness for the work in
[`docs/sysnet-windows-implementation-testing-plan.md`](docs/sysnet-windows-implementation-testing-plan.md).

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

`System.OutNet` binds each TCP or UDP socket to the selected IPv4 or IPv6
underlay before bind or connect. It supports the generic and typed dial,
listener, and packet methods in `gonnect.Network`. Returned sockets, listeners,
and accepted TCP connections belong to the System and close during
`System.Close`. New operations fail after close starts. `IsNative` is false so a
caller cannot bypass binding, DNS routing, or resource tracking.

Use an explicit `tcp4`, `tcp6`, `udp4`, or `udp6` network for a wildcard local
address. OutNet rejects ambiguous generic wildcards, IPv4-mapped IPv6 addresses,
raw sockets, and multicast. An explicit local address must equal the selected
underlay source. Loss of the selected underlay makes new operations fail; there
is no unbound retry.

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

This configuration is not a system-wide DNS enforcement boundary.
`DefaultTunWarnings` returns `default_tun_dns_route_not_exclusive` for each
active default TUN. The System changes only the name-server field on its own
adapter. It does not change DNS settings on other interfaces, the suffix search
list, NRPT, encrypted-DNS policy, or application-owned DoH/DoT. Windows can use
those paths, and a more-specific route can take priority over a default route.
No per-application behavior is claimed for requests sent through the shared
Windows DNS Client service. A process which sends DNS itself can use a separate
path.

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

The shell pins Go 1.25.5, installs the Go, documentation, Nix, shell, and CI
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
