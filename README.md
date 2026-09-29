# sysnet-windows

Windows network integration for `github.com/asciimoth/gonnect`.

The root package implements host-aware allocation, regular Wintun ownership,
underlay selection, the outbound network bypass, and confined local networking.
Later milestones will add the default TUN, managed DNS, matchers, and
application exclusions. The repository also contains the locked development
environment and Windows test harness for the work in
[`docs/sysnet-windows-implementation-testing-plan.md`](docs/sysnet-windows-implementation-testing-plan.md).

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

OutNet resolves names through `System.OutDNS`. At this milestone, OutDNS uses
the host DNS server list that exists before managed DNS takeover. The managed
DNS milestone will replace this discovery path with saved underlay DNS state.

## Local network

`System.LocalNet` supports native TCP and UDP sockets only on IPv4 and IPv6
loopback. It resolves names before socket creation and rejects the complete
result if any address is outside loopback. Listener wildcard addresses become an
explicit `127.0.0.1` or `::1` bind, so they do not expose a service on a
physical or TUN interface.

LocalNet tracks listeners, accepted TCP connections, and UDP sockets as System
resources. `System.Close` closes them, and new operations fail after close
starts. LocalNet is separate from the private listener that a later managed DNS
implementation can bind to a TUN-owned DNS address.

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
