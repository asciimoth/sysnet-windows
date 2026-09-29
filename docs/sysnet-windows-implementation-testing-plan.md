# sysnet-windows: remaining work

These items are not required for the initial release. Keep their capability
entries unavailable until implementation and capability-specific tests are
complete.

## Include-only application routing

Implement application inclusion without approximating it by excluding all other
executables. Define driver ownership, process-tree behavior, DNS behavior, and
packet paths for included and non-included processes. Add independent IPv4,
IPv6, and dual-stack packet captures before the capability is enabled.

## Strict routing

Add explicit WFP policy for tunnel traffic, necessary service traffic, DNS,
loopback, DHCP, IPv6 neighbor discovery, and the selected LAN policy. Define how
exclusions interact with strict routing. Live strict routing and a persistent
boot-time kill switch are separate features and require separate recovery tests.

## Preferred-source routes

Add a Windows implementation for `SourceRoutes` only if it can preserve the
contract's per-destination source selection. Ordinary Windows route rows do not
provide this behavior. Continue to reject this option before host mutation until
a suitable implementation exists.

## Dynamic default-TUN updates

Support default-TUN address, route, DNS-address, and MTU setters only after each
change reconciles the adapter, DNS proxy, Windows DNS state, split-driver
address roles, and rollback journal as one policy update. The initial
implementation requires a default-TUN rebuild for these changes.

## Multicast bypass

Define and test multicast membership, redirected binds, interface selection, and
excluded-process behavior. Do not advertise general multicast support until
packet-flow tests cover each supported socket operation and address family.

## Adapter rename

Implement rename only if stable ownership and recovery can be preserved across
the Windows adapter-name change. Continue to return `sysnet.ErrNotSupported`
before mutation until then.

## Stronger DNS policy

Possible extensions include NRPT and suffix-search compatibility, native
encrypted DNS, DNS-port enforcement, and explicitly scoped application DoH or
DoT behavior. Each extension must state whether it configures DNS or enforces an
exclusive DNS path. Do not claim per-application attribution for requests sent
by the shared Windows DNS Client service.

## Richer ownership attribution

Possible extensions include improved wildcard UDP attribution, more process
metadata, and additional rule types. Unknown or ambiguous ownership must remain
an error. Do not use best-effort ownership matching as a security boundary.

## Support-matrix expansion

Qualify additional Windows builds, Windows 10, other Windows Server releases, or
more deployment configurations only through new matrix entries. Dedicated host
testing can extend claims for sleep and resume, physical-adapter changes, Secure
Boot, and endpoint-security or firewall coexistence.

## Performance work

Measure Wintun batching, copying, DNS proxy load, owner-cache cost, and
sustained throughput before publishing performance targets. Performance changes
must keep the existing cleanup, packet fidelity, and resource-growth gates.
