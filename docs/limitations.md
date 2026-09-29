# Limitations

## Platform and deployment scope

The qualified matrix contains Windows Server 2022 amd64, Windows 11 amd64, and
Windows 11 arm64. An API minimum, a successful cross-build, or an unprivileged
test does not qualify another Windows release.

The application must provide architecture-matched Wintun inputs. Executable
exclusions require the compatible signed split-driver package. Native networking
and driver operations can require elevation.

The stock split driver is global and exclusive. It does not support independent
simultaneous ownership by multiple VPN controllers. Renaming its service does
not create an independent driver instance.

## Unsupported routing features

Include-only application routing, strict routing, preferred-source routes,
adapter rename, and multicast bypass are unsupported. Requests are rejected
before native mutation. Default routing is not a leak-prevention or persistent
kill-switch contract.

More-specific LAN, enterprise, or other VPN routes can take priority over a
non-strict default route. An automatically selected non-owned underlay can
itself be another VPN. Use `UnderlaySelector` when the integration requires a
preferred interface.

Default-TUN address, route, DNS-address, and MTU changes require rebuilding the
default TUN. Existing flows can stop or require reconnection after policy or
underlay changes. Transparent flow migration is not supported.

## DNS scope

Managed interface DNS is not system-wide DNS enforcement. The implementation
does not control other interface DNS settings, suffix search, NRPT, native
encrypted DNS, application DoH or DoT, or every resolver implementation.

The shared Windows DNS Client service prevents reliable attribution of one DNS
request to the application that requested it. An excluded application's normal
Windows resolver traffic therefore has no per-application bypass guarantee. An
application-owned resolver is a separate path.

`SetDNS(nil)` drops managed requests. It does not select an unbound fallback.
OutDNS also returns an error when the underlay has no usable numeric upstream.

## Executable rules

`win-exe-tree` uses exact local Windows executable paths and descendant
inheritance. UNC paths, relative paths, globs, regular expressions, alternate
data streams, and device or extended path forms are unsupported.

Hard links are separate identities. Rename, replacement, junction, or volume
mapping changes can require a policy update. A pre-existing browser or service
process reached through IPC is not a descendant only because an excluded process
uses it. Conversely, child inheritance can affect tools launched by an excluded
application.

## Ownership matchers

Socket ownership is best effort and is not a security boundary. UDP ownership
lacks a remote endpoint in the Windows table. Wildcard or shared ports,
short-lived sockets, PID reuse, inaccessible processes, fragments, and ICMP can
produce unknown or ambiguous results.

A successful matcher result identifies an observed socket owner. It does not
prove that kernel routing enforcement selected the expected packet path.

## Local and multicast traffic

LocalNet supports explicit IPv4 and IPv6 loopback TCP and UDP behavior. Excluded
third-party applications that use an unbound UDP socket can still have problems
with localhost communication. LocalNet cannot correct every external
application's bind behavior.

General multicast bypass is not supported. Redirected binds and multicast
membership can select different interfaces on Windows.

## Cleanup and recovery

Cancellation of a native driver operation does not prove rollback. The System
uses readback and retains its ownership journal when the result is uncertain. A
reset failure or Zombie driver state can require an explicit recovery retry.

The controller's local `Close` does not by itself prove that driver policy was
reset. The System preserves referenced WFP objects when safe deletion cannot be
verified and reports recovery-required state.

## Performance

Wintun buffering, packet copies, DNS proxy work, and ownership lookup costs
differ from the Linux backend. The project does not publish Linux-equivalent
throughput or latency guarantees.
