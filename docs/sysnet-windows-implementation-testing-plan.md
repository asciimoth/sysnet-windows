# sysnet-windows: implementation and testing plan

Status: proposed work, not a completed implementation or qualification report.
Prepared 2026-09-26.

## 1. Goal, baseline, and initial release boundary

Build `github.com/asciimoth/sysnet-windows`, implementing `gonnect/sysnet.System`
and the optional capability interfaces proposed in the companion document.
Keep the VPN packet transport and protocol outside this library. The library
owns local networking integration, configuration, reconciliation, and cleanup.

The initial release should support regular and default Wintun devices,
IPv4/IPv6 addresses and destination routes, outbound bypass, local networking,
DNS integration, executable-tree exclusions, and best-effort TCP/UDP matchers.
Include-only application routing, strict mode, preferred-source routes,
multicast bypass, and adapter renaming may remain explicitly unsupported.
Enable families and combined profiles only after their acceptance tests pass.

The inspected source baseline is:

| Repository | Revision | Relevant material |
| --- | --- | --- |
| asciimoth/gonnect | `260fb7b56c218f267f55bfd271a7ab4eff615977` | sysnet contract, Network contract, Windows sockowner/sockopt |
| asciimoth/sysnet-linux | `2b846deee13b5e3faa0b09a87f0a551b2c8c1b14` | dependency injection, normalization, reconciliation, DNS tests, flake and justfile |
| asciimoth/mullvad-split-tunnel-go | `f5db35e093d7be835882cbf68911f83be1cdacff` | controller, integration guide, VM harness, locks, qualification records |
| asciimoth/tuntap | `c77bd95431d175227c37a89cb40d0e7f9ff3838d` | existing Windows Wintun implementation returning `gonnect/tun.Tun` |

These are reviewed inputs, not instructions to permanently freeze every
dependency. Record chosen module versions and source revisions in the new
repository. Dependency upgrades require rerunning the affected gates.

Use the existing controller's accepted Windows Server 2022 amd64 and Windows 11
arm64 configurations as starting test environments. Add a Windows 11 amd64
desktop qualification entry before claiming desktop amd64 support. The DNS API
baseline can be Windows build 19041+, but an API minimum is not a tested support
matrix. Do not advertise Windows 10 or arbitrary Server versions without tests.

## 2. Components and responsibilities

| Proposed package/file area | Responsibility | Main dependency |
| --- | --- | --- |
| Root `windows` package | `System`, configuration, public lifecycle, object ownership, capabilities, validation | gonnect/sysnet |
| `internal/tun` | Wintun factory/adaptor, native identity, MTU/event integration | asciimoth/tuntap |
| `internal/netio` | Address, route, interface metric and MTU operations | wireguard/windows/tunnel/winipcfg; x/sys/windows |
| `internal/underlay` | Select current non-owned routes/interfaces per family; process change notifications | winipcfg callbacks |
| `internal/network` | OutNet/LocalNet wrappers, all socket entry points, resolver and resource tracking | gonnect NativeConfig; Winsock options |
| `internal/dns` | Local server, upstream selection, interface configuration and restoration | gonnect/dns; NetIO DNS APIs |
| `internal/wfp` | Caller-owned sublayers, later firewall/DNS enforcement, recovery inventory | tailscale/wf and narrow native wrappers |
| `internal/split` | Adapt controller lifecycle, path policy and events | mullvad-split-tunnel-go |
| `internal/owner` | PID/path enrichment, bounded lookup cache, matcher compilation | gonnect/sockowner; process APIs |
| `internal/allocator` | Shared reservations and host-address/subnet conflict filters | gonnect/subnet |
| `internal/reconcile` | Serialized desired-state transitions, owned-resource journal and rollback | injected interfaces |
| `cmd/debug` | Readable capabilities, validation, current warnings and explicit lifecycle exercises | root package |
| `integration`, `dev/winvm` | Privileged native and independent packet-path tests | adapted controller harness |

Keep platform-neutral policy/model code buildable on Linux for fast tests and
the race detector. Put actual Windows calls behind `//go:build windows` and
supported-architecture constraints. Provide an unsupported-platform constructor
stub so module tests/builds remain meaningful on other hosts.

Use `New(SystemConfig)` for normal integrations and an injectable constructor
for tests, following sysnet-linux's pattern. Suggested dependencies include
TUNFactory, NetIO, UnderlaySource, DNSConfigurator, SplitController, WFPManager,
OwnerLookup, Clock and Logger. Inject behavior at OS boundaries, not every small
helper function. Avoid starting goroutines from package initialization.

The main implementation can remain Go using existing signed drivers. Do not
require the Windows Driver Kit for ordinary library builds. Custom driver work
is a separate project if include-only routing or stronger attribution becomes
necessary later.

## 3. Public behavior and implementation work

### 3.1 Configuration and feature negotiation

Add `var _ sysnet.System = (*System)(nil)` and assertions for implemented
optional capability/validator interfaces. Keep exact current signatures,
including `GetTunRotue` and `SetTunName`.

Configuration should distinguish desired features from effective capabilities.
Recommended options: adapter naming prefix/stable GUID policy, optional
underlay selector, DNS upstream policy, split-controller factory, feature
enable/disable settings, logger, operation timeouts, and recovery policy.
Do not install or replace drivers as a surprise side effect of `New`.

Prefer lazy acquisition of the exclusive split driver when exclusions are first
needed. Missing split support must not prevent regular TUN creation, full
routing, or socket matchers. `Capabilities()` is a cached snapshot; unknown
ownership is resolved by an explicit operation, not by a UI polling the getter.

Validation and construction must share normalization. Reject nonempty Include,
unsupported Strict, SourceRoutes, wrong-context rules, and unsupported families
before network changes. Ignore loopback addresses/routes where the current
contract requires it. Normalize MTU and DnsIP exactly once; return the same
effective behavior from validation and construction. Address selection may race
host changes, so recheck immediately before applying.

Do not silently omit an unsupported exclusion or IP family to make a build pass.
Return actionable typed errors with preserved Windows/controller causes.

### 3.2 Ownership, reconciliation, and concurrency

One System instance owns its TUN registry, underlay snapshot, default-TUN policy,
network wrappers, and controller session. Serialize mutations through one policy
owner. Network callbacks queue reconciliation work and return quickly; do not
call arbitrary user code or block on native mutation while holding global locks.

Maintain desired state separately from observed state and an exact inventory of
created/changed resources. Track TUN GUID/LUID/index, address and route keys,
WFP provider/sublayer/filter identifiers, DNS previous/applied values, and driver
ownership/recovery state. LUID/index are current-instance identifiers, not a
durable identity across all recreations; use stable ownership metadata plus
current observations for recovery.

Use per-resource journals and reverse-order cleanup. Native subsystems do not
share one transaction. On a partial failure, either restore the previous valid
configuration or enter an explicit failed/recovery-required state. Return joined
errors if cleanup also fails. Do not return the old object as healthy after a
failed replacement unless its policy was actually restored.

Initially, a repeated `BuildDefaultTun` may close and replace the previous
default TUN, as permitted by the interface. Validate before retiring it. Document
that a later apply failure can leave no active default TUN and restore the prior
system configuration. Leave `reconfigure_in_place` unsupported until updates
really preserve the native device for supported changes. Linux's stable wrapper
and source-generation extension do not have to be copied into the first release.

`System.Close` must cancel/join owned workers, close tracked connections/listeners
and TUNs, and restore owned networking state. It must be idempotent. Plain
`gonnect.Network` is not itself an `io.Closer` contract; use private closable
wrappers and a resource registry. A fresh operation through a closed wrapper
must fail, not create an untracked socket.

### 3.3 TUN and NetIO

Reuse `tuntap.CreateTUNWithRequestedGUID` and its Windows LUID access. Configure
addresses with unicast-address APIs, routes with IP-forward APIs, and IP-family
MTU/metric settings with IP-interface APIs, preferably through winipcfg.

Important adapter details:

- `NativeTun.ForceMTU` updates reported state/event delivery; it is not a
  substitute for changing the Windows IP-interface MTU. Coordinate both.
- Preserve the actual `BatchSize`, MRO and MWO contract; consumers must allocate
  buffers accordingly. Wintun has no usable Unix-style packet file descriptor.
- Verify close unblocks reads and makes future I/O match `os.ErrClosed`.
- Respect the implementation's read/write concurrency assumptions. Review
  MTU/event updates and close races in the wrapper; harden tuntap if necessary.
- If a wrapper intercepts required packets or metadata, report native status
  according to whether bypassing its methods would bypass required behavior.
- Wait for usable addresses with a deadline; do not treat an asynchronous
  address-install success as proof that source selection is ready.

Diff desired owned addresses/routes. Delete exact owned rows, never flush a
physical adapter's route/address table. Leave unrelated routes and interfaces
untouched. Route preference includes interface metric plus route metric.
Retain the underlying default routes needed by bound outbound sockets and
excluded applications. More-specific LAN/enterprise routes can remain preferred
under non-strict default routing; document this.

Regular TUN address/route/MTU setters and getters are achievable in the first
release. Default-TUN updates must also reconcile DNS and split-driver addresses;
until this is complete, reject their setters rather than mutate only the adapter.
Keep rename unsupported initially. Keep per-destination preferred-source routes
unsupported: Windows ordinary route rows do not supply the required equivalent.

Use host-aware allocation filters that consider Hyper-V/WSL/other VPN interface
subnets and this System's reservations. Avoid treating a catch-all default route
as a conflict with every possible allocation. Recheck candidates at application
time and surface enumeration failures instead of assuming a conflict-free host.

### 3.4 Underlay selection and outbound bypass

Select one effective underlying interface/address per IP family. Exclude every
TUN owned by this System. Account for operational state, route destination,
route+interface metric, address usability, and scope. A configurable explicit
selector helps integrations with another VPN; another non-owned VPN adapter is
not automatically a physical Internet path.

Subscribe to interface, unicast-address and route changes, debounce bursts,
then rebuild a coherent snapshot. Avoid feedback loops from the routes the
backend itself creates. The selected IPv4 and IPv6 underlays may be different.
Do not keep sending with a stale index after interface recreation.

Build a raw-socket helper used before bind/connect:

- IPv4: set `IP_UNICAST_IF` with network-byte-order interface index.
- IPv6: set `IPV6_UNICAST_IF` with host-byte-order interface index.
- Supply/validate the source address where required for the operation.
- Propagate failures. No unrestricted dial fallback is permitted.

The current gonnect Windows `SetBindToInterface` helper expects `net.Conn` and
cannot directly serve the pre-connect `syscall.RawConn` hook. Add the helper in
this backend or as a focused gonnect contribution.

Cover `Dial`, `DialTCP`, `DialUDP`, `PacketDial`, `Listen`, `ListenTCP`,
`ListenUDP`, `ListenPacket`, and the configured UDP/packet-listen variants.
Support UDP packet connections only if subsequent writes to arbitrary remote
endpoints retain the intended interface policy. Reject conflicting local
addresses, family mismatches, and unsupported multicast/raw operations. Compose
caller control hooks without allowing them to override the required final
binding policy during creation.

Use policy wrappers reporting `IsNative=false` where native fast paths would
bypass required binding, DNS, or resource tracking. Apply the same reasoning to
LocalNet. Preserve normal network errors for unsupported operations.

Do not exclude the entire host executable merely to implement OutNet: exclusions
also affect unrelated sockets and descendants. Establish how the hosting service
behaves if it is itself classified as excluded due to its launch ancestry; test
this explicitly and reject configurations that break managed DNS/local traffic.

Underlay loss makes dependent operations unavailable. New outbound attempts
must fail rather than fall back through the default TUN. Existing TCP sessions
may need reconnection; do not promise seamless migration. Rebind/recreate UDP
transports only under an explicitly tested policy. Update the controller's four
address roles coherently and reconcile uncertain IOCTL completion.

### 3.5 LocalNet and matchers

Bind LocalNet operations to loopback and validate addresses after resolution.
Define support for IPv4/IPv6 localhost and reject nonlocal destinations. Bind
UDP explicitly to loopback where needed to avoid excluded wildcard-bind
redirection. Use a separate private listener for a DNS service bound to DnsIP
when DnsIP is a non-loopback local adapter address.

Use `sockowner.GetSockOwner` for lookup. For TUN packets, use the outgoing tuple
from `FlowTupleFromOutgoingIPPacket`; for an accepted local connection, use the
peer-oriented tuple through `sysnet.MatchConn`. Do not accidentally identify the
listener's own process. Keep packet parsing separate from ownership lookup.

Implement `win-pid` and `win-exe-path` first. Exact path matching needs full-path
enrichment through process APIs; `SocketOwner.ProcName` currently retains only
the basename. Normalize path representations consistently and bound cache size
and lifetime. Include process creation time in PID metadata cache identity where
available. Short-lived sockets and PID reuse remain races, not guaranteed IDs.

Current UDP owner lookup checks exact local addresses. Define and test wildcard
lookup behavior before extending it; return ambiguous/no-owner results rather
than picking the first PID. Retry table-buffer growth races with a bounded loop
if the native table grows between size and data calls. Avoid reading entire
owner tables once per packet on a busy tunnel; cache per-flow results with short
negative caching and bounded memory.

Unknown/ambiguous owner is an explicit lookup failure. Do not make it a confirmed
nonmatch or use it to enforce a security boundary. Full executable metadata can
be unavailable for protected/exited processes. ICMP and fragments can still pass
through the TUN even when the matcher cannot attribute them.

### 3.6 DNS integration

Implement a local DNS service at the effective DnsIP, supporting UDP and TCP 53,
forwarding to the atomically replaceable `gonnect/dns.Interface` provider.
`SetDns(nil)` drops managed requests without upstream fallback. Establish
listeners and native configuration during build so setup errors can be returned;
ordinary provider swapping should not need a fallible OS reconfiguration.

Use NetIO/winipcfg to configure the intended resolver interface. Save previous
settings before changing them. On shutdown restore the prior mode as well as
values: DHCP-derived configuration must not become a stale static server list.
Use compare-with-applied/ownership checks before restoration to avoid clobbering
changes made by administrators, DHCP, or another VPN. Observe changes and keep
recovery metadata sufficient to undo abandoned owned configuration.

Build OutDNS from observed original/underlay upstream servers, using bound
OutNet sockets and explicit numeric upstream endpoints. Exclude the managed
proxy from upstream discovery. Wire every OutNet resolver entry point to this
path; Windows' default resolver after DNS takeover can create a loop. Separate
DNS transport family from question type: an IPv4 upstream must answer AAAA too.

Report `WarningDefaultTunDNSRouteNotExclusive` when exclusivity is unproven.
The initial backend can support configuration and forwarding without claiming
system-wide exclusivity. Port-53 firewall enforcement alone does not cover
application DoH/DoT or necessarily every OS resolver configuration. Corporate
split DNS/NRPT, native encrypted DNS, suffix search, hosts-file behavior and
other resolvers require scoped compatibility tests before claims are expanded.

Do not promise per-application DNS bypass: the Windows DNS Client service often
originates queries for multiple applications, so the driver cannot attribute
them to the requesting app. An excluded app using its own resolver is a
different path and must be tested separately.

### 3.7 Application exclusions and WFP integration

Use `win-exe-tree` only for non-strict Exclude. Use the controller's path resolver
for existing absolute local drive-letter paths; preserve exact NT-path semantics
and case treatment. Treat UNC/network executable paths, globs, regexes and
arbitrary PID/include routing as unsupported by this rule. Multiple entries are
ORed; setters replace the complete driver configuration.

Recommended owned-session sequence:

1. Validate requested policy. Open and inspect the exclusive driver; require an
   understood owned/clean state. Do not reset another application's leftovers.
2. Establish the TUN, usable addresses, underlay snapshot, transport bypass,
   routes and DNS resources required by this policy.
3. Create caller-owned baseline and DNS sublayers in a non-dynamic WFP session;
   commit creation before calling the controller. Non-dynamic lifetime is not
   the same thing as a promise of persistence across reboot.
4. Call Initialize, then SnapshotProcesses, then RegisterProcesses. Preserve
   partial snapshot entries and surface their warnings.
5. Apply current tunnel/Internet addresses and the complete exclusion set.
   Internet addresses are local underlay addresses, not gateways/public NAT IPs.
6. Run one event reader and one serialized policy reconciler. Treat splitting
   error events as failures requiring reconciliation, not successful policy.
7. On close, stop/join workers; reset using a fresh bounded cleanup context.
   Remove referenced sublayers only after reset is confirmed.

Keep caller WFP transactions closed while controller calls mutate WFP. Cancellation
of an IOCTL is not rollback: read State, Addresses or ExcludedDevicePaths with a
fresh context to determine the result. If reset fails, preserve referenced
objects and journal information and mark recovery_required. Document whether
the TUN remains quarantined pending recovery or is removed; never infer the
remaining packet policy from a closed local handle.

The backend must preserve ownership of ordinary DNS/routes even when split
cleanup fails and report their cleanup outcomes separately. Recovery should
inspect recorded ownership, installed driver identity and current native state,
then take an explicit bounded action. Do not loop forever resetting Zombie.

No cross-application coexistence claim: the stock device is globally exclusive
and has fixed WFP identifiers. Different service names are not independent
instances. Driver installation belongs to deployment tooling. Verify signed
package version/hash before service start; controller Open has no version-query
IOCTL. Maintain pinned driver-package provenance in the release artifacts.

### 3.8 Strict mode and future capabilities

Initial strict profiles and Include profiles are unsupported. Verify them before
any mutation. Never emulate Include by enumerating all other executables or by
swapping tunnel/Internet address roles.

For a later strict release, implement explicit WFP policy for the tunnel path,
necessary service transport, DNS, loopback, DHCP/IPv6 neighbor discovery as
required, and the chosen LAN policy. Excluded traffic under strict must be
dropped. Mullvad's ordinary exclusions permit underlay traffic, so filter
arbitration must be designed and measured, including higher/lower sublayers,
existing flows and DNS-specific permits. Enable exact strict profiles only when
qualified. Crash-persistent/boot-time kill-switch behavior is a separate contract
from live strict mode and requires its own recovery and test gates.

## 4. Development environment

### 4.1 Reuse the existing environments deliberately

sysnet-linux supplies a small Nix shell with Go, gopls, golangci-lint, just,
spelling/commit tools, DNS diagnostics and Python. Its privileged end-to-end
tests run Linux Docker environments. Reuse its fast-check organization,
dependency injection and deterministic DNS cases; Linux containers do not test
Windows NetIO, WFP or kernel drivers.

The controller repository is the closer environment template. Its flake pins
inputs via flake.lock, exposes signed driver packages, checks Nix/Markdown/CI,
and provides Linux QEMU/OVMF/SSH tools. Its justfile has native/cross builds,
race/fuzz tests, harness checks, and baseline/e2e/flow VM gates. Adapt that
environment and harness, keeping upstream attribution and license notices.
Do not copy its qualification results as evidence for sysnet-windows.

### 4.2 Host shell and lock files

Start development on Linux amd64 with KVM/QEMU support for the existing Windows
Server appliance. Keep native Windows amd64 and arm64 runners for qualification.
The Nix flake should expose:

- Go, gopls, golangci-lint, govulncheck, just and a C compiler for host race tests;
- actionlint, typos, commitizen, mdformat+GFM, markdownlint, nixfmt, deadnix,
  statix, shellcheck and shfmt;
- on Linux: QEMU/qemu-img, OVMF, Python, jq, OpenSSH, curl, util-linux and xorriso;
- signed-driver package output for amd64 and arm64;
- verified Wintun archive/DLL input for both architectures;
- host-only harness checks and an offline/pinned Go module dependency input.

Keep `flake.lock`, `go.mod`, `go.sum`, VM image lock, native-driver lock,
Wintun lock, and qualification matrix under version control. Reuse the
controller's locked versions as a reproducible starting point:

| Input | Inspected baseline | New-repository action |
| --- | --- | --- |
| Go | Guest/CI lock 1.25.5; controller module declares 1.25.0 | Pin one compatible toolchain after resolving all selected dependencies; update every lock/check together |
| Windows image | Server 2022 Standard Evaluation Server Core amd64, build 20348.587 image | Supply approved local media matching the lock; record actual patched runtime build |
| VirtIO | 0.1.285 | Copy provenance/hash from image-lock.json |
| OpenSSH | 9.8.3.0p2-Preview in the inspected image lock | Review/pin deliberately; do not treat this historical pin as a current recommendation |
| Split driver | 1.3.0.0, upstream 0a0eb97 | Copy both architecture manifests and verify signatures/version |
| Driver binaries source | 5b6f46cde692acb77ee74b37b9fd3f1678c45a52 | Fetch catalog, INF and SYS with their exact committed hashes |
| Wintun | 0.14.1 | Copy verified archive provenance/hash; stage matching architecture DLL |

The existing Wintun archive SHA-256 is
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Use the source lock files for the remaining hashes rather than manually
transcribing a second inconsistent list. Hashes are reproducibility inputs;
verify the intended signature and version too. Check dependency minimum Go
versions before committing a toolchain choice, and use `GOTOOLCHAIN=local` in
qualification to avoid an unrecorded toolchain download.

The flake's general `pkgs.go` selection follows the locked nixpkgs revision; it
is not automatically the same as the explicit VM/CI version. Add a consistency
check or select an explicit compatible Go package. Recompute dependency vendor
hashes when go.mod changes. Unit tests should not fetch drivers or install them.

### 4.3 First-time Linux-host setup

These are existing controller recipe names to preserve when adapting the harness.
They become sysnet-windows commands only after the corresponding scripts/recipes
have been added:

```sh
nix develop
cp dev/winvm/env.example dev/winvm/env
```

Edit `dev/winvm/env` to supply local, absolute paths:

```sh
WINVM_WINDOWS_ISO=/absolute/path/to/SERVER_EVAL_x64FRE_en-us.iso
WINVM_VIRTIO_ISO=/absolute/path/to/virtio-win-0.1.285.iso
# Optional task-specific cache and firmware paths:
# WINVM_CACHE_DIR=/absolute/path/to/private/sysnet-windows-cache
# WINVM_OVMF_CODE=/absolute/path/to/OVMF_CODE.fd
# WINVM_OVMF_VARS=/absolute/path/to/OVMF_VARS.fd
```

Then run:

```sh
just winvm-input-hashes
just winvm-doctor
just winvm-image
just test-windows-vm
just test-windows-e2e
just test-windows-flow
```

Doctor should check media hashes, KVM/access, required tools, disk capacity,
firmware, Go version, and driver/Wintun inputs before a long image build. The
developer supplies licensed/evaluation media; the repository must not contain
Windows ISOs, keys, base disks or credentials.

Give sysnet-windows its own cache namespace, for example
`${XDG_CACHE_HOME:-$HOME/.cache}/sysnet-windows/winvm`. Do not mutate the
controller's cached base. A base image stages verified inputs and a demand-start
split-driver service without engaging network policy. Ordinary native tests run
as a standard user; privileged suites run in a disposable guest under the
required account, typically SYSTEM for the live-driver harness.

Preserve the harness's content-addressed base identity, exclusive image-build
lock, shared run locks, unique overlays/OVMF state, locked SSH ports, readiness
generation token across provisioning reboots, host-key verification, bounded
guest execution, and required artifact retrieval. Package the actual working
tree and record its SHA-256; do not accidentally test only committed HEAD while
the developer is editing source.

### 4.4 Native Windows development

Install the chosen Go toolchain and Git. Native scripts must work through
PowerShell without requiring Nix. Stage architecture-matched Wintun only for the
explicit native networking suites; ordinary tests may use fakes and read-only
process/socket helpers. A missing DLL must not prevent all portable tests.

Provide/adapt these entry points:

```powershell
./dev/winvm/test.ps1 -ArtifactDir .artifacts/native-unit
./dev/winvm/host-e2e.ps1 -AllowDisposableHost -ArtifactDir .artifacts/live
```

The second entry point changes networking and stages a kernel driver. Require a
disposable test host/VM and elevation; refuse to overwrite an existing service,
driver file, or active owner. Run a standard-user permission-denial test as a
separate case, not by accidentally giving the whole baseline Administrator.

The inspected baseline script sets `CGO_ENABLED=0`: it is not a race run.
Use a separate Windows amd64 race job with cgo enabled and a pinned compatible
MinGW-w64 compiler. The Go race detector requires cgo/a C compiler and currently
lists Windows amd64, not Windows arm64. Keep arm64 native behavior tests and
Linux portable race tests; never label them an arm64 Windows race run. [W7]

### 4.5 Proposed command contract

| Recipe | Required behavior |
| --- | --- |
| `just check-fast` | Module verification/tidy-diff, format check, lint/vet, portable unit/race/fuzz, cross-builds and host-harness checks; no guest networking mutation |
| `just test` | Portable tests with bounded timeout; Linux race detector enabled |
| `just fuzz` | Short deterministic gate for parsers/policy inputs; longer nightly fuzz separately |
| `just build-windows` | Build all production packages for amd64 and arm64 with CGO_ENABLED=0; compile relevant test packages too |
| `just test-windows-vm` | Native unprivileged baseline with required-test manifest |
| `just test-windows-e2e` | Privileged owned TUN/NetIO/DNS/WFP/controller integration, serialized |
| `just test-windows-flow` | Isolated independent packet-path evidence including actual sysnet-windows public API |
| `just test-total` | Portable tests plus all required Windows native/live/flow gates |
| `just check` | All checks plus test-total; state its media/VM prerequisites clearly |
| `just qualify-windows ENTRY EVIDENCE` | Verify evidence identity, required cases, captures and cleanup against a declared platform entry |
| `just winvm-shell RUN`, `just winvm-clean` | Inspect retained failed guest; clean only validated test artifacts |

Add separate editing recipes `fmt`/`tidy`; CI uses nonmutating checks. The existing
repos' `just check` includes formatting/tidy mutations, so make this deliberate
when adapting it. Cross-build test packages individually or via a script rather
than sending multiple packages to one `go test -c -o FILE` output.

If a full gate is requested and media or a platform runner is missing, report
incomplete/blocked, not pass. A portable-only job may intentionally exclude live
tests, but its job name and evidence must say so.

## 5. Implementation milestones and exit criteria

| Milestone | Work | Exit criteria |
| --- | --- | --- |
| M0: contract and scaffold | Adopt capability proposal, constructors, unsupported stubs, injected OS interfaces, flake/just/CI, test manifest | Old System conformance; portable policy tests; Windows package/test compilation |
| M1: ordinary TUN | Wintun creation, allocation, addresses, routes, MTU, exact ownership cleanup | TUN/NetIO cases pass on native Windows; foreign resources unchanged |
| M2: network bypass | Underlay selection/monitoring, all OutNet and LocalNet entry points, resource tracking | TCP/UDP v4/v6 bypass proven while default TUN routes exist; no fallback on underlay loss |
| M3: default TUN and DNS | Full routing, provider service, OutDNS, resolver wiring, rollback/warnings | Controlled OS DNS and outbound DNS tests; repeated build/close and failure recovery |
| M4: matchers | PID/path rules, bounded caches, context validation | TCP/UDP/local-peer/unknown-owner tests; documented attribution limits |
| M5: exclusions | Controller ownership, WFP sublayers, process bootstrap, rule/address reconciliation | Included/excluded/descendant independent captures; live reconfiguration and reset failure tests |
| M6: release qualification | Desktop/server/architecture matrix, soak, failure injection, limitations and packaging | Required tests actually ran, matching clean revision/artifacts, release support matrix accepted |
| Later | Dynamic default updates, stronger DNS policy, strict profiles, optional richer attribution | Separate capability-specific gates; no automatic enablement with dependency upgrade |

M2 must precede accepting a full-tunnel release. M3 is not complete when DNS
configuration merely returns success; the real resolver and OutDNS paths must
be observed. M5 depends on actual packet-path evidence, not QueryProcess alone.

### 5.1 Step-by-step execution plan

Use the steps below in order. A later step can start early only when it uses
interfaces or fakes from an earlier step and does not assume that the earlier
native implementation is complete. Do not enable a capability row or add a test
to the required manifest until its complete gate passes.

For each step, use this work cycle:

1. Add or update the public contract test and the injected OS-boundary
   interface first.
2. Add the portable success, rejection and failure-injection tests.
3. Implement the smallest state transition that passes the portable tests.
4. Add the native Windows test. Read native state through an independent API
   when the test verifies an OS change.
5. Add the packet-flow case when the step makes a packet-path claim.
6. Run the step checks. Save diagnostic artifacts for a failed native run.
7. Update the capability table, required-test manifest and user documentation
   only after the applicable checks pass.

Keep commits and reviews inside one step where practical. If a step changes a
native ownership rule, include its rollback test in the same change. Do not
defer rollback to a later milestone.

#### M0: freeze the contract and create the implementation skeleton

1. **Step 1 - Record the exact gonnect contract. (Completed)**

   - List each `sysnet.System`, TUN, default-TUN, `Network`, matcher and DNS
     method from the selected gonnect revision.
   - Add compile-time interface assertions in the root package. Add a test that
     builds the old `Features` and `RulesInfo` projections from the new internal
     capability model.
   - Decide whether the companion capability API is available in gonnect. If it
     is not available, keep the model internal and expose only current gonnect
     interfaces. Do not add a private public API with conflicting names.
   - Record accepted deviations, including the misspelled `GetTunRotue` method,
     in a short contract note or a source comment next to the assertion.
   - Complete this step when Linux tests compile the root contract and both
     Windows architectures cross-compile it.

2. **Step 2 - Create the package and build-tag skeleton. (Completed)**

   - Add the root `System`, `SystemConfig`, constructor and lifecycle state
     types. Add `windows` implementations and non-Windows constructor stubs.
   - Create the internal package boundaries from Section 2. Define only the
     OS-boundary interfaces needed by the next steps: TUN factory, NetIO,
     underlay source, DNS configurator, split controller, WFP manager, owner
     lookup, clock and logger.
   - Add an injectable constructor for tests. It must not be exported as the
     normal integration path.
   - Make construction side-effect free except for explicit read-only probes.
     Do not start a worker, install a driver or change the host in package
     initialization.
   - Complete this step when `just check-fast` passes with production packages
     and test packages for Windows amd64 and arm64.

3. **Step 3 - Implement normalization and validation as pure policy code. (Completed)**

   - Convert raw TUN options, default-TUN options and rules to one normalized
     desired-state representation.
   - Validate address families, DnsIP ownership, MTU bounds, route families,
     rule context and unsupported option combinations.
   - Reject Include, Strict, SourceRoutes, rename and unsupported multicast
     before an OS dependency receives a call.
   - Return typed errors that retain the cause and identify the rejected field,
     profile or rule.
   - Use the same function in validation and construction. Add a fake mutator
     counter and require zero calls for every rejection case.
   - Complete this step when C04-C06, C13-C18 and the equivalent companion
     capability cases pass under the race detector.

4. **Step 4 - Build capability snapshots and lifecycle state. (Completed)**

   - Build an immutable internal report from implementation support, configured
     feature switches, probe facts, active ownership and lifecycle state.
   - Deep-copy slices and diagnostic data at the public boundary. Increase the
     revision only when semantic content changes.
   - Define transitions for new, ready, applying, active, closing, closed and
     recovery-required states. Reject new work after closing starts.
   - Make a missing or busy split driver affect exclusion profiles only. It must
     not disable regular TUN or full-routing rows.
   - Complete this step when C01-C03 and C07-C12 pass concurrently with the race
     detector and no getter performs a native mutation.

5. **Step 5 - Implement the reconciliation core and resource journal. (Completed)**

   - Define desired, observed and applied records for adapters, addresses,
     routes, DNS, WFP objects and split-driver state.
   - Give every journal entry an ownership key, apply operation, inverse
     operation and verification operation. Never use a table-wide flush as an
     inverse operation.
   - Serialize mutations through one policy worker. Let callbacks enqueue a
     reason and return without waiting for reconciliation.
   - On failure, undo completed entries in reverse order. Join the primary and
     cleanup errors. Set recovery-required when readback cannot prove a safe
     state.
   - Make `Close` idempotent. It must stop intake, cancel and join workers, close
     tracked sockets and TUNs, and then undo owned host state.
   - Complete this step when a fake test fails before and after every journal
     operation and proves exact reverse cleanup, foreign-resource preservation
     and bounded close.

6. **Step 6 - Make the harness enforce the new contract. (Completed)**

   - Add package-level test names to `dev/winvm/test-manifest.json` only when
     they exist. Mark later milestone cases as planned, not optional passes.
   - Make baseline, live and flow scripts report the source archive hash, Go
     version, OS identity, architecture and dependency locks.
   - Add a minimal native smoke test that creates no network resource. Confirm
     that the baseline suite can run without Wintun or the split driver.
   - Add a validator self-test that rejects a missing required case, a skipped
     case and a mismatched source identity.
   - Complete this step when `just winvm-check` and a disposable
     `just test-windows-vm` run produce valid evidence.

#### M1: implement ordinary TUN and NetIO ownership

1. **Step 7 - Implement host-aware address and subnet allocation. (Completed)**

   - Enumerate usable host addresses, interface prefixes and routes through the
     injected NetIO reader.
   - Filter loopback, existing host subnets, Hyper-V, WSL, other VPN ranges and
     reservations owned by this System. Treat a default route as reachability,
     not as a conflict with all address space.
   - Reserve a candidate under the System lock, re-read conflicts immediately
     before use and release the reservation on failure or close.
   - Fail allocation when enumeration is incomplete. Do not select a candidate
     from a partial snapshot.
   - Complete this step when T25-T27 pass, including concurrent allocation and
     an enumeration error after initial selection.

2. **Step 8 - Adapt Wintun without changing its packet contract. (Completed)**

   - Wrap `CreateTUNWithRequestedGUID`. Store stable GUID metadata and the
     current LUID/index separately.
   - Preserve batch size, offsets, MRO, MWO, event delivery and the documented
     read/write concurrency contract.
   - Coordinate `ForceMTU` with the later NetIO MTU apply. A successful wrapper
     update alone must not report a successful native MTU change.
   - Make close unblock pending I/O and make later I/O return an error compatible
     with `os.ErrClosed`.
   - Complete this step when T01-T03, T10-T15 and architecture-specific native
     smoke tests pass with the staged Wintun DLL.

3. **Step 9 - Implement exact address, route, metric and MTU operations. (Completed)**

   - Add narrow NetIO adapters for unicast addresses, forward rows and per-family
     IP-interface properties. Convert native rows to stable comparison keys.
   - Apply deltas only for resources in the System inventory. Before delete or
     restore, compare current state with the recorded applied value.
   - Wait for address usability with a context deadline. Read back every MTU,
     metric, address and route operation before journal commit.
   - Preserve foreign sentinel rows on the owned interface and all rows on
     physical interfaces.
   - Complete this step when T04-T09 pass and independent PowerShell or NetIO
     snapshots show only the expected delta.

4. **Step 10 - Finish the regular-TUN public lifecycle. (Completed)**

    - Connect allocation, Wintun and NetIO through the reconciliation worker.
    - Implement getters from verified observed state. Implement supported
      setters as complete transactions with revalidation immediately before
      apply.
    - Reject a TUN that belongs to another System, a closed TUN and an object
      whose native adapter identity was reused.
    - Handle external adapter, address and route removal with bounded reconcile
      attempts and a visible failed state.
    - Run create/use/close in a loop and compare adapter, route, address and
      handle state before and after the batch.
    - Complete this step when T16-T18, T22-T24 and T28-T30 pass. Enable only the
      regular-TUN operation rows that the tests cover.

#### M2: implement underlay selection, OutNet and LocalNet

1. **Step 11 - Select and monitor one underlay per family. (Completed)**

    - Rank candidates by explicit selector result, operational state, usable
      source address, destination reachability, route metric and interface
      metric. Use stable tie-breakers.
    - Exclude all adapters owned by this System. Do not automatically exclude
      every other VPN; let explicit configuration select the intended path.
    - Register interface, route and address callbacks. Debounce each burst and
      read one coherent replacement snapshot.
    - Publish IPv4 and IPv6 selections atomically. Mark a family unavailable
      when it has no valid underlay.
    - Complete this step when N17-N24 pass with separate IPv4/IPv6 paths,
      interface recreation, DHCP change and resume.

2. **Step 12 - Implement the pre-connect socket binding primitive. (Completed)**

    - Use `syscall.RawConn.Control` before bind or connect. Set
      `IP_UNICAST_IF` for IPv4 in network byte order and `IPV6_UNICAST_IF` for
      IPv6 in host byte order.
    - Validate the requested local address against the selected underlay. Add an
      explicit source bind only where the Winsock operation requires it.
    - Compose the caller control hook before the final mandatory binding check.
      Reject any resulting conflict. Never retry without the binding option.
    - Return the underlying Winsock error with operation, family and interface
      context.
    - Complete this step when focused native TCP and UDP tests prove the source
      interface and all permission, family and stale-index failures are visible.

3. **Step 13 - Cover every OutNet socket entry point. (Completed)**

    - Implement generic and typed TCP/UDP dial, packet dial, listen and packet
      listen methods, including configured UDP/listener variants.
    - Wrap returned connections and listeners in the System resource registry.
      A wrapper must reject new work after System close.
    - Verify unconnected UDP writes to more than one remote endpoint. Reject an
      operation if Windows cannot retain the required interface policy.
    - Route each resolver method through OutDNS. Report `IsNative=false` when a
      native shortcut could omit binding, resolution or tracking.
    - Complete this step when N01-N16 and N29-N32 pass and captures show no
      recursive transport through the owned TUN.

4. **Step 14 - Implement and confine LocalNet. (Completed)**

    - Resolve localhost names and validate the result before connection. Accept
      only the supported IPv4 or IPv6 loopback scope.
    - Bind TCP and UDP listeners explicitly to loopback. Do not turn a wildcard
      request into an externally reachable listener.
    - Keep the private DNS listener path separate when DnsIP is a non-loopback
      address owned by the TUN.
    - Track all returned resources and preserve peer orientation for the later
      `MatchConn` implementation.
    - Complete this step when N25-N28 pass from a second local process and an
      external probe confirms that the listeners are not exposed.

5. **Step 15 - Prove bypass before full routing is accepted. (Completed)**

    - Install a disposable default route through the test TUN while the
      controlled peer remains reachable on the underlay.
    - Exercise each supported OutNet operation for IPv4 and IPv6. Capture both
      the TUN path and direct link with unique tokens.
    - Remove the selected underlay during active and new connections. Require
      new operations to fail instead of falling back to the TUN.
    - Verify that close releases sockets and callbacks and restores the pre-test
      route state.
    - Complete this step when the M2 flow cases pass on each family that will be
      advertised. Do not proceed to an initial full-tunnel release without this
      gate.

#### M3: implement default routing and DNS

1. **Step 16 - Build the default-TUN transaction. (Completed)**

    - Validate and reserve all inputs before changing the old default TUN.
    - Create the new adapter, addresses and underlay dependencies before adding
      family default routes. Preserve the underlay routes needed by OutNet.
    - Apply route and interface metrics in a deterministic order and read them
      back. Publish the new object only after the complete policy is usable.
    - For replacement, record the exact point where the old object retires. On a
      later failure, either restore the old policy or publish that no default TUN
      is active.
    - Complete this step when T19-T21 pass for every failure point and ordinary
      invalid input leaves the old object unchanged.

2. **Step 17 - Implement the local DNS proxy. (Completed)**

    - Bind UDP and TCP port 53 at the effective DnsIP before OS DNS changes.
    - Forward requests to an atomically replaceable `gonnect/dns.Interface`.
      Add bounded request contexts and TCP truncation/fallback behavior.
    - Make `SetDns(nil)` drop managed requests. It must not discover or use an
      implicit host fallback.
    - Track listeners and active requests so close cannot return while they can
      still access System state.
    - Complete this step when D01-D08 pass under concurrent provider swaps and
      shutdown.

3. **Step 18 - Configure and restore Windows DNS by ownership. (Completed)**

    - Read and record the prior DNS mode and values. Distinguish DHCP-derived
      configuration from static configuration.
    - Apply the proxy address to the intended interface and read back effective
      state. If apply fails, restore only values that still match this System's
      partial write.
    - On close or recovery, compare current state with the recorded applied
      value. Do not overwrite an administrator, DHCP or another VPN change.
    - Detect unsupported APIs, access denial and port conflicts before route
      publication where possible.
    - Complete this step when D13-D20 pass and independent pre/post snapshots
      prove ownership-aware restoration.

4. **Step 19 - Implement OutDNS and resolver-loop prevention. (Completed)**

    - Derive numeric upstream endpoints from the original or selected underlay
      DNS state. Exclude the managed proxy address from discovery.
    - Send UDP and TCP DNS traffic through bound OutNet sockets. Keep upstream
      transport family independent from A or AAAA question type.
    - Refresh upstreams after relevant interface and DNS changes without
      feeding the applied proxy value back into discovery.
    - Exercise every OutNet resolver entry point through controlled upstreams
      that return unique answers.
    - Complete this step when D09-D12 and N13-N16 pass with captures that prove
      the proxy and upstream legs separately.

5. **Step 20 - Finish default-TUN cleanup, warnings and scope tests. (Completed)**

    - Join default routes, DNS resources and TUN resources into one ordered
      journal without treating native subsystems as one atomic transaction.
    - Report nonexclusive DNS and route behavior through stable warnings. Do not
      claim system-wide DNS exclusivity from interface configuration alone.
    - Test multihomed DNS, NRPT, suffix search and encrypted resolver settings.
      Record unsupported or unqualified behavior without changing the host
      setting under test.
    - Run repeated build/use/provider-swap/close cycles and crash recovery in a
      disposable guest.
    - Complete this step when D21-D28, all applicable T28-T30 cases and the M3
      resource-accounting batch pass.

#### M4: implement best-effort ownership and matchers

1. **Step 21 - Separate packet parsing from owner lookup. (Completed)**

    - Parse outgoing IPv4 and IPv6 TCP/UDP tuples without native calls. Bound all
      header and extension-header reads and return typed unsupported results for
      fragments or protocols without a usable tuple.
    - For local accepted connections, create the peer-oriented tuple required by
      `sysnet.MatchConn`.
    - Fuzz valid, truncated and malformed packets. The parser must not panic or
      read beyond the supplied packet.
    - Complete this step when R17-R20 and R25-R28 parser cases pass on Linux and
      Windows.

2. **Step 22 - Implement Windows owner and executable enrichment. (Completed)**

    - Wrap `sockowner.GetSockOwner`. Retry owner-table size races with a small
      fixed limit.
    - Define exact wildcard UDP behavior. Return unknown or ambiguous when more
      than one owner can match.
    - Enrich PID results with normalized full executable path and process
      creation time where access permits. Preserve access-denied and exited
      process outcomes.
    - Cache by flow and process identity with bounded entry count, positive and
      negative lifetimes, and invalidation on creation-time mismatch.
    - Complete this step when R17-R24 pass for controlled native processes and
      cache resource limits remain stable during churn.

3. **Step 23 - Compile and expose matcher rules. (Completed)**

    - Implement `win-pid` and `win-exe-path` validation, completion and matching.
      Use one path canonicalization policy for configuration and observed
      processes.
    - Keep lookup failure distinct from a confirmed nonmatch. Never use a
      best-effort matcher as proof of routing enforcement.
    - Test case variation, Unicode, spaces, long paths, extended paths, hard
      links, rename/replacement, UNC and inaccessible processes.
    - Report matcher family, transport, fields and quality independently in the
      capability snapshot.
    - Complete this step when R01-R08 and R21-R28 pass and all unsupported path
      forms fail before lookup.

#### M5: implement executable-tree exclusions

1. **Step 24 - Acquire and verify the exclusive split session. (Completed)**

    - Open the pinned driver lazily on the first exclusion request. Verify
      service identity, signed package provenance and current driver state.
    - Refuse a competing owner, an unknown dirty state or an incompatible ABI.
      Do not reset state that this System cannot prove it owns.
    - Create caller-owned baseline and DNS WFP sublayers in a committed
      non-dynamic session before controller initialization.
    - Journal provider, sublayer and filter identifiers. Keep them if driver
      reset fails and still references them.
    - Complete this step when C01-C03, R37-R40 and native foreign-owner sentinel
      tests pass.

2. **Step 25 - Bootstrap process state and apply exclusions. (Completed)**

    - Call Initialize, snapshot processes and register the full snapshot in the
      required order. Preserve usable partial entries and their diagnostics.
    - Resolve each accepted drive-letter executable path to the controller's
      required identity. Compile the full replacement exclusion set before its
      mutation call.
    - Set tunnel and Internet address roles from the same policy generation.
      Internet addresses are local underlay addresses.
    - Start one event reader. Send process and network changes to the serialized
      reconciler and record the applied generation.
    - Complete this step when R09-R16 and R33-R36 pass, including births during
      snapshot and a missing-family case.

3. **Step 26 - Handle live policy changes and uncertain driver results. (Completed)**

    - Replace exclusions as one complete desired set. Observe and document the
      effect on established TCP and UDP flows.
    - After a cancelled or timed-out IOCTL, use a fresh bounded context to read
      State, Addresses or ExcludedDevicePaths. Reconcile the read result instead
      of assuming rollback.
    - Treat all splitting error events as failures that require readback. Do not
      infer start or stop direction from the event ID.
    - Update underlay and tunnel address roles as one generation after interface
      changes.
    - Complete this step when R29-R36 and the cancellation/readback cases pass
      with independent packet captures.

4. **Step 27 - Implement reset, close and explicit recovery. (Completed)**

    - Stop intake and join the event reader before reset. Use a fresh cleanup
      context that is not the cancelled operation context.
    - Remove referenced WFP objects only after readback confirms reset. If reset
      fails or the driver is Zombie, preserve the journal and publish
      recovery-required.
    - Clean ordinary routes and DNS by their own ownership rules even when split
      cleanup fails. Return all cleanup errors.
    - On a later recovery request, verify the journal, driver package, service
      identity and current native state before a bounded action.
    - Complete this step when R37-R44 and failure injection at every controller
      transition leave the documented state with no foreign changes.

5. **Step 28 - Prove application path behavior through the public API. (Completed)**

    - Run the controller's nine-mode dependency conformance gate first.
    - Through the sysnet-windows constructor, test an included process, an
      excluded process, a newly created descendant and a pre-existing IPC
      target for each advertised family/profile.
    - Capture the transport and direct links. Require each run token on only the
      expected link. Use positive controls before all absence assertions.
    - Test explicit application DNS and the shared Windows DNS Client path as
      separate cases. Record the attribution limitation.
    - Complete this step when the independent evidence validator accepts all M5
      cases and rejects deliberately damaged captures.

#### M6: qualify and prepare the release

1. **Step 29 - Run failure, concurrency and resource gates. (Completed)**

    - Run failure injection before and after every native create, apply and
      cleanup operation listed in Section 6.7.
    - Run 10 warm-up cycles and four measured batches of 25 lifecycle cycles.
      Run the 30-minute transfer/reconfiguration soak and 100 cancellation
      cycles.
    - Compare adapters, addresses, routes, DNS settings, WFP objects, driver
      state, handles, goroutines and private bytes with the post-warm-up
      baseline.
    - Investigate every persistent trend or unexplained foreign-state change.
      Do not waive it with a larger arbitrary threshold.
    - Complete this step when owned native objects return to the exact expected
      state and process-resource measurements have no unexplained growth.

2. **Step 30 - Qualify each support-matrix entry independently. (Completed)**

    - Run the portable, native baseline, live integration and packet-flow gates
      against the same clean source identity and dependency locks.
    - Qualify Windows 11 amd64, Windows 11 arm64 and Windows Server 2022 amd64 as
      separate entries. Do not substitute a cross-build for a native run.
    - Verify the actual OS build, product type, native architecture, code
      integrity mode, driver signer and binary hashes in the evidence.
    - Reject a qualification when a required test is absent, skipped, stale or
      from a different source archive.
    - Complete this step when `just qualify-windows ENTRY EVIDENCE` produces an
      accepted record for each platform that the release will advertise.

## 6. Test layers and acceptance principles

1. **Portable unit/model tests:** normalization, capability projections, rule
   validation, desired/observed state, journals and failure handling using fakes.
2. **Native unprivileged tests:** Windows path/process helpers, owner tables with
   controlled sockets, API availability, permission-denial behavior.
3. **Native privileged tests:** real TUN, NetIO, DNS and WFP resources; driver
   lifecycle; exact cleanup and failure recovery.
4. **Independent packet tests:** observed payloads and absence on forbidden
   links, with independently configured endpoints and OS-state checks.
5. **Soak/qualification:** repetitions, concurrency, leaks, network changes,
   supported platforms, signed deployment inputs and retained evidence.

Required cases must fail qualification when skipped, absent, or unsupported on a
platform claiming the corresponding capability. Optional unsupported behavior
is tested by its explicit rejection; it is not disguised as a passing success
case. Do not use blanket `t.Parallel` for host networking or the global driver.

### 6.1 Capability and policy tests

| IDs | Cases | Assertions |
| --- | --- | --- |
| C01–C03 | Available, absent, disabled, incompatible, busy and unknown split dependency; permission-denied NetIO | Correct state/reason; unrelated features remain usable |
| C04–C06 | Include, Strict, SourceRoutes, mixed Include+Exclude, invalid family/rule context | Exact error; fake mutator call count remains zero |
| C07–C09 | Deep-copy snapshots, revision changes, concurrent readers, legacy projections | No state aliasing/race; no inferred combination |
| C10–C12 | Available snapshot becomes stale; unknown snapshot resolved during build; System close | Final checks authoritative; no weaker fallback |
| C13–C15 | Empty/default/loopback options, malformed CIDRs, DnsIP not owned by TUN | Existing contract normalization preserved; no inconsistent validate/build result |
| C16–C18 | One-family support, dual profile, lookup versus enforcement quality | No false dual/include/strict guarantee; matcher quality explicit |

Reuse all CAP-01…CAP-16 cases in the companion proposal. Maintain shared
conformance fixtures in gonnect where backend-neutral; keep native behavior
assertions in sysnet-windows.

### 6.2 TUN, routes, allocation and lifecycle tests

| IDs | Cases | Assertions |
| --- | --- | --- |
| T01–T03 | Create unaddressed/v4/v6/dual TUN; empty/default options; name/GUID collision | Correct identity/families; no takeover of a foreign adapter |
| T04–T06 | Add/replace/remove addresses and routes; duplicates; invalid input | Correct owned delta; foreign sentinel entries survive |
| T07–T09 | Zero/small/normal MTU, OS MTU readback, packet sizes near boundary | Wrapper and native settings agree; fragmentation/PMTU behavior bounded |
| T10–T12 | Read/write offsets, batch size, short buffers, ICMP and IPv6 extension headers | Packet fidelity; ordinary IP I/O not limited by matcher support |
| T13–T15 | Close while blocked in Read/Write; concurrent Close; calls after Close | Bounded shutdown, correct errors, closed events, no leaked handles |
| T16–T18 | Owned versus foreign/stale regular and default TUN arguments | ErrUnknownTun for foreign/stale objects; no host mutation |
| T19–T21 | Repeated BuildDefaultTun, invalid replacement, failure after old retirement | Documented identity behavior; invalid options preserve old state; failures restore or explicitly deactivate |
| T22–T24 | External adapter removal, address change, route removal/metric change | Reconcile or visible failure; no endless retry or stale healthy report |
| T25–T27 | LAN/Hyper-V/WSL overlap, concurrent allocations, enumeration failure | No conflicting reservation; no silent assumption on unreadable host state |
| T28–T30 | Failure after every create/apply step; failure during rollback | Reverse cleanup, preserved foreign resources, joined errors and recovery state |

Check state via Windows read APIs/PowerShell independently of the backend's
cached getters. Record pre/post snapshots and explicitly allow only expected
owned changes.

### 6.3 OutNet, LocalNet and underlying network tests

| IDs | Cases | Assertions |
| --- | --- | --- |
| N01–N04 | All generic/typed TCP and UDP dials with default TUN active | Requests and replies use the selected underlay; no recursive TUN transport |
| N05–N08 | PacketDial, ListenPacket, ListenUDP, configured variants, TCP listeners | Subsequent traffic retains policy; accepted/tracked resources close |
| N09–N12 | Explicit local address, wildcard, conflicting caller hook, IPv4-mapped address | Correct source/family or explicit rejection; no unbound fallback |
| N13–N16 | Hostname resolution, A/AAAA, every resolver method, local hosts behavior | Resolver uses intended OutDNS path and never the managed proxy recursively |
| N17–N20 | Equal route metrics, different interface metrics, separate v4/v6 underlays, another VPN | Deterministic selected policy; owned TUN excluded from discovery |
| N21–N24 | Underlay loss, DHCP address change, interface recreation/index change, resume | New connections fail or use reconciled underlay; established behavior documented |
| N25–N28 | Local TCP/UDP, localhost names, explicit loopback bind, nonlocal request | Correct loopback confinement; no exposure from wildcard listeners |
| N29–N32 | Caller bypass optimization, closed network wrappers, host process inherited exclusion, unsupported multicast/raw | Required hooks retained; false native status where necessary; explicit unsupported errors |

Test `OutDNS` independently of application traffic; a numeric transport endpoint
test alone does not prove hostname resolution will bypass the tunnel.

### 6.4 DNS tests

| IDs | Cases | Assertions |
| --- | --- | --- |
| D01–D04 | Windows system resolver to controlled A/AAAA answer over UDP/TCP; truncation fallback | Actual resolver reaches managed provider; both transports work |
| D05–D08 | Provider replacement, nil provider, concurrent queries, provider shutdown | No stale-provider race, no nil fallback, bounded requests/cleanup |
| D09–D12 | OutDNS before/after takeover; original upstream changes; proxy rediscovery; v4 upstream/AAAA | No recursion or stale feedback; correct independent underlay queries |
| D13–D16 | Port 53 already occupied, API denied, missing DNS API, apply failure | Build fails cleanly; previous system DNS remains/restores |
| D17–D20 | Close/crash recovery, DHCP versus static DNS, external edit while active, new adapter | Ownership-aware restoration and useful warnings; no clobber of unrelated configuration |
| D21–D24 | Multihomed Windows DNS, NRPT/suffix search, OS encrypted DNS, app DoH/DoT | Explicit supported scope or documented limitation; no false exclusivity claim |
| D25–D28 | Excluded app via DNS Client, app-owned DNS, external port 53, missing upstream | Expected attribution limits; no untested bypass guarantee; errors observable |

Use controlled upstream servers returning distinguishable answers and unique
query names to avoid cache hits. Flush only test-relevant caches where possible
and record when cache manipulation was necessary. Observe OS queries separately
from a direct query to the local proxy: the latter alone does not validate system
DNS configuration. Bound retries and distinguish intentional packet drops from
DNS failures in the evidence.

### 6.5 Rules, ownership and split-routing tests

| IDs | Cases | Assertions |
| --- | --- | --- |
| R01–R04 | Same path case variation, Unicode/spaces/long path, extended path, junction resolution | Canonical behavior matches controller path rules |
| R05–R08 | Hard-link alternate launch, rename/replacement, volume mapping change, UNC/relative/glob input | Separate identity/reconfiguration or explicit rejection; no silent reinterpretation |
| R09–R12 | Excluded executable, new child/grandchild, already-running IPC target, child exit/parent PID reuse | Actual process-tree inheritance, not assumed user intent |
| R13–R16 | Existing processes at bootstrap; births during snapshot; partial process metadata; inaccessible processes | No discarded tree entries or bootstrap hole; diagnostics retained |
| R17–R20 | TCP/UDP v4/v6 PID/path lookup, LocalNet peer orientation | Correct process when determinable; listener is not mistaken for peer |
| R21–R24 | Wildcard/shared UDP port, fast close/reuse, PID reuse, protected process | Explicit unknown/ambiguous result; cache bounded and invalidated |
| R25–R28 | ICMP, non-first fragments, IPv6 extensions, malformed tuple | Defined unsupported/parse outcome; no panic or false owner |
| R29–R32 | Add/remove exclusions with established TCP and UDP; long-lived sessions | Observe driver change semantics; do not assume seamless flow migration |
| R33–R36 | Four address roles across nine driver modes; invalid combinations; address changes; one missing family | Correct path/block result per pinned driver mode; unqualified combinations rejected |
| R37–R40 | Competing owner, Close without reset, cancelled mutation, reset failure/Zombie | No foreign takeover; reconcile result; preserve references and report recovery |
| R41–R44 | Baseline/DNS WFP arbitration, port 53 traffic, driver splitting errors, initial no-exclusion full mode | Driver/WFP composition verified; optional driver dependency remains optional |

Reuse the controller's complete nine-mode conformance gate unchanged as a
dependency gate. The backend gate must additionally exercise its own public API
for every mode/profile it advertises. Do not expose all nine modes just because
the controller can encode them; its ABI contains only one local address per
role/family and rejects some combinations when engaging.

### 6.6 Independent packet test topology and evidence

Use the existing two-guest/two-data-link design with a separate management path.
Management SSH/QGA must remain usable when the test deliberately breaks routes
or DNS. Isolate test links from the public network.

| Path | Purpose | Existing harness example |
| --- | --- | --- |
| Transport link | Carries test tunnel encapsulation to the controlled endpoint | 198.18.0.0/24, fd00:18:0::/64 |
| Direct underlay link | Carries bypass traffic directly | 198.18.1.0/24, fd00:18:1::/64 |
| Service addresses | Same destination reachable over expected paths | 203.0.113.1, 2001:db8:ffff::1 |
| Management | Readiness, command execution, artifact retrieval | Separate management connectivity |

Drive the actual sysnet-windows constructor and returned TUN/OutNet/DefaultTun,
not only the controller's demo. A controlled packet peer can provide the test
transport; it must remain an explicitly isolated test tool, not be presented as
an encrypted VPN implementation.

Each observation has a random run token, case ID, process role, family, protocol,
source/destination, expected path and expected response. Capture both links
independently. For a routed case require the token on the expected link and
absence on the forbidden path during a bounded observation window, with packet
loss/drop counters and capture readiness checked. Decode encapsulation separately
so inner payloads are not misclassified as direct traffic. A response alone or
the local socket address alone is insufficient.

For a blocked case require a healthy positive control on the same endpoints,
correct installed policy, and absence of the forbidden packet/response. Timeout
alone can mean a broken peer or capture. Start captures before probes, use ready
barriers instead of arbitrary sleeps, and wait for a recorded policy generation
before asserting post-update behavior. Test TCP SYNs, established streams,
unconnected UDP and request/reply traffic independently.

Pktmon on Windows can add drop/path diagnostics and export pcapng; host link
captures provide an independent view. Preserve original captures and validator
output. Add validator-negative tests for missing markers, markers on both links,
wrong family/process, truncated captures, stale run tokens, and missing capture
files. The evidence checker must fail these corruptions.

### 6.7 Failure injection, resource accounting and fuzzing

Inject failure immediately before and after TUN creation, address/route changes,
DNS listener/configuration, sublayer creation, Initialize, process registration,
address/exclusion mutation, and reset. Kill the controlling process at selected
stages in a disposable guest, then exercise explicit recovery. Include an IOCTL
timeout where readback shows the mutation committed.

For each failure assert: resulting object state; capability/warning transition;
owned and foreign native resources; remaining driver state; cleanup diagnostics;
and packet behavior where a guarantee is claimed. A journal entry alone does not
prove cleanup. Keep foreign sentinel routes/DNS/WFP objects in test fixtures to
catch overly broad deletion.

Use a warm-up phase then fixed repeated lifecycle batches, following the
controller tests. Suggested initial backend gate: 10 warm-up plus four batches
of 25 build/use/close cycles; a separate 30-minute single-session transfer and
reconfiguration soak; 100 cancellations with queries/events active. Measure
handles, goroutines, private bytes, pending native callbacks, adapters, routes,
DNS overrides and WFP objects. Require exact cleanup of owned network objects;
for process counters compare a bounded post-warm-up baseline/trend and investigate
growth rather than choosing an arbitrary universal handle count.

Fuzz CIDR/options normalization, rule validation, report cloning/lookup and
serialization if provided, path input preprocessing, packet tuple parsing, and
journal decoding. Seed valid and invalid family/rule combinations. Keep parser
fuzzing unprivileged; never let generated inputs install services or mutate real
host networking. Reuse controller protocol fuzzing as its dependency gate rather
than duplicating its ABI implementation in sysnet-windows.

## 7. CI and release qualification

Use separate jobs for portable checks, amd64/arm64 cross-builds, native Windows
unprivileged tests, Windows amd64 race tests, disposable privileged integration,
and independent packet qualification. Verify the actual runner OS/build/arch;
`windows-latest` is not an immutable platform definition. Do not run privileged
network changes on shared workstations or on untrusted pull-request code with
release credentials. Use an isolated ephemeral test environment.

Expected release evidence:

- exact clean sysnet-windows commit and source archive hash;
- gonnect/tuntap/controller module versions and controller/driver ABI revision;
- Nix lock identity, Go version, Windows edition/build/product type and native
  architecture, firmware/virtualization relevant to the run;
- split-driver version, package hashes/signer, service configuration and Wintun
  archive/DLL identity;
- requested capabilities, actual capability snapshots and warnings;
- go-test JSON with a required-case manifest, not just an exit code;
- native pre/post interface, route, DNS, WFP and driver-state snapshots;
- independent captures, marker expectations/results, drop counters and negative
  validator tests;
- rollback/recovery, soak and resource-accounting results;
- final qualification decision with explicit missing/waived unsupported cases.

Keep artifacts under `.artifacts/winvm/run-ID/` or the native equivalent. Adapt
the existing qualifier to use `sysnetWindowsRevision` plus dependency identities;
do not continue calling the new backend revision `controllerRevision`.
Local dirty-tree runs are useful diagnostics, but release qualification must
reject dirty/mismatched or unknown revisions. Retrieve guest artifacts before
marking a gate successful. Keep failed overlays for diagnosis; clean only
validated run paths.

Do not carry over the controller's numerical observation threshold (1,486) as a
proof of backend coverage. Define required semantic backend cases and a minimum
derived from that manifest. More duplicated packets do not replace a missing
DNS, IPv6, cleanup or failure scenario.

The initial support matrix should name exact qualified configurations. Add
Windows 11 amd64, Windows 11 arm64 and the Server 2022 amd64 VM separately.
Test Secure Boot/code-integrity configurations used in distribution; a
test-signing-only success must not qualify ordinary signed deployment. Exercise
sleep/resume, real adapter transitions and relevant endpoint-security/firewall
coexistence on dedicated hosts beyond the isolated VM where those claims matter.

Release gate checklist:

1. Every advertised operation/profile has a linked required passing case.
2. Unsupported requests are rejected before mutation.
3. OutNet and OutDNS bypass and DNS rollback are observed end to end.
4. Driver ownership, normal close and interrupted recovery leave documented state.
5. No unexplained foreign-resource changes or persistent resource growth.
6. Documentation states exactly the qualified platforms and remaining limits.

## 8. Limitations to document for users and integrators

| Limitation | Required documentation and API behavior |
| --- | --- |
| Architecture/platform scope | Name qualified Windows builds and amd64/arm64 targets; distinguish minimum APIs, cross-builds and native qualification |
| Privileges | TUN/NetIO/DNS/WFP and driver-service work may require elevation/service identity; unprivileged matchers can still be usable |
| Driver dependencies | Wintun DLL/driver and compatible signed split-driver package are deployment inputs; module download alone does not install them |
| Global split ownership | One stock driver owner; incompatible with simultaneous independent use by another VPN/controller; renaming service is insufficient |
| Rule semantics | Exact local NT-path identity and descendant inheritance; no Linux exec-glob/UID/group/cgroup equivalence |
| Path changes | Hard links require separate entries; rename/replacement/remount can require policy refresh; UNC/network executables unsupported by normal resolver |
| Process-tree meaning | Existing browser IPC targets are not children; parent inheritance can affect tools launched by an excluded application |
| Include routing | Unsupported initially; return ErrNotSupported, never emulate by enumerating the complement |
| Strict mode | Unsupported initially; default routing is not a leak-prevention or crash-persistent kill switch |
| Route preference | More-specific LAN/enterprise routes can bypass a non-strict default route; underlying interface may itself be another VPN |
| Source routes | No initial per-destination preferred-source policy; SourceRoutes rejected |
| Family scope | IPv4-only support says nothing about other system IPv6 traffic; exact dual-stack/driver-mode profile must be checked |
| DNS attribution | Shared DNS Client service prevents reliable per-request app attribution; excluded apps' ordinary DNS normally stays managed/tunneled |
| DNS exclusivity | Interface DNS setup alone is not exclusivity; expose the existing warning; scope NRPT, OS/app encrypted DNS and corporate DNS claims |
| Nil DNS provider | Managed requests are dropped, not silently sent to a fallback resolver; application-owned encrypted DNS is a separate path |
| UDP localhost | Excluded unbound UDP applications may fail localhost communication; explicit loopback bind helps controlled local sockets, not every external app |
| Multicast | Redirected bind and multicast membership can disagree; no general upstream workaround; do not advertise multicast bypass initially |
| Flow changes | Existing flows can be blocked or require reconnect on policy/underlay changes; no promise of transparent migration |
| Socket ownership | Best effort, race-prone; UDP lacks remote endpoint; wildcard/shared sockets, protected processes and PID reuse can produce unknowns |
| Matcher versus routing | Successful owner matching does not prove kernel enforcement, and driver QueryProcess does not prove packet path |
| Dynamic updates | List supported setters separately; default DNS-address changes may require rebuilding; object/source identity behavior is explicit |
| Close/recovery | Controller Close does not reset policy; reset failure preserves references and can require explicit recovery; cancellations may have committed |
| Upstream driver diagnostics | Both start/stop splitting failures may use the same stop-error event ID in 1.3.0.0; use IsSplittingError rather than infer direction |
| Throughput and buffering | Initial Wintun batching/copying and ownership-cache costs differ from Linux; publish measured limits, not Linux performance assumptions |

Publish these in README support/scope sections and in detailed integration docs.
Expose machine-readable limitations/reasons in capabilities where useful, with
stable identifiers. Application UI should explain relevant user effects without
requiring users to understand WFP or driver IOCTLs.

## 9. Planned documentation deliverables in the new repository

- `README.md`: supported platform/feature table, installation prerequisites,
  minimal constructor example and effective-capability discovery.
- `docs/integration.md`: ownership, startup/shutdown, OutNet/OutDNS use,
  rule semantics, threading, configuration replacement and error handling.
- `docs/limitations.md`: scoped behavior from Section 8 and known compatibility
  issues, each linked to a test or an explicitly unqualified claim.
- `dev/winvm/README.md`: setup, required media, all commands, artifact paths,
  failed-run inspection and safe cleanup.
- `VALIDATION.md`: dated, revision-specific evidence; separate passed,
  untested, unsupported, and blocked results.
- Versioned lock files and `qualification-matrix.json`, plus a required-case
  manifest and independently tested evidence validator.

## 10. Sources and reproduction references

Repository-specific recommendations above come from the inspected source,
including material that is not available in older pkg.go.dev snapshots. The
design and test IDs in this document are proposed new work.

- [R1: sysnet-linux flake][r1], [justfile][r2], [DNS end-to-end cases][r3].
- [R2: controller flake][r4], [justfile][r5], [CI workflow directory][r6].
- [R3: Windows VM guide][r7], [image lock][r8], [native driver lock][r9],
  [Wintun lock][r10], [qualification matrix][r11], [validation record][r12].
- [R4: controller integration guide][r13], [session example][r14],
  [tunneldemo guide][r15].
- [R5: tuntap Windows implementation][r16], [gonnect socket ownership][r17],
  [socket options][r18], [Network interface][r19], [sysnet interface][r20].
- [W1: winipcfg package][w1].
- [W2: Windows DNS interface API][w2].
- [W3: IPv4][w3] and [IPv6 outgoing-interface socket options][w4].
- [W4: Windows route structure and metrics][w5].
- [W5: WFP filter arbitration][w6] and [tailscale/wf][w8].
- [W6: Windows Packet Monitor][w9].
- [W7: Go race detector requirements][w7].

[r1]: https://github.com/asciimoth/sysnet-linux/blob/2b846deee13b5e3faa0b09a87f0a551b2c8c1b14/flake.nix
[r2]: https://github.com/asciimoth/sysnet-linux/blob/2b846deee13b5e3faa0b09a87f0a551b2c8c1b14/justfile
[r3]: https://github.com/asciimoth/sysnet-linux/blob/2b846deee13b5e3faa0b09a87f0a551b2c8c1b14/e2e/dns/README.md
[r4]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/flake.nix
[r5]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/justfile
[r6]: https://github.com/asciimoth/mullvad-split-tunnel-go/tree/f5db35e093d7be835882cbf68911f83be1cdacff/.github/workflows
[r7]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/dev/winvm/README.md
[r8]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/dev/winvm/image-lock.json
[r9]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/dev/winvm/native-driver-lock.json
[r10]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/dev/winvm/tunneldemo-lock.json
[r11]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/dev/winvm/qualification-matrix.json
[r12]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/VALIDATION.md
[r13]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/docs/integration.md
[r14]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/examples/session/session.go
[r15]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/docs/tunneldemo.md
[r16]: https://github.com/asciimoth/tuntap/blob/c77bd95431d175227c37a89cb40d0e7f9ff3838d/tun_windows.go
[r17]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sockowner/sockowner_windows.go
[r18]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sockopt/sockopt_windows.go
[r19]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/ftypes.go
[r20]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sysnet/iface.go
[w1]: https://pkg.go.dev/golang.zx2c4.com/wireguard/windows/tunnel/winipcfg
[w2]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
[w3]: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
[w4]: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
[w5]: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
[w6]: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
[w7]: https://go.dev/doc/articles/race_detector
[w8]: https://github.com/tailscale/wf
[w9]: https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon
