# Proposal: granular capabilities for gonnect/sysnet

Status: implementation proposal, not an implemented API. Prepared 2026-09-26.

Companion document: `sysnet-windows-implementation-testing-plan.md`.

## 1. Recommendation and compatibility strategy

Add an optional `CapabilityReporter` interface alongside `sysnet.System`. Keep
`System`, `Features`, `RulesInfo`, and the existing method signatures intact in
the first release. New applications use the detailed report; existing ones keep
using the old methods and handle errors as before. An optional validator supplies
structured, context-specific rejection reasons.

The report must distinguish:

- implemented behavior from behavior currently usable on this host;
- regular TUN operations from default-TUN operations;
- IPv4, IPv6, and simultaneous dual-stack configurations;
- full/default routing, include routing, and exclude routing;
- each routing mode combined with strict mode;
- rule types accepted for routing from rule types accepted for matchers;
- best-effort owner lookup from kernel routing enforcement;
- system-wide potential from restrictions on an already-created TUN.

Do not add a growing list of booleans such as `AppRules`, `WindowsRules`, or
`AdvancedRouting`. These conceal the combinations a caller actually needs.
Do not change `Features()` to return another type: that breaks every backend.
Adding a method directly to `System` also breaks every implementation and mock.

The recommended minimum implementation is Sections 3–7 and 10. Per-TUN reports
and change notifications are additive extensions; they are not prerequisites for
the first Windows backend.

## 2. Gaps in the current contract

The inspected contract is [gonnect/sysnet/iface.go at 260fb7b][sysnet]. Linux was
inspected at [2b846de][linux].

| Current API | Missing distinction |
| --- | --- |
| `Features.Tun`, `DefaultTun` | Usable families and missing host prerequisites |
| `DynTun`, `DynDefaultTun` | MTU, address, route, and name operations differ |
| `TunNames`, `DefaultTunNames` | Creation-time naming versus later renaming |
| `StrictMode` | Full+strict can differ from exclude+strict or include+strict |
| `RulesInfo.TunRules` | Include and exclude support can differ |
| `RuleVerify(Rule) bool` | No use context, diagnostic, or availability result |
| `OutNet`, `LocalNet`, `OutDNS` | No transport/family capability description |
| `BuildMatcher` | Owner lookup can differ by protocol, family, field, and quality |
| Runtime warnings | Warnings describe an active object, not feature availability |

The current `TunOpts` and `DefaultTunOpts` have no name field. The interface also
forbids `SetTunName` on a default TUN. Capability work must not accidentally
advertise a name-setting operation that the API cannot express.

## 3. Availability and diagnostic vocabulary

Use a four-state value. Zero must be unknown, never available.

```go
type CapabilityState uint8

const (
    CapabilityUnknown CapabilityState = iota
    CapabilityUnsupported
    CapabilityUnavailable
    CapabilityAvailable
)

type CapabilityReason string
type LimitationID string

type Capability struct {
    State       CapabilityState
    Reasons     []CapabilityReason
    Detail      string
    Limitations []LimitationID
}
```

| State | Exact interpretation | Windows example |
| --- | --- | --- |
| Unknown | The backend cannot currently establish availability, or an older reporter omitted this entry | Driver ownership has not been checked |
| Unsupported | This implementation does not implement the requested behavior | Include-only application routing in the initial backend |
| Unavailable | Implemented, but disabled or blocked by a known prerequisite | Missing driver, insufficient privileges, no IPv6 underlay |
| Available | Implemented and known prerequisites currently hold for the stated scope | IPv4 exclusion routing with an owned, verified driver session |

Available is a snapshot, not a reservation, an authorization grant, or a promise
that every input or subsequent OS call succeeds. File access, resource limits,
and host state may change immediately afterwards. A limitation must not weaken
the behavior named by the capability: an inability to enforce strict mode is an
unsupported/unavailable strict profile, not an available profile with a warning.

Standardize these reason strings in `sysnet`: `not_implemented`,
`unsupported_platform`, `unsupported_combination`, `disabled_by_config`,
`missing_dependency`, `dependency_incompatible`, `permission_denied`,
`resource_busy`, `no_underlay`, `address_family_unavailable`,
`recovery_required`, `system_closed`, `probe_not_run`, and `probe_failed`.
Backend-specific reasons use a namespace, for example
`windows.split_driver_zombie`. Localize reason codes in the application; `Detail`
is diagnostic text and must not be parsed or used as a stable identifier.

Use unsupported for implementation limitations even when the host also lacks a
dependency. Use unavailable for an implemented feature disabled by configuration.
Return all material reasons in deterministic order. Do not put credentials,
complete process inventories, or unrelated local paths in capability reports.

## 4. Proposed report types

Use typed keys with exported constants for the identifiers listed below. String
backing permits unknown future values without inventing bit positions. A report
is an inventory of exact rows, not a set of booleans whose Cartesian product may
be assumed to work.

The following declarations are the proposed data model. String-value tables in
Sections 5–6 define the initial constants to add alongside these types.

```go
type CapabilityReporter interface {
    Capabilities() CapabilityReport
}

type Target string
type Operation string
type AddressFamily string
type RoutingMode string
type Transport string
type MatchQuality string
type RuleValueKind string
type OwnerField string

type OperationKey struct {
    Target    Target
    Operation Operation
    Family    AddressFamily
}

type OperationCapability struct {
    Key OperationKey
    Capability
}

type RoutingProfileKey struct {
    Family AddressFamily
    Mode   RoutingMode
    Strict bool
}

type RuleBinding struct {
    Type string
    Capability
}

type DefaultTunProfile struct {
    Key RoutingProfileKey
    Capability
    Rules []RuleBinding
}

type MatcherProfileKey struct {
    Family    AddressFamily
    Transport Transport
}

type MatcherProfile struct {
    Key MatcherProfileKey
    Capability
    Quality MatchQuality
}

type RuleCapability struct {
    Type        string
    Description string
    ValueKind   RuleValueKind
    SemanticsID string
    Validation  Capability
    Completion  Capability
    Matchers    []MatcherProfile
}

type OwnerFieldCapability struct {
    Field OwnerField
    Capability
}

type OwnerCapability struct {
    Key MatcherProfileKey
    Capability
    Quality MatchQuality
    Fields  []OwnerFieldCapability
}

type CapabilityReport struct {
    SchemaVersion      uint32
    Revision           uint64
    Operations         []OperationCapability
    DefaultTunProfiles []DefaultTunProfile
    Rules              []RuleCapability
    Ownership          []OwnerCapability
}
```

`SchemaVersion=1` names this report schema. `Revision` is an instance-local,
monotonically increasing revision of its semantic contents. It is not a time,
configuration generation, repository revision, or value comparable across System
instances. It changes when an effective state, reason, limitation, or catalog
entry changes. Equal snapshots can retain the same revision.

Provide `CapabilityReport.Clone`, lookup helpers `Operation(key)`,
`DefaultTunProfile(key)`, and `Rule(type)`, and a report consistency validator.
Unknown keys or absent rows return `CapabilityUnknown` through lookup helpers.
Reporters should explicitly list unsupported entries for the published core
catalog; consumers must still tolerate missing/future entries conservatively.
Reject duplicate keys in report conformance tests. Unknown states are treated as
unknown by consumers, never as available.

`Capabilities()` returns a deep copy or an independently owned immutable value.
It is cheap, concurrency-safe, and performs no disruptive probe. It must not
create a TUN, open the exclusive driver merely to test it, install a service,
change routes, or rewrite DNS. Initialization and monitor workers gather facts;
the getter reads their cached result. Read-only failed probes may leave a row
unknown with a diagnostic. Constructors may provide an explicit opt-in probe
policy, but querying capabilities does not trigger privileged changes.

### 4.1 Avoid false certainty about dependencies

Seeing the driver service installed does not prove exclusive device ownership.
Before acquiring a session, an exclusion profile may be unknown. Once a busy
device is observed it becomes unavailable/resource_busy. Once this System owns
and verifies the session, it can be available. A driver claimed by this System
is not busy relative to the same System. Ordinary full routing must not depend
on the split driver if no exclusions were requested.

## 5. Operation catalog and scope

Targets are `system`, `tun`, `default_tun`, `out_net`, `local_net`, and `out_dns`.
Families are `none`, `ipv4`, `ipv6`, and `dual`. `none` means family-independent;
it is not an alias for any family. `dual` means simultaneous operation, not
merely separate success for IPv4 and IPv6. Ownership/matcher rows use IPv4 or
IPv6, never dual. Transport constants are `tcp` and `udp` initially.

| Target | Operation identifiers | Family scope and interpretation |
| --- | --- | --- |
| `system` | `allocate_ip`, `allocate_subnet` | IPv4/IPv6; host-aware allocation, no route mutation |
| `tun` | `create` | IPv4, IPv6, dual, or none for an unaddressed device |
| `tun`, `default_tun` | `set_mtu`, `rename` | `none`; on a live owned object |
| `tun`, `default_tun` | `set_addresses`, `add_address`, `get_addresses`, `set_routes`, `add_route`, `get_routes` | IPv4/IPv6/dual where applicable; dual for mixed-list updates |
| `default_tun` | `create`, `reconfigure_in_place`, `source_routes` | IPv4/IPv6/dual; create combines with an explicit routing profile |
| `default_tun` | `dns_provider`, `dns_configure`, `dns_port53_exclusive`, `dns_system_exclusive` | DNS transport families, not the A/AAAA query type |
| `out_net`, `local_net` | `dial_tcp`, `dial_udp`, `packet_dial_udp`, `listen_tcp`, `listen_udp`, `listen_packet_udp`, `multicast_udp` | IPv4/IPv6; dual only where a single dual-stack listener is genuinely supported |
| `out_net`, `local_net` | `resolve`, `interfaces` | `none`; resolver methods and interface enumeration |
| `out_dns` | `query_udp`, `query_tcp` | IPv4/IPv6 upstream transport |

Every identifier gets a Go constant, such as `TargetDefaultTun`, `OpSetMTU`, and
`FamilyIPv4`. Add separate identifiers if raw-IP or Unix-domain operations are
later exposed as capabilities. Do not infer them from UDP/TCP support.

`dial_tcp` covers both generic `Dial("tcp...")` and typed `DialTCP`;
`listen_udp` covers `ListenUDP` and `ListenUDPConfig`. Configured variants may
impose input-specific restrictions that validation must report. Bypass or
loopback policy must hold through every variant, including caller-supplied
control hooks. `resolve` must hold for all supported `gonnect.Resolver` methods,
not just `LookupIP`.

`reconfigure_in_place` means updates through a repeated `BuildDefaultTun` can
preserve the active native device for supported configuration-only changes.
It does not promise preservation following external device deletion. Public
wrapper identity and source-generation extensions remain backend-specific and
must be documented separately. Keeping a wrapper while replacing its native
source alone is insufficient to advertise this capability for ordinary changes.

`dns_provider` includes provider replacement and `SetDns(nil)` dropping managed
requests. It does not mean all applications' DNS is captured. `dns_configure`
means configure/restore the intended OS resolver path. `dns_port53_exclusive`
means enforcement for the documented conventional TCP/UDP 53 scope.
`dns_system_exclusive` means exclusivity of the supported OS-managed resolver
path, including any OS-managed encrypted-DNS configuration within the claimed
scope. Application-owned DoH/DoT and arbitrary encrypted payloads are not
implicitly covered. Neither weaker DNS capability implies the stronger one.

Object `Close`, basic TUN I/O, and mandatory nil-provider behavior are contracts,
not optional capabilities. A backend unable to meet them must not advertise
creation. Packet I/O for a native TUN is not restricted to TCP/UDP merely because
its owner lookup is; preserve valid IP traffic, including ICMP, independently.

## 6. Routing and rule capabilities

Routing modes are `full`, `exclude`, and `include`. Full means no application
selection list. It does not override more-specific routes by itself. Strict
means traffic outside the permitted tunnel policy is dropped, subject to the
explicitly defined infrastructure exceptions needed for the backend to operate.

Evaluate an exact `(family, mode, strict)` profile. IPv4 exclude and IPv6 full
support do not imply dual-stack exclude support. Full+strict support does not
imply exclude+strict support. Make unsupported profile combinations explicit.

For full mode, `Rules` is empty. For include/exclude modes it lists the rule types
accepted in that exact context with their individual availability. An available
include/exclude profile must have at least one available rule binding. Every
requested binding must be available or be resolved during the operation's final
preflight. A catalog entry in `Rules` is descriptive; it is not permission to use
that rule anywhere.

Define application lists as OR across entries. Include and exclude remain
mutually exclusive. A profile lists candidate rule types, but arbitrary mixtures
are not guaranteed: exact options validation remains authoritative for mixed
types, counts, syntax, and other combinations. Do not advertise a rule after
silently reducing its semantics to a weaker Windows approximation.

Recommended initial Windows rules:

| Type | Routing bindings | Matcher profiles | Semantics |
| --- | --- | --- | --- |
| `win-exe-tree` | Non-strict exclude only | None | Resolved local executable NT path plus driver inheritance |
| `win-exe-path` | None | TCP/UDP, IPv4/IPv6 when implemented | Exact normalized owning executable path, no inheritance |
| `win-pid` | None | TCP/UDP, IPv4/IPv6 when implemented | Current reported owning PID; no lifetime identity promise |
| `win-process-name` | None; optional | Same as above | Basename match, ambiguous between distinct executables |

`ValueKind` can be `path`, `pid`, `name`, `regex`, or `opaque`; it is a UI hint,
not a substitute for validation. `SemanticsID`, for example
`windows.nt-path-descendants.v1`, identifies a documented behavior contract.
Changing path identity, case treatment, inheritance, or matching language should
use another semantics version or rule type, not silently reinterpret saved rules.

### 6.1 Owner lookup and matcher quality

Initial quality values are `unknown`, `best_effort_tuple`, and
`best_effort_local_endpoint`. Neither is a security guarantee. TCP table lookup
uses endpoints but races socket lifetime; Windows UDP tables lack a remote
endpoint and can be ambiguous. The Mullvad controller is not an owner-query API.

Field identifiers include `pid`, `process_name`, `executable_path`, `uid`, `gid`,
and `user_sid`. Mark unsupported fields individually. Windows numeric Linux UID
and GID remain unsupported; a future SID extension must not put a SID into them.
Mark executable-path enrichment best effort even when the underlying operation
is available, because protected or exited processes can deny the data.

These rows describe a backend's ability to implement matchers. They do not add a
socket-metadata getter to `System`. Add a separate optional metadata interface
only if consumers actually need the raw information.

Unknown owner, malformed tuple, ambiguity, permission failure, and confirmed
nonmatch must not collapse into the same successful result. Preserve errors such
as `sockowner.ErrNoOwner`; callers decide their policy for unknown attribution.
Never infer enforceable routing support from an available best-effort matcher.

## 7. Context-aware validation and errors

Preserve `VerifyTunOpts`, `VerifyDefaultTunOpts`, and `RuleVerify` for compatibility.
Add an optional detailed validator:

```go
type RuleContext struct {
    // Exactly one is non-nil.
    Routing *RoutingProfileKey
    Matcher *MatcherProfileKey
}

type ValidationIssue struct {
    Path       string // e.g. "Exclude[0]", "SourceRoutes[1].Source"
    Reason     CapabilityReason
    State      CapabilityState
    Detail     string
    Err        error
}

type ValidationReport struct {
    CapabilityRevision uint64
    Issues             []ValidationIssue
}

type OptionValidator interface {
    CheckTunOpts(TunOpts) ValidationReport
    CheckDefaultTunOpts(DefaultTunOpts) ValidationReport
    CheckRule(Rule, RuleContext) ValidationReport
}
```

Provide `ValidationReport.Err()` and typed errors supporting `errors.Is/As`.
Keep `ErrNotSupported`; add `ErrUnavailable`, `ErrCapabilityUnknown`, and
`ErrInvalidOptions`. A known unsupported profile wraps `ErrNotSupported`; a busy
driver wraps `ErrUnavailable` plus the native cause. Invalid input wraps
`ErrInvalidOptions`. `State` on a syntax-only issue is unknown and is not an
availability judgment. Reports contain blocking/indeterminate issues; nonfatal
runtime warnings remain in the existing warning APIs.

Validation must share the normalization and rule compiler used by construction:

1. Check structural conflicts such as both include and exclude lists.
2. Normalize addresses/routes using the existing loopback/default rules. Determine
   the effective families, including implicit addresses and routes. An allocation
   preview must not reserve anything or mutate host state.
3. Check the create operation and exact routing profile.
4. Check each rule binding and value in its actual context.
5. Check source routes, DNS requirements, and object-specific restrictions.
6. Return deterministic issues with input locations and the observed revision.

Read-only validation may inspect executable paths but must be bounded. A path
that cannot be inspected is not automatically syntactically invalid. Snapshot
queries do not enumerate arbitrary filesystem trees for rule completion.

`Verify*` can delegate to detailed validation and `Err()`. `RuleVerify` remains
a context-free syntax hint; true does not mean usable for routing or on this
host. Document this explicitly. New UIs use `CheckRule` with a context.

A capability snapshot can be unknown while an actual operation would work. A
caller may attempt construction after an indeterminate validation result. Build
methods perform final prerequisite resolution under their ownership lock,
revalidate, and either perform the requested behavior or return an error.
They must not reject solely because an earlier cached getter had not probed a
resource. They must not substitute weaker policy to resolve uncertainty.

Validation is advisory and nonmutating; it cannot guarantee success or atomicity.
Build/update errors must still report rollback/recovery failures. Do not claim a
cross-subsystem transaction covering DNS, NetIO, WFP, and driver IOCTLs.

## 8. Optional instance reports and refresh notifications

An address setter can be supported generally but reject removing the active DNS
address from a particular default TUN. For applications needing more accurate
controls, add:

```go
type TunCapabilityReport struct {
    SystemRevision   uint64
    InstanceRevision uint64
    Operations       []OperationCapability
}

type TunCapabilityReporter interface {
    CapabilitiesForTun(tun.Tun) (TunCapabilityReport, error)
}
```

Return `ErrUnknownTun` for foreign, stale, or closed objects. Instance availability
narrows the system report; it does not expand unsupported system features.
Available still describes an operation for valid values, not every possible
mutation. Keep exact setter validation authoritative.

If needed, add `WatchCapabilities(ctx context.Context) <-chan uint64` as a
separate optional interface. Each subscription receives a current revision and
then coalesced change notifications; consumers re-read `Capabilities()`. Use a
bounded channel, close it on context cancellation/System close, and never run
user callbacks under backend locks. Polling the cheap snapshot is sufficient for
the first release. Do not change `System` just to add event delivery.

## 9. Concrete Windows reporting examples

The following describes the intended backend, once each feature has passed its
tests. It is not a claim that the unbuilt library already has these capabilities.

For example, this partial snapshot reports a usable IPv4 exclusion profile and
an explicitly unsupported include profile. A real snapshot includes the other
operation, rule, family and ownership rows as well:

```go
report := sysnet.CapabilityReport{
    SchemaVersion: 1,
    Revision:      7,
    Operations: []sysnet.OperationCapability{{
        Key: sysnet.OperationKey{
            Target: "default_tun", Operation: "create", Family: "ipv4",
        },
        Capability: sysnet.Capability{State: sysnet.CapabilityAvailable},
    }},
    DefaultTunProfiles: []sysnet.DefaultTunProfile{
        {
            Key: sysnet.RoutingProfileKey{Family: "ipv4", Mode: "exclude"},
            Capability: sysnet.Capability{State: sysnet.CapabilityAvailable},
            Rules: []sysnet.RuleBinding{{
                Type: "win-exe-tree",
                Capability: sysnet.Capability{State: sysnet.CapabilityAvailable},
            }},
        },
        {
            Key: sysnet.RoutingProfileKey{Family: "ipv4", Mode: "include"},
            Capability: sysnet.Capability{
                State:   sysnet.CapabilityUnsupported,
                Reasons: []sysnet.CapabilityReason{"not_implemented"},
            },
        },
    },
}
```

Consumer procedure: type-assert `CapabilityReporter`; retrieve one snapshot;
look up the exact create operation and routing profile; filter the profile's
rule bindings to available entries; use the rule catalog for labels/value hints;
validate the complete proposed options; then attempt Build and handle its error.
An unknown row can be shown as “availability not established,” with an explicit
attempt action. An unsupported row should not be offered as usable. Re-read the
snapshot after relevant host changes or an unavailable operation failure.

| Situation | Report |
| --- | --- |
| Wintun, NetIO, DNS, and an IPv4 underlay available | IPv4 default create and full/non-strict profile available |
| Split driver absent | Exclusion profile unavailable/missing_dependency; full routing remains available |
| Another application owns the device | Exclusion profile unavailable/resource_busy |
| Driver ownership not established | Exclusion profile unknown/probe_not_run; exact build may acquire it |
| Driver version mismatched or reset failed | Exclusion unavailable/dependency_incompatible or recovery_required |
| No IPv6 underlay | IPv6 OutNet unavailable/no_underlay; only routing profiles dependent on that underlay are affected |
| `Include` requested | Unsupported/not_implemented for all initial profiles |
| Any strict profile requested initially | Unsupported/not_implemented |
| Nonempty source-route policy requested | source_routes unsupported/not_implemented |
| TCP PID matcher usable | Available with best_effort_tuple quality |
| UDP PID matcher usable | Available with best_effort_local_endpoint quality and wildcard/ambiguity limitations |
| Regular-TUN rename not implemented | rename unsupported, even if constructor configuration chooses an adapter name |
| System closed | Previously usable operations unavailable/system_closed; static unsupported rows stay unsupported |

Do not advertise a dual-stack exclusion profile from the existence of IPv4 and
IPv6 code alone. The selected tunnel/underlay address combination must fit the
pinned driver's modes and the backend's qualified integration scope.

## 10. Legacy API projection and migration

For backends implementing the new report, maintain one underlying capability
model. Derive old flags/catalogs from it instead of maintaining independent
booleans that can disagree. Preserve the existing meaning of legacy flags where
it was defined; tighten ambiguity conservatively and document the change.

| Legacy member | Conservative projection for an upgraded backend |
| --- | --- |
| `Tun` | At least one regular create row is available |
| `DefaultTun` | At least one create row and compatible full/non-strict profile are available |
| `DynTun` | Live MTU, address and route mutation bundle is available for the advertised default regular-TUN family configuration; rename is separate |
| `DynDefaultTun` | Corresponding live default-TUN mutation bundle is available for the advertised default family configuration |
| `TunNames` | Regular rename is available; constructor-only names do not qualify |
| `DefaultTunNames` | False while `SetTunName` forbids default TUNs and creation has no name option |
| `StrictMode` | At least one usable strict profile; exact options validation still required |
| `DefaultTunSourceRoutes` | At least one usable preferred-source operation; validate requested families |
| `TunRules` | Deduplicated union of available rule bindings in usable routing profiles |
| `MatcherRules` | Types with at least one available matcher profile |

The mutation bundle for the two dynamic flags is `set_mtu`, `set_addresses`,
`add_address`, `set_routes`, and `add_route`. If only a subset is supported, the
legacy flag is false and detailed clients can still use the supported subset.
Reads and renaming have their own detailed entries. A legacy union catalog is
necessarily lossy: a rule shown there is not a promise of every mode/family.

For a backend without `CapabilityReporter`, provide an explicit
`LegacyCapabilities(System)` helper if useful. It can carry over facts the old
contract actually states, but all family-, mode-, strict-combination-, and
quality-specific entries remain unknown. Never infer include routing from
`TunRules`, exact owner lookup from `MatcherRules`, or DNS exclusivity from
`DefaultTun=true`. A strict consumer may decline an unknown guarantee.

Migration sequence:

1. Add capability types, constants, cloning/lookups, validation types and errors
   to `gonnect/sysnet`, without adding required `System` methods.
2. Add contract tests and opt-in capability fixtures to `sysnet/debug`. Preserve
   old mock defaults; explicit reports must be checked against exercised methods.
3. Update `sysnet-linux` to report actual dependencies and combinations. Retain
   p-mark, routing, DNS and killswitch distinctions. Do not claim DNS exclusivity
   just because a DNS backend can configure a resolver.
4. Add the Windows reporter and validator using the same model as operations.
5. Update applications to build UI controls from exact rows and contextual rule
   validation, while keeping handling for older implementations.
6. Consider requiring the reporter only in a deliberate breaking API release.

### 10.1 Adjacent API corrections to keep separate

- Keep `GetTunRotue` in the current interface. Offer a correctly spelled helper
  or optional method; remove the typo only in a breaking migration.
- Keep the unusual `SetTunName(...)([]string,error)` signature during this work.
  Fix its return type separately, not as an unnoticed capability change.
- If creation-time naming is needed, add `Name` to options in a separately
  documented change. Added exported struct fields can break unkeyed literals;
  audit downstream code. Specify regular/default naming independently.
- `SetDns` cannot return errors today. Establish native DNS configuration during
  build so it can fail there; keep provider swapping local. Consider an optional
  error-returning extension if later swaps need OS mutations. Do not silently
  swallow failures.
- Policy-enforcing `OutNet`/`LocalNet` wrappers must report `IsNative=false` if
  consumers bypassing their methods would bypass binding, resolver, tracking,
  or loopback restrictions. This follows `gonnect.Network`'s existing contract.
- Consider a raw-socket/family interface-binding helper in `gonnect/sockopt`;
  the current Windows helper expects `net.Conn`, not a dial-hook `RawConn`.

## 11. API acceptance tests

| ID | Test and required result |
| --- | --- |
| CAP-01 | Zero/missing/future states never become available; duplicate keys rejected |
| CAP-02 | Mutating returned nested slices cannot change backend state |
| CAP-03 | Concurrent readers and capability updates are race-free; unchanged contents retain revision |
| CAP-04 | Exclude-only catalog never advertises include; full+strict never implies exclude+strict |
| CAP-05 | Separate IPv4/IPv6 support never implies dual-stack support |
| CAP-06 | Missing, disabled, incompatible, busy, unprobed, and closed dependencies yield distinct states/reasons |
| CAP-07 | Missing split driver does not disable ordinary TUN/full routing/matchers unnecessarily |
| CAP-08 | Unsupported options fail before any fake mutator is called |
| CAP-09 | Capabilities getter/validation do not install, reserve, reset, or change host resources |
| CAP-10 | Windows tree-routing rule rejected for matching; PID matcher rejected for routing |
| CAP-11 | Legacy projections match the defined bundle; old implementations remain assignable to `System` |
| CAP-12 | Typed errors preserve sentinels and native causes through wrapping/joining |
| CAP-13 | Unknown preflight can be resolved by a later build; stale available snapshots cannot bypass final checks |
| CAP-14 | DNS weaker guarantees do not imply system exclusivity; warnings remain available on active objects |
| CAP-15 | Foreign/closed TUN capability queries fail with `ErrUnknownTun` |
| CAP-16 | Optional watcher coalesces, closes, and does not block policy work |

Also run the existing Linux and debug behavior tests after migration. A matching
report alone does not prove behavior: use the Windows plan's packet and recovery
tests to qualify every advertised guarantee.

## 12. Source baseline

- [Current sysnet contract][sysnet]
- [Linux effective features][linux-features] and [rules][linux-rules]
- [Debug implementation][debug]
- [Network interface contract][network]
- [Windows socket-owner implementation][owner]
- [Windows socket-option implementation][sockopt]
- [Split-controller integration contract][split]

[sysnet]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sysnet/iface.go
[linux]: https://github.com/asciimoth/sysnet-linux/tree/2b846deee13b5e3faa0b09a87f0a551b2c8c1b14
[linux-features]: https://github.com/asciimoth/sysnet-linux/blob/2b846deee13b5e3faa0b09a87f0a551b2c8c1b14/sysnet.go
[linux-rules]: https://github.com/asciimoth/sysnet-linux/blob/2b846deee13b5e3faa0b09a87f0a551b2c8c1b14/rules.go
[debug]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sysnet/debug/debug.go
[network]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/ftypes.go
[owner]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sockowner/sockowner_windows.go
[sockopt]: https://github.com/asciimoth/gonnect/blob/260fb7b56c218f267f55bfd271a7ab4eff615977/sockopt/sockopt_windows.go
[split]: https://github.com/asciimoth/mullvad-split-tunnel-go/blob/f5db35e093d7be835882cbf68911f83be1cdacff/docs/integration.md
