# gonnect contract baseline

This repository compiles against `github.com/asciimoth/gonnect v0.55.0`, commit
`823c6fe6c55755880ec217d5643134a89d339f03`. `go.mod` and `go.sum` lock the
module. This note records the contract used by the Windows implementation.

The capability proposal is available in this gonnect revision. Therefore, this
repository uses `sysnet.CapabilityReport`, `sysnet.TunCapabilityReport`, and the
validation types from gonnect. It does not publish a second capability API.

## System

`sysnet.System` has these methods:

```go
Close() error
Capabilities() sysnet.CapabilityReport
CapabilitiesForTun(tun.Tun) (sysnet.TunCapabilityReport, error)
CheckTunOpts(sysnet.TunOpts) sysnet.ValidationReport
CheckDefaultTunOpts(sysnet.DefaultTunOpts) sysnet.ValidationReport
CheckRule(sysnet.Rule, sysnet.RuleContext) sysnet.ValidationReport
CompleteRule(sysnet.Rule, sysnet.RuleContext) ([]string, error)
AllocIP() subnet.IPAllocator
AllocSubnet() subnet.SubnetAllocator
OutDNS() dns.Interface
OutNet() gonnect.Network
LocalNet() gonnect.Network
BuildMatcher(sysnet.Rule) (sysnet.Matcher, error)
BuildDefaultTun(sysnet.DefaultTunOpts) (sysnet.DefaultTun, error)
DefaultTunWarnings(sysnet.DefaultTun) []sysnet.Warning
BuildTun(sysnet.TunOpts) (tun.Tun, error)
TunWarnings(tun.Tun) []sysnet.Warning
SetTunMTU(tun.Tun, int) error
SetTunAddrs(tun.Tun, []string) error
AddTunAddr(tun.Tun, string) error
GetTunAddrs(tun.Tun) ([]string, error)
SetTunRoutes(tun.Tun, []string) error
AddTunRoute(tun.Tun, string) error
GetTunRoutes(tun.Tun) ([]string, error)
SetTunName(tun.Tun, string) error
```

The assertion in `system.go` makes a build fail if this method set changes.
Capability reporting and validation are part of `System` in v0.55.0. They are
not optional extension interfaces in this revision.

## TUN and default TUN

`tun.Tun` has these methods:

```go
File() *os.File
IsNative() bool
Read([][]byte, []int, int) (int, error)
Write([][]byte, int) (int, error)
MWO() int
MRO() int
MTU() (int, error)
Name() (string, error)
Events() <-chan tun.Event
Close() error
BatchSize() int
```

`sysnet.DefaultTun` embeds `tun.Tun` and adds:

```go
SetDNS(dns.Interface) error
```

The option records are part of the contract. `sysnet.TunOpts` contains `Name`,
`TunAddrs`, `TunRoutes`, and `MTU`. `sysnet.DefaultTunOpts` contains those
fields and `SourceRoutes`, `DnsIP`, `Strict`, `Exclude`, and `Include`.

## Network

`gonnect.Network` embeds `gonnect.Resolver` and has these direct methods:

```go
IsNative() bool
Dial(context.Context, string, string) (net.Conn, error)
Listen(context.Context, string, string) (net.Listener, error)
PacketDial(context.Context, string, string) (gonnect.PacketConn, error)
ListenPacket(context.Context, string, string) (gonnect.PacketConn, error)
DialTCP(context.Context, string, string, string) (gonnect.TCPConn, error)
ListenTCP(context.Context, string, string) (gonnect.TCPListener, error)
DialUDP(context.Context, string, string, string) (gonnect.UDPConn, error)
ListenUDP(context.Context, string, string) (gonnect.UDPConn, error)
ListenPacketConfig(context.Context, *gonnect.ListenConfig, string, string) (gonnect.PacketConn, error)
ListenUDPConfig(context.Context, *gonnect.ListenConfig, string, string) (gonnect.UDPConn, error)
ListenMulticastUDP(context.Context, string, string, gonnect.MulticastOptions) (gonnect.MulticastPacketConn, error)
Interfaces() ([]gonnect.NetworkInterface, error)
InterfaceAddrs() ([]net.Addr, error)
InterfaceMulticastAddrs() ([]net.Addr, error)
InterfacesByIndex(int) ([]gonnect.NetworkInterface, error)
InterfacesByName(string) ([]gonnect.NetworkInterface, error)
```

The embedded resolver has these methods:

```go
LookupIP(context.Context, string, string) ([]net.IP, error)
LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
LookupHost(context.Context, string) ([]string, error)
LookupAddr(context.Context, string) ([]string, error)
LookupCNAME(context.Context, string) (string, error)
LookupPort(context.Context, string, string) (int, error)
LookupNS(context.Context, string) ([]*net.NS, error)
LookupMX(context.Context, string) ([]*net.MX, error)
LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
LookupTXT(context.Context, string) ([]string, error)
```

## Matcher and DNS

`sysnet.Matcher` has these methods:

```go
Close() error
Match(sockowner.FlowTuple) (bool, error)
```

`dns.Interface` has these methods:

```go
Requests() chan<- dns.Request
Close() error
```

The DNS request contains a context, message, and response channel. The default
TUN replaces its active DNS provider through `SetDNS`.

## Accepted changes from the inspected plan baseline

The implementation plan inspected gonnect commit
`260fb7b56c218f267f55bfd271a7ab4eff615977`. The selected v0.55.0 contract
includes these accepted changes:

- `GetTunRotue` is now `GetTunRoutes`. The Windows package implements only the
  selected, correctly spelled method.
- `SetTunName` returns `error`.
- `DefaultTun.SetDNS` returns `error` and uses the `SetDNS` spelling.
- `TunOpts` and `DefaultTunOpts` include `Name` for creation-time names.
- `Capabilities`, per-TUN capabilities, and validation are in `System`.
- The old `Features`, `RulesInfo`, `VerifyTunOpts`, `VerifyDefaultTunOpts`,
  `RuleVerify`, and `ListRules` surface is not in v0.55.0.

The package keeps the old `Features` and `RulesInfo` projection model private.
Its test checks the conservative mapping described in the companion proposal.
This gives migration coverage without adding obsolete public names.
