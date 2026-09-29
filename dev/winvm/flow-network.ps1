[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Client', 'Endpoint')][string]$Role
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FlowAdapter([string]$MacAddress) {
    $adapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq $MacAddress }
    if (@($adapter).Count -ne 1) {
        throw "Expected one flow adapter with MAC address $MacAddress"
    }
    return $adapter
}

function Reset-FlowAdapter($Adapter, [bool]$WeakHost) {
    $weakHostState = if ($WeakHost) { 'Enabled' } else { 'Disabled' }
    Set-NetIPInterface -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled
    Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressFamily -eq 'IPv4' -or $_.PrefixOrigin -ne 'WellKnown' } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceIndex $Adapter.ifIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -ne 'ff00::/8' } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 `
        -AutomaticMetric Disabled -InterfaceMetric 5 `
        -WeakHostReceive $weakHostState -WeakHostSend $weakHostState
    Set-NetIPInterface -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv6 `
        -AutomaticMetric Disabled -InterfaceMetric 5 `
        -WeakHostReceive $weakHostState -WeakHostSend $weakHostState
}

$macSuffix = if ($Role -eq 'Client') { @('10', '11') } else { @('20', '21') }
$tunnel = Get-FlowAdapter "52-54-00-12-34-$($macSuffix[0])"
$underlay = Get-FlowAdapter "52-54-00-12-34-$($macSuffix[1])"
$weakHost = $Role -eq 'Endpoint'
Reset-FlowAdapter $tunnel $weakHost
Reset-FlowAdapter $underlay $weakHost

if ($Role -eq 'Client') {
    New-NetIPAddress -InterfaceIndex $tunnel.ifIndex -IPAddress '198.18.0.2' -PrefixLength 24 | Out-Null
    New-NetIPAddress -InterfaceIndex $tunnel.ifIndex -IPAddress 'fd00:18:0::2' -PrefixLength 64 | Out-Null
    New-NetIPAddress -InterfaceIndex $underlay.ifIndex -IPAddress '198.18.1.2' -PrefixLength 24 | Out-Null
    New-NetIPAddress -InterfaceIndex $underlay.ifIndex -IPAddress 'fd00:18:1::2' -PrefixLength 64 | Out-Null

    # The dependency conformance gate starts with a preferred physical tunnel
    # route. e2e.ps1 removes these two routes before the public Wintun gate.
    New-NetRoute -InterfaceIndex $tunnel.ifIndex -DestinationPrefix '203.0.113.1/32' `
        -NextHop '198.18.0.1' -RouteMetric 5 | Out-Null
    New-NetRoute -InterfaceIndex $underlay.ifIndex -DestinationPrefix '203.0.113.1/32' `
        -NextHop '198.18.1.1' -RouteMetric 50 | Out-Null
    New-NetRoute -InterfaceIndex $tunnel.ifIndex -DestinationPrefix '2001:db8:ffff::1/128' `
        -NextHop 'fd00:18:0::1' -RouteMetric 5 | Out-Null
    New-NetRoute -InterfaceIndex $underlay.ifIndex -DestinationPrefix '2001:db8:ffff::1/128' `
        -NextHop 'fd00:18:1::1' -RouteMetric 50 | Out-Null
    # OutDNS discovers these controlled numeric upstreams before the default
    # TUN replaces its own resolver configuration with the managed proxy.
    Set-DnsClientServerAddress -InterfaceIndex $underlay.ifIndex `
        -ServerAddresses @('203.0.113.1', '2001:db8:ffff::1')
} else {
    New-NetIPAddress -InterfaceIndex $tunnel.ifIndex -IPAddress '198.18.0.1' -PrefixLength 24 | Out-Null
    New-NetIPAddress -InterfaceIndex $tunnel.ifIndex -IPAddress 'fd00:18:0::1' -PrefixLength 64 | Out-Null
    New-NetIPAddress -InterfaceIndex $underlay.ifIndex -IPAddress '198.18.1.1' -PrefixLength 24 | Out-Null
    New-NetIPAddress -InterfaceIndex $underlay.ifIndex -IPAddress 'fd00:18:1::1' -PrefixLength 64 | Out-Null
    New-NetIPAddress -InterfaceIndex $tunnel.ifIndex -IPAddress '203.0.113.1' `
        -PrefixLength 32 -SkipAsSource $true | Out-Null
    New-NetIPAddress -InterfaceIndex $tunnel.ifIndex -IPAddress '2001:db8:ffff::1' `
        -PrefixLength 128 -SkipAsSource $true | Out-Null
}

$evidence = [ordered]@{
    role = $Role
    tunnel = [ordered]@{ name=$tunnel.Name; index=$tunnel.ifIndex; mac=$tunnel.MacAddress }
    underlay = [ordered]@{ name=$underlay.Name; index=$underlay.ifIndex; mac=$underlay.MacAddress }
    addresses = @(Get-NetIPAddress -InterfaceIndex $tunnel.ifIndex, $underlay.ifIndex |
        Select-Object InterfaceIndex, AddressFamily, IPAddress, PrefixLength, SkipAsSource)
    routes = @(Get-NetRoute -InterfaceIndex $tunnel.ifIndex, $underlay.ifIndex |
        Select-Object InterfaceIndex, AddressFamily, DestinationPrefix, NextHop, RouteMetric)
}
$evidence | ConvertTo-Json -Depth 5
