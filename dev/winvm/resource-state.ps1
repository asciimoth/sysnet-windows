$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Get-NativeResourceSnapshot returns only stable configuration fields. Runtime
# counters, address lifetimes, and connection state are intentionally absent.
# The resource gate compares the complete result before and after its workload.
function Get-NativeResourceSnapshot {
    $adapters = @(Get-NetAdapter -IncludeHidden | Sort-Object InterfaceGuid | ForEach-Object {
            [ordered]@{
                interfaceGuid = $_.InterfaceGuid.ToString().ToLowerInvariant()
                interfaceIndex = [uint32]$_.ifIndex
                name = $_.Name
                description = $_.InterfaceDescription
                status = $_.Status.ToString()
            }
        })
    $addresses = @(Get-NetIPAddress | Sort-Object InterfaceIndex, AddressFamily, IPAddress, PrefixLength | ForEach-Object {
            [ordered]@{
                interfaceIndex = [uint32]$_.InterfaceIndex
                family = $_.AddressFamily.ToString()
                address = $_.IPAddress
                prefixLength = [uint32]$_.PrefixLength
                prefixOrigin = $_.PrefixOrigin.ToString()
                suffixOrigin = $_.SuffixOrigin.ToString()
                skipAsSource = [bool]$_.SkipAsSource
            }
        })
    $routes = @(Get-NetRoute -PolicyStore ActiveStore | Sort-Object InterfaceIndex, AddressFamily, DestinationPrefix, NextHop, RouteMetric | ForEach-Object {
            [ordered]@{
                interfaceIndex = [uint32]$_.InterfaceIndex
                family = $_.AddressFamily.ToString()
                destination = $_.DestinationPrefix
                nextHop = $_.NextHop
                metric = [uint32]$_.RouteMetric
                protocol = $_.Protocol.ToString()
            }
        })
    $dns = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex, AddressFamily | ForEach-Object {
            [ordered]@{
                interfaceIndex = [uint32]$_.InterfaceIndex
                family = $_.AddressFamily.ToString()
                servers = @($_.ServerAddresses)
            }
        })
    [ordered]@{
        schemaVersion = 1
        adapters = $adapters
        addresses = $addresses
        routes = $routes
        dns = $dns
    }
}

function Compare-NativeResourceSnapshot([object]$Before, [object]$After) {
    $beforeJSON = $Before | ConvertTo-Json -Depth 8 -Compress
    $afterJSON = $After | ConvertTo-Json -Depth 8 -Compress
    if ($beforeJSON -cne $afterJSON) {
        throw 'Native adapters, addresses, routes, or DNS settings changed across the resource gate'
    }
}
