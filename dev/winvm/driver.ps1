$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Get-DriverEvidence([string]$ManifestPath) {
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $driver = 'C:\Windows\System32\drivers\mullvad-split-tunnel.sys'
    $packageDirectory = if ($manifest.PSObject.Properties['driverDirectory']) { $manifest.driverDirectory } else { 'C:\winvm\driver' }
    foreach ($property in $manifest.driverFiles.PSObject.Properties) {
        $packageFile = Join-Path $packageDirectory $property.Name
        if ((Get-FileHash $packageFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $property.Value) { throw "Driver package hash mismatch: $($property.Name)" }
    }
    if ((Get-FileHash $driver -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.driverFiles.'mullvad-split-tunnel.sys') { throw 'Installed driver hash mismatch' }
    $signature = Get-AuthenticodeSignature -LiteralPath $driver
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw "Driver signature is $($signature.Status)" }
    $mullvadSigner = 'CN=Mullvad VPN AB'
    $windowsSigner = 'CN=Microsoft Windows Hardware Compatibility Publisher'
    if ($manifest.driverSigner -notmatch [regex]::Escape($mullvadSigner)) {
        throw 'The staged package does not have the expected Mullvad signer'
    }
    if ($signature.SignerCertificate.Subject -notmatch [regex]::Escape($mullvadSigner) -and
        $signature.SignerCertificate.Subject -notmatch [regex]::Escape($windowsSigner)) {
        throw 'The installed driver does not have an expected package or WHCP signer'
    }
    $version = (Get-Item $driver).VersionInfo.FileVersionRaw.ToString()
    if ($version -ne $manifest.driverVersion) { throw "Driver version is $version, not $($manifest.driverVersion)" }
    $service = Get-CimInstance Win32_SystemDriver -Filter "Name='$($manifest.driverService)'"
    if (-not $service -or $service.StartMode -ne 'Manual') { throw 'Driver service is absent or is not demand-start' }
    $validPaths = @(
        '\SystemRoot\System32\drivers\mullvad-split-tunnel.sys',
        (Join-Path $env:SystemRoot 'System32\drivers\mullvad-split-tunnel.sys')
    )
    if ($service.PathName -notin $validPaths) { throw "Unexpected driver path: $($service.PathName)" }
    [ordered]@{service=$service.Name; state=$service.State; startMode=$service.StartMode; path=$service.PathName; version=$version; signer=$signature.SignerCertificate.Subject; signature=$signature.Status.ToString()}
}
