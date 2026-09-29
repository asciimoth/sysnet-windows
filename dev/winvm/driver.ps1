$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Get-DriverEvidence([string]$ManifestPath) {
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $driver = 'C:\Windows\System32\drivers\mullvad-split-tunnel.sys'
    $packageDirectory = if ($manifest.PSObject.Properties['driverDirectory']) { $manifest.driverDirectory } else { 'C:\winvm\driver' }
    $packageFiles = [ordered]@{}
    foreach ($property in $manifest.driverFiles.PSObject.Properties) {
        $packageFile = Join-Path $packageDirectory $property.Name
        $actualHash = (Get-FileHash $packageFile -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $property.Value) { throw "Driver package hash mismatch: $($property.Name)" }
        $packageFiles[$property.Name] = $actualHash
    }
    $installedFileHash = (Get-FileHash $driver -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedFileHash -ne $manifest.driverFiles.'mullvad-split-tunnel.sys') { throw 'Installed driver hash mismatch' }
    $packageDriverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $packageDirectory 'mullvad-split-tunnel.sys')
    $packageCatalogSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $packageDirectory 'mullvad-split-tunnel.cat')
    if ($packageDriverSignature.Status -ne 'Valid' -or -not $packageDriverSignature.SignerCertificate -or
        $packageCatalogSignature.Status -ne 'Valid' -or -not $packageCatalogSignature.SignerCertificate) {
        throw 'The staged driver package signature is not valid'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $driver
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw "Driver signature is $($signature.Status)" }
    $mullvadSigner = 'CN=Mullvad VPN AB'
    $windowsSigner = 'CN=Microsoft Windows Hardware Compatibility Publisher'
    if ($manifest.driverSigner -notmatch [regex]::Escape($mullvadSigner)) {
        throw 'The staged package does not have the expected Mullvad signer'
    }
    foreach ($stagedSigner in @(
        $packageDriverSignature.SignerCertificate.Subject,
        $packageCatalogSignature.SignerCertificate.Subject
    )) {
        if ($stagedSigner -notmatch [regex]::Escape($mullvadSigner) -and
            $stagedSigner -notmatch [regex]::Escape($windowsSigner)) {
            throw 'The staged package has an unexpected signer'
        }
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
    [ordered]@{
        service=$service.Name; state=$service.State; startMode=$service.StartMode
        path=$service.PathName; version=$version
        packageFiles=$packageFiles
        packageSigner=$manifest.driverSigner
        stagedDriverSigner=$packageDriverSignature.SignerCertificate.Subject
        packageCatalogSigner=$packageCatalogSignature.SignerCertificate.Subject
        installedFileSha256=$installedFileHash
        signer=$signature.SignerCertificate.Subject
        signature=$signature.Status.ToString()
    }
}
