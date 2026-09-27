[CmdletBinding()]
param(
    [string]$SourceDir = $PWD,
    [string]$ArtifactDir = (Join-Path $PWD '.artifacts-windows-live'),
    [switch]$AllowDisposableHost
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -ne 'true' -and -not $AllowDisposableHost) {
    throw 'This script changes a disposable Windows host; use -AllowDisposableHost'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The native live-driver gate requires an administrator'
}
$architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "Unsupported native architecture: $env:PROCESSOR_ARCHITECTURE" }
}
$SourceDir = (Resolve-Path $SourceDir).Path
$sysnetWindowsRevision = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { (& git -C $SourceDir rev-parse HEAD | Out-String).Trim() }
if (-not $sysnetWindowsRevision) { throw 'Cannot identify the sysnet-windows revision' }
$sysnetWindowsTreeState = if (& git -C $SourceDir status --porcelain) { 'dirty' } else { 'clean' }
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
$temporaryRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$work = Join-Path $temporaryRoot "mullvad-split-tunnel-$architecture-$PID"
$driverDirectory = Join-Path $work 'driver'
$manifestPath = Join-Path $work 'manifest.json'
$resultFile = Join-Path $work 'result.txt'
$service = 'mullvad-split-tunnel'
$installedDriver = Join-Path $env:SystemRoot 'System32\drivers\mullvad-split-tunnel.sys'
$taskName = "mullvad-split-tunnel-e2e-$PID"
$sourceArchive = Join-Path $work 'source.tar'

if (Get-Service $service -ErrorAction SilentlyContinue) {
    throw "Refusing to replace existing service $service"
}
if (Test-Path $installedDriver) {
    throw "Refusing to replace existing driver file $installedDriver"
}
New-Item -ItemType Directory -Force -Path $driverDirectory | Out-Null
$lock = Get-Content (Join-Path $SourceDir 'dev\winvm\native-driver-lock.json') -Raw | ConvertFrom-Json
$architectureLock = $lock.architectures.$architecture
$hashes = $architectureLock.files
$baseURL = "https://raw.githubusercontent.com/mullvad/mullvadvpn-app-binaries/$($lock.binariesRevision)/$($architectureLock.source)/split-tunnel"

try {
    foreach ($property in $hashes.PSObject.Properties) {
        $destination = Join-Path $driverDirectory $property.Name
        Invoke-WebRequest "$baseURL/$($property.Name)" -OutFile $destination
        $actual = (Get-FileHash $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $property.Value) {
            throw "Driver package hash mismatch: $($property.Name)"
        }
    }
    $catalog = Get-AuthenticodeSignature (Join-Path $driverDirectory 'mullvad-split-tunnel.cat')
    $driver = Get-AuthenticodeSignature (Join-Path $driverDirectory 'mullvad-split-tunnel.sys')
    if ($catalog.Status -ne 'Valid' -or $driver.Status -ne 'Valid' -or
        $driver.SignerCertificate.Subject -notmatch [regex]::Escape('CN=Mullvad VPN AB')) {
        throw 'Driver package signature or signer is not valid'
    }
    & pnputil.exe /add-driver (Join-Path $driverDirectory 'mullvad-split-tunnel.inf')
    if ($LASTEXITCODE -ne 0) { throw "Cannot stage driver package: $LASTEXITCODE" }
    Copy-Item (Join-Path $driverDirectory 'mullvad-split-tunnel.sys') $installedDriver -Force
    & sc.exe create $service type= kernel start= demand error= normal binPath= '\SystemRoot\System32\drivers\mullvad-split-tunnel.sys'
    if ($LASTEXITCODE -ne 0) { throw "Cannot create driver service: $LASTEXITCODE" }

    [ordered]@{
        architecture=$architecture
        driverVersion=$lock.version
        upstreamCommit=$lock.upstreamCommit
        driverService=$service
        driverDirectory=$driverDirectory
        driverFiles=$hashes
        driverSigner=$driver.SignerCertificate.Subject
    } | ConvertTo-Json -Depth 4 | Set-Content $manifestPath

    $goExecutable = (Get-Command go).Source
    & git -C $SourceDir archive --format=tar --output=$sourceArchive HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create the source identity archive' }
    $sourceArchiveSHA256 = (Get-FileHash $sourceArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    $goModCache = Join-Path $work 'gomodcache'
    New-Item -ItemType Directory -Force -Path $goModCache | Out-Null
    $savedGoModCache = $env:GOMODCACHE
    $env:GOMODCACHE = $goModCache
    try {
        & $goExecutable -C $SourceDir mod download
        if ($LASTEXITCODE -ne 0) { throw "Cannot populate the Go module cache: $LASTEXITCODE" }
    } finally {
        $env:GOMODCACHE = $savedGoModCache
    }
    $systemScript = Join-Path $SourceDir 'dev\winvm\system-e2e.ps1'
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $systemScript + '"'),
        '-SourceDir', ('"' + $SourceDir + '"'),
        '-ArtifactDir', ('"' + $ArtifactDir + '"'),
        '-ImageManifest', ('"' + $manifestPath + '"'),
        '-GoExecutable', ('"' + $goExecutable + '"'),
        '-GoModCache', ('"' + $goModCache + '"'),
        '-SysnetWindowsRevision', ('"' + $sysnetWindowsRevision + '"'),
        '-SysnetWindowsTreeState', $sysnetWindowsTreeState,
        '-SourceArchiveSHA256', $sourceArchiveSHA256,
        '-ResultFile', ('"' + $resultFile + '"')
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddMinutes(15)
    while ($true) {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $taskName
        if ((Get-Date) -gt $deadline) { throw 'Native live-driver gate timed out' }
        if (Test-Path $resultFile) { break }
        if ($task.State -ne 'Running') {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
            throw "Native live-driver task exited without a result: $($taskInfo.LastTaskResult)"
        }
    }
    if ((Get-Content $resultFile -Raw).Trim() -ne '0') {
        $errorLog = Join-Path $ArtifactDir 'system-e2e-error.log'
        if (Test-Path $errorLog) {
            Write-Host (Get-Content $errorLog -Raw)
        }
        throw 'Native live-driver gate failed; inspect its artifacts'
    }
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Get-Service $service -ErrorAction SilentlyContinue) {
        Stop-Service $service -Force -ErrorAction SilentlyContinue
        & sc.exe delete $service | Out-Null
    }
    Remove-Item $installedDriver -Force -ErrorAction SilentlyContinue
}
