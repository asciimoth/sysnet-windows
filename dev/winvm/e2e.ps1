[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$ArtifactDir,
    [string]$ImageManifest = 'C:\winvm\manifest.json',
    [string]$GoExecutable = 'go',
    [string]$SysnetWindowsRevision = $env:GITHUB_SHA,
    [ValidateSet('clean', 'dirty', 'unknown')][string]$SysnetWindowsTreeState = 'unknown',
    [string]$SourceArchiveSHA256 = $env:SYSNET_WINDOWS_SOURCE_ARCHIVE_SHA256,
    [switch]$Flow
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem) { throw 'The live-driver gate must run as SYSTEM' }
if (-not [Environment]::Is64BitProcess) { throw 'The live-driver gate needs a 64-bit process' }
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$startedAt = (Get-Date).ToUniversalTime().ToString('o')
. (Join-Path $SourceDir 'dev\winvm\driver.ps1')
. (Join-Path $SourceDir 'dev\winvm\test-output.ps1')
$SourceArchiveSHA256 = Resolve-SourceArchiveSHA256 $SourceDir $SourceArchiveSHA256
$manifest = Get-Content $ImageManifest -Raw | ConvertFrom-Json
if ($manifest.driverVersion -ne '1.3.0.0' -or $manifest.upstreamCommit -ne '0a0eb97f67d1dbcb3d08bda66d3b24f465d95475') { throw 'Driver identity does not match the split-driver ABI' }
$nativeArchitecture = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw "Unsupported native architecture: $env:PROCESSOR_ARCHITECTURE" } }
if ($manifest.architecture.ToString().ToLowerInvariant() -ne $nativeArchitecture) { throw 'Driver package and native architecture do not match' }
$goVersion = (& $GoExecutable version | Out-String).Trim()
if ($goVersion -notmatch " windows/$nativeArchitecture$") { throw "Go process does not target native $nativeArchitecture" }
if (-not $SysnetWindowsRevision) {
    $SysnetWindowsRevision = (& git -C $SourceDir rev-parse HEAD 2>$null | Out-String).Trim()
}
if (-not $SysnetWindowsRevision) { $SysnetWindowsRevision = 'unknown' }
if ($SysnetWindowsTreeState -eq 'unknown' -and (Test-Path (Join-Path $SourceDir '.git'))) {
    $SysnetWindowsTreeState = if (& git -C $SourceDir status --porcelain) { 'dirty' } else { 'clean' }
}
$before = Get-DriverEvidence $ImageManifest; $before | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-before.json')
$service = $manifest.driverService; $started = $false
try {
    if ((Get-Service $service).Status -ne 'Stopped') { throw 'Driver service was not stopped at gate start' }
    Start-Service $service; $started = $true
    Set-Location $SourceDir
    $tags = 'winintegration'
    $timeout = '10m'
    $runPattern = '.'
    if ($Flow) {
        $tags = 'winintegration,winflow'
        $timeout = '20m'
        $runPattern = '^TestPacketFlow'
        $env:FLOW_ARTIFACT_DIR = $ArtifactDir
        $env:SYSNET_FLOW_EXE = Join-Path (Split-Path $SourceDir -Parent) 'sysnetflow.exe'
    }
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $coverProfile = Join-Path $ArtifactDir 'e2e-cover.out'
    $coverageArguments = @()
    if (-not $Flow) {
        $coverageArguments = @(
            '-covermode=atomic',
            '-coverpkg=github.com/asciimoth/sysnet-windows',
            "-coverprofile=$coverProfile"
        )
    }
    & $GoExecutable test -json -count=1 "-tags=$tags" "-run=$runPattern" -p=1 -timeout $timeout `
        @coverageArguments ./integration 2>&1 |
        Tee-Object -FilePath (Join-Path $ArtifactDir 'e2e-events.jsonl') |
        Format-GoTestOutput
    $testExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($testExitCode -ne 0) { throw "live-driver tests failed with exit code $testExitCode" }
    $events = @(Get-Content (Join-Path $ArtifactDir 'e2e-events.jsonl') | Where-Object { $_ -match '^\s*\{' } | ConvertFrom-Json)
    $testManifest = Get-Content (Join-Path $PSScriptRoot 'test-manifest.json') -Raw | ConvertFrom-Json
    if ($testManifest.schemaVersion -ne 1) { throw 'Unsupported test manifest schema' }
    $suiteName = if ($Flow) { 'packet-flow' } else { 'live-driver' }
    $required = @($testManifest.suites.$suiteName.requiredTests)
    $testResults = Get-RequiredTestResults $events $required
    if (-not $Flow) {
        & $GoExecutable tool cover "-func=$coverProfile" | Set-Content (Join-Path $ArtifactDir 'e2e-coverage.txt')
        if ($LASTEXITCODE -ne 0) { throw "coverage report failed with exit code $LASTEXITCODE" }
    }
} finally {
    if ($started) {
        Stop-Service $service -Force -ErrorAction Continue
        (Get-Service $service).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $after = Get-DriverEvidence $ImageManifest
    $after | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-after.json')
    if ($after.state -ne 'Stopped') { throw "Driver service final state is $($after.state)" }
}
$windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$productType = if ($windows.InstallationType -like 'Server*') { 3 } else { 1 }
$suite = if ($Flow) { 'packet-flow' } else { 'live-driver' }
$evidenceName = if ($Flow) { 'packet-flow-suite-evidence.json' } else { 'live-driver-evidence.json' }
[ordered]@{
    schemaVersion=1; suite=$suite; outcome='passed'; startedAt=$startedAt
    finishedAt=(Get-Date).ToUniversalTime().ToString('o')
    sysnetWindowsRevision=$SysnetWindowsRevision; sysnetWindowsTreeState=$SysnetWindowsTreeState
    sourceArchiveSha256=$SourceArchiveSHA256.ToLowerInvariant()
    architecture=$nativeArchitecture
    os=[ordered]@{
        caption=$windows.ProductName; version=[Environment]::OSVersion.Version.ToString()
        build=$windows.CurrentBuildNumber; productType=$productType
    }
    goVersion=$goVersion
    dependencyLocks=(Get-DependencyLockEvidence $SourceDir)
    driver=[ordered]@{
        version=$manifest.driverVersion; upstreamCommit=$manifest.upstreamCommit
        files=$manifest.driverFiles; packageSigner=$manifest.driverSigner
        installedSigner=$after.signer; finalState=$after.state
    }
    requiredTests=$required; testResults=$testResults
} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ArtifactDir $evidenceName)
