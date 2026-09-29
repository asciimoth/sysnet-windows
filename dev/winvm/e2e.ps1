[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$ArtifactDir,
    [string]$ImageManifest = 'C:\winvm\manifest.json',
    [string]$GoExecutable = 'go',
    [string]$SysnetWindowsRevision = $env:GITHUB_SHA,
    [ValidateSet('clean', 'dirty', 'unknown')][string]$SysnetWindowsTreeState = 'unknown',
    [string]$SourceArchiveSHA256 = $env:SYSNET_WINDOWS_SOURCE_ARCHIVE_SHA256,
    [switch]$Flow,
    [switch]$Resource,
    [string]$SoakDuration
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
if ($Flow -and $Resource) { throw 'Flow and Resource modes are mutually exclusive' }
$env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
$evidenceName = if ($Flow) { 'packet-flow-suite-evidence.json' } elseif ($Resource) { 'resource-gate-evidence.json' } else { 'live-driver-evidence.json' }
$evidencePath = Join-Path $ArtifactDir $evidenceName
Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsSystem) { throw 'The live-driver gate must run as SYSTEM' }
if (-not [Environment]::Is64BitProcess) { throw 'The live-driver gate needs a 64-bit process' }
$startedAt = (Get-Date).ToUniversalTime().ToString('o')
. (Join-Path $SourceDir 'dev\winvm\driver.ps1')
. (Join-Path $SourceDir 'dev\winvm\test-output.ps1')
if ($Resource) { . (Join-Path $SourceDir 'dev\winvm\resource-state.ps1') }
$SourceArchiveSHA256 = Resolve-SourceArchiveSHA256 $SourceDir $SourceArchiveSHA256
$manifest = Get-Content $ImageManifest -Raw | ConvertFrom-Json
if ($manifest.driverVersion -ne '1.3.0.0' -or $manifest.upstreamCommit -ne '0a0eb97f67d1dbcb3d08bda66d3b24f465d95475') { throw 'Driver identity does not match the split-driver ABI' }
$nativeArchitecture = Get-NativeArchitecture
if ($manifest.architecture.ToString().ToLowerInvariant() -ne $nativeArchitecture) { throw 'Driver package and native architecture do not match' }
$goVersion = (& $GoExecutable version | Out-String).Trim()
if ($goVersion -notmatch " windows/$nativeArchitecture$") { throw "Go process does not target native $nativeArchitecture" }
$wintunDLL = Join-Path (Split-Path $SourceDir -Parent) 'wintun.dll'
if (-not (Test-Path -LiteralPath $wintunDLL -PathType Leaf)) { throw 'The staged Wintun DLL is absent' }
$env:SYSNET_WINDOWS_WINTUN_DLL = $wintunDLL
if (-not $SysnetWindowsRevision) {
    $SysnetWindowsRevision = (& git -C $SourceDir rev-parse HEAD 2>$null | Out-String).Trim()
}
if (-not $SysnetWindowsRevision) { $SysnetWindowsRevision = 'unknown' }
if ($SysnetWindowsTreeState -eq 'unknown' -and (Test-Path (Join-Path $SourceDir '.git'))) {
    $SysnetWindowsTreeState = if (& git -C $SourceDir status --porcelain) { 'dirty' } else { 'clean' }
}
$before = Get-DriverEvidence $ImageManifest; $before | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'driver-before.json')
$resourceBefore = $null
if ($Resource) {
    $resourceBefore = Get-NativeResourceSnapshot
    $resourceBefore | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ArtifactDir 'resources-before.json')
}
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
        $sysnetIntegrationExecutable = Join-Path (Split-Path $SourceDir -Parent) `
            'sysnetintegration.test.exe'
        if (-not (Test-Path -LiteralPath $sysnetIntegrationExecutable -PathType Leaf)) {
            throw 'The staged sysnet integration test executable is absent'
        }
        $splitConformanceExecutable = Join-Path (Split-Path $SourceDir -Parent) `
            'splitconformance.test.exe'
        if (-not (Test-Path -LiteralPath $splitConformanceExecutable -PathType Leaf)) {
            throw 'The staged split-controller conformance test executable is absent'
        }

        # Run the pinned controller's complete nine-mode gate before the
        # sysnet-windows public API gate. Keep its observations separate until
        # both suites pass, then validate all markers against the same captures.
        $dependencyArtifacts = Join-Path $ArtifactDir 'dependency-conformance'
        New-Item -ItemType Directory -Force -Path $dependencyArtifacts | Out-Null
        $controllerModule = 'github.com/asciimoth/mullvad-split-tunnel-go'
        $controllerRequirement = Select-String -LiteralPath (Join-Path $SourceDir 'go.mod') `
            -Pattern ('^\s*' + [regex]::Escape($controllerModule) + '\s+(\S+)')
        if (@($controllerRequirement).Count -ne 1) {
            throw 'Cannot resolve the split-controller module version from go.mod'
        }
        $controllerVersion = $controllerRequirement.Matches[0].Groups[1].Value
        $savedFlowArtifactDir = $env:FLOW_ARTIFACT_DIR
        $env:FLOW_ARTIFACT_DIR = $dependencyArtifacts
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $splitConformanceExecutable '-test.v' `
            '-test.run=^TestPacketFlow(Characterization|PolicyTable)$' `
            '-test.timeout=20m' 2>&1 |
            Tee-Object -FilePath (Join-Path $dependencyArtifacts 'test-output.log')
        $dependencyExitCode = $LASTEXITCODE
        $ErrorActionPreference = $savedPreference
        $env:FLOW_ARTIFACT_DIR = $savedFlowArtifactDir
        if ($dependencyExitCode -ne 0) {
            throw "split-controller nine-mode conformance failed with exit code $dependencyExitCode"
        }
        # The dependency gate models its VPN with the physical tunnel link.
        # Remove the dependency fixture's preferred physical-tunnel routes,
        # but keep its equal-prefix underlay routes. The public gate adds the
        # preferred service routes to Wintun. The split driver then moves an
        # excluded flow to the retained underlay route. High-metric underlay
        # defaults also keep OutNet directly reachable.
        $tunnelAdapter = @(Get-NetAdapter | Where-Object MacAddress -eq '52-54-00-12-34-10')
        $underlayAdapter = @(Get-NetAdapter | Where-Object MacAddress -eq '52-54-00-12-34-11')
        if ($tunnelAdapter.Count -ne 1 -or $underlayAdapter.Count -ne 1) {
            throw 'Cannot identify the packet-flow adapters for the public API transition'
        }
        foreach ($route in @(
            @{ Index=$tunnelAdapter[0].ifIndex; Family='IPv4'; Prefix='203.0.113.1/32'; Hop='198.18.0.1' },
            @{ Index=$tunnelAdapter[0].ifIndex; Family='IPv6'; Prefix='2001:db8:ffff::1/128'; Hop='fd00:18:0::1' }
        )) {
            $owned = @(Get-NetRoute -PolicyStore ActiveStore `
                -InterfaceIndex $route.Index `
                -AddressFamily $route.Family -DestinationPrefix $route.Prefix |
                Where-Object NextHop -eq $route.Hop)
            if ($owned.Count -gt 1) { throw "Dependency route $($route.Prefix) is duplicated" }
            if ($owned.Count -eq 1) { $owned[0] | Remove-NetRoute -Confirm:$false }
        }
        foreach ($route in @(
            @{ Family='IPv4'; Prefix='0.0.0.0/0'; Hop='198.18.1.1' },
            @{ Family='IPv6'; Prefix='::/0'; Hop='fd00:18:1::1' }
        )) {
            New-NetRoute -PolicyStore ActiveStore `
                -InterfaceIndex $underlayAdapter[0].ifIndex `
                -AddressFamily $route.Family -DestinationPrefix $route.Prefix `
                -NextHop $route.Hop -RouteMetric 5000 | Out-Null
        }
        [ordered]@{
            module=$controllerModule
            version=$controllerVersion
            modes=9
            tests=@('TestPacketFlowPolicyTable', 'TestPacketFlowCharacterization')
        } | ConvertTo-Json | Set-Content (Join-Path $ArtifactDir 'dependency-conformance-passed.json')
    }
    if ($Resource) {
        $tags = 'winintegration,winresource'
        $timeout = '60m'
        $runPattern = '^TestM6'
        $env:SYSNET_RESOURCE_ARTIFACT = Join-Path $ArtifactDir 'process-resources.json'
        if ($SoakDuration) {
            $env:SYSNET_WINDOWS_SOAK_DURATION = $SoakDuration
        } else {
            Remove-Item Env:SYSNET_WINDOWS_SOAK_DURATION -ErrorAction SilentlyContinue
        }
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
    if ($Flow) {
        & $GoExecutable tool test2json -t `
            -p github.com/asciimoth/sysnet-windows/integration `
            $sysnetIntegrationExecutable '-test.v' "-test.run=$runPattern" `
            "-test.timeout=$timeout" 2>&1 |
            Tee-Object -FilePath (Join-Path $ArtifactDir 'e2e-events.jsonl') |
            Format-GoTestOutput
    } else {
        & $GoExecutable test -json -count=1 "-tags=$tags" "-run=$runPattern" -p=1 -timeout $timeout `
            @coverageArguments ./integration 2>&1 |
            Tee-Object -FilePath (Join-Path $ArtifactDir 'e2e-events.jsonl') |
            Format-GoTestOutput
    }
    $testExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($testExitCode -ne 0) { throw "live-driver tests failed with exit code $testExitCode" }
    if ($Flow) {
        $observationInputs = @(
            (Join-Path $ArtifactDir 'dependency-conformance\packet-flow-observations.jsonl'),
            (Join-Path $ArtifactDir 'packet-flow-outnet-observations.jsonl'),
            (Join-Path $ArtifactDir 'packet-flow-public-api-observations.jsonl')
        )
        foreach ($input in $observationInputs) {
            if (-not (Test-Path -LiteralPath $input -PathType Leaf)) {
                throw "packet observation input is absent: $input"
            }
        }
        Get-Content -LiteralPath $observationInputs |
            Set-Content (Join-Path $ArtifactDir 'packet-flow-observations.jsonl')
    }
    $events = @(Get-Content (Join-Path $ArtifactDir 'e2e-events.jsonl') | Where-Object { $_ -match '^\s*\{' } | ConvertFrom-Json)
    $testManifest = Get-Content (Join-Path $PSScriptRoot 'test-manifest.json') -Raw | ConvertFrom-Json
    if ($testManifest.schemaVersion -ne 1) { throw 'Unsupported test manifest schema' }
    $suiteName = if ($Flow) { 'packet-flow' } elseif ($Resource) { 'resource-gate' } else { 'live-driver' }
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
    if ($Resource) {
        $resourceAfter = Get-NativeResourceSnapshot
        $resourceAfter | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ArtifactDir 'resources-after.json')
        Compare-NativeResourceSnapshot $resourceBefore $resourceAfter
    }
}
$suite = if ($Flow) { 'packet-flow' } elseif ($Resource) { 'resource-gate' } else { 'live-driver' }
$resourceGate = $null
if ($Resource) {
    $effectiveSoakDuration = if ($SoakDuration) { $SoakDuration } else { '30m' }
    $resourceGate = [ordered]@{
        warmupCycles=10; batchCount=4; cyclesPerBatch=25
        cancellationCycles=100
        soakDuration=$effectiveSoakDuration
        diagnosticOverride=[bool]$SoakDuration
    }
}
[ordered]@{
    schemaVersion=1; suite=$suite; outcome='passed'; startedAt=$startedAt
    finishedAt=(Get-Date).ToUniversalTime().ToString('o')
    sysnetWindowsRevision=$SysnetWindowsRevision; sysnetWindowsTreeState=$SysnetWindowsTreeState
    sourceArchiveSha256=$SourceArchiveSHA256.ToLowerInvariant()
    architecture=$nativeArchitecture
    os=(Get-WindowsPlatformEvidence)
    goVersion=$goVersion
    dependencyLocks=(Get-DependencyLockEvidence $SourceDir)
    driver=[ordered]@{
        version=$manifest.driverVersion; upstreamCommit=$manifest.upstreamCommit
        files=$after.packageFiles; packageSigner=$after.packageSigner
        stagedDriverSigner=$after.stagedDriverSigner
        packageCatalogSigner=$after.packageCatalogSigner
        installedSigner=$after.signer; installedSignature=$after.signature
        installedFileSha256=$after.installedFileSha256
        finalState=$after.state
    }
    wintun=[ordered]@{
        version=(Get-Content (Join-Path $SourceDir 'dev\winvm\wintun-lock.json') -Raw | ConvertFrom-Json).wintun.version
        dllSha256=(Get-FileSHA256 $wintunDLL)
    }
    resourceGate=$resourceGate
    requiredTests=$required; testResults=$testResults
} | ConvertTo-Json -Depth 6 | Set-Content $evidencePath
