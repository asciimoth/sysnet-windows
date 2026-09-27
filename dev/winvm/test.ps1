[CmdletBinding()]
param(
    [string]$ArtifactDir = (Join-Path $PWD '.artifacts-windows'),
    [string]$ImageManifest = $env:WINVM_IMAGE_MANIFEST,
    [string]$ExpectedGoVersion = $env:GO_EXPECTED_VERSION,
    [string]$SysnetWindowsRevision = $env:GITHUB_SHA,
    [ValidateSet('clean', 'dirty', 'unknown')][string]$SysnetWindowsTreeState = 'unknown',
    [switch]$RequireStandardUser
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $SysnetWindowsRevision) {
    $SysnetWindowsRevision = (& git -C $sourceRoot rev-parse HEAD 2>$null | Out-String).Trim()
}
if (-not $SysnetWindowsRevision) { $SysnetWindowsRevision = 'unknown' }
if ($SysnetWindowsTreeState -eq 'unknown' -and (Test-Path (Join-Path $sourceRoot '.git'))) {
    $SysnetWindowsTreeState = if (& git -C $sourceRoot status --porcelain) { 'dirty' } else { 'clean' }
}
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
$startedAt = (Get-Date).ToUniversalTime().ToString('o')
Start-Transcript -Path (Join-Path $ArtifactDir 'powershell.log') -Force | Out-Null
. (Join-Path $PSScriptRoot 'test-output.ps1')
function Invoke-Logged([string]$Name, [string]$Command, [string[]]$Arguments) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $Command @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $ArtifactDir "$Name.log")
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($exitCode -ne 0) { throw "$Name failed with exit code $exitCode" }
}
try {
    Get-ChildItem (Join-Path $PSScriptRoot '*.ps1') | ForEach-Object {
        $tokens = $null
        $parseErrors = $null
        [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count -ne 0) { throw "PowerShell parse failed for $($_.Name): $($parseErrors -join '; ')" }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($RequireStandardUser -and ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        throw 'The baseline must run as a standard user'
    }
    if ($ImageManifest) {
        $manifest = Get-Content -LiteralPath $ImageManifest -Raw | ConvertFrom-Json
        if (-not $ExpectedGoVersion) {
            if ($manifest.goVersion -notmatch '^go version go(?<Version>\S+) windows/(?<Architecture>amd64|arm64)$') { throw 'Invalid image Go version' }
            $ExpectedGoVersion = $Matches.Version
        }
    }
    if ($ExpectedGoVersion) {
        $actual = (& go env GOVERSION | Out-String).Trim()
        if ($actual -ne "go$ExpectedGoVersion") { throw "Go version is $actual, not go$ExpectedGoVersion" }
    }
    $nativeArchitecture = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { throw "Unsupported native architecture: $env:PROCESSOR_ARCHITECTURE" } }
    $goArchitecture = (& go env GOARCH | Out-String).Trim()
    if ($goArchitecture -ne $nativeArchitecture) { throw "Go architecture is $goArchitecture, not native $nativeArchitecture" }
    Invoke-Logged 'go-version' 'go' @('version')
    Invoke-Logged 'go-env' 'go' @('env')
    Invoke-Logged 'go-mod-verify' 'go' @('mod', 'verify')
    Invoke-Logged 'go-mod-tidy' 'go' @('mod', 'tidy', '-diff')
    Invoke-Logged 'go-vet' 'go' @('vet', './...')
    $events = Join-Path $ArtifactDir 'test-events.jsonl'
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & go test -json -count=1 -timeout 2m ./... 2>&1 |
        Tee-Object -FilePath $events |
        Format-GoTestOutput
    $testExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($testExitCode -ne 0) { throw "tests failed with exit code $testExitCode" }
    $parsed = @(Get-Content $events | Where-Object { $_ -match '^\s*\{' } | ConvertFrom-Json)
    $testManifest = Get-Content (Join-Path $PSScriptRoot 'test-manifest.json') -Raw | ConvertFrom-Json
    if ($testManifest.schemaVersion -ne 1) { throw 'Unsupported test manifest schema' }
    $required = @($testManifest.suites.'native-unit'.requiredTests)
    foreach ($test in $required) {
        if ($parsed | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $test -and $_.Action -eq 'skip' }) { throw "$test was skipped" }
        if (-not ($parsed | Where-Object { $_.PSObject.Properties['Test'] -and $_.Test -eq $test -and $_.Action -eq 'pass' })) { throw "$test has no pass event" }
    }
    $parsed | Where-Object Action -eq output | ForEach-Object Output | Set-Content (Join-Path $ArtifactDir 'tests.log')
    Invoke-Logged 'go-build' 'go' @('build', './...')
    $windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $productType = if ($windows.InstallationType -like 'Server*') { 3 } else { 1 }
    [ordered]@{
        schemaVersion=1; suite='native-unit'; outcome='passed'; startedAt=$startedAt
        finishedAt=(Get-Date).ToUniversalTime().ToString('o')
        sysnetWindowsRevision=$SysnetWindowsRevision; sysnetWindowsTreeState=$SysnetWindowsTreeState
        architecture=$nativeArchitecture
        os=[ordered]@{
            caption=$windows.ProductName; version=[Environment]::OSVersion.Version.ToString()
            build=$windows.CurrentBuildNumber; productType=$productType
        }
        goVersion=(& go version | Out-String).Trim(); requiredTests=$required
    } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ArtifactDir 'native-unit-evidence.json')
} finally { Stop-Transcript | Out-Null }
