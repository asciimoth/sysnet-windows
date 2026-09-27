[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceDir,
    [Parameter(Mandatory)][string]$ArtifactDir,
    [Parameter(Mandatory)][string]$ImageManifest,
    [Parameter(Mandatory)][string]$GoExecutable,
    [Parameter(Mandatory)][string]$GoModCache,
    [Parameter(Mandatory)][string]$SysnetWindowsRevision,
    [Parameter(Mandatory)][string]$SysnetWindowsTreeState,
    [Parameter(Mandatory)][string]$SourceArchiveSHA256,
    [Parameter(Mandatory)][string]$ResultFile
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
    $env:GOMODCACHE = $GoModCache
    & (Join-Path $SourceDir 'dev\winvm\e2e.ps1') -SourceDir $SourceDir `
        -ArtifactDir $ArtifactDir -ImageManifest $ImageManifest `
        -GoExecutable $GoExecutable -SysnetWindowsRevision $SysnetWindowsRevision `
        -SysnetWindowsTreeState $SysnetWindowsTreeState `
        -SourceArchiveSHA256 $SourceArchiveSHA256
    [IO.File]::WriteAllText($ResultFile, '0')
} catch {
    $_ | Out-String | Set-Content (Join-Path $ArtifactDir 'system-e2e-error.log')
    [IO.File]::WriteAllText($ResultFile, '1')
    throw
}
