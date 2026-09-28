function Format-GoTestOutput {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowEmptyString()]
        [object]$InputObject
    )
    process {
        $line = [string]$InputObject
        if ($line -notmatch '^\s*\{') {
            Write-Output $line
        } else {
            try {
                $event = $line | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Write-Output $line
                $event = $null
            }
            if ($null -ne $event -and $event.Action -eq 'output') {
                $output = ([string]$event.Output).TrimEnd([char[]]"`r`n")
                if ($output.Length -gt 0) { Write-Output $output }
            }
        }
    }
}

function Get-FileSHA256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Evidence input is absent: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-SourceArchiveSHA256([string]$SourceRoot, [string]$SuppliedHash) {
    if ($SuppliedHash) {
        if ($SuppliedHash -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'The source archive SHA-256 is invalid'
        }
        return $SuppliedHash.ToLowerInvariant()
    }
    $archive = Join-Path ([IO.Path]::GetTempPath()) "sysnet-windows-source-$PID.tar"
    try {
        & git -C $SourceRoot archive --format=tar --output=$archive HEAD
        if ($LASTEXITCODE -ne 0) { throw 'Cannot create the source identity archive' }
        return (Get-FileSHA256 $archive)
    } finally {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
    }
}

function Get-DependencyLockEvidence([string]$SourceRoot) {
    return [ordered]@{
        goMod = (Get-FileSHA256 (Join-Path $SourceRoot 'go.mod'))
        goSum = (Get-FileSHA256 (Join-Path $SourceRoot 'go.sum'))
        imageLock = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\image-lock.json'))
        nativeDriverLock = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\native-driver-lock.json'))
        wintunLock = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\wintun-lock.json'))
        testManifest = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\test-manifest.json'))
    }
}

function Get-RequiredTestResults([object[]]$Events, [string[]]$RequiredTests) {
    $results = [ordered]@{}
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($identity in $RequiredTests) {
        if ($identity -notmatch '^(?<Package>[^:\s]+)::(?<Test>Test[A-Za-z0-9_]+)$') {
            throw "Required test identity is invalid: $identity"
        }
        if (-not $seen.Add($identity)) {
            throw "Required test identity is duplicated: $identity"
        }
        $package = $Matches.Package
        $test = $Matches.Test
        if ($Events | Where-Object {
                $_.PSObject.Properties['Package'] -and $_.Package -eq $package -and
                $_.PSObject.Properties['Test'] -and
                ($_.Test -eq $test -or $_.Test.StartsWith("$test/", [StringComparison]::Ordinal)) -and
                $_.Action -eq 'skip'
            }) {
            throw "$identity was skipped"
        }
        if (-not ($Events | Where-Object {
                    $_.PSObject.Properties['Package'] -and $_.Package -eq $package -and
                    $_.PSObject.Properties['Test'] -and $_.Test -eq $test -and $_.Action -eq 'pass'
                })) {
            throw "$identity has no pass event"
        }
        $results[$identity] = 'pass'
    }
    return $results
}
