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
        flakeLock = (Get-FileSHA256 (Join-Path $SourceRoot 'flake.lock'))
        imageLock = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\image-lock.json'))
        nativeDriverLock = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\native-driver-lock.json'))
        qualificationMatrix = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\qualification-matrix.json'))
        wintunLock = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\wintun-lock.json'))
        testManifest = (Get-FileSHA256 (Join-Path $SourceRoot 'dev\winvm\test-manifest.json'))
    }
}

function Get-NativeArchitecture {
    # RuntimeInformation reports the OS architecture even when a process can
    # run through an architecture compatibility layer.
    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    switch ($architecture) {
        'X64' { return 'amd64' }
        'Arm64' { return 'arm64' }
        default { throw "Unsupported native architecture: $architecture" }
    }
}

function Get-CodeIntegrityEvidence {
    # SystemCodeIntegrityInformation (103) returns the kernel's effective
    # policy. Registry and boot configuration text can describe requested
    # settings that are not active on the running kernel.
    if (-not ('SysnetWindows.CodeIntegrity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace SysnetWindows {
    public static class CodeIntegrity {
        [StructLayout(LayoutKind.Sequential)]
        private struct Information {
            public UInt32 Length;
            public UInt32 Options;
        }

        [DllImport("ntdll.dll")]
        private static extern Int32 NtQuerySystemInformation(
            Int32 informationClass,
            ref Information information,
            UInt32 informationLength,
            out UInt32 returnLength);

        public static UInt32 Options() {
            Information information = new Information();
            information.Length = (UInt32)Marshal.SizeOf(information);
            UInt32 returned;
            Int32 status = NtQuerySystemInformation(
                103, ref information, information.Length, out returned);
            if (status != 0 || returned < information.Length) {
                throw new InvalidOperationException(
                    String.Format("Cannot query code integrity: status 0x{0:x8}, length {1}",
                        status, returned));
            }
            return information.Options;
        }
    }
}
'@
    }
    $options = [SysnetWindows.CodeIntegrity]::Options()
    return [ordered]@{
        options = [uint32]$options
        enabled = [bool]($options -band 0x1)
        testSigning = [bool]($options -band 0x2)
        debugMode = [bool]($options -band 0x80)
    }
}

function Convert-WindowsProductType([string]$ProductType) {
    switch ($ProductType) {
        'WinNT' { return 1 }
        'LanmanNT' { return 2 }
        'ServerNT' { return 3 }
        default { throw "Unsupported Windows product type: $ProductType" }
    }
}

function Get-WindowsCaption([string]$ProductName, [int]$ProductType, [int]$Build) {
    if (-not $ProductName) { throw 'The Windows product name is absent' }
    # Some Windows 11 installations retain "Windows 10" in ProductName. The
    # client build boundary is authoritative for the product generation.
    if ($ProductType -eq 1 -and $Build -ge 22000 -and $ProductName -match 'Windows 10') {
        return $ProductName -replace 'Windows 10', 'Windows 11'
    }
    return $ProductName
}

function Get-WindowsPlatformEvidence {
    # These machine-wide identity keys are readable by the standard-user
    # baseline. Win32_OperatingSystem CIM access is not guaranteed for that
    # account on hardened guests.
    $windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $product = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions'
    $build = [int]$windows.CurrentBuildNumber
    $productType = Convert-WindowsProductType $product.ProductType
    $updateBuild = if ($null -ne $windows.UBR) { [int]$windows.UBR } else { 0 }
    $majorVersion = [int]$windows.CurrentMajorVersionNumber
    $minorVersion = [int]$windows.CurrentMinorVersionNumber
    return [ordered]@{
        caption = (Get-WindowsCaption $windows.ProductName $productType $build)
        version = "$majorVersion.$minorVersion.$build.$updateBuild"
        build = $windows.CurrentBuildNumber
        productType = $productType
        nativeArchitecture = (Get-NativeArchitecture)
        codeIntegrity = (Get-CodeIntegrityEvidence)
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
