$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\test-output.ps1')

function Assert-Throws([scriptblock]$Action, [string]$Message) {
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notlike "*$Message*") {
            throw "Error '$($_.Exception.Message)' does not contain '$Message'"
        }
        return
    }
    throw "Expected an error containing '$Message'"
}

$package = 'example.test/correct'
$identity = "$package::TestRequired"
$pass = [pscustomobject]@{
    Action = 'pass'
    Package = $package
    Test = 'TestRequired'
}
$wrongPackagePass = [pscustomobject]@{
    Action = 'pass'
    Package = 'example.test/wrong'
    Test = 'TestRequired'
}
$wrongPackageSkip = [pscustomobject]@{
    Action = 'skip'
    Package = 'example.test/wrong'
    Test = 'TestRequired'
}
$exactSkip = [pscustomobject]@{
    Action = 'skip'
    Package = $package
    Test = 'TestRequired'
}
$requiredSubtestSkip = [pscustomobject]@{
    Action = 'skip'
    Package = $package
    Test = 'TestRequired/native-prerequisite'
}
$requiredNestedSubtestSkip = [pscustomobject]@{
    Action = 'skip'
    Package = $package
    Test = 'TestRequired/native-prerequisite/arm64'
}
$similarTestSkip = [pscustomobject]@{
    Action = 'skip'
    Package = $package
    Test = 'TestRequiredExtra/native-prerequisite'
}
$wrongPackageSubtestSkip = [pscustomobject]@{
    Action = 'skip'
    Package = 'example.test/wrong'
    Test = 'TestRequired/native-prerequisite'
}

$result = Get-RequiredTestResults @($pass) @($identity)
if ($result[$identity] -ne 'pass' -or $result.Count -ne 1) {
    throw 'An exact package and test pass was not accepted'
}

$result = Get-RequiredTestResults @($wrongPackageSkip, $pass) @($identity)
if ($result[$identity] -ne 'pass') {
    throw 'A skip from another package blocked the exact passing test'
}

$result = Get-RequiredTestResults @($similarTestSkip, $wrongPackageSubtestSkip, $pass) @($identity)
if ($result[$identity] -ne 'pass') {
    throw 'An unrelated subtest skip blocked the exact passing test'
}

Assert-Throws {
    Get-RequiredTestResults @($wrongPackagePass) @($identity) | Out-Null
} "$identity has no pass event"
Assert-Throws {
    Get-RequiredTestResults @($wrongPackagePass, $exactSkip) @($identity) | Out-Null
} "$identity was skipped"
Assert-Throws {
    Get-RequiredTestResults @($pass, $requiredSubtestSkip) @($identity) | Out-Null
} "$identity was skipped"
Assert-Throws {
    Get-RequiredTestResults @($pass, $requiredNestedSubtestSkip) @($identity) | Out-Null
} "$identity was skipped"
Assert-Throws {
    Get-RequiredTestResults @($pass) @('TestRequired') | Out-Null
} 'Required test identity is invalid'
Assert-Throws {
    Get-RequiredTestResults @($pass) @('example.test/correct::NotATest') | Out-Null
} 'Required test identity is invalid'
Assert-Throws {
    Get-RequiredTestResults @($pass) @('example.test/correct::TestRequired::extra') | Out-Null
} 'Required test identity is invalid'
Assert-Throws {
    Get-RequiredTestResults @($pass) @($identity, $identity) | Out-Null
} 'Required test identity is duplicated'

if ((Convert-WindowsProductType 'WinNT') -ne 1 -or
    (Convert-WindowsProductType 'LanmanNT') -ne 2 -or
    (Convert-WindowsProductType 'ServerNT') -ne 3) {
    throw 'Windows product types were not mapped to the documented values'
}
Assert-Throws { Convert-WindowsProductType 'Unknown' } 'Unsupported Windows product type'
if ((Get-WindowsCaption 'Microsoft Windows 10 Pro' 1 26100) -ne 'Microsoft Windows 11 Pro') {
    throw 'A Windows 11 client retained the stale Windows 10 registry caption'
}
if ((Get-WindowsCaption 'Microsoft Windows Server 2022' 3 20348) -ne 'Microsoft Windows Server 2022') {
    throw 'A Windows Server caption was changed'
}
Assert-Throws { Get-WindowsCaption '' 1 26100 } 'Windows product name is absent'

Write-Output 'PowerShell test-evidence tests passed.'
