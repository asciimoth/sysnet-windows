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

$result = Get-RequiredTestResults @($pass) @($identity)
if ($result[$identity] -ne 'pass' -or $result.Count -ne 1) {
    throw 'An exact package and test pass was not accepted'
}

$result = Get-RequiredTestResults @($wrongPackageSkip, $pass) @($identity)
if ($result[$identity] -ne 'pass') {
    throw 'A skip from another package blocked the exact passing test'
}

Assert-Throws {
    Get-RequiredTestResults @($wrongPackagePass) @($identity) | Out-Null
} "$identity has no pass event"
Assert-Throws {
    Get-RequiredTestResults @($wrongPackagePass, $exactSkip) @($identity) | Out-Null
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

Write-Output 'PowerShell test-evidence tests passed.'
