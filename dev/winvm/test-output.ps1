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
