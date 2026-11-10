<#
.SYNOPSIS
    Runs every toolkit script that has number parameters with an out-of-range value and checks it
    answers in plain English with a clean exit, instead of PowerShell's parameter-binding error.

.DESCRIPTION
    Development-side check; never run on client machines. Finds every script that calls
    Test-MSPParameterRange and reads its ranges from that line, then runs the script once per
    range parameter with the maximum + 1 (and the first parameter also with the minimum - 1).
    Each run must:
      - exit 1;
      - print "-<Name> must be between <min> and <max> (you gave <value>)";
      - print none of PowerShell's binding-error text ("Cannot validate argument", "CategoryInfo",
        "FullyQualifiedErrorId", "At line:");
      - write a JSON result whose findings are only that Setup finding (nothing else ran).
    The scripts stop before any check runs, so nothing on this computer or the network is read or
    changed. Runs on whichever PowerShell runs it (5.1 and 7 in the harness on Windows).

    Scripts with other mandatory parameters get them from $extraArgs below; a new script with a
    mandatory parameter makes this test fail until it is added there.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-ParameterRangeMessages.ps1

.NOTES
    Risk Level    : Safe -- the scripts stop at the parameter check; writes only to a temporary folder
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-True (Name, Condition, Detail) is a one-line test assertion used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-ranges-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force

# Other mandatory parameters, by script file name.
$extraArgs = @{
    'Get-UserMailboxStatus.ps1'       = @('-UserPrincipalName', 'nobody@contoso.com')
    'Get-UserLicenseReport.ps1'       = @('-UserPrincipalName', 'nobody@contoso.com')
    'Get-AccountCompromiseTriage.ps1' = @('-UserPrincipalName', 'nobody@contoso.com')
}

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

# The script's own call (the embedded helper's help text shows an example call too).
$callPattern = '^if \(-not \(Test-MSPParameterRange -Bound \$PSBoundParameters'
$scripts = @(Get-ChildItem -LiteralPath $repo -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notmatch '[\\/](_archive|tests|tools|\.git)[\\/]' } |
        Where-Object { (Select-String -LiteralPath $_.FullName -Pattern $callPattern -Quiet) })
Assert-True 'scripts with range checks found' ($scripts.Count -ge 20) ('{0} found' -f $scripts.Count)

try {
    foreach ($s in $scripts) {
        $line = [string](Select-String -LiteralPath $s.FullName -Pattern $callPattern | Select-Object -First 1).Line
        $ranges = @([regex]::Matches($line, '(\w+) = (-?\d+), (-?\d+)') | ForEach-Object { [pscustomobject]@{ Name = $_.Groups[1].Value; Min = [int]$_.Groups[2].Value; Max = [int]$_.Groups[3].Value } })
        Assert-True ('{0}: ranges read' -f $s.Name) ($ranges.Count -gt 0) $line
        $cases = @($ranges | ForEach-Object { [pscustomobject]@{ Range = $_; Value = $_.Max + 1 } })
        if ($ranges.Count -gt 0) { $cases += [pscustomobject]@{ Range = $ranges[0]; Value = $ranges[0].Min - 1 } }
        foreach ($c in $cases) {
            $label = '{0} -{1} {2}' -f $s.Name, $c.Range.Name, $c.Value
            $out = Join-Path $work ([guid]::NewGuid().ToString('N').Substring(0, 8))
            $null = New-Item -ItemType Directory -Path $out -Force
            $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $s.FullName) + @($extraArgs[$s.Name]) + @(('-{0}' -f $c.Range.Name), [string]$c.Value, '-OutputPath', $out)
            $argList = @($argList | Where-Object { $null -ne $_ })
            # 'Continue': Windows PowerShell 5.1 turns a child's stderr line into a terminating error under 'Stop'.
            $console = & { $ErrorActionPreference = 'Continue'; & $exe @argList 2>&1 } | Out-String
            $code = $LASTEXITCODE
            $expected = '-{0} must be between {1} and {2} (you gave {3})' -f $c.Range.Name, $c.Range.Min, $c.Range.Max, $c.Value
            Assert-True ('{0}: exit 1' -f $label) ($code -eq 1) ('exit {0}' -f $code)
            Assert-True ('{0}: plain message' -f $label) ($console.Contains($expected)) $console
            Assert-True ('{0}: no binding error or stack trace' -f $label) ($console -notmatch 'Cannot validate argument|CategoryInfo|FullyQualifiedErrorId|ParameterBindingValidation|At line:') $console
            $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
            $ok = $false
            if ($json.Count -eq 1) {
                $r = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json
                $ok = (@($r.Findings | Where-Object { $_.Check -eq 'Parameters' -and $_.Status -eq 'ERROR' -and $_.Category -eq 'Setup' }).Count -eq 1) -and (@($r.Findings | Where-Object { $_.Category -ne 'Setup' }).Count -eq 0)
            }
            Assert-True ('{0}: result has only the Setup finding (nothing else ran)' -f $label) $ok ('{0} JSON file(s)' -f $json.Count)
        }
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
