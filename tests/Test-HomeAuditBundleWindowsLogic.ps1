<#
.SYNOPSIS
    Tests Invoke-HomeAuditBundle.ps1's -Passive switch against a mocked Start-Process, so the
    Windows bundle's option handling is tested on any platform without running A1-A8.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux).

    The bundle is copied into a temporary flat folder next to empty A1-A8 .ps1 files (the
    bundle looks next to itself first). A wrapper script defines a Start-Process function, which
    is found before the cmdlet: it records each command line, writes a small result file for
    that script into the results folder and returns a finished "process". Nothing is started,
    and nothing can be sent on the network.

      -Passive               A2 gets -Passive, A7 is not started (SKIPPED with the reason), no
                             -ScanLan / -Online anywhere, the other six scripts complete.
      no -Passive            A2 without -Passive, A7 started with -SkipChecklistPrompt.
      -Passive -ScanLan      refused with exit 2 before anything is started (also
                             -OnlineUpdateSearch).

.EXAMPLE
    pwsh -NoProfile -File tests/Test-HomeAuditBundleWindowsLogic.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
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
$bundle = (Resolve-Path -LiteralPath (Join-Path $here '../security-operations/diagnostics/Invoke-HomeAuditBundle.ps1')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-bundle-win-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

$scripts = 'Get-EndpointSecurityStatus', 'Get-HomeNetworkMap', 'Get-WiFiSecurityAudit', 'Get-OpenPortScan',
'Get-BrowserSecurityCheck', 'Get-WindowsUpdateCompliance', 'Get-RouterSecurityCheck', 'Get-HomeDeviceInventory'

# Stand-in for Start-Process: records the command line, writes a result file, "exits" with 0.
$mock = @'
function Start-Process {
    [CmdletBinding()]
    param([string]$FilePath, [string]$ArgumentList, [switch]$NoNewWindow, [switch]$PassThru, [switch]$Wait)
    Add-Content -LiteralPath $env:MSP_TEST_CALLS -Value $ArgumentList
    $file = [regex]::Match($ArgumentList, '-File "([^"]+)"').Groups[1].Value
    $out = [regex]::Match($ArgumentList, '-OutputPath "([^"]+)"').Groups[1].Value
    if ($file -and $out) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($file)
        $json = '{"SchemaVersion":"2.0","ScriptName":"' + $name + '","Summary":{"PASS":1,"WARN":0,"FAIL":0,"INFO":0,"SKIPPED":0,"ERROR":0},"Findings":[]}'
        [System.IO.File]::WriteAllText((Join-Path $out ('{0}_TESTPC_mock.json' -f $name)), $json)
    }
    $p = [pscustomobject]@{ Handle = 1; ExitCode = 0 }
    $p | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { return $true }
    $p | Add-Member -MemberType ScriptMethod -Name Kill -Value { }
    return $p
}
$env:COMPUTERNAME = 'TESTPC'
'@

function Invoke-Bundle {
    <# Runs the copied bundle with the mock; returns exit code, recorded command lines and the bundle's own result. #>
    param([string]$Name, [string]$Options)
    $dir = Join-Path $work $Name
    $flat = Join-Path $dir 'usb'
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $flat, $out -Force
    Copy-Item -LiteralPath $bundle -Destination $flat
    foreach ($s in $scripts) { [System.IO.File]::WriteAllText((Join-Path $flat ('{0}.ps1' -f $s)), '# placeholder') }
    $calls = Join-Path $dir 'calls.txt'
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "{0}`n`$env:MSP_TEST_CALLS = '{1}'`n& '{2}' -OutputPath '{3}' {4}`nexit `$LASTEXITCODE`n" -f $mock, ($calls -replace "'", "''"),
        ((Join-Path $flat 'Invoke-HomeAuditBundle.ps1') -replace "'", "''"), ($out -replace "'", "''"), $Options
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 | Out-String
    $code = $LASTEXITCODE
    $lines = @()
    if (Test-Path -LiteralPath $calls) { $lines = @(Get-Content -LiteralPath $calls) }
    $result = $null
    $json = @(Get-ChildItem -LiteralPath $out -Filter 'Invoke-HomeAuditBundle_*.json' -File -Recurse)
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json }
    return [pscustomobject]@{ Code = $code; Calls = $lines; Result = $result; Console = $console }
}

try {
    # --- -Passive ---------------------------------------------------------------------------
    $r = Invoke-Bundle 'passive' '-Passive'
    Assert-True 'passive: exit 0' ($r.Code -eq 0) ("exit {0}`n{1}" -f $r.Code, $r.Console)
    Assert-True 'passive: 7 scripts started' ($r.Calls.Count -eq 7) ($r.Calls -join "`n")
    $a2 = @($r.Calls | Where-Object { $_ -match 'Get-HomeNetworkMap\.ps1' })
    Assert-True 'passive: A2 started with -Passive' ($a2.Count -eq 1 -and $a2[0] -match ' -Passive( |$)') ($a2 -join '')
    Assert-True 'passive: A7 never started' (@($r.Calls | Where-Object { $_ -match 'Get-RouterSecurityCheck' }).Count -eq 0)
    Assert-True 'passive: no -ScanLan or -Online' (@($r.Calls | Where-Object { $_ -match '-ScanLan|-Online' }).Count -eq 0)
    $a7 = @($r.Result.Findings | Where-Object { $_.Check -eq 'Get-RouterSecurityCheck' })
    Assert-True 'passive: A7 recorded as SKIPPED with the reason' ($a7.Count -eq 1 -and $a7[0].Status -eq 'SKIPPED' -and $a7[0].Detail -match 'Not run with -Passive') ($a7 | ConvertTo-Json -Compress)
    Assert-True 'passive: mode noted' (@($r.Result.Findings | Where-Object { $_.Check -eq 'Passive mode' }).Count -eq 1)
    Assert-True 'passive: no ERROR' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) (($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }) | ConvertTo-Json -Compress)
    Assert-True 'passive: Runs table says Skipped (passive)' (@($r.Result.Data.Runs | Where-Object { $_.Script -eq 'Get-RouterSecurityCheck' -and $_.Result -eq 'Skipped (passive)' }).Count -eq 1)

    # --- without -Passive -------------------------------------------------------------------
    $r = Invoke-Bundle 'default' ''
    Assert-True 'default: exit 0' ($r.Code -eq 0) $r.Console
    Assert-True 'default: 8 scripts started' ($r.Calls.Count -eq 8) ($r.Calls -join "`n")
    $a2 = @($r.Calls | Where-Object { $_ -match 'Get-HomeNetworkMap\.ps1' })
    Assert-True 'default: A2 without -Passive' ($a2.Count -eq 1 -and $a2[0] -notmatch '-Passive') ($a2 -join '')
    Assert-True 'default: A7 started without the checklist prompt' (@($r.Calls | Where-Object { $_ -match 'Get-RouterSecurityCheck\.ps1.*-SkipChecklistPrompt' }).Count -eq 1)

    # --- refused combinations ---------------------------------------------------------------
    foreach ($combo in '-Passive -ScanLan', '-Passive -OnlineUpdateSearch') {
        $r = Invoke-Bundle ('refuse{0}' -f ($combo -replace '[^A-Za-z]', '')) $combo
        Assert-True ('{0}: exit 2' -f $combo) ($r.Code -eq 2) ("exit {0}" -f $r.Code)
        Assert-True ('{0}: nothing started' -f $combo) ($r.Calls.Count -eq 0) ($r.Calls -join "`n")
        Assert-True ('{0}: reason printed' -f $combo) ($r.Console -match 'cannot be combined') $r.Console
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
