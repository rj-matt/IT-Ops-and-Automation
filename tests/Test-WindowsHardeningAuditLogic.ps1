<#
.SYNOPSIS
    Runs Set-InactivityTimeout.ps1 and Get-KerberosRC4Usage.ps1 against mocked Windows cmdlets
    and checks their findings, so their logic is tested on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux). Same method as Test-BatchBWindowsLogic.ps1.

    SAFETY: every registry read and write of Set-InactivityTimeout goes to stand-in functions
    (Get-ItemProperty, Test-Path, New-Item, New-ItemProperty, Remove-ItemProperty), which keep the
    value in memory and record each write. The real registry is never touched, even when this
    test runs elevated on Windows.

    "Administrator" is simulated on macOS/Linux with a stand-in "id" command (the helper asks
    "id -u" there). On Windows the real elevation counts, so the change paths are asserted only
    when the result says the run was elevated.

      Set-InactivityTimeout  -WhatIf (plan, nothing written); non-interactive without -Force
                             (refuses, exit 1, nothing written); -Force: 60 -> 15 minutes with
                             before/after and the undo command; already 15 (nothing to do);
                             -Remove; a value that does not stick (FAIL, exit 2).
      Get-KerberosRC4Usage   Not a domain controller (SKIPPED); RC4 tickets, an RC4-only service
                             account and computer, KDC refusal events, RC4 allowed by default;
                             a clean domain controller; events without key details (old
                             servers, SKIPPED); no events (auditing off, WARN); not elevated.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-WindowsHardeningAuditLogic.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network,
                    no registry
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
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-hardening-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$idle = 'security-operations/hardening/server-hardening/Set-InactivityTimeout.ps1'
$rc4 = 'security-operations/audit/Get-KerberosRC4Usage.ps1'

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}
function Invoke-Mocked {
    <# Runs SCRIPT with MOCKS defined first; returns exit code, JSON result and the write log. #>
    param([string]$Name, [string]$Mocks, [string]$Script, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $writes = Join-Path $dir 'writes.txt'
    $argText = ($ScriptArgs | ForEach-Object { if ($_ -like '-*') { $_ } else { "'{0}'" -f ($_ -replace "'", "''") } }) -join ' '
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "`$env:MSP_TEST_WRITES = '{0}'`n{1}`n& '{2}' -OutputPath '{3}' {4}`nexit `$LASTEXITCODE`n" -f ($writes -replace "'", "''"), $Mocks, ((Join-Path $repo $Script) -replace "'", "''"), ($out -replace "'", "''"), $argText
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 | Out-String
    $code = $LASTEXITCODE
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    $result = $null
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json }
    else { Assert-True ('{0}: JSON written' -f $Name) $false $console }
    $log = @()
    if (Test-Path -LiteralPath $writes) { $log = @(Get-Content -LiteralPath $writes) }
    return [pscustomobject]@{ Code = $code; Result = $result; Writes = $log; Console = $console }
}
function Get-Finding {
    param($Run, [string]$Check)
    if (-not $Run.Result) { return $null }
    return @($Run.Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1
}
function Assert-Finding {
    param($Run, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '')
    $f = Get-Finding $Run $Check
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern)
    $got = 'missing'
    if ($f) { $got = '[{0}] {1}' -f $f.Status, $f.Detail }
    Assert-True $Label $ok $got
}
function Assert-NoError {
    param($Run, [string]$Label)
    if (-not $Run.Result) { return }
    $errors = @($Run.Result.Findings | Where-Object { $_.Status -eq 'ERROR' })
    Assert-True $Label ($errors.Count -eq 0) ((@($errors | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
}

$admin = "function id { '0' }`n"

# =========================================================================================
# Set-InactivityTimeout.ps1
# =========================================================================================
$idleMocks = @'
# $global:Idle = current value (seconds) or $null; $global:Sticky = $false makes writes not stick.
$global:Sticky = $true
function Write-Change { param([string]$Text) Add-Content -LiteralPath $env:MSP_TEST_WRITES -Value $Text }
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Name)
    $p = $LiteralPath; if (-not $p) { $p = $Path }
    if ($p -like 'HK*:\*\Policies\System') {
        if ($null -eq $global:Idle) { return $null }
        return [pscustomobject]@{ InactivityTimeoutSecs = $global:Idle }
    }
    if ($p -like 'HK*:\*') { return $null }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
function Test-Path {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$PathType)
    $p = $LiteralPath; if (-not $p) { $p = $Path }
    if ($p -like 'HK*:\*') { return $true }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function New-Item {
    [CmdletBinding()] param([string]$Path, [string]$ItemType, [switch]$Force, [string]$Name, $Value)
    if ($Path -like 'HK*:\*') { Write-Change ('New-Item {0}' -f $Path); return }
    Microsoft.PowerShell.Management\New-Item @PSBoundParameters
}
function New-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Name, [string]$PropertyType, $Value, [switch]$Force)
    Write-Change ('Set {0}={1} ({2})' -f $Name, $Value, $PropertyType)
    if ($global:Sticky) { $global:Idle = [int]$Value }
}
function Remove-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Name)
    Write-Change ('Remove {0}' -f $Name)
    $global:Idle = $null
}
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName)
    if ($ClassName -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ PartOfDomain = $true; Domain = 'contoso.local'; DomainRole = 1 } }
    CimCmdlets\Get-CimInstance @PSBoundParameters
}
'@

$r = Invoke-Mocked 'idle-whatif' ($idleMocks + "`$global:Idle = `$null") $idle @('-Minutes', '15', '-WhatIf')
Assert-True 'Idle -WhatIf: exit 0' ($r.Code -eq 0) ("exit {0}`n{1}" -f $r.Code, $r.Console)
Assert-True 'Idle -WhatIf: nothing written' ($r.Writes.Count -eq 0) ($r.Writes -join '; ')
Assert-Finding $r 'Idle -WhatIf: current state shown' 'Current setting' 'INFO' 'not set'
Assert-Finding $r 'Idle -WhatIf: dry run recorded' 'Dry run' 'INFO' 'nothing was changed'
Assert-True 'Idle -WhatIf: plan printed' ($r.Console -match '1\. Set .*InactivityTimeoutSecs to 900 seconds \(15 minutes\) \(now not set') $r.Console
Assert-Finding $r 'Idle: domain Group Policy note' 'Group Policy' 'INFO' 'contoso\.local'
Assert-True 'Idle: risk level Elevated' ($r.Result -and $r.Result.RiskLevel -eq 'Elevated')

$r = Invoke-Mocked 'idle-noforce' ($idleMocks + $admin + "`$global:Idle = 3600") $idle @('-Minutes', '15')
Assert-True 'Idle non-interactive without -Force: exit 1' ($r.Code -eq 1) ("exit {0}" -f $r.Code)
Assert-True 'Idle non-interactive without -Force: nothing written' ($r.Writes.Count -eq 0) ($r.Writes -join '; ')
$why = @($r.Result.Findings | Where-Object { $_.Check -in 'Confirmation', 'Administrator' -and $_.Status -eq 'SKIPPED' })
Assert-True 'Idle non-interactive: refusal recorded' ($why.Count -eq 1)

$r = Invoke-Mocked 'idle-set' ($idleMocks + $admin + "`$global:Idle = 3600") $idle @('-Minutes', '15', '-Force')
if ($r.Result -and $r.Result.IsAdmin) {
    Assert-True 'Idle -Force: exit 0' ($r.Code -eq 0) ("exit {0}`n{1}" -f $r.Code, $r.Console)
    Assert-True 'Idle -Force: one DWORD write of 900' (($r.Writes -join '|') -eq 'Set InactivityTimeoutSecs=900 (DWord)') ($r.Writes -join '; ')
    Assert-Finding $r 'Idle -Force: after state' 'Machine inactivity limit' 'PASS' 'Now 900 seconds \(15 minutes\) \(was 3600 seconds \(60 minutes\)\)\. Restart'
    Assert-Finding $r 'Idle -Force: undo command' 'Undo' 'INFO' 'Set-InactivityTimeout\.ps1 -Minutes 60$'
    Assert-True 'Idle -Force: before/after table' (@($r.Result.Data.Setting)[0].Before -eq 3600 -and @($r.Result.Data.Setting)[0].After -eq 900)
}
else { Assert-True 'Idle -Force without elevation refuses' ($r.Code -eq 1 -and $r.Writes.Count -eq 0) }

$r = Invoke-Mocked 'idle-same' ($idleMocks + $admin + "`$global:Idle = 900") $idle @('-Minutes', '15', '-Force')
Assert-True 'Idle already 15: exit 0, nothing written' ($r.Code -eq 0 -and $r.Writes.Count -eq 0) ("exit {0}; {1}" -f $r.Code, ($r.Writes -join '; '))
Assert-Finding $r 'Idle already 15: nothing to change' 'Result' 'INFO' 'already 900 seconds'

$r = Invoke-Mocked 'idle-remove' ($idleMocks + $admin + "`$global:Idle = 900") $idle @('-Remove', '-Force')
if ($r.Result -and $r.Result.IsAdmin) {
    Assert-True 'Idle -Remove: removed' (($r.Writes -join '|') -eq 'Remove InactivityTimeoutSecs') ($r.Writes -join '; ')
    Assert-Finding $r 'Idle -Remove: after state' 'Machine inactivity limit' 'PASS' 'Now not set'
    Assert-Finding $r 'Idle -Remove: undo command' 'Undo' 'INFO' '-Minutes 15$'
}

$r = Invoke-Mocked 'idle-notsticky' ($idleMocks + $admin + "`$global:Idle = 3600`n`$global:Sticky = `$false") $idle @('-Minutes', '15', '-Force')
if ($r.Result -and $r.Result.IsAdmin) {
    Assert-True 'Idle not sticking: exit 2' ($r.Code -eq 2) ("exit {0}" -f $r.Code)
    Assert-Finding $r 'Idle not sticking: FAIL' 'Machine inactivity limit' 'FAIL' 'Read back 3600 seconds'
}

# =========================================================================================
# Get-KerberosRC4Usage.ps1
# =========================================================================================
$rc4Mocks = @'
$global:Role = 5
$global:Kdc = $null
$global:KdcEvents = @()
$global:SecEvents = @()
function New-FakeKerbEvent {
    param([int]$Id, [string]$Account, [string]$Target, $Ticket, $Session, [string]$Keys, [string]$Ip, [int]$Fields = 23, [int]$HoursAgo = 5)
    $values = New-Object object[] $Fields
    if ($Id -eq 4769) { $values[0] = $Account; $values[2] = $Target; $values[5] = $Ticket; $values[6] = $Ip; $values[16] = $Keys; if ($Fields -gt 20) { $values[20] = $Session } }
    else { $values[0] = $Account; $values[3] = $Target; $values[7] = $Ticket; $values[9] = $Ip; $values[16] = $Keys; if ($Fields -gt 22) { $values[22] = $Session } }
    [pscustomobject]@{ Id = $Id; TimeCreated = (Get-Date).AddHours(-$HoursAgo); Properties = @($values | ForEach-Object { [pscustomobject]@{ Value = $_ } }) }
}
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName)
    if ($ClassName -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ DomainRole = $global:Role; Domain = 'contoso.local'; PartOfDomain = $true } }
    CimCmdlets\Get-CimInstance @PSBoundParameters
}
function Get-WinEvent {
    [CmdletBinding()] param($FilterXml, [hashtable]$FilterHashtable)
    $list = $global:SecEvents
    if ($FilterHashtable) { $list = $global:KdcEvents }
    if (@($list).Count -eq 0) { throw 'No events were found that match the specified selection criteria.' }
    return $list
}
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Name)
    $p = $LiteralPath; if (-not $p) { $p = $Path }
    if ($p -like '*\Services\Kdc') { return $global:Kdc }
    if ($p -like 'HK*:\*') { return $null }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
'@
$rc4Bad = @'
$global:SecEvents = @(
    (New-FakeKerbEvent 4768 'alice' 'krbtgt' 18 18 'AES-SHA1, RC4' '::ffff:198.51.100.10'),
    (New-FakeKerbEvent 4769 'bob' 'svc_legacy' 23 23 'RC4' '::ffff:198.51.100.20'),
    (New-FakeKerbEvent 4769 'bob' 'svc_legacy' '0x17' '0x17' 'RC4' '::ffff:198.51.100.20' 23 2),
    (New-FakeKerbEvent 4768 'nas01$' 'krbtgt' 23 18 'RC4' '198.51.100.30')
)
$global:KdcEvents = @([pscustomobject]@{ Id = 203 }, [pscustomobject]@{ Id = 201 }, [pscustomobject]@{ Id = 201 })
$global:Kdc = [pscustomobject]@{ DefaultDomainSupportedEncTypes = 0x24 }
'@
$rc4Good = @'
$global:SecEvents = @((New-FakeKerbEvent 4768 'alice' 'krbtgt' 18 18 'AES-SHA1, RC4' '198.51.100.10'), (New-FakeKerbEvent 4769 'alice' 'fs01$' 18 18 'AES-SHA1, RC4' '198.51.100.10'))
$global:Kdc = [pscustomobject]@{ DefaultDomainSupportedEncTypes = 0x18 }
'@

$r = Invoke-Mocked 'rc4-notdc' ($rc4Mocks + $admin + "`$global:Role = 3") $rc4
Assert-True 'RC4 not a DC: exit 0' ($r.Code -eq 0)
Assert-Finding $r 'RC4 not a DC: SKIPPED' 'Domain controller' 'SKIPPED' 'not a domain controller'
Assert-True 'RC4 not a DC: nothing else checked' ($null -eq (Get-Finding $r 'Kerberos events'))
Assert-True 'RC4: CheckId' ($r.Result -and $r.Result.CheckId -eq 'RC4')

$r = Invoke-Mocked 'rc4-bad' ($rc4Mocks + $admin + $rc4Bad) $rc4 @('-Days', '7')
if ($r.Result -and $r.Result.IsAdmin) {
    Assert-Finding $r 'RC4: events counted' 'Kerberos events' 'INFO' '^4 Kerberos ticket request\(s\) for 3 account\(s\)'
    Assert-Finding $r 'RC4: RC4 tickets' 'RC4 tickets issued' 'WARN' '^3 of 4 ticket request\(s\) \(75 %\) used RC4 \(1 sign-in tickets, 2 service tickets\)'
    Assert-Finding $r 'RC4: RC4-only service account and computer, most events first' 'Accounts with only RC4 keys' 'FAIL' '^svc_legacy \(Service.*; nas01\$ \(Computer'
    Assert-True 'RC4: alice not RC4-only' ([string](Get-Finding $r 'Accounts with only RC4 keys').Detail -notmatch 'alice')
    Assert-Finding $r 'RC4: alice has both' 'Accounts with RC4 and AES keys' 'INFO' '^1 account'
    Assert-Finding $r 'RC4: use by account with address' 'RC4 use by account' 'INFO' 'bob: 2 request\(s\) from 198\.51\.100\.20; nas01\$: 1 request\(s\) from 198\.51\.100\.30'
    Assert-Finding $r 'RC4: KDC refusals' 'KDC RC4 events' 'FAIL' 'REFUSED 1 request.*201 x2, 203 x1'
    Assert-Finding $r 'RC4: RC4 allowed by default' 'KDC encryption settings' 'WARN' 'DefaultDomainSupportedEncTypes: 0x24'
    Assert-True 'RC4: AccountKeys table' (@($r.Result.Data.AccountKeys).Count -eq 3)
    Assert-True 'RC4: AES keys expanded from AES-SHA1' ([string](@($r.Result.Data.AccountKeys | Where-Object { $_.Account -eq 'alice' })[0].Keys) -eq 'AES128-SHA96; AES256-SHA96; RC4')
    Assert-NoError $r 'RC4 bad: no ERROR findings'
}
else { Assert-Finding $r 'RC4 not elevated: Security log SKIPPED' 'Kerberos events' 'SKIPPED' 'administrator' }

$r = Invoke-Mocked 'rc4-good' ($rc4Mocks + $admin + $rc4Good) $rc4
if ($r.Result -and $r.Result.IsAdmin) {
    foreach ($c in 'RC4 tickets issued', 'Accounts with only RC4 keys', 'KDC RC4 events', 'KDC encryption settings') { Assert-Finding $r ('RC4 good: {0} PASS' -f $c) $c 'PASS' }
    Assert-NoError $r 'RC4 good: no ERROR findings'
}

$r = Invoke-Mocked 'rc4-oldschema' ($rc4Mocks + $admin + "`$global:SecEvents = @((New-FakeKerbEvent 4768 'alice' 'krbtgt' 18 18 'AES' '198.51.100.10' 18))") $rc4
if ($r.Result -and $r.Result.IsAdmin) {
    Assert-Finding $r 'RC4 old schema: SKIPPED with the update advice' 'Kerberos events' 'SKIPPED' 'January 2025'
    Assert-True 'RC4 old schema: no RC4 verdict' ($null -eq (Get-Finding $r 'RC4 tickets issued'))
}

$r = Invoke-Mocked 'rc4-noevents' ($rc4Mocks + $admin) $rc4
if ($r.Result -and $r.Result.IsAdmin) {
    Assert-Finding $r 'RC4 no events: auditing off WARN' 'Kerberos events' 'WARN' 'auditing is probably off'
    Assert-NoError $r 'RC4 no events: no ERROR findings'
}

$r = Invoke-Mocked 'rc4-notadmin' ($rc4Mocks + $rc4Bad) $rc4
if ($r.Result -and -not $r.Result.IsAdmin) {
    Assert-Finding $r 'RC4 not elevated: Security log SKIPPED' 'Kerberos events' 'SKIPPED' 'administrator'
    Assert-Finding $r 'RC4 not elevated: KDC events still read' 'KDC RC4 events' 'FAIL'
}

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
