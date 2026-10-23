<#
.SYNOPSIS
    Runs C3 Windows (Get-SuspiciousActivityReport.ps1) against mocked Windows cmdlets and
    checks its findings, so its logic is tested on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux). Same method as Test-BatchBWindowsLogic.ps1: a wrapper
    defines stand-in functions for the cmdlets the script calls (registry Run keys, scheduled
    tasks, services, processes, signatures, connections, Defender, Security log) and runs the
    real script. Calls for anything else go to the real cmdlet. The hosts file is read from a
    temporary folder (MSP_TEST_ROOT).

      infected  A Run key in Temp, an unsigned program in AppData, an encoded-PowerShell task
                added two days ago, a service directly in ProgramData, the Temp program running
                with an internet connection, a Defender detection not removed, a hosts entry
                for update.microsoft.com, a proxy. Signed programs in AppData and programs in
                Program Files are not flagged.
      clean     The same checks PASS.

    The administrator-only checks (Defender exclusions, Security log) are asserted as SKIPPED
    when the test is not elevated, and against the mocks when it is (Windows as administrator).
    Startup folders are read from the real computer and not asserted.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-SuspiciousActivityWindowsLogic.ps1

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
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-c3win-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$c3 = Join-Path $repo 'security-operations/diagnostics/endpoint-posture/Get-SuspiciousActivityReport.ps1'

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

$mocks = @'
$global:Signed = @{ 'C:\Users\bob\AppData\Local\Helper\helper.exe' = 'NotSigned' }
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path)
    $p = $LiteralPath
    if (-not $p) { $p = $Path }
    if ($global:FakeReg.ContainsKey($p)) { return $global:FakeReg[$p] }
    if ($p -match '\\CurrentVersion\\(Run|RunOnce|Internet Settings)$') { return $null }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
function Get-ScheduledTask { [CmdletBinding()] param() return $global:FakeTasks }
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Filter)
    if ($ClassName -eq 'Win32_Service') { return $global:FakeServices }
    CimCmdlets\Get-CimInstance @PSBoundParameters
}
function Get-Process { [CmdletBinding()] param() return $global:FakeProcesses }
function Get-AuthenticodeSignature {
    [CmdletBinding()] param([string]$FilePath)
    $s = $global:Signed[$FilePath]
    if (-not $s) { $s = 'Valid' }
    return [pscustomobject]@{ Status = $s }
}
function Get-NetTCPConnection { [CmdletBinding()] param([string]$State) return $global:FakeConnections }
function Get-MpThreatDetection { [CmdletBinding()] param() return $global:FakeDetections }
function Get-MpThreat { [CmdletBinding()] param() return @([pscustomobject]@{ ThreatID = 2147735503; ThreatName = 'Trojan:Win32/Wacatac.B!ml' }) }
function Get-MpPreference { [CmdletBinding()] param() return $global:FakePref }
function Get-WinEvent { [CmdletBinding()] param([hashtable]$FilterHashtable) return @() }
'@
$infected = @'
$global:FakeReg = @{
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' = [pscustomobject]@{ Updater = 'C:\Users\bob\AppData\Local\Temp\upd.exe /silent'; Helper = '"C:\Users\bob\AppData\Local\Helper\helper.exe" --tray'; Teams = 'C:\Users\bob\AppData\Local\Microsoft\Teams\Update.exe --processStart Teams.exe' }
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' = [pscustomobject]@{ SecurityHealth = 'C:\Windows\system32\SecurityHealthSystray.exe' }
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' = [pscustomobject]@{ ProxyEnable = 1; ProxyServer = '127.0.0.1:8080' }
}
$global:FakeTasks = @(
    [pscustomobject]@{ TaskPath = '\'; TaskName = 'Updater Task'; State = 'Ready'; Date = (Get-Date).AddDays(-2).ToString('s'); Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = '-w hidden -enc SQBFAFgA' }) },
    [pscustomobject]@{ TaskPath = '\'; TaskName = 'GoogleUpdateTaskMachineCore'; State = 'Ready'; Date = (Get-Date).AddDays(-200).ToString('s'); Actions = @([pscustomobject]@{ Execute = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'; Arguments = '/c' }) },
    [pscustomobject]@{ TaskPath = '\Microsoft\Windows\Defrag\'; TaskName = 'ScheduledDefrag'; State = 'Ready'; Date = $null; Actions = @([pscustomobject]@{ Execute = 'C:\Users\Public\x.exe'; Arguments = '' }) }
)
$global:FakeServices = @(
    [pscustomobject]@{ Name = 'svcx'; PathName = 'C:\ProgramData\svcx.exe -k' },
    [pscustomobject]@{ Name = 'Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe' }
)
$global:FakeProcesses = @(
    [pscustomobject]@{ Id = 4321; ProcessName = 'upd'; Path = 'C:\Users\bob\AppData\Local\Temp\upd.exe' },
    [pscustomobject]@{ Id = 555; ProcessName = 'helper'; Path = 'C:\Users\bob\AppData\Local\Helper\helper.exe' },
    [pscustomobject]@{ Id = 777; ProcessName = 'chrome'; Path = 'C:\Program Files\Google\Chrome\Application\chrome.exe' },
    [pscustomobject]@{ Id = 888; ProcessName = 'Teams'; Path = 'C:\Users\bob\AppData\Local\Microsoft\Teams\current\Teams.exe' },
    [pscustomobject]@{ Id = 4; ProcessName = 'System'; Path = $null }
)
$global:FakeConnections = @(
    [pscustomobject]@{ OwningProcess = 4321; RemoteAddress = '203.0.113.50'; RemotePort = 443 },
    [pscustomobject]@{ OwningProcess = 777; RemoteAddress = '198.51.100.7'; RemotePort = 443 }
)
$global:FakeDetections = @([pscustomobject]@{ ThreatID = 2147735503; InitialDetectionTime = (Get-Date).AddDays(-1); ActionSuccess = $false })
$global:FakePref = [pscustomobject]@{ ExclusionPath = @('C:\Users\bob\AppData'); ExclusionProcess = @(); ExclusionExtension = @() }
'@
$clean = @'
$global:FakeReg = @{ 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' = [pscustomobject]@{ SecurityHealth = 'C:\Windows\system32\SecurityHealthSystray.exe' } }
$global:FakeTasks = @()
$global:FakeServices = @([pscustomobject]@{ Name = 'Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe' })
$global:FakeProcesses = @([pscustomobject]@{ Id = 777; ProcessName = 'chrome'; Path = 'C:\Program Files\Google\Chrome\Application\chrome.exe' })
$global:FakeConnections = @([pscustomobject]@{ OwningProcess = 777; RemoteAddress = '198.51.100.7'; RemotePort = 443 })
$global:FakeDetections = @()
$global:FakePref = [pscustomobject]@{ ExclusionPath = @(); ExclusionProcess = @(); ExclusionExtension = @() }
'@

function Invoke-Scenario {
    param([string]$Name, [string]$Scene, [string]$Hosts)
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    [System.IO.File]::WriteAllText((Join-Path $dir 'hosts'), $Hosts)
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "`$env:MSP_TEST_ROOT = '{0}'`n{1}`n{2}`n& '{3}' -OutputPath '{4}'`nexit `$LASTEXITCODE`n" -f ($dir -replace "'", "''"), $mocks, $Scene, ($c3 -replace "'", "''"), ($out -replace "'", "''")
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 | Out-String
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    if ($json.Count -eq 0) { Assert-True ('{0}: JSON written' -f $Name) $false $console; return $null }
    return (Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json)
}
function Assert-Finding {
    param($Result, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '')
    $f = @($Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern)
    $got = 'missing'
    if ($f) { $got = '[{0}] {1}' -f $f.Status, $f.Detail }
    Assert-True $Label $ok $got
}

try {
    $r = Invoke-Scenario 'infected' $infected "127.0.0.1 localhost`n0.0.0.0 update.microsoft.com`n# comment`n"
    if ($r) {
        Assert-True 'infected: CheckId C3' ($r.CheckId -eq 'C3')
        Assert-Finding $r 'infected: labelled as triage, not EDR' 'Scope' 'INFO' 'not an antivirus or EDR'
        Assert-Finding $r 'infected: Run key in Temp' 'Startup items in unusual folders' 'WARN' 'Updater.*Temp\\upd\.exe'
        Assert-Finding $r 'infected: service in ProgramData root' 'Startup items in unusual folders' 'WARN' 'Service "svcx"'
        Assert-True 'infected: Microsoft task folder ignored' ([string](@($r.Findings | Where-Object { $_.Check -eq 'Startup items in unusual folders' })[0].Detail) -notmatch 'Defrag')
        Assert-Finding $r 'infected: encoded PowerShell task' 'Startup items that run scripts' 'WARN' 'Updater Task.*-enc'
        Assert-Finding $r 'infected: unsigned AppData program' 'Unsigned startup programs' 'WARN' 'helper\.exe'
        Assert-True 'infected: signed AppData program not flagged' ([string](@($r.Findings | Where-Object { $_.Check -eq 'Unsigned startup programs' })[0].Detail) -notmatch 'Teams')
        Assert-Finding $r 'infected: new task' 'New startup items' 'WARN' 'Updater Task'
        Assert-True 'infected: old task not new' ([string](@($r.Findings | Where-Object { $_.Check -eq 'New startup items' })[0].Detail) -notmatch 'GoogleUpdate')
        Assert-Finding $r 'infected: Temp program running' 'Programs running from unusual folders' 'WARN' 'upd\.exe \(PID 4321\)'
        Assert-Finding $r 'infected: unsigned profile program running' 'Unsigned programs running from the user profile' 'WARN' 'helper\.exe \(PID 555\)'
        Assert-Finding $r 'infected: its connection' 'Connections from flagged programs' 'WARN' 'upd\.exe -> 203\.0\.113\.50:443'
        Assert-True 'infected: Chrome connection not listed' ([string](@($r.Findings | Where-Object { $_.Check -eq 'Connections from flagged programs' })[0].Detail) -notmatch '198\.51\.100\.7')
        Assert-Finding $r 'infected: detection not removed' 'Defender detections' 'WARN' 'Wacatac.*NOT removed'
        Assert-True 'infected: detection is High' (@($r.Findings | Where-Object { $_.Check -eq 'Defender detections' -and $_.Severity -eq 'High' }).Count -eq 1)
        Assert-Finding $r 'infected: hosts entry for Microsoft' 'Hosts file' 'WARN' 'update\.microsoft\.com'
        Assert-Finding $r 'infected: proxy' 'Proxy settings' 'WARN' '127\.0\.0\.1:8080'
        if ($r.IsAdmin) {
            Assert-Finding $r 'infected (admin): AppData exclusion' 'Defender exclusions' 'WARN' 'AppData'
            Assert-Finding $r 'infected (admin): no new accounts' 'New local accounts' 'PASS'
        }
        else {
            foreach ($c in 'Defender exclusions', 'New local accounts', 'Failed sign-ins') { Assert-Finding $r ('infected (not admin): {0} SKIPPED' -f $c) $c 'SKIPPED' 'administrator' }
        }
        Assert-True 'infected: StartupItems table' (@($r.Data.StartupItems).Count -ge 5)
        Assert-True 'infected: no ERROR findings' (@($r.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) ((@($r.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
    }

    $r = Invoke-Scenario 'clean' $clean "# Copyright (c) Microsoft Corp.`n#  127.0.0.1 localhost`n"
    if ($r) {
        foreach ($c in 'Startup items that run scripts', 'Unsigned startup programs', 'Programs running from unusual folders', 'Connections from flagged programs', 'Defender detections', 'Hosts file', 'Proxy settings') {
            Assert-Finding $r ('clean: {0} PASS' -f $c) $c 'PASS'
        }
        Assert-True 'clean: no ERROR findings' (@($r.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) ((@($r.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
