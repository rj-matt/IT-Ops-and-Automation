<#
.SYNOPSIS
    Runs B6 Get-PerformanceSnapshot.ps1 against mocked Windows cmdlets (performance counters,
    processes, startup items, power, registry), so its logic is tested on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. Get-CimInstance, Get-Process,
    powercfg.exe and the registry reads (Test-Path / Get-ItemProperty on HK* paths) are stand-ins;
    the script samples for 5 real seconds per scenario.

      Slow PC      CPU 95 % (WARN High, the step names the busiest process), memory 96 % with
                   300 MB available, heavy paging and commit 95 %, disk 99 % busy, the CPU at 40 %
                   of its speed while busy, 20 startup programs (the heaviest running one named),
                   up 45 days, Windows Update restart pending, power saver plan, Defender and
                   Windows Update installing using CPU, the system drive nearly full (B5's rule).
      Healthy PC   Everything PASS / INFO and a "nothing stood out" step.
      Range        -SampleSeconds 200: plain message, exit 1.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-PerformanceSnapshotWindowsLogic.ps1

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
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-b6-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$b6 = Join-Path $repo 'endpoint-systems/diagnostics/performance/Get-PerformanceSnapshot.ps1'

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

$mocks = @'
$global:FakeReg = @{}
$global:ProcCalls = 0
function Test-Path {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$PathType)
    $p = $LiteralPath
    if (-not $p) { $p = $Path }
    if ($p -like 'HK*:\*') { return $global:FakeReg.ContainsKey($p) }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Name)
    $p = $LiteralPath
    if (-not $p) { $p = $Path }
    if ($p -like 'HK*:\*') { if ($global:FakeReg.ContainsKey($p)) { return $global:FakeReg[$p] } return $null }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Filter, [string]$Namespace)
    switch ($ClassName) {
        'Win32_OperatingSystem' { return [pscustomobject]@{ TotalVisibleMemorySize = 8388608; LastBootUpTime = (Get-Date).AddDays(-$global:UpDays) } }
        'Win32_PerfFormattedData_PerfOS_Processor' { return [pscustomobject]@{ Name = '_Total'; PercentProcessorTime = $global:Cpu } }
        'Win32_PerfFormattedData_PerfOS_Memory' { return [pscustomobject]@{ AvailableMBytes = $global:AvailMB; PagesPersec = $global:Pages; PercentCommittedBytesInUse = $global:Commit } }
        'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' { return [pscustomobject]@{ Name = '_Total'; PercentIdleTime = $global:DiskIdle } }
        'Win32_Processor' { return [pscustomobject]@{ CurrentClockSpeed = $global:ClockNow; MaxClockSpeed = 3000 } }
        'Win32_StartupCommand' { return $global:Startup }
        'Win32_Battery' { return $global:Battery }
        'Win32_LogicalDisk' { return [pscustomobject]@{ DeviceID = 'C:'; Size = 256GB; FreeSpace = $global:FreeC } }
    }
    throw ('Unexpected class {0}' -f $ClassName)
}
function Get-Process {
    [CmdletBinding()] param([int]$Id)
    if ($PSBoundParameters.ContainsKey('Id')) { return Microsoft.PowerShell.Management\Get-Process -Id $Id }
    $global:ProcCalls++
    $cores = [Environment]::ProcessorCount
    foreach ($p in $global:Procs) {
        # Second call: CPU seconds used during the window = share x 6 s x cores.
        $sec = 100.0
        if ($global:ProcCalls -gt 1) { $sec += $p.Share * 6 * $cores }
        [pscustomobject]@{ Id = $p.Id; ProcessName = $p.Name; TotalProcessorTime = [timespan]::FromSeconds($sec); WorkingSet64 = [long]($p.MB * 1MB); Path = ('C:\Program Files\{0}\{0}.exe' -f $p.Name) }
    }
}
function powercfg.exe { $global:LASTEXITCODE = 0; return $global:PowerCfg }
'@
$slow = @'
$global:UpDays = 45; $global:Cpu = 95; $global:AvailMB = 300; $global:Pages = 2500; $global:Commit = 95; $global:DiskIdle = 1; $global:ClockNow = 1200; $global:FreeC = 3GB
$global:Procs = @(
    @{ Id = 10; Name = 'chrome'; Share = 0.6; MB = 2500 }, @{ Id = 11; Name = 'MsMpEng'; Share = 0.3; MB = 300 }, @{ Id = 12; Name = 'TiWorker'; Share = 0.2; MB = 200 },
    @{ Id = 13; Name = 'Teams'; Share = 0.02; MB = 900 }, @{ Id = 14; Name = 'OneDrive'; Share = 0.01; MB = 150 }, @{ Id = 15; Name = 'explorer'; Share = 0.0; MB = 120 }
)
$global:Startup = @(1..20 | ForEach-Object { [pscustomobject]@{ Name = ('Helper{0}' -f $_); Command = ('"C:\Program Files\Helper{0}\helper{0}.exe" /min' -f $_); Location = 'HKU\...\Run' } })
$global:Startup += @([pscustomobject]@{ Name = 'Microsoft Teams'; Command = '"C:\Program Files\Teams\Teams.exe" --process-start-args "--system-initiated"'; Location = 'Startup' })
$global:Battery = @([pscustomobject]@{ BatteryStatus = 1; EstimatedChargeRemaining = 40 })
$global:PowerCfg = 'Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)'
$global:FakeReg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'] = [pscustomobject]@{}
'@
$healthy = @'
$global:UpDays = 3; $global:Cpu = 12; $global:AvailMB = 5000; $global:Pages = 20; $global:Commit = 40; $global:DiskIdle = 90; $global:ClockNow = 2900; $global:FreeC = 150GB
$global:Procs = @(@{ Id = 10; Name = 'chrome'; Share = 0.05; MB = 800 }, @{ Id = 15; Name = 'explorer'; Share = 0.01; MB = 120 })
$global:Startup = @([pscustomobject]@{ Name = 'OneDrive'; Command = '"C:\Program Files\OneDrive\OneDrive.exe" /background'; Location = 'HKU\...\Run' })
$global:Battery = @()
$global:PowerCfg = 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)'
'@

function Invoke-Mocked {
    param([string]$Name, [string]$Scene, [string[]]$ScriptArgs = @('-SampleSeconds', '5'))
    $dir = Join-Path $work ('run-' + $Name)
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "{0}`n{1}`n& '{2}' -OutputPath '{3}' {4}`nexit `$LASTEXITCODE`n" -f $mocks, $Scene, ($b6 -replace "'", "''"), ($out -replace "'", "''"), ($ScriptArgs -join ' ')
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & { $ErrorActionPreference = 'Continue'; & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 } | Out-String
    $code = $LASTEXITCODE
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    $result = $null
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json }
    return [pscustomobject]@{ Code = $code; Console = $console; Result = $result }
}
function Get-Finding { param($Run, [string]$Check) if ($Run.Result) { @($Run.Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1 } }
function Assert-Finding {
    param($Run, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '', [string]$Severity = '')
    $f = Get-Finding $Run $Check
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern) -and (-not $Severity -or $f.Severity -eq $Severity)
    $got = 'missing'
    if ($f) { $got = '[{0}/{1}] {2}' -f $f.Status, $f.Severity, $f.Detail }
    Assert-True $Label $ok $got
}

try {
    $r = Invoke-Mocked 'slow' $slow
    Assert-True 'slow: exit 0, JSON, CheckId B6' ($r.Code -eq 0 -and $r.Result -and $r.Result.CheckId -eq 'B6') $r.Console
    Assert-True 'slow: no ERROR findings' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) ((@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
    Assert-True 'slow: several samples over the window' (@($r.Result.Data.Samples).Count -ge 3) ('{0} samples' -f @($r.Result.Data.Samples).Count)
    Assert-Finding $r 'CPU 95 % = WARN High' 'CPU' 'WARN' '^Average 95 %, peak 95 % over 5 seconds' 'High'
    Assert-Finding $r 'memory 96 % = WARN' 'Memory' 'WARN' '9[0-9](\.\d)? % of 8\.0 GB in use on average; lowest available 300 MB' 'High'
    Assert-Finding $r 'paging and commit = WARN' 'Memory pressure' 'WARN' 'heavy paging to disk, commit near the limit' 'High'
    Assert-Finding $r 'disk 99 % busy = WARN' 'Disk activity' 'WARN' 'busy 99 % of the time' 'High'
    Assert-Finding $r 'top CPU: chrome first' 'Top processes by CPU' 'INFO' '^chrome [\d.]+ %; MsMpEng [\d.]+ %; TiWorker'
    Assert-Finding $r 'top memory: chrome first' 'Top processes by memory' 'INFO' '^chrome 2,?500 MB; Teams 900 MB'
    Assert-Finding $r '21 startup programs = WARN, Teams heaviest' 'Startup programs' 'WARN' '^21 programs start with Windows\. Heaviest running now: Microsoft Teams 900 MB' 'Low'
    Assert-Finding $r 'up 45 days = WARN' 'Uptime' 'WARN' 'Up 45 days'
    Assert-Finding $r 'restart pending = WARN' 'Restart pending' 'WARN' 'Windows Update'
    Assert-Finding $r 'CPU at 40 % of its speed while busy = WARN' 'CPU speed' 'WARN' '1,?200 MHz of 3,?000 MHz rated \(40 %\) while the CPU was 95 % busy'
    Assert-Finding $r 'power saver on battery = WARN' 'Power plan' 'WARN' 'Power plan: Power saver; on battery, battery 40 %'
    Assert-Finding $r 'known causes: Defender, Windows Update, disk 100 %, full drive' 'Known causes' 'WARN' 'Antivirus scan .*Windows Update installing .*disk at 100 % .*system drive nearly full \(3\.0 GB free'
    Assert-True 'known causes: indexing not claimed' ([string](Get-Finding $r 'Known causes').Detail -notmatch 'Search indexing')
    $steps = @($r.Result.Data.NextSteps | Sort-Object { [int]$_.Step } | ForEach-Object { [string]$_.Action })
    foreach ($p in '^CPU is busy .*look at chrome first', '^Memory is nearly full', '^Memory pressure', '^Too many startup programs \(21\).*starting with Microsoft Teams', '^Restart the PC \(up 45 days', '^Restart to finish the pending updates',
        'CPU is running slow while busy', '^Power saving is on', '^Microsoft Defender is scanning', '^Windows Update is installing', '^The disk is at 100 %', '^The system drive is nearly full .*B5 Get-DiskSpaceReport\.ps1') {
        Assert-True ('what to do: {0}' -f $p) (@($steps | Where-Object { $_ -match $p }).Count -eq 1) ($steps -join ' | ')
    }
    foreach ($t in 'Samples', 'TopCpu', 'TopMemory', 'Startup', 'NextSteps') { Assert-True ('table {0}' -f $t) (@($r.Result.Data.$t).Count -gt 0) }

    $r = Invoke-Mocked 'healthy' $healthy
    Assert-True 'healthy: exit 0, no ERROR' ($r.Code -eq 0 -and @($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) $r.Console
    Assert-True 'healthy: no WARN or FAIL' (@($r.Result.Findings | Where-Object { $_.Status -in 'WARN', 'FAIL' }).Count -eq 0) ((@($r.Result.Findings | Where-Object { $_.Status -in 'WARN', 'FAIL' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
    Assert-Finding $r 'healthy: power plan noted' 'Power plan' 'INFO' 'Balanced; no battery'
    $steps = @($r.Result.Data.NextSteps | ForEach-Object { [string]$_.Action })
    Assert-True 'healthy: nothing stood out' ($steps.Count -eq 1 -and $steps[0] -match '^Nothing stood out while sampling') ($steps -join ' | ')

    $r = Invoke-Mocked 'range' $healthy @('-SampleSeconds', '200')
    Assert-True '-SampleSeconds 200: plain message, exit 1' ($r.Code -eq 1 -and $r.Console.Contains('-SampleSeconds must be between 5 and 120 (you gave 200)')) $r.Console
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
