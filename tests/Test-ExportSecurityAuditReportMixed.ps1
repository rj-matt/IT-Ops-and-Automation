<#
.SYNOPSIS
    Tests that A9 (Export-SecurityAuditReport.ps1) builds one report from Windows, macOS and
    Linux results: coverage table, router checklist, other-devices checklist, bundle lines.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux).

    Writes made-up results to a temporary folder:
      TEST-PC   Windows: A1, A2 (with a Devices table), A7 (checklist answers) and an
                Invoke-HomeAuditBundle result in which A3 was skipped and A4 failed to run.
      TEST-MAC  macOS (bash script names): A1, A7 checklist answers, and a
                run-home-audit-bundle result in which A7 was not run (--passive).
      TEST-LNX  Linux (bash script names): A1 and A2 (with a Devices table that repeats one of
                TEST-PC's devices, with the MAC address written the macOS/Linux way).
    then runs A9 on them and checks that every platform's scripts fill the coverage table by
    catalog ID, that both A7 versions feed the router checklist, and that the devices found by
    A2 are listed once in the other-devices checklist without the router, the computer that ran
    A2 or the audited computers.

    -ExtraInputPath copies more result folders in (for example a real run-home-audit-bundle.sh
    folder from this Mac) to check the report on real data; -ReportPath keeps the report.

.PARAMETER ExtraInputPath
    Result folders to add to the made-up results (copied, not changed).

.PARAMETER ReportPath
    Where to keep the HTML report. Default: deleted with the temporary folder.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-ExportSecurityAuditReportMixed.ps1

.EXAMPLE
    pwsh -NoProfile -File tests/Test-ExportSecurityAuditReportMixed.ps1 -ExtraInputPath $macFolder, $linuxFolder -ReportPath ./mixed.html

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-True (Name, Condition, Detail) is a one-line test assertion used throughout.')]
[CmdletBinding()]
param(
    [string[]]$ExtraInputPath = @(),
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$scriptPath = (Resolve-Path -LiteralPath (Join-Path $here '../security-operations/diagnostics/Export-SecurityAuditReport.ps1')).ProviderPath

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-a9-mixed-{0}' -f [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force

function Get-FakeFinding {
    param([string]$Id, [string]$Category, [string]$Check, [string]$Status, [string]$Severity = 'Info', [string]$Target, [string]$Detail = 'test')
    return [ordered]@{ Id = $Id; Category = $Category; Check = $Check; Status = $Status; Severity = $Severity; Target = $Target; Detail = $Detail; Recommendation = 'Fix it.'; Evidence = $null }
}
function Write-Result {
    <# One schema 2.0 result file. #>
    param([string]$CheckId, [string]$ScriptName, [string]$Platform, [string]$OSVersion, [string]$Computer, [object[]]$Findings, [hashtable]$Data = @{})
    $summary = [ordered]@{}
    foreach ($s in 'PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR') { $summary[$s] = @($Findings | Where-Object { $_.Status -eq $s }).Count }
    $result = [ordered]@{
        SchemaVersion = '2.0'; CheckId = $CheckId; ScriptName = $ScriptName; Version = '1.0.0'; Platform = $Platform
        OSVersion = $OSVersion; Shell = 'test'; Host = $Computer; User = 'user'; IsAdmin = $false; RiskLevel = 'Read-Only'
        Parameters = @{}; Timestamp = '2026-10-20T10:00:00+00:00'; EndTime = '2026-10-20T10:01:00+00:00'; Summary = $summary
        Findings = @($Findings); Data = $Data
    }
    $name = '{0}_{1}.json' -f $ScriptName, $Computer
    [System.IO.File]::WriteAllText((Join-Path $work $name), ($result | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
}
function Get-FakeDevice {
    param([string]$Ip, [string]$Mac, [string]$Vendor, [string]$Hostname, [string]$Type, [bool]$Gateway = $false, [bool]$Self = $false)
    return [ordered]@{ IPAddress = $Ip; MacAddress = $Mac; Vendor = $Vendor; Hostname = $Hostname; DeviceType = $Type; RespondedToPing = $true; RandomizedMac = $false; Identified = $true; IsGateway = $Gateway; IsSelf = $Self }
}

# --- Windows -------------------------------------------------------------------------------
Write-Result 'A1' 'Get-EndpointSecurityStatus' 'Windows' 'Windows 11 Pro 26200' 'TEST-PC' @(
    (Get-FakeFinding 'A1.Encryption.System-drive-encryption' 'Encryption' 'System drive encryption' 'FAIL' 'High' 'TEST-PC'))
Write-Result 'A2' 'Get-HomeNetworkMap' 'Windows' 'Windows 11 Pro 26200' 'TEST-PC' @(
    (Get-FakeFinding 'A2.Discovery.Devices-found' 'Discovery' 'Devices found' 'INFO' 'Info' 'TEST-PC')) @{
    Devices = @(
        (Get-FakeDevice '198.51.100.1' 'AA-00-00-00-00-01' 'Netgear' '' 'Router / gateway' -Gateway $true),
        (Get-FakeDevice '198.51.100.10' 'AA-00-00-00-00-10' 'Microsoft' 'TEST-PC' 'This computer' -Self $true),
        (Get-FakeDevice '198.51.100.11' 'AA-00-00-00-00-11' 'Apple' 'TEST-MAC.local' 'Computer'),
        (Get-FakeDevice '198.51.100.20' 'AA-00-00-00-00-20' 'Samsung' 'LivingRoomTV' 'TV / streaming'),
        (Get-FakeDevice '198.51.100.21' 'AA-00-00-00-00-21' 'Sony' '' 'Game console'))
}
Write-Result 'A7' 'Get-RouterSecurityCheck' 'Windows' 'Windows 11 Pro 26200' 'TEST-PC' @(
    (Get-FakeFinding 'A7.Checklist.Checklist-WPS' 'Checklist' 'Checklist: WPS' 'FAIL' 'High' '198.51.100.1' 'WPS is on (technician).'))
Write-Result 'Bundle' 'Invoke-HomeAuditBundle' 'Windows' 'Windows 11 Pro 26200' 'TEST-PC' @(
    (Get-FakeFinding 'Bundle.Run.Get-WiFiSecurityAudit' 'Run' 'Get-WiFiSecurityAudit' 'SKIPPED' 'Info' 'TEST-PC' 'Skipped with -Skip.'),
    (Get-FakeFinding 'Bundle.Run.Get-OpenPortScan' 'Run' 'Get-OpenPortScan' 'ERROR' 'Info' 'TEST-PC' 'Did not complete (exited with code 3). The other scripts still ran.'))

# --- macOS ---------------------------------------------------------------------------------
Write-Result 'A1' 'get-endpoint-security-status-macos' 'macOS' 'macOS 26.0' 'TEST-MAC' @(
    (Get-FakeFinding 'A1.Encryption.System-drive-encryption' 'Encryption' 'System drive encryption' 'FAIL' 'High' 'TEST-MAC'),
    (Get-FakeFinding 'A1.System.Gatekeeper' 'System' 'Gatekeeper' 'WARN' 'Medium' 'TEST-MAC'))
Write-Result 'A7' 'get-router-security-check' 'macOS' 'macOS 26.0' 'TEST-MAC' @(
    (Get-FakeFinding 'A7.Checklist.Checklist-Remote-management' 'Checklist' 'Checklist: Remote management' 'PASS' 'Info' '198.51.100.1' 'Confirmed by technician.'))
Write-Result 'Bundle' 'run-home-audit-bundle' 'macOS' 'macOS 26.0' 'TEST-MAC' @(
    (Get-FakeFinding 'Bundle.Run.get-home-network-map' 'Run' 'get-home-network-map' 'ERROR' 'Info' 'TEST-MAC' 'Did not complete (stopped after the 15-minute time limit). The other scripts still ran.'),
    (Get-FakeFinding 'Bundle.Run.get-router-security-check' 'Run' 'get-router-security-check' 'SKIPPED' 'Info' 'TEST-MAC' 'Not run with --passive: every router check sends traffic to the router.'))

# --- Linux ---------------------------------------------------------------------------------
Write-Result 'A1' 'get-endpoint-security-status-linux' 'Linux' 'Ubuntu 24.04.1 LTS' 'TEST-LNX' @(
    (Get-FakeFinding 'A1.Firewall.Firewall' 'Firewall' 'Firewall' 'WARN' 'Medium' 'TEST-LNX'))
Write-Result 'A2' 'get-home-network-map' 'Linux' 'Ubuntu 24.04.1 LTS' 'TEST-LNX' @(
    (Get-FakeFinding 'A2.Discovery.Devices-found' 'Discovery' 'Devices found' 'INFO' 'Info' 'TEST-LNX')) @{
    Devices = @(
        (Get-FakeDevice '198.51.100.1' 'AA:00:00:00:00:01' 'Netgear' '' 'Router / gateway' -Gateway $true),
        (Get-FakeDevice '198.51.100.12' 'AA:00:00:00:00:12' '' 'test-lnx' 'This computer' -Self $true),
        (Get-FakeDevice '198.51.100.20' 'aa:00:00:00:00:20' 'Samsung' 'LivingRoomTV' 'TV / streaming'),
        (Get-FakeDevice '198.51.100.30' '3A:11:22:33:44:99' '' '' 'Phone / tablet / laptop (private MAC)'),
        (Get-FakeDevice '198.51.100.31' 'AA:00:00:00:00:31' 'Hikvision' 'cam1' 'Camera / recorder'))
}

try {
    # "pwsh -File" passes a list as one "a,b" string; split so both forms work.
    foreach ($extra in @($ExtraInputPath | ForEach-Object { $_ -split ',' } | Where-Object { $_ })) {
        Get-ChildItem -LiteralPath $extra -Filter '*.json' -File | Copy-Item -Destination $work
    }
    $report = Join-Path $work 'report.html'
    $psExe = (Get-Process -Id $PID).Path
    $null = (& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptPath -InputPath $work -TechnicianName 'Test' -ReportPath $report 2>&1 | Out-String)
    Assert-True 'A9 exit code 0' ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE"
    Assert-True 'report written' (Test-Path -LiteralPath $report)
    $html = [System.IO.File]::ReadAllText($report)
    function Get-Section {
        param([string]$From, [string]$To)
        $a = $html.IndexOf(('id="{0}"' -f $From)); $b = $html.IndexOf(('id="{0}"' -f $To))
        if ($a -lt 0 -or $b -lt 0) { return '' }
        return $html.Substring($a, $b - $a)
    }
    $coverage = Get-Section 'coverage' 'router'
    $router = Get-Section 'router' 'other-devices'
    $other = Get-Section 'other-devices' 'devices'
    $perDevice = Get-Section 'devices' 'gaps'
    $plan = Get-Section 'plan' 'coverage'
    function Get-CoverageRow {
        param([string]$Computer, [string]$Area)
        return [regex]::Match($coverage, ('<tr><td>{0}</td><td>{1}</td>.*?</tr>' -f [regex]::Escape($Computer), [regex]::Escape($Area))).Value
    }

    # Coverage by catalog ID, any platform.
    Assert-True 'coverage: macOS A1 counted' ((Get-CoverageRow 'TEST-MAC' 'Computer security settings') -match '2026-10-20') (Get-CoverageRow 'TEST-MAC' 'Computer security settings')
    Assert-True 'coverage: Linux A1 counted' ((Get-CoverageRow 'TEST-LNX' 'Computer security settings') -match '2026-10-20')
    Assert-True 'coverage: Linux A2 counted' ((Get-CoverageRow 'TEST-LNX' 'Devices on the network') -match '2026-10-20')
    Assert-True 'coverage: macOS A7 counted' ((Get-CoverageRow 'TEST-MAC' 'Router') -match '2026-10-20')
    Assert-True 'coverage: Windows A1 still counted' ((Get-CoverageRow 'TEST-PC' 'Computer security settings') -match '2026-10-20')
    Assert-True 'coverage: bash bundle failure shown' ((Get-CoverageRow 'TEST-MAC' 'Devices on the network') -match 'Failed to run: Did not complete \(stopped after')
    Assert-True 'coverage: Windows bundle failure shown' ((Get-CoverageRow 'TEST-PC' 'Open ports') -match 'Failed to run: Did not complete \(exited with code 3\)')
    Assert-True 'coverage: Windows bundle skip shown' ((Get-CoverageRow 'TEST-PC' 'Wi-Fi security') -match 'Not run: Skipped with -Skip')
    Assert-True 'coverage: never-run script' ((Get-CoverageRow 'TEST-LNX' 'Web browsers') -match '>Not run<')
    Assert-True 'coverage: no Windows-only area name' ($coverage -notmatch 'Windows updates|PC security settings')

    # Router checklist from both A7 versions.
    Assert-True 'router: Windows A7 answer' ($router -match '>WPS<')
    Assert-True 'router: bash A7 answer' ($router -match '>Remote management<')
    Assert-True 'router: section not "not run"' ($router -notmatch 'was not run')

    # Remediation plan: one item across platforms, area by catalog ID.
    Assert-True 'plan: encryption once' (([regex]::Matches($plan, '<b>System drive encryption</b>')).Count -eq 1)
    Assert-True 'plan: macOS-only item has the A1 area name' ($plan -match '<b>Gatekeeper</b> <span class="muted small">\(Computer security settings\)</span>')
    Assert-True 'summary: bundle failures counted' ($html -match '2 audit script\(s\) did not run')

    # Other-devices checklist.
    foreach ($g in 'Phones and tablets', 'Smart TVs and streaming boxes', 'Game consoles', 'Smart-home devices', 'Printers and network storage') {
        Assert-True ('checklist group: {0}' -f $g) ($other -match [regex]::Escape($g))
    }
    $found = $other.Substring([math]::Max(0, $other.IndexOf('Devices found on the network')))
    Assert-True 'devices: TV listed once (same MAC from Windows and Linux A2)' (([regex]::Matches($found, 'LivingRoomTV')).Count -eq 1)
    Assert-True 'devices: console listed' ($found -match 'Game consoles</td><td>\(no name\) Game console')
    Assert-True 'devices: private-MAC phone listed' ($found -match '198\.51\.100\.30')
    Assert-True 'devices: camera under smart-home' ($found -match 'Smart-home devices[^<]*</td><td>cam1')
    Assert-True 'devices: router left out' ($found -notmatch '198\.51\.100\.1<')
    Assert-True 'devices: computers that ran A2 left out' ($found -notmatch '198\.51\.100\.10<|198\.51\.100\.12<')
    Assert-True 'devices: audited Mac (by host name) left out' ($found -notmatch 'TEST-MAC')

    # Per-device headings show the OS.
    Assert-True 'per-device: macOS version shown' ($perDevice -match '<h3>TEST-MAC <span class="muted small">macOS 26\.0</span>')
    Assert-True 'per-device: bash script labelled by area' ($perDevice -match 'Computer security settings \(get-endpoint-security-status-linux\)')

    if ($ReportPath) { Copy-Item -LiteralPath $report -Destination $ReportPath -Force; Write-Host ('Report kept: {0}' -f $ReportPath) }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
