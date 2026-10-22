<#
.SYNOPSIS
    Runs the Windows Batch B diagnostics (B1, B2 -Passive, B3) against mocked Windows cmdlets and
    checks their findings, so their logic is tested on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux).

    Each scenario writes a small wrapper script to a temporary folder that defines stand-in
    functions for the Windows cmdlets the script calls (Get-CimInstance, Get-NetAdapter,
    Get-WinEvent ...) and then runs the real script with -OutputPath. Functions are found before
    cmdlets, so the script sees the made-up data. The JSON result is then checked.

      B1  Disk-space rule (FAIL under 10 % / 5 GB, PASS from 100 GB free), memory and CPU
          thresholds, uptime, last update from Get-HotFix.
      B2  -Passive only (nothing can be sent): a working configuration, and a self-assigned
          (169.254) address that must be named as the first failing layer.
      B3  Blue screen, unexpected shutdown, disk error, service failure (with the service name),
          application crash (with the program name), DCOM noise left out; and "no events"
          (Get-WinEvent's NoMatchingEventsFound) reported as PASS, not as an error.

    Checks that read the real computer (Windows Update COM, pending-restart registry keys) are
    not asserted: they differ between platforms.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-BatchBWindowsLogic.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-Equal / Assert-True (Name, Expected, Actual) are one-line test assertions used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$temp = [System.IO.Path]::GetTempPath()
$work = Join-Path $temp ('msp-batchb-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force

$script:passed = 0
$script:failed = 0
function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    if ("$Expected" -ceq "$Actual") { $script:passed++ }
    else { $script:failed++; Write-Host ("FAIL: {0}`n  expected: [{1}]`n  actual:   [{2}]" -f $Name, $Expected, $Actual) -ForegroundColor Red }
}
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

function Invoke-Mocked {
    <# Runs SCRIPT (repo-relative) with the MOCKS text defined first; returns the JSON result. #>
    param([string]$Name, [string]$Mocks, [string]$Script, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $target = Join-Path $repo $Script
    # Parameter names stay bare; values are quoted.
    $argText = ($ScriptArgs | ForEach-Object { if ($_ -like '-*') { $_ } else { "'{0}'" -f $_ } }) -join ' '
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "{0}`n& '{1}' -OutputPath '{2}' {3}`n" -f $Mocks, ($target -replace "'", "''"), ($out -replace "'", "''"), $argText
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    if ($json.Count -eq 0) {
        Write-Host ("FAIL: {0}: no JSON result. Console:`n{1}" -f $Name, (($console | Out-String).Trim())) -ForegroundColor Red
        $script:failed++
        return $null
    }
    return (Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json)
}

function Get-Finding {
    param($Result, [string]$Check)
    if (-not $Result) { return $null }
    return @($Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1
}

function Assert-Finding {
    <# The finding exists with STATUS and its detail matches PATTERN. #>
    param([string]$Label, $Result, [string]$Check, [string]$Status, [string]$Pattern = '')
    $f = Get-Finding -Result $Result -Check $Check
    if (-not $f) { Assert-True $Label $false ('(no finding "{0}")' -f $Check); return }
    Assert-Equal ('{0}: status' -f $Label) $Status $f.Status
    if ($Pattern) { Assert-True ('{0}: detail' -f $Label) ($f.Detail -match $Pattern) ('(detail: {0})' -f $f.Detail) }
}

try {
    # --- B1 -------------------------------------------------------------------------------------
    $b1Mocks = @'
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Filter)
    switch ($ClassName) {
        'Win32_ComputerSystem' { [pscustomobject]@{ Manufacturer = 'Contoso'; Model = 'Laptop 9'; PartOfDomain = $false; Workgroup = 'WORKGROUP'; Domain = '' } }
        'Win32_BIOS' { [pscustomobject]@{ SerialNumber = 'SN123' } }
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; Version = '10.0.26100'; BuildNumber = '26100'; OSArchitecture = '64-bit'; InstallDate = (Get-Date).AddDays(-400); LastBootUpTime = (Get-Date).AddDays(-45).AddHours(-2); TotalVisibleMemorySize = 16777216; FreePhysicalMemory = 838861 } }
        'Win32_Processor' { [pscustomobject]@{ Name = 'Mock CPU 3000 '; NumberOfCores = 4; NumberOfLogicalProcessors = 8; LoadPercentage = 20 } }
        'Win32_LogicalDisk' {
            [pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'Windows'; FileSystem = 'NTFS'; Size = 107374182400; FreeSpace = 4294967296 }
            [pscustomobject]@{ DeviceID = 'D:'; VolumeName = 'Data'; FileSystem = 'NTFS'; Size = 2147483648000; FreeSpace = 161061273600 }
            [pscustomobject]@{ DeviceID = 'E:'; VolumeName = ''; FileSystem = 'NTFS'; Size = 107374182400; FreeSpace = 16106127360 }
        }
    }
}
function Get-HotFix { [CmdletBinding()] param() [pscustomobject]@{ HotFixID = 'KB5000001'; InstalledOn = (Get-Date).AddDays(-60) } }
$env:SystemDrive = 'C:'
'@
    $r = Invoke-Mocked -Name 'b1' -Mocks $b1Mocks -Script 'endpoint-systems/diagnostics/system-info/Get-ClientHealthSnapshot.ps1'
    Assert-Finding 'B1 computer' $r 'Computer' 'INFO' 'Contoso Laptop 9 \(S/N SN123\), WORKGROUP \(workgroup\)'
    Assert-Finding 'B1 45 days up' $r 'Uptime' 'WARN' '^Up 45 day'
    Assert-Finding 'B1 memory 95 %' $r 'Memory' 'WARN' '^95 % of 16 GB'
    Assert-Finding 'B1 CPU 20 %' $r 'CPU' 'PASS' 'Mock CPU 3000 \(4 cores / 8 threads\): 20 %'
    Assert-Finding 'B1 system drive 4 GB free' $r 'System drive space' 'FAIL' '^C: \(Windows\): 4 GB free of 100 GB'
    Assert-Finding 'B1 150 GB free is fine at 7.5 %' $r 'Disk space D:' 'PASS'
    Assert-Finding 'B1 15 GB free of 100 GB' $r 'Disk space E:' 'WARN'
    Assert-Finding 'B1 last update 60 days ago' $r 'Last update installed' 'WARN' '\(60 days ago\)'
    if ($r) {
        Assert-Equal 'B1 CheckId' 'B1' $r.CheckId
        Assert-Equal 'B1 Disks table rows' 3 @($r.Data.Disks).Count
        Assert-True 'B1 IDs match the bash version' ((Get-Finding $r 'System drive space').Id -eq 'B1.Resources.System-drive-space')
    }

    # --- B2 -Passive ------------------------------------------------------------------------------
    $b2Base = @'
function Get-NetAdapter { [CmdletBinding()] param() $global:mockAdapters }
function Get-NetIPAddress { [CmdletBinding()] param([string]$AddressFamily) $global:mockAddresses }
function Get-NetRoute { [CmdletBinding()] param([string]$DestinationPrefix) $global:mockRoutes }
function Get-DnsClientServerAddress { [CmdletBinding()] param([string]$AddressFamily) [pscustomobject]@{ InterfaceIndex = 12; ServerAddresses = @('198.51.100.1') } }
function Get-VpnConnection { [CmdletBinding()] param() }
function Get-ItemProperty { [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Name) [pscustomobject]@{ ProxyEnable = 0; ProxyServer = ''; AutoConfigURL = '' } }
function netsh.exe { 'Current WinHTTP proxy settings:', '    Direct access (no proxy server).' }
function Test-Connection { throw 'Test-Connection must not be called with -Passive' }
function Resolve-DnsName { throw 'Resolve-DnsName must not be called with -Passive' }
function Invoke-WebRequest { throw 'Invoke-WebRequest must not be called with -Passive' }
$global:mockAdapters = @(
    [pscustomobject]@{ Name = 'Wi-Fi'; InterfaceDescription = 'Mock Wireless 6E'; Status = 'Up'; Virtual = $false; ifIndex = 12; LinkSpeed = '866 Mbps'; MacAddress = '02-00-00-00-00-01' }
    [pscustomobject]@{ Name = 'vEthernet (Default Switch)'; InterfaceDescription = 'Hyper-V Virtual Ethernet Adapter'; Status = 'Up'; Virtual = $true; ifIndex = 30; LinkSpeed = '10 Gbps'; MacAddress = '02-00-00-00-00-02' }
)
$global:mockRoutes = @([pscustomobject]@{ NextHop = '198.51.100.1'; InterfaceIndex = 12; InterfaceAlias = 'Wi-Fi'; RouteMetric = 25 })
'@
    $b2Good = $b2Base + "`n" + '$global:mockAddresses = @([pscustomobject]@{ IPAddress = ''198.51.100.23''; PrefixLength = 24; InterfaceIndex = 12; InterfaceAlias = ''Wi-Fi''; PrefixOrigin = ''Dhcp'' })'
    $r = Invoke-Mocked -Name 'b2-good' -Mocks $b2Good -Script 'endpoint-systems/diagnostics/networking/Get-NetworkConnectivityReport.ps1' -ScriptArgs @('-Passive')
    Assert-Finding 'B2 adapter (virtual left out)' $r 'Network adapter' 'PASS' '^Wi-Fi \(Mock Wireless 6E'
    Assert-Finding 'B2 address' $r 'IP address' 'PASS' '198\.51\.100\.23/24 on Wi-Fi \(Dhcp\)'
    Assert-Finding 'B2 gateway' $r 'Default gateway' 'INFO' '198\.51\.100\.1 via Wi-Fi'
    Assert-Finding 'B2 no proxy' $r 'Proxy' 'INFO' 'No proxy'
    Assert-Finding 'B2 passive: nothing sent' $r 'Connectivity tests' 'SKIPPED' 'nothing was sent'
    Assert-Finding 'B2 passive diagnosis' $r 'First failing layer' 'INFO' 'No configuration problem found'
    if ($r) { Assert-Equal 'B2 no ERROR findings' 0 @($r.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count }
    $b2Apipa = $b2Base + "`n" + '$global:mockAddresses = @([pscustomobject]@{ IPAddress = ''169.254.10.20''; PrefixLength = 16; InterfaceIndex = 12; InterfaceAlias = ''Wi-Fi''; PrefixOrigin = ''WellKnown'' })'
    $r = Invoke-Mocked -Name 'b2-apipa' -Mocks $b2Apipa -Script 'endpoint-systems/diagnostics/networking/Get-NetworkConnectivityReport.ps1' -ScriptArgs @('-Passive')
    Assert-Finding 'B2 self-assigned address' $r 'IP address' 'FAIL' 'self-assigned address \(169\.254\.10\.20\)'
    Assert-Finding 'B2 diagnosis names the address layer' $r 'First failing layer' 'FAIL' '^IP address: '
    Assert-Finding 'B2 gateway skipped after the address failed' $r 'Default gateway' 'SKIPPED'

    # --- B3 -------------------------------------------------------------------------------------
    $b3Mocks = @'
function New-MockEvent {
    param([string]$Log, [string]$Provider, [int]$Id, [int]$Level, [double]$HoursAgo, [string]$Message, [string[]]$Props = @())
    [pscustomobject]@{ LogName = $Log; ProviderName = $Provider; Id = $Id; Level = $Level; TimeCreated = (Get-Date).AddHours(-$HoursAgo); Message = $Message
        Properties = @($Props | ForEach-Object { [pscustomobject]@{ Value = $_ } }) }
}
function Get-WinEvent {
    [CmdletBinding()] param([hashtable]$FilterHashtable)
    if ($global:mockNoEvents) { throw (New-Object System.Exception('No events were found that match the specified selection criteria.')) }
    if ($FilterHashtable.LogName -eq 'System') {
        New-MockEvent System 'Microsoft-Windows-Kernel-Power' 41 1 5 'The system has rebooted without cleanly shutting down first.'
        New-MockEvent System 'Microsoft-Windows-WER-SystemErrorReporting' 1001 2 5 'The computer has rebooted from a bugcheck. The bugcheck was: 0x0000009f.'
        New-MockEvent System 'disk' 7 2 10 'The device, \Device\Harddisk0\DR0, has a bad block.'
        New-MockEvent System 'Service Control Manager' 7031 2 12 'The Print Spooler service terminated unexpectedly.' @('Print Spooler', '1')
        New-MockEvent System 'Microsoft-Windows-DistributedCOM' 10016 2 1 'The application-specific permission settings do not grant Local Activation permission.'
    }
    else {
        New-MockEvent Application 'Application Error' 1000 2 3 'Faulting application name: EXCEL.EXE' @('EXCEL.EXE', '16.0')
    }
}
'@
    $r = Invoke-Mocked -Name 'b3' -Mocks $b3Mocks -Script 'endpoint-systems/diagnostics/event-logs/Get-RecentCriticalErrors.ps1'
    Assert-Finding 'B3 blue screen' $r 'System crashes' 'FAIL' '^1 blue screen'
    Assert-Finding 'B3 unexpected shutdown' $r 'Unexpected shutdowns' 'WARN' '^1 unexpected shutdown'
    Assert-Finding 'B3 disk error' $r 'Disk errors' 'FAIL' 'disk 7: The device'
    Assert-Finding 'B3 service named' $r 'Service failures' 'WARN' 'services: Print Spooler'
    Assert-Finding 'B3 program named' $r 'Application crashes' 'WARN' 'EXCEL\.EXE x1'
    Assert-Finding 'B3 noise left out of the count' $r 'Error events' 'INFO' '^5 critical/error event\(s\) .*\(1 critical\).*noise left out'
    if ($r) {
        Assert-Equal 'B3 Events table rows' 5 @($r.Data.Events).Count
        Assert-Equal 'B3 no ERROR findings' 0 @($r.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count
    }
    $r = Invoke-Mocked -Name 'b3-none' -Mocks ($b3Mocks + "`n`$global:mockNoEvents = `$true") -Script 'endpoint-systems/diagnostics/event-logs/Get-RecentCriticalErrors.ps1' -ScriptArgs @('-Hours', '24')
    Assert-Finding 'B3 no events = PASS, not ERROR' $r 'System crashes' 'PASS' 'None in the last 24 hours'
    Assert-Finding 'B3 no events counted' $r 'Error events' 'INFO' '^0 critical/error'
    if ($r) { Assert-Equal 'B3 no events: no ERROR findings' 0 @($r.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed' -f $script:passed, $script:failed)
if ($script:failed -gt 0) { exit 1 }
exit 0
