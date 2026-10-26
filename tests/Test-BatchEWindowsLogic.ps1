<#
.SYNOPSIS
    Runs the Windows Batch E scripts (E1-E4) against mocked Windows cmdlets and checks their
    findings, so their logic is tested on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux). Same method as Test-BatchBWindowsLogic.ps1: a wrapper
    defines stand-in functions for the cmdlets the script (and its embedded helper) calls and
    runs the real script. Calls the stand-ins do not recognize go to the real cmdlet.

      E1  Built-in Administrator enabled, too many admins, an unused admin, an old password, an
          admin allowed an empty password, an orphaned SID, an Entra ID group, Windows LAPS.
      E2  Apps & Features from fake uninstall keys: Flash and Office 2016 (end of support),
          CCleaner (watchlist), a recent install, a hidden system component; a missing
          watchlist file (SKIPPED, not ERROR).
      E3  File History 3 days old (PASS), 40 days old (FAIL), nothing at all (WARN High), only
          Veeam Agent (WARN Medium, no date); OneDrive folder backup.
      E4  A domain controller with a full system drive, an 80-day-old update, a stopped DNS
          role service, a stopped automatic service (Google updater ignored), a restart pending,
          a critical event, a CMOS-clock time source and a certificate expiring in 10 days;
          then a healthy server.

    Administrator-only checks (E3 Windows Server Backup, System Restore) are asserted as
    SKIPPED when the test is not elevated.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-BatchEWindowsLogic.ps1

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
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-batche-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

function Invoke-Mocked {
    <# Runs SCRIPT (repo-relative) with MOCKS defined first; returns the JSON result (or $null). #>
    param([string]$Name, [string]$Mocks, [string]$Script, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $argText = ($ScriptArgs | ForEach-Object { if ($_ -like '-*') { $_ } else { "'{0}'" -f ($_ -replace "'", "''") } }) -join ' '
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "{0}`n& '{1}' -OutputPath '{2}' {3}`nexit `$LASTEXITCODE`n" -f $Mocks, ((Join-Path $repo $Script) -replace "'", "''"), ($out -replace "'", "''"), $argText
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 | Out-String
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    if ($json.Count -eq 0) { Assert-True ('{0}: JSON written' -f $Name) $false $console; return $null }
    return (Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json)
}
function Assert-Finding {
    param($Result, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '')
    if (-not $Result) { Assert-True $Label $false 'no result'; return }
    $f = @($Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern)
    $got = 'missing'
    if ($f) { $got = '[{0}] {1}' -f $f.Status, $f.Detail }
    Assert-True $Label $ok $got
}
function Assert-NoError {
    param($Result, [string]$Label)
    if (-not $Result) { return }
    $errors = @($Result.Findings | Where-Object { $_.Status -eq 'ERROR' })
    Assert-True $Label ($errors.Count -eq 0) ((@($errors | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
}

# Registry stand-ins shared by every scenario: $global:FakeReg maps a key path to its values;
# $global:FakeSoftware lists Apps & Features entries (uninstall keys).
$common = @'
$global:FakeReg = @{}
$global:FakeSoftware = @()
function Test-Path {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$PathType)
    $p = $LiteralPath
    if (-not $p) { $p = $Path }
    if ($p -like 'HK*:\*Uninstall') { return ($global:FakeSoftware.Count -gt 0) }
    if ($p -like 'HK*:\*') { return $global:FakeReg.ContainsKey($p) }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-ChildItem {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Filter, [switch]$File, [switch]$Force, [switch]$Recurse)
    $p = $LiteralPath
    if (-not $p) { $p = $Path }
    if ($p -like 'HK*:\*Uninstall') {
        $scope = 'HKLM64'
        if ($p -like 'HKCU:*') { $scope = 'HKCU' } elseif ($p -like '*WOW6432Node*') { $scope = 'HKLM32' }
        $i = 0
        foreach ($s in $global:FakeSoftware) { $i++; if ($s.Hive -eq $scope) { [pscustomobject]@{ PSPath = ('FAKE:{0}' -f $i) } } }
        return
    }
    if ($p -eq 'Cert:\LocalMachine\My') { return $global:FakeCerts }
    Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
}
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Name)
    $p = $LiteralPath
    if (-not $p) { $p = $Path }
    if ($p -like 'FAKE:*') { return $global:FakeSoftware[[int]$p.Substring(5) - 1] }
    if ($global:FakeReg.ContainsKey($p)) { return $global:FakeReg[$p] }
    if ($p -like 'HK*:\*') { return $null }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
function New-FakeApp {
    param([string]$Name, [string]$Version, [string]$Hive = 'HKLM64', [string]$Date = '20250101', [int]$System = 0)
    [pscustomobject]@{ DisplayName = $Name; DisplayVersion = $Version; Publisher = 'Test'; InstallDate = $Date; SystemComponent = $System; Hive = $Hive }
}
'@

# =========================================================================================
# E1 Get-LocalAdminReport.ps1
# =========================================================================================
$e1 = @'
$global:FakeReg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'] = [pscustomobject]@{ BackupDirectory = 1 }
$global:Users = @{
    'S-1-5-21-1-2-3-500'  = [pscustomobject]@{ Name = 'Administrator'; SID = 'S-1-5-21-1-2-3-500'; Enabled = $true; LastLogon = (Get-Date).AddDays(-2); PasswordLastSet = (Get-Date).AddDays(-30); PasswordRequired = $true }
    'S-1-5-21-1-2-3-1001' = [pscustomobject]@{ Name = 'alice'; SID = 'S-1-5-21-1-2-3-1001'; Enabled = $true; LastLogon = (Get-Date).AddDays(-5); PasswordLastSet = (Get-Date).AddDays(-400); PasswordRequired = $true }
    'S-1-5-21-1-2-3-1002' = [pscustomobject]@{ Name = 'olduser'; SID = 'S-1-5-21-1-2-3-1002'; Enabled = $true; LastLogon = (Get-Date).AddDays(-200); PasswordLastSet = (Get-Date).AddDays(-200); PasswordRequired = $false }
    'S-1-5-21-1-2-3-1003' = [pscustomobject]@{ Name = 'bob'; SID = 'S-1-5-21-1-2-3-1003'; Enabled = $false; LastLogon = $null; PasswordLastSet = $null; PasswordRequired = $true }
}
function Get-LocalGroupMember {
    [CmdletBinding()] param([string]$SID)
    @(
        [pscustomobject]@{ Name = 'PC1\Administrator'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-500' },
        [pscustomobject]@{ Name = 'PC1\alice'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-1001' },
        [pscustomobject]@{ Name = 'PC1\olduser'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-1002' },
        [pscustomobject]@{ Name = 'PC1\bob'; ObjectClass = 'User'; PrincipalSource = 'Local'; SID = 'S-1-5-21-1-2-3-1003' },
        [pscustomobject]@{ Name = 'AzureAD\Device Administrators'; ObjectClass = 'Group'; PrincipalSource = 'AzureAD'; SID = 'S-1-12-1-111-222-333-444' },
        [pscustomobject]@{ Name = 'S-1-5-21-9-8-7-1105'; ObjectClass = 'User'; PrincipalSource = 'Unknown'; SID = 'S-1-5-21-9-8-7-1105' }
    )
}
function Get-LocalUser {
    [CmdletBinding()] param([string]$SID)
    if ($SID) { return $global:Users[$SID] }
    return @($global:Users.Values)
}
'@
$r = Invoke-Mocked 'e1' ($common + $e1) 'endpoint-systems/audit/local-admins/Get-LocalAdminReport.ps1'
Assert-True 'E1: CheckId' ($r -and $r.CheckId -eq 'E1')
Assert-Finding $r 'E1: members listed, bob disabled' 'Administrators' 'INFO' 'PC1\\bob \(Local user, disabled\)'
Assert-Finding $r 'E1: too many admins' 'Number of administrators' 'WARN' '^3 enabled administrator'
Assert-Finding $r 'E1: built-in Administrator enabled' 'Built-in Administrator account' 'WARN' 'PC1\\Administrator" is enabled'
Assert-Finding $r 'E1: unused admin' 'Unused administrator accounts' 'WARN' 'olduser'
Assert-True 'E1: active admins not unused' ([string](@($r.Findings | Where-Object { $_.Check -eq 'Unused administrator accounts' })[0].Detail) -notmatch 'alice|Administrator')
Assert-Finding $r 'E1: old password' 'Administrator password age' 'WARN' 'alice'
Assert-Finding $r 'E1: empty password allowed' 'Administrators without a password' 'WARN' 'olduser'
Assert-Finding $r 'E1: orphaned SID' 'Orphaned administrator entries' 'WARN' 'S-1-5-21-9-8-7-1105'
Assert-Finding $r 'E1: Entra ID group listed' 'Domain and cloud administrators' 'INFO' 'Device Administrators \(AzureAD group\)'
Assert-Finding $r 'E1: Windows LAPS' 'Local admin password management' 'PASS' 'Windows LAPS \(backup to Entra ID\)'
Assert-True 'E1: Admins table' ($r -and @($r.Data.Admins).Count -eq 6)
Assert-NoError $r 'E1: no ERROR findings'

# =========================================================================================
# E2 Get-InstalledSoftwareReport.ps1
# =========================================================================================
$e2 = @'
$today = (Get-Date).ToString('yyyyMMdd')
$global:FakeSoftware = @(
    (New-FakeApp 'Adobe Flash Player 32 NPAPI' '32.0.0.465'),
    (New-FakeApp 'Microsoft Office Professional Plus 2016' '16.0.4266.1001' 'HKLM32'),
    (New-FakeApp 'CCleaner' '6.20'),
    (New-FakeApp 'Google Chrome' '130.0.6723.92'),
    (New-FakeApp 'Notepad++ (64-bit x64)' '8.7' 'HKLM64' $today),
    (New-FakeApp 'Zoom Workplace' '6.2' 'HKCU'),
    (New-FakeApp 'Hidden Runtime' '1.0' 'HKLM64' '20250101' 1)
)
'@
$r = Invoke-Mocked 'e2' ($common + $e2) 'endpoint-systems/audit/software-inventory/Get-InstalledSoftwareReport.ps1'
Assert-Finding $r 'E2: watchlist loaded, unverified dates counted' 'Watchlist file' 'INFO' 'Windows entr\(ies\).*not yet confirmed'
Assert-Finding $r 'E2: six programs (system component hidden)' 'Installed software' 'INFO' '^6 program'
Assert-Finding $r 'E2: Flash and Office 2016 end of support' 'End-of-support software' 'WARN' 'Adobe Flash Player 32 NPAPI .*no support since 2020-12-31, date unverified.*Office Professional Plus 2016'
Assert-True 'E2: Chrome not end of support' ([string](@($r.Findings | Where-Object { $_.Check -eq 'End-of-support software' })[0].Detail) -notmatch 'Chrome')
Assert-Finding $r 'E2: CCleaner on the watchlist' 'Watchlist software' 'WARN' '^CCleaner 6\.20: '
Assert-Finding $r 'E2: recent install' 'Recently installed software' 'INFO' '^1 in the last 30 day\(s\): Notepad\+\+'
Assert-True 'E2: Flagged table' ($r -and @($r.Data.Flagged).Count -eq 3)
Assert-NoError $r 'E2: no ERROR findings'

$r = Invoke-Mocked 'e2-nowatch' ($common + $e2) 'endpoint-systems/audit/software-inventory/Get-InstalledSoftwareReport.ps1' @('-WatchlistPath', (Join-Path $work 'missing.txt'))
Assert-Finding $r 'E2 no watchlist: SKIPPED' 'Watchlist file' 'SKIPPED' 'was not found'
Assert-Finding $r 'E2 no watchlist: end-of-support SKIPPED' 'End-of-support software' 'SKIPPED'
Assert-Finding $r 'E2 no watchlist: inventory still listed' 'Installed software' 'INFO' '^6 program'
Assert-NoError $r 'E2 no watchlist: no ERROR findings'

# =========================================================================================
# E3 Get-BackupRecency.ps1
# =========================================================================================
function Get-E3Scene {
    param([int]$FileHistoryDays, [switch]$Veeam, [switch]$OneDrive)
    $text = ''
    if ($FileHistoryDays -ge 0) { $text += "`$global:FakeReg['HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory'] = [pscustomobject]@{ ProtectedUpToTime = (Get-Date).AddDays(-$FileHistoryDays).ToFileTime() }`n" }
    if ($OneDrive) { $text += "`$global:FakeReg['HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'] = [pscustomobject]@{ Desktop = 'C:\Users\bob\OneDrive - Contoso\Desktop'; Personal = 'C:\Users\bob\OneDrive - Contoso\Documents'; 'My Pictures' = 'C:\Users\bob\Pictures' }`n" }
    if ($Veeam) { $text += "`$global:FakeSoftware = @((New-FakeApp 'Veeam Agent for Microsoft Windows' '6.2.0.121'))`n" }
    return $text
}
$e3 = 'core-infrastructure/backups-dr/diagnostics/Get-BackupRecency.ps1'
$r = Invoke-Mocked 'e3-recent' ($common + (Get-E3Scene -FileHistoryDays 3 -OneDrive)) $e3
Assert-Finding $r 'E3: File History date read' 'File History' 'INFO' 'files protected up to .*\(3 day\(s\) ago\)'
Assert-Finding $r 'E3: OneDrive folders' 'OneDrive folder backup' 'INFO' '^Desktop, Documents are kept in OneDrive'
Assert-Finding $r 'E3: 3-day-old backup PASS' 'Backup recency' 'PASS' 'Newest backup: File History.*Also present \(no date read\): OneDrive folder backup'
if ($r -and -not $r.IsAdmin) {
    Assert-Finding $r 'E3 (not admin): Windows Server Backup SKIPPED' 'Windows Server Backup' 'SKIPPED' 'administrator'
    Assert-Finding $r 'E3 (not admin): System Restore SKIPPED' 'System Restore' 'SKIPPED' 'administrator'
}
Assert-NoError $r 'E3 recent: no ERROR findings'

$r = Invoke-Mocked 'e3-old' ($common + (Get-E3Scene -FileHistoryDays 40)) $e3
Assert-Finding $r 'E3: 40-day-old backup FAIL' 'Backup recency' 'FAIL' '40 day\(s\) ago'
$r = Invoke-Mocked 'e3-none' ($common + (Get-E3Scene -FileHistoryDays -1)) $e3
Assert-Finding $r 'E3: no backup WARN High' 'Backup recency' 'WARN' '^No backup this script knows about'
Assert-True 'E3: no backup is High' ($r -and @($r.Findings | Where-Object { $_.Check -eq 'Backup recency' -and $_.Severity -eq 'High' }).Count -eq 1)
$r = Invoke-Mocked 'e3-veeam' ($common + (Get-E3Scene -FileHistoryDays -1 -Veeam)) $e3
Assert-Finding $r 'E3: Veeam detected' 'Other backup software' 'INFO' 'Veeam Agent \(Veeam Agent for Microsoft Windows 6\.2\.0\.121\)'
Assert-Finding $r 'E3: only an undated product = WARN Medium' 'Backup recency' 'WARN' '^No backup date could be read here\. Present: Veeam Agent'
Assert-NoError $r 'E3 veeam: no ERROR findings'

# =========================================================================================
# E4 Get-ServerHealthReport.ps1
# =========================================================================================
$e4mocks = @'
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Filter)
    switch ($ClassName) {
        'Win32_OperatingSystem' { return $global:Os }
        'Win32_ComputerSystem' { return [pscustomobject]@{ DomainRole = $global:Role; PartOfDomain = $true; Domain = 'contoso.local' } }
        'Win32_LogicalDisk' { return $global:Disks }
        'Win32_Service' {
            if ($Filter -match "Name='([^']+)'") { $n = $Matches[1]; return @($global:Services | Where-Object { $_.Name -eq $n }) }
            return @($global:Services | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
        }
    }
    CimCmdlets\Get-CimInstance @PSBoundParameters
}
function Get-HotFix { [CmdletBinding()] param() return $global:HotFixes }
function Get-WindowsFeature { [CmdletBinding()] param() return $global:Features }
function Get-WinEvent {
    [CmdletBinding()] param([hashtable]$FilterHashtable)
    if ($global:Events.Count -eq 0) { throw 'No events were found that match the specified selection criteria.' }
    return $global:Events
}
function w32tm.exe { $global:LASTEXITCODE = 0; return $global:W32tm }
'@
$e4bad = @'
$global:FakeReg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'] = [pscustomobject]@{}
$global:Os = [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Standard'; BuildNumber = '20348'; ProductType = 2; LastBootUpTime = (Get-Date).AddDays(-90); TotalVisibleMemorySize = 16777216; FreePhysicalMemory = 8388608 }
$global:Role = 5
$global:Disks = @([pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; Size = 107374182400; FreeSpace = 3221225472 }, [pscustomobject]@{ DeviceID = 'D:'; VolumeName = 'Data'; Size = 1099511627776; FreeSpace = 549755813888 })
$global:Services = @(
    [pscustomobject]@{ Name = 'NTDS'; DisplayName = 'Active Directory Domain Services'; StartMode = 'Auto'; State = 'Running'; ExitCode = 0 },
    [pscustomobject]@{ Name = 'Netlogon'; DisplayName = 'Netlogon'; StartMode = 'Auto'; State = 'Running'; ExitCode = 0 },
    [pscustomobject]@{ Name = 'DNS'; DisplayName = 'DNS Server'; StartMode = 'Auto'; State = 'Stopped'; ExitCode = 1067 },
    [pscustomobject]@{ Name = 'VeeamBackupSvc'; DisplayName = 'Veeam Backup Service'; StartMode = 'Auto'; State = 'Stopped'; ExitCode = 1 },
    [pscustomobject]@{ Name = 'gupdate'; DisplayName = 'Google Update Service'; StartMode = 'Auto'; State = 'Stopped'; ExitCode = 0 }
)
$global:HotFixes = @([pscustomobject]@{ HotFixID = 'KB5040437'; InstalledOn = (Get-Date).AddDays(-80) })
$global:Features = @(
    [pscustomobject]@{ Name = 'AD-Domain-Services'; DisplayName = 'Active Directory Domain Services'; Installed = $true; FeatureType = 'Role' },
    [pscustomobject]@{ Name = 'DNS'; DisplayName = 'DNS Server'; Installed = $true; FeatureType = 'Role' },
    [pscustomobject]@{ Name = 'Web-Server'; DisplayName = 'Web Server (IIS)'; Installed = $false; FeatureType = 'Role' }
)
$global:Events = @([pscustomobject]@{ Level = 1; ProviderName = 'Microsoft-Windows-Kernel-Power' }, [pscustomobject]@{ Level = 2; ProviderName = 'Service Control Manager' }, [pscustomobject]@{ Level = 2; ProviderName = 'Service Control Manager' })
$global:W32tm = @('Leap Indicator: 3(not synchronized)', 'Stratum: 0 (unspecified)', 'Last Successful Sync Time: unspecified', 'Source: Local CMOS Clock')
$global:FakeCerts = @([pscustomobject]@{ Subject = 'CN=dc1.contoso.local'; NotAfter = (Get-Date).AddDays(10); Thumbprint = 'AA' }, [pscustomobject]@{ Subject = 'CN=old'; NotAfter = (Get-Date).AddDays(-100); Thumbprint = 'BB' })
'@
$e4good = @'
$global:Os = [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Standard'; BuildNumber = '20348'; ProductType = 3; LastBootUpTime = (Get-Date).AddDays(-10); TotalVisibleMemorySize = 16777216; FreePhysicalMemory = 8388608 }
$global:Role = 3
$global:Disks = @([pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; Size = 107374182400; FreeSpace = 53687091200 })
$global:Services = @([pscustomobject]@{ Name = 'LanmanServer'; DisplayName = 'Server'; StartMode = 'Auto'; State = 'Running'; ExitCode = 0 })
$global:HotFixes = @([pscustomobject]@{ HotFixID = 'KB5044281'; InstalledOn = (Get-Date).AddDays(-12) })
$global:Features = @([pscustomobject]@{ Name = 'FS-FileServer'; DisplayName = 'File Server'; Installed = $true; FeatureType = 'Role Service' }, [pscustomobject]@{ Name = 'FileAndStorage-Services'; DisplayName = 'File and Storage Services'; Installed = $true; FeatureType = 'Role' })
$global:Events = @()
$global:W32tm = @('Leap Indicator: 0(no warning)', ('Last Successful Sync Time: {0}' -f (Get-Date).AddHours(-3).ToString('M/d/yyyy h:mm:ss tt', [Globalization.CultureInfo]::InvariantCulture)), 'Source: dc1.contoso.local')
$global:FakeCerts = @([pscustomobject]@{ Subject = 'CN=fs1.contoso.local'; NotAfter = (Get-Date).AddDays(300); Thumbprint = 'CC' })
'@
$e4 = 'core-infrastructure/servers/windows/diagnostics/Get-ServerHealthReport.ps1'
$r = Invoke-Mocked 'e4-bad' ($common + $e4mocks + $e4bad) $e4
Assert-Finding $r 'E4: domain controller recognized' 'Server' 'INFO' 'primary domain controller of contoso\.local'
Assert-Finding $r 'E4: 90-day uptime' 'Uptime' 'WARN' 'Up 90 day'
Assert-Finding $r 'E4: restart pending' 'Restart pending' 'WARN' 'Windows Update'
Assert-Finding $r 'E4: 80-day-old update FAIL' 'Last update installed' 'FAIL' 'KB5040437 .*80 days ago'
Assert-Finding $r 'E4: full system drive FAIL' 'System drive space' 'FAIL' 'C: 3 GB free of 100 GB'
Assert-Finding $r 'E4: data drive fine' 'Disk space D:' 'PASS'
Assert-Finding $r 'E4: memory fine' 'Memory' 'PASS' '50 %'
Assert-Finding $r 'E4: stopped service, updater ignored' 'Stopped automatic services' 'WARN' 'Veeam Backup Service'
Assert-True 'E4: Google updater not flagged' ([string](@($r.Findings | Where-Object { $_.Check -eq 'Stopped automatic services' })[0].Detail) -notmatch 'gupdate')
Assert-Finding $r 'E4: DNS role service down' 'Server roles' 'FAIL' 'DNS: DNS is Stopped'
Assert-Finding $r 'E4: critical event' 'Critical events' 'WARN' '^1 critical and 2 error'
Assert-Finding $r 'E4: CMOS clock on a DC' 'Time synchronization' 'WARN' 'Local CMOS Clock'
Assert-True 'E4: time problem on a DC is High' ($r -and @($r.Findings | Where-Object { $_.Check -eq 'Time synchronization' -and $_.Severity -eq 'High' }).Count -eq 1)
Assert-Finding $r 'E4: certificate expiring' 'Certificates' 'WARN' 'CN=dc1\.contoso\.local.*1 expired certificate'
Assert-NoError $r 'E4 bad: no ERROR findings'

$r = Invoke-Mocked 'e4-good' ($common + $e4mocks + $e4good) $e4
foreach ($c in 'Uptime', 'Restart pending', 'Last update installed', 'System drive space', 'Memory', 'Stopped automatic services', 'Server roles', 'Critical events', 'Time synchronization', 'Certificates') {
    Assert-Finding $r ('E4 good: {0} PASS' -f $c) $c 'PASS'
}
Assert-NoError $r 'E4 good: no ERROR findings'

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
