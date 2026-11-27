<#
.SYNOPSIS
    Read-only disk space report for this PC: free space on every fixed volume, where the space
    went, how much is known to be reclaimable, disk health, and the cleanup steps to take by hand.

.DESCRIPTION
    Measures only; deletes nothing. The "What to do" section lists the cleanup steps, biggest
    first, for the technician to do by hand.

    Checks
      Disk space          Every fixed volume: size, free, percent free. Less than 5 % or 5 GB free
                          = FAIL, less than 15 % or 20 GB = WARN. Volumes under 50 GB (EFI,
                          recovery) are judged on the percentage only.
      Largest folders     The biggest folders one and two levels under the user profile and the
                          system drive. The walk stops at -ScanSeconds (default 60), so it
                          never hangs on a huge disk; folders it could not finish are marked
                          "at least". Junctions and symbolic links are not followed.
      Reclaimable space   Measured, never deleted: your and Windows' temporary files, the Windows
                          Update cache (clean it with D1 Clear-WindowsUpdateCache.ps1), the Recycle
                          Bin, a previous Windows installation (Windows.old), the Delivery
                          Optimization cache, crash dumps and error reports. Folders only
                          administrators may read are measured as far as allowed.
      Disk health         Get-PhysicalDisk health and operational status (built in, no extra
                          tools); the Windows reliability index; disk and file system errors in
                          the System log (last 7 days).
      What to do          Cleanup steps by hand, biggest first.

.PARAMETER ScanSeconds
    How long the folder scan may take in total (10-600 seconds, default 60): half for the user
    profile, the rest for the system drive. Give it more on a big disk; folders it could not
    finish are marked "at least" and the result names this setting. Each reclaimable item has its
    own share of up to 20 seconds. -TimeLimitSeconds (the earlier name) still works.

.PARAMETER TopFolders
    How many of the largest folders to list for each place (5-50, default 10).

.PARAMETER Rmm
    RMM mode, for RMM agents such as Kaseya: no colours or prompts, the JSON result always saved
    to %ProgramData%\MSP-Toolkit\results (macOS/Linux: /var/tmp/msp-toolkit/results; the newest
    10 per script are kept), a one-line summary on stdout and an exit code to alert on: 0 OK,
    1 WARN, 2 FAIL, 3 ERROR or not run. See the README, "Running from an RMM".

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with Volumes, LargestFolders,
    Reclaimable and NextSteps tables. Folder names can include user names: keep them with the ticket.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-DiskSpaceReport.ps1

.EXAMPLE
    .\Get-DiskSpaceReport.ps1 -ScanSeconds 300 -OutputPath C:\Temp\Ticket123

.NOTES
    Purpose       : "Where did the disk space go, and what can safely be cleaned?"
    Use Case      : Low disk space warnings, updates failing for lack of space, slow PCs.
    Scope         : This PC only. No network traffic.
    Risk Level    : Read-Only -- reads volume information, folder sizes and logs; deletes nothing.
    Prerequisites : Windows 10/11 or Server 2016+ | Windows PowerShell 5.1 or PowerShell 7 |
                    Admin: No (administrator measures Windows' own temp, Delivery Optimization and
                    error-report folders completely, and other users' Recycle Bins)
    Version       : 1.2.1
    Limitations   : Folder sizes count file sizes (not space on disk: compressed and sparse files
                    and hard links are counted at their full size). OneDrive files that are online
                    only count as their full size too. A folder walk stopped by the time limit is
                    a minimum.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Alias('TimeLimitSeconds')][int]$ScanSeconds = 60,
    [int]$TopFolders = 10,
    [switch]$Rmm,
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core | SHA256: db95eb05d22ede36a7c9150140b0a23629db22f4386e772dcd482d9c7bd0f79b
#region MSPHelper:Core
# --- Run state ---------------------------------------------------------------------------
# One toolkit script = one "run": one log file, one findings list, one optional export.
$script:MSPRun = $null
$script:MSPSchemaVersion = '2.0'
$script:MSPStatusOrder = @('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR')
$script:MSPSeverityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

function Get-MSPPlatform {
    <# 'Windows', 'macOS' or 'Linux'. Windows PowerShell 5.1 has no $IsWindows; its edition is 'Desktop'. #>
    if ($PSVersionTable.PSEdition -ne 'Core') { return 'Windows' }
    if (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) { return 'Windows' }
    if (Get-Variable -Name IsMacOS -ValueOnly -ErrorAction SilentlyContinue) { return 'macOS' }
    return 'Linux'
}

function Get-MSPOSVersion {
    <# Short OS description, matching what the bash helper reports ("macOS 15.1", PRETTY_NAME on Linux). #>
    param([string]$Platform = (Get-MSPPlatform))
    try {
        if ($Platform -eq 'Windows') {
            $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $build = [int]$cv.CurrentBuildNumber
            # ProductName still says "Windows 10" on Windows 11; the build number decides.
            $name = [string]$cv.ProductName
            if ($build -ge 22000) { $name = $name -replace 'Windows 10', 'Windows 11' }
            $release = [string]$cv.DisplayVersion
            if (-not $release) { $release = [string]$cv.ReleaseId }
            return (('{0} {1} (build {2}.{3})' -f $name, $release, $build, $cv.UBR) -replace '\s+', ' ')
        }
        if ($Platform -eq 'macOS') {
            return ('macOS {0}' -f ([string](& sw_vers -productVersion 2>$null)).Trim())
        }
        $line = Get-Content -LiteralPath '/etc/os-release' -ErrorAction Stop | Where-Object { $_ -like 'PRETTY_NAME=*' } | Select-Object -First 1
        if ($line) { return ($line -replace '^PRETTY_NAME=', '').Trim('"') }
    }
    catch {
        Write-Verbose ('OS version lookup failed: {0}' -f $_.Exception.Message)
    }
    return $Platform
}

function Get-MSPLogFolder {
    <#
        The folder this run's log is in (Initialize-MSPLogFolder chose it). Before a run has one:
        Windows %TEMP%\MSP-Toolkit, macOS/Linux ${TMPDIR:-/tmp}/msp-toolkit (same folder the bash
        scripts use).
    #>
    if ($script:MSPRun -and $script:MSPRun.LogFolder) { return $script:MSPRun.LogFolder }
    if ((Get-MSPPlatform) -eq 'Windows') { return (Join-Path -Path $env:TEMP -ChildPath 'MSP-Toolkit') }
    $base = $env:TMPDIR
    if (-not $base) { $base = '/tmp' }
    return (Join-Path -Path $base -ChildPath 'msp-toolkit')
}

function Test-MSPTestForeignOwner {
    <#
        Development tests only: MSP_TEST_FOREIGN_OWNER lists folders ('|' between them) to treat as
        owned by another account, because a test cannot create a folder that someone else owns. It
        can only make a folder be refused, never accepted.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not $env:MSP_TEST_FOREIGN_OWNER) { return $false }
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    foreach ($p in ($env:MSP_TEST_FOREIGN_OWNER -split '\|')) {
        if ($p -and [System.IO.Path]::GetFullPath($p).TrimEnd('\', '/') -eq $full) { return $true }
    }
    return $false
}

function Test-MSPOwnedFolder {
    <#
        True when PATH is a real folder (not a link, junction or other reparse point) owned by the
        running account (Windows: or by Administrators or SYSTEM). A folder that another account
        created in advance in a shared place (C:\Windows\Temp, %ProgramData%, /tmp, /var/tmp)
        fails, so the toolkit never writes logs or results into it.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $false }
    if (Test-MSPTestForeignOwner -Path $Path) { return $false }
    if ((Get-MSPPlatform) -ne 'Windows') {
        & /bin/sh -c 'test -d "$1" && test ! -L "$1" && test -O "$1"' sh $Path
        return ($LASTEXITCODE -eq 0)
    }
    try { $owner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $false }
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return ($owner -in @('S-1-5-32-544', 'S-1-5-18', $me))
}

function Protect-MSPPrivateFolder {
    <#
        Windows: access only for Administrators, SYSTEM and the running account, inheritance off
        (as SYSTEM, owner Administrators). macOS/Linux: mode 700. Throws if it cannot.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if ((Get-MSPPlatform) -ne 'Windows') {
        & chmod 700 $Path
        if ($LASTEXITCODE -ne 0) { throw ('Could not restrict {0}.' -f $Path) }
        return
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $sids = @('S-1-5-32-544', 'S-1-5-18')
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($sids -notcontains $me) { $sids += $me }
    foreach ($sid in $sids) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    # Owner Administrators, so an account that created the folder in advance cannot change it back.
    if ($sids.Count -eq 2) { $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))) }
    Set-Acl -LiteralPath $Path -AclObject $acl -WhatIf:$false
}

function Add-MSPPrivateFolder {
    <# Creates PATH (fails if anything is already there): mode 700 on macOS/Linux; restricted by Protect-MSPPrivateFolder. #>
    param([Parameter(Mandatory)][string]$Path)
    if ((Get-MSPPlatform) -eq 'Windows') { $null = New-Item -ItemType Directory -Path $Path -ErrorAction Stop -WhatIf:$false }
    else { & /bin/sh -c 'umask 077 && mkdir "$1"' sh $Path 2>$null; if ($LASTEXITCODE -ne 0) { throw ('Could not create {0}.' -f $Path) } }
}

function Initialize-MSPLogFolder {
    <#
        Returns a private folder for the run's log, or $null if there is none. The standard folder
        (Get-MSPLogFolder) is created if missing and used only if Test-MSPOwnedFolder accepts it,
        then restricted (Protect-MSPPrivateFolder). If it is a link, a junction or a folder another
        account created in advance, a new folder with a random name is made next to it
        (MSP-Toolkit-<random> / msp-toolkit.XXXXXX) and restricted the same way. If that fails
        too, $null: the run has no log file and the console output is still complete.
    #>
    $preferred = Get-MSPLogFolder
    try {
        if (-not (Get-Item -LiteralPath $preferred -Force -ErrorAction SilentlyContinue)) { Add-MSPPrivateFolder -Path $preferred }
        if (Test-MSPOwnedFolder -Path $preferred) {
            Protect-MSPPrivateFolder -Path $preferred
            return $preferred
        }
    }
    catch { Write-Verbose ('Log folder {0} not used: {1}' -f $preferred, $_.Exception.Message) }
    try {
        $parent = Split-Path -Path $preferred -Parent
        if ((Get-MSPPlatform) -eq 'Windows') {
            $dir = Join-Path -Path $parent -ChildPath ('MSP-Toolkit-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12))
            Add-MSPPrivateFolder -Path $dir
        }
        else {
            $dir = [string](& /bin/sh -c 'umask 077 && mktemp -d "$1/msp-toolkit.XXXXXX"' sh $parent 2>$null)
            if ($LASTEXITCODE -ne 0 -or -not $dir) { return $null }
        }
        if (-not (Test-MSPOwnedFolder -Path $dir)) { return $null }
        Protect-MSPPrivateFolder -Path $dir
        return $dir
    }
    catch {
        Write-Verbose ('No private log folder: {0}' -f $_.Exception.Message)
        return $null
    }
}

function Add-MSPLogFile {
    <#
        Creates PATH as a new, empty log file. Fails if anything is already there (a file, a link
        or a hard link planted at the expected name), so the log is never written through it.
        Mode 600 on macOS/Linux.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $fs.Dispose()
    if ((Get-MSPPlatform) -ne 'Windows') {
        & chmod 600 $Path
        if ($LASTEXITCODE -ne 0) { throw ('Could not restrict {0}.' -f $Path) }
    }
}

function Test-MSPIsAdmin {
    <# True when elevated: "Run as administrator" on Windows, root (sudo) on macOS/Linux. #>
    if ($env:MSP_TEST_SERVICE_ACCOUNT -eq '1') { return $true }
    try {
        if ((Get-MSPPlatform) -ne 'Windows') { return ([string](& id -u) -eq '0') }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        # If the OS cannot tell us, assume not elevated: admin-only checks are SKIPPED, nothing breaks.
        return $false
    }
}

function Test-MSPServiceAccount {
    <#
        True when running the way RMM agents run scripts: as SYSTEM (or LocalService /
        NetworkService) on Windows, or as root with no signed-in technician (no SUDO_USER) on
        macOS/Linux. Such an account has no user profile of its own, so per-user checks must cover
        every user profile or say SKIPPED. MSP_TEST_SERVICE_ACCOUNT=1 (development tests only)
        simulates it.
    #>
    if ($env:MSP_TEST_SERVICE_ACCOUNT -eq '1') { return $true }
    try {
        if ((Get-MSPPlatform) -ne 'Windows') { return ([string](& id -u) -eq '0' -and -not $env:SUDO_USER) }
        return ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20'))
    }
    catch { return $false }
}

function Test-MSPRmmMode {
    <# True in RMM mode (-Rmm, or MSP_TOOLKIT_RMM=1 in the environment). #>
    return [bool]($script:MSPRun -and $script:MSPRun.Rmm)
}

function Get-MSPResultFolder {
    <#
        Where RMM mode saves results: %ProgramData%\MSP-Toolkit\results on Windows,
        /var/tmp/msp-toolkit/results on macOS/Linux. MSP_TEST_RESULTS_ROOT (development tests
        only) moves it.
    #>
    if ($env:MSP_TEST_RESULTS_ROOT) { return (Join-Path -Path $env:MSP_TEST_RESULTS_ROOT -ChildPath 'results') }
    if ((Get-MSPPlatform) -eq 'Windows') { return (Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath 'MSP-Toolkit') -ChildPath 'results') }
    return '/var/tmp/msp-toolkit/results'
}

function Protect-MSPResultFolder {
    <#
        Results hold device and user details: Windows - access for only Administrators and SYSTEM
        (plus the running account when it is neither, so it can keep writing its own results),
        inheritance off, owner Administrators when run as SYSTEM; macOS/Linux - mode 700 (the
        running account, normally root). Throws, without changing anything, if the folder is a
        link or belongs to another account (Windows: an owner other than Administrators, SYSTEM or
        the running account), so a folder planted by someone else in advance is never used or
        taken over.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw ('{0} is a link or not a folder; it was not used.' -f $Path)
    }
    if (-not (Test-MSPOwnedFolder -Path $Path)) { throw ('{0} belongs to another account; it was not used.' -f $Path) }
    Protect-MSPPrivateFolder -Path $Path
}

function Initialize-MSPResultFolder {
    <#
        Creates the RMM results folder and its parent (MSP-Toolkit / msp-toolkit) as needed and
        restricts both (Protect-MSPResultFolder). Returns the results folder; throws if either
        folder cannot be used safely.
    #>
    $folder = Get-MSPResultFolder
    $parent = Split-Path -Path $folder -Parent
    foreach ($f in @($parent, $folder)) {
        if (-not (Test-Path -LiteralPath $f)) {
            if ((Get-MSPPlatform) -eq 'Windows') { $null = New-Item -ItemType Directory -Path $f -ErrorAction Stop -WhatIf:$false }
            else { & /bin/sh -c 'umask 077 && mkdir "$1"' sh $f; if ($LASTEXITCODE -ne 0) { throw ('Could not create {0}.' -f $f) } }
        }
        Protect-MSPResultFolder -Path $f
    }
    return $folder
}

function Limit-MSPResultHistory {
    <# Keeps the newest KEEP results of SCRIPT in FOLDER (RMM mode) and deletes the older ones. #>
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$ScriptName, [int]$Keep = 10)
    $files = @(Get-ChildItem -LiteralPath $Folder -Filter ('{0}_*.json' -f $ScriptName) -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime, Name -Descending)
    foreach ($f in @($files | Select-Object -Skip $Keep)) {
        Remove-Item -LiteralPath $f.FullName -Force -WhatIf:$false
        Write-MSPLog -Message ('Removed old result {0} (keeping the newest {1})' -f $f.Name, $Keep)
    }
}

function Get-MSPUserProfile {
    <#
        Windows: the real user profiles on this PC (no system or service profiles), with the folder
        and whether the user's registry is loaded (signed in). Used by per-user checks when running
        as SYSTEM, which has no profile of its own.
    #>
    $out = foreach ($p in @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special = FALSE' -ErrorAction Stop)) {
        if (-not $p.LocalPath) { continue }
        $name = Split-Path -Path $p.LocalPath -Leaf
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { $name = Split-Path -Path $p.LocalPath -Leaf }
        [pscustomobject]@{ User = $name; Path = [string]$p.LocalPath; Sid = [string]$p.SID; Loaded = [bool]$p.Loaded }
    }
    return @($out)
}

function Get-MSPAdminTerm {
    <# The word technicians see for elevation on this platform. #>
    if ((Get-MSPPlatform) -eq 'Windows') { return 'administrator' }
    return 'root (sudo)'
}

function Write-MSPLog {
    <# Appends one line to the run log. Never throws: a full or locked disk must not stop a diagnostic. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    if (-not $script:MSPRun -or -not $script:MSPRun.LogPath -or $script:MSPRun.LogFailed) { return }
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        Add-Content -LiteralPath $script:MSPRun.LogPath -Value $line -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
    }
    catch {
        # Stop retrying after the first failure; the console output is still complete.
        $script:MSPRun.LogFailed = $true
    }
}

function Format-MSPParameter {
    <# Turns a parameter dictionary into "Name=Value; Name=Value" for the log. #>
    param([System.Collections.IDictionary]$Parameters)
    if (-not $Parameters -or $Parameters.Count -eq 0) { return '(none)' }
    $parts = foreach ($key in $Parameters.Keys) { '{0}={1}' -f $key, $Parameters[$key] }
    return ($parts -join '; ')
}

function Initialize-MSPRun {
    <#
        Starts a run: creates the log (see Get-MSPLogFolder), records start time, host, user,
        version and parameters, and prints the banner. Call once at the top of every script.
        -CheckId is the catalog ID (A1, B2, ...), identical for the Windows, macOS and Linux
        versions of a script so reports can line their results up.
        -AdminSections names the parts that need elevation, so the banner says so up front.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$ScriptVersion,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9-]*$')][string]$CheckId,
        [Parameter(Mandatory)][ValidateSet('Read-Only', 'Safe', 'Elevated', 'Destructive')][string]$RiskLevel,
        [System.Collections.IDictionary]$Parameters = @{},
        [string]$Description = '',
        [string[]]$AdminSections = @()
    )
    $start = Get-Date
    $platform = Get-MSPPlatform
    # Short host name on every platform (macOS can report "name.local").
    $hostName = ([Environment]::MachineName -split '\.')[0]
    # A previous run in the same session must not decide this run's log folder.
    $script:MSPRun = $null
    $logDir = $null
    $logPath = $null
    try {
        $logDir = Initialize-MSPLogFolder
        if ($logDir) {
            $candidate = Join-Path -Path $logDir -ChildPath ('{0}_{1}_{2}.log' -f $ScriptName, $hostName, $start.ToString('yyyyMMdd-HHmmss'))
            Add-MSPLogFile -Path $candidate
            $logPath = $candidate
        }
    }
    catch {
        $logPath = $null
    }

    # Copy parameters to plain strings so the log and JSON never hold live objects.
    $paramCopy = [ordered]@{}
    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) { $value = $value.IsPresent }
        elseif ($value -is [array]) { $value = ($value -join ', ') }
        $paramCopy[$key] = [string]$value
    }

    $user = [Environment]::UserName
    if ($platform -eq 'Windows') { $user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME }
    # RMM mode: -Rmm on the script, or MSP_TOOLKIT_RMM=1 set by the RMM procedure.
    $rmm = (@($Parameters.Keys) -contains 'Rmm' -and [bool]$Parameters['Rmm']) -or $env:MSP_TOOLKIT_RMM -eq '1'
    if ($rmm -and (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue)) { $PSStyle.OutputRendering = 'PlainText' }
    $shell = 'PowerShell {0}' -f $PSVersionTable.PSVersion
    if ($PSVersionTable.PSEdition -ne 'Core') { $shell = 'Windows PowerShell {0}' -f $PSVersionTable.PSVersion }

    $script:MSPRun = [pscustomobject]@{
        CheckId       = $CheckId
        ScriptName    = $ScriptName
        ScriptVersion = $ScriptVersion
        RiskLevel     = $RiskLevel
        Platform      = $platform
        OSVersion     = (Get-MSPOSVersion -Platform $platform)
        Shell         = $shell
        Host          = $hostName
        User          = $user
        IsAdmin       = (Test-MSPIsAdmin)
        IsServiceAccount = (Test-MSPServiceAccount)
        Rmm           = [bool]$rmm
        StartTime     = $start
        EndTime       = $null
        Parameters    = $paramCopy
        LogFolder     = $logDir
        LogPath       = $logPath
        LogFailed     = $false
        Findings      = New-Object System.Collections.Generic.List[object]
        Data          = [ordered]@{}
    }
    $run = $script:MSPRun

    Write-MSPLog -Message ('===== START {0} v{1} ({2}) =====' -f $ScriptName, $ScriptVersion, $CheckId)
    Write-MSPLog -Message ('Host={0}; User={1}; Elevated={2}; Platform={3}; OS={4}; Shell={5}; Risk={6}' -f `
            $run.Host, $run.User, $run.IsAdmin, $run.Platform, $run.OSVersion, $run.Shell, $RiskLevel)
    Write-MSPLog -Message ('Parameters: {0}' -f (Format-MSPParameter -Parameters $paramCopy))
    if ($run.Rmm) { Write-MSPLog -Message ('RMM mode; service account (no user profile): {0}' -f $run.IsServiceAccount) }

    $adminTerm = Get-MSPAdminTerm
    $adminText = 'No'
    if ($run.IsAdmin) { $adminText = 'Yes' }
    $bar = '=' * 72
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host (' {0} v{1}   [{2}]   [Risk: {3}]' -f $ScriptName, $ScriptVersion, $CheckId, $RiskLevel) -ForegroundColor Cyan
    if ($Description) { Write-Host (' {0}' -f $Description) -ForegroundColor Gray }
    Write-Host (' Computer: {0} ({1})' -f $run.Host, $run.OSVersion) -ForegroundColor Gray
    Write-Host (' User    : {0}   Elevated ({1}): {2}' -f $run.User, $adminTerm, $adminText) -ForegroundColor Gray
    Write-Host (' Started : {0}' -f $start.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Gray
    if ($logPath) { Write-Host (' Log     : {0}' -f $logPath) -ForegroundColor Gray }
    if ($run.Rmm) { Write-Host (' Mode    : RMM (no prompts; result saved to {0}; exit 0 OK, 1 WARN, 2 FAIL, 3 ERROR or not run)' -f (Get-MSPResultFolder)) -ForegroundColor Gray }
    if ($run.IsServiceAccount) { Write-Host ' Account : SYSTEM / root with no signed-in user: per-user checks cover every user profile or say SKIPPED.' -ForegroundColor Gray }
    Write-Host $bar -ForegroundColor Cyan
    if (-not $run.IsAdmin) {
        Write-Host (' Not running as {0}. Checks that need it will show SKIPPED;' -f $adminTerm) -ForegroundColor DarkGray
        Write-Host ' everything else still runs.' -ForegroundColor DarkGray
        if ($AdminSections.Count -gt 0) {
            Write-Host (' Needs {0}: {1}' -f $adminTerm, ($AdminSections -join ', ')) -ForegroundColor DarkGray
        }
        if ($platform -eq 'Windows') { Write-Host ' For full results, use "Run as administrator".' -ForegroundColor DarkGray }
    }
}

function Write-MSPSection {
    <# Prints a section heading so long output is easy to follow on a screen share. #>
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host ('--- {0} ' -f $Title).PadRight(72, '-') -ForegroundColor Cyan
    Write-MSPLog -Message ('--- {0}' -f $Title)
}

function Get-MSPStatusColor {
    param([string]$Status)
    switch ($Status) {
        'PASS' { return 'Green' }
        'WARN' { return 'Yellow' }
        'FAIL' { return 'Red' }
        'INFO' { return 'Cyan' }
        'SKIPPED' { return 'DarkGray' }
        'ERROR' { return 'Magenta' }
        default { return 'White' }
    }
}

function ConvertTo-MSPIdPart {
    <# "Remote-access tool: Kaseya" -> "Remote-access-tool-Kaseya". Must match msp_id_part in the bash helper. #>
    param([AllowEmptyString()][string]$Text)
    $part = ($Text -replace '[^A-Za-z0-9]+', '-').Trim('-')
    if (-not $part) { $part = 'General' }
    return $part
}

function Add-MSPFinding {
    <#
        Records one finding and prints it as a colored line.
        Status   = what the check found (PASS/WARN/FAIL/INFO) or why it has no answer (SKIPPED/ERROR).
        Severity = how much it matters if it is not a PASS. Drives remediation priority in reports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR')][string]$Status,
        [AllowEmptyString()][string]$Detail = '',
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [AllowEmptyString()][string]$Recommendation = '',
        [string]$Category = 'General',
        [string]$Id,
        [string]$Target,
        [System.Collections.IDictionary]$Evidence,
        [switch]$NoConsole
    )
    if (-not $script:MSPRun) { throw 'Initialize-MSPRun must be called before Add-MSPFinding.' }

    if (-not $Severity) {
        switch ($Status) {
            'FAIL' { $Severity = 'High' }
            'WARN' { $Severity = 'Medium' }
            default { $Severity = 'Info' }
        }
    }
    if (-not $Target) { $Target = $script:MSPRun.Host }
    if (-not $Id) {
        # Stable, platform-neutral ID (<CheckId>.<Category>.<Check>) so reports can line up the
        # same check across runs and across Windows/macOS/Linux. The bash helper builds it the same way.
        $Id = '{0}.{1}.{2}' -f $script:MSPRun.CheckId, (ConvertTo-MSPIdPart -Text $Category), (ConvertTo-MSPIdPart -Text $Check)
    }

    $finding = [pscustomobject]@{
        Id             = $Id
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Severity       = $Severity
        Target         = $Target
        Detail         = $Detail
        Recommendation = $Recommendation
        Evidence       = $Evidence
    }
    $script:MSPRun.Findings.Add($finding)
    Write-MSPLog -Message ('[{0}/{1}] {2} | {3} | {4}' -f $Status, $Severity, $Check, $Target, $Detail)

    if (-not $NoConsole) {
        $tag = ('[{0}]' -f $Status).PadRight(10)
        Write-Host ('  {0}' -f $tag) -ForegroundColor (Get-MSPStatusColor -Status $Status) -NoNewline
        if ($Detail) { Write-Host ('{0} - {1}' -f $Check, $Detail) }
        else { Write-Host $Check }
        if ($Recommendation -and $Status -in @('WARN', 'FAIL')) {
            Write-Host ('            -> {0}' -f $Recommendation) -ForegroundColor DarkGray
        }
    }
}

function ConvertTo-MSPFriendlyError {
    <# Turns an exception into one plain-English sentence a Tier 1 tech can paste into a ticket. #>
    param([Parameter(Mandatory)]$ErrorRecord)
    $exception = $ErrorRecord.Exception
    # .NET method errors wrap the useful exception one level down.
    if ($exception -is [System.Management.Automation.MethodInvocationException] -and $exception.InnerException) {
        $exception = $exception.InnerException
    }
    $message = $exception.Message
    $os = 'Windows'
    if ((Get-MSPPlatform) -ne 'Windows') { $os = 'The operating system' }
    if ($exception -is [System.UnauthorizedAccessException] -or $message -match 'Access is denied|access denied|Unauthorized|Permission denied') {
        return ('{0} denied access to this information for the current account. Running as {1} may allow it.' -f $os, (Get-MSPAdminTerm))
    }
    if ($exception -is [System.Management.Automation.CommandNotFoundException]) {
        return ('A command this check needs ({0}) is not available on this computer. This is normal on some editions or versions.' -f $ErrorRecord.CategoryInfo.TargetName)
    }
    if ($message -match 'Invalid namespace|Invalid class|Not supported|not supported') {
        return 'This component is not present on this computer (common on Windows Server or older/limited editions).'
    }
    if ($message -match 'timed out|timeout') {
        return 'The check took too long to answer and was stopped.'
    }
    if ($exception -is [System.Runtime.InteropServices.COMException]) {
        return ('A Windows component did not respond (error 0x{0:X8}). {1}' -f $exception.HResult, $message.Trim())
    }
    return ('The check could not complete: {0}' -f $message.Trim())
}

function Test-MSPParameterRange {
    <#
        Checks number parameters against their allowed ranges. Scripts do this in the body instead
        of with [ValidateRange], so a wrong value gets a plain-English Setup finding, the usual
        summary, log and export, and a clean exit (the caller exits 1), on Windows PowerShell 5.1
        and PowerShell 7 alike. Only values given on the command line are checked (defaults are
        always in range). Returns $true when every value is in range.
        Example: Test-MSPParameterRange -Bound $PSBoundParameters -Range ([ordered]@{ Days = 1, 30 })
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Bound,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Range
    )
    $ok = $true
    # Keys, not .Contains(): on $PSBoundParameters .Contains() is the key/value-pair overload.
    $given = @($Bound.Keys)
    foreach ($name in @($Range.Keys)) {
        if ($given -notcontains $name) { continue }
        $min = $Range[$name][0]
        $max = $Range[$name][1]
        $value = $Bound[$name]
        if ($value -ge $min -and $value -le $max) { continue }
        $ok = $false
        Add-MSPFinding -Check 'Parameters' -Category 'Setup' -Status ERROR `
            -Detail ('-{0} must be between {1} and {2} (you gave {3}). Nothing was checked or changed.' -f $name, $min, $max, $value) `
            -Recommendation ('Run it again with -{0} set to a number from {1} to {2}, or leave it out to use the default.' -f $name, $min, $max)
    }
    return $ok
}

function Skip-MSPCheck {
    <#
        Ends the current Invoke-MSPCheck with SKIPPED instead of ERROR, for "could not be checked
        here, and that is expected" cases (for example: only a VPN adapter has a gateway).
    #>
    param(
        [Parameter(Mandatory)][string]$Reason,
        [string]$Recommendation = ''
    )
    $exception = New-Object System.OperationCanceledException($Reason)
    $marker = @{ MSPSkip = $true; Reason = $Reason; Recommendation = $Recommendation }
    $record = New-Object System.Management.Automation.ErrorRecord($exception, 'MSPCheckSkipped', [System.Management.Automation.ErrorCategory]::NotEnabled, $marker)
    throw $record
}

function Invoke-MSPCheck {
    <#
        Runs one check safely:
          - If -RequiresAdmin and not elevated: records SKIPPED with a plain-language note instead of failing.
          - Skip-MSPCheck inside the check records SKIPPED with its reason.
          - Any other error inside the check becomes an ERROR finding; the script keeps going.
        Anything the script block outputs is passed back to the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$Category = 'General',
        [switch]$RequiresAdmin,
        [string]$AdminReason = ''
    )
    if ($RequiresAdmin -and -not $script:MSPRun.IsAdmin) {
        $detail = 'Skipped: requires {0}.' -f (Get-MSPAdminTerm)
        if ($AdminReason) { $detail = '{0} {1}' -f $detail, $AdminReason }
        $how = 'Re-run with sudo to include this check.'
        if ($script:MSPRun.Platform -eq 'Windows') { $how = 'Re-run from PowerShell opened with "Run as administrator" to include this check.' }
        Add-MSPFinding -Check $Name -Category $Category -Status SKIPPED -Severity Info -Detail $detail -Recommendation $how
        return
    }
    Write-MSPLog -Message ('Check start: {0}' -f $Name)
    # Make every error inside the check catchable, including non-terminating cmdlet errors.
    $ErrorActionPreference = 'Stop'
    try {
        & $ScriptBlock
    }
    catch {
        $marker = $_.TargetObject
        if ($marker -is [System.Collections.IDictionary] -and $marker['MSPSkip']) {
            Write-MSPLog -Message ('Check skipped "{0}": {1}' -f $Name, $marker['Reason'])
            Add-MSPFinding -Check $Name -Category $Category -Status SKIPPED -Severity Info -Detail $marker['Reason'] -Recommendation $marker['Recommendation']
            return
        }
        $friendly = ConvertTo-MSPFriendlyError -ErrorRecord $_
        Write-MSPLog -Level ERROR -Message ('Check error in "{0}": {1}: {2} | {3}' -f $Name, $_.Exception.GetType().FullName, $_.Exception.Message, $_.InvocationInfo.PositionMessage)
        Add-MSPFinding -Check $Name -Category $Category -Status ERROR -Severity Info -Detail $friendly `
            -Recommendation 'This check could not run; the other results are still valid. If it matters for this ticket, re-run as administrator or escalate with the log file.'
    }
}

function Add-MSPData {
    <# Attaches a table (for example a device or software list) to the run for JSON/CSV export. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyCollection()][object[]]$Rows = @()
    )
    $script:MSPRun.Data[$Name] = @($Rows)
}

function Get-MSPSummaryCount {
    $counts = [ordered]@{}
    foreach ($status in $script:MSPStatusOrder) {
        $counts[$status] = @($script:MSPRun.Findings | Where-Object { $_.Status -eq $status }).Count
    }
    return $counts
}

function Get-MSPSortedIssue {
    <# FAIL/WARN findings, most severe first (FAIL before WARN at equal severity). #>
    $issues = @($script:MSPRun.Findings | Where-Object { $_.Status -in @('FAIL', 'WARN') })
    return @($issues | Sort-Object -Property @{ Expression = { $script:MSPSeverityRank[$_.Severity] } }, @{ Expression = { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } })
}

function Get-MSPTicketText {
    <# Plain-text block (no colors, no special characters) for pasting into a ticket. #>
    param([int]$MaxIssueLines = 40)
    $run = $script:MSPRun
    $end = $run.EndTime
    if (-not $end) { $end = Get-Date }
    $duration = [int]($end - $run.StartTime).TotalSeconds
    $counts = Get-MSPSummaryCount
    $adminText = 'No'
    if ($run.IsAdmin) { $adminText = 'Yes' }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('[MSP Toolkit] {0} {1} v{2} | Risk: {3}' -f $run.CheckId, $run.ScriptName, $run.ScriptVersion, $run.RiskLevel))
    $lines.Add(('Computer: {0} ({1}) | User: {2} | Elevated: {3} | Run: {4} ({5}s)' -f $run.Host, $run.OSVersion, $run.User, $adminText, $run.StartTime.ToString('yyyy-MM-dd HH:mm'), $duration))
    $lines.Add(('Result: PASS {0} | WARN {1} | FAIL {2} | INFO {3} | SKIPPED {4} | ERROR {5}' -f `
                $counts['PASS'], $counts['WARN'], $counts['FAIL'], $counts['INFO'], $counts['SKIPPED'], $counts['ERROR']))

    $issues = @(Get-MSPSortedIssue)
    if ($issues.Count -gt 0) {
        $lines.Add('Issues (most severe first):')
        $shown = 0
        foreach ($f in $issues) {
            if ($shown -ge $MaxIssueLines) {
                $lines.Add(('  ... {0} more issue(s) - see the exported CSV/JSON or the log.' -f ($issues.Count - $shown)))
                break
            }
            $target = ''
            if ($f.Target -and $f.Target -ne $run.Host) { $target = ' [{0}]' -f $f.Target }
            $text = '  - [{0}/{1}] {2}{3}: {4}' -f $f.Status, $f.Severity, $f.Check, $target, $f.Detail
            if ($f.Recommendation) { $text = '{0} Action: {1}' -f $text, $f.Recommendation }
            $lines.Add($text)
            $shown++
        }
    }
    else {
        $lines.Add('Issues: none found by the checks that ran.')
    }

    $errors = @($run.Findings | Where-Object { $_.Status -eq 'ERROR' })
    if ($errors.Count -gt 0) {
        $lines.Add('Could not run (ERROR - not the same as a failed check):')
        foreach ($f in $errors) { $lines.Add(('  - {0}: {1}' -f $f.Check, $f.Detail)) }
    }
    $skipped = @($run.Findings | Where-Object { $_.Status -eq 'SKIPPED' })
    if ($skipped.Count -gt 0) {
        $lines.Add('Skipped:')
        foreach ($f in $skipped) { $lines.Add(('  - {0}: {1}' -f $f.Check, $f.Detail)) }
    }
    if ($run.LogPath -and -not $run.LogFailed) { $lines.Add(('Log: {0}' -f $run.LogPath)) }
    return ($lines -join [Environment]::NewLine)
}

function Write-MSPSummary {
    <# Prints the colored summary, the top issues, and the plain-text ticket block. #>
    $counts = Get-MSPSummaryCount
    $bar = '=' * 72
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host ' SUMMARY  ' -ForegroundColor Cyan -NoNewline
    foreach ($status in $script:MSPStatusOrder) {
        $color = 'DarkGray'
        if ($counts[$status] -gt 0) { $color = Get-MSPStatusColor -Status $status }
        Write-Host ('{0}: {1}   ' -f $status, $counts[$status]) -ForegroundColor $color -NoNewline
    }
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan

    $issues = @(Get-MSPSortedIssue)
    if ($issues.Count -gt 0) {
        Write-Host ' Most important items:' -ForegroundColor White
        foreach ($f in ($issues | Select-Object -First 10)) {
            Write-Host ('  [{0}/{1}] ' -f $f.Status, $f.Severity) -ForegroundColor (Get-MSPStatusColor -Status $f.Status) -NoNewline
            Write-Host ('{0}: {1}' -f $f.Check, $f.Detail)
        }
        if ($issues.Count -gt 10) { Write-Host ('  ... and {0} more (see ticket block below).' -f ($issues.Count - 10)) -ForegroundColor DarkGray }
    }
    else {
        Write-Host ' No WARN or FAIL items from the checks that ran.' -ForegroundColor Green
    }
    if ($counts['ERROR'] -gt 0) {
        Write-Host (' {0} check(s) could not run (ERROR). That is not a failed check - see details above.' -f $counts['ERROR']) -ForegroundColor Magenta
    }

    $ticket = Get-MSPTicketText
    Write-Host ''
    Write-Host '----- COPY FOR TICKET (plain text) ' -ForegroundColor White -NoNewline
    Write-Host ('-' * 37) -ForegroundColor White
    Write-Host $ticket
    Write-Host ('-' * 72) -ForegroundColor White
    Write-MSPLog -Message ('Ticket block:{0}{1}' -f [Environment]::NewLine, $ticket)
}

function Get-MSPResultObject {
    <# Builds the shared-schema result (see README "Output schema"). #>
    $run = $script:MSPRun
    $endTime = $run.EndTime
    if (-not $endTime) { $endTime = Get-Date }
    $findings = foreach ($f in $run.Findings) {
        [ordered]@{
            Id             = $f.Id
            Category       = $f.Category
            Check          = $f.Check
            Status         = $f.Status
            Severity       = $f.Severity
            Target         = $f.Target
            Detail         = $f.Detail
            Recommendation = $f.Recommendation
            Evidence       = $f.Evidence
        }
    }
    # Field order and names are shared with the bash helper (msp_json_result).
    return [ordered]@{
        SchemaVersion = $script:MSPSchemaVersion
        CheckId       = $run.CheckId
        ScriptName    = $run.ScriptName
        Version       = $run.ScriptVersion
        Platform      = $run.Platform
        OSVersion     = $run.OSVersion
        Shell         = $run.Shell
        Host          = $run.Host
        User          = $run.User
        IsAdmin       = $run.IsAdmin
        RiskLevel     = $run.RiskLevel
        Parameters    = $run.Parameters
        Timestamp     = (ConvertTo-MSPIsoTime -Time $run.StartTime)
        EndTime       = (ConvertTo-MSPIsoTime -Time $endTime)
        Summary       = (Get-MSPSummaryCount)
        Findings      = @($findings)
        Data          = $run.Data
    }
}

function ConvertTo-MSPIsoTime {
    <# ISO 8601 local time with offset, to the second (2026-10-16T14:05:09+02:00), as the bash helper writes it. #>
    param([Parameter(Mandatory)][datetime]$Time)
    return $Time.ToString('yyyy-MM-ddTHH:mm:sszzz')
}

function Export-MSPResult {
    <#
        Writes <Script>_<Host>_<yyyyMMdd-HHmmss>.json (full result), ..._findings.csv
        (one row per finding) and ..._<Table>.csv for each attached data table.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputPath, [switch]$JsonOnly)
    $run = $script:MSPRun
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop -WhatIf:$false
    }
    $folder = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $base = '{0}_{1}_{2}' -f $run.ScriptName, $run.Host, $run.StartTime.ToString('yyyyMMdd-HHmmss')

    $jsonPath = Join-Path -Path $folder -ChildPath ('{0}.json' -f $base)
    $json = Get-MSPResultObject | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    if ($JsonOnly) {
        Write-Host (' Result saved: {0}' -f $jsonPath) -ForegroundColor Gray
        Write-MSPLog -Message ('Exported: {0}' -f $jsonPath)
        return [pscustomobject]@{ Json = $jsonPath; FindingsCsv = $null; DataCsv = @() }
    }

    # Same columns, in the same order, as the bash helper's findings CSV.
    $csvPath = Join-Path -Path $folder -ChildPath ('{0}_findings.csv' -f $base)
    $timestamp = ConvertTo-MSPIsoTime -Time $run.StartTime
    $run.Findings | Select-Object @{ n = 'CheckId'; e = { $run.CheckId } }, @{ n = 'ScriptName'; e = { $run.ScriptName } },
    @{ n = 'Platform'; e = { $run.Platform } }, @{ n = 'Host'; e = { $run.Host } }, @{ n = 'Timestamp'; e = { $timestamp } },
    Id, Category, Check, Status, Severity, Target, Detail, Recommendation |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

    $dataPaths = @()
    foreach ($name in $run.Data.Keys) {
        $rows = @($run.Data[$name])
        if ($rows.Count -eq 0) { continue }
        $dataPath = Join-Path -Path $folder -ChildPath ('{0}_{1}.csv' -f $base, ($name -replace '[^A-Za-z0-9]+', ''))
        $rows | Export-Csv -LiteralPath $dataPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        $dataPaths += $dataPath
    }

    Write-Host ''
    Write-Host ' Results saved:' -ForegroundColor Green
    Write-Host ('   {0}' -f $jsonPath) -ForegroundColor Gray
    Write-Host ('   {0}' -f $csvPath) -ForegroundColor Gray
    foreach ($p in $dataPaths) { Write-Host ('   {0}' -f $p) -ForegroundColor Gray }
    Write-MSPLog -Message ('Exported: {0}; {1}; {2}' -f $jsonPath, $csvPath, ($dataPaths -join '; '))
    return [pscustomobject]@{ Json = $jsonPath; FindingsCsv = $csvPath; DataCsv = $dataPaths }
}

function Get-MSPRmmExitCode {
    <#
        RMM exit code: 3 could not run, 2 any FAIL, 1 any WARN, 3 any ERROR (with no FAIL or WARN),
        0 only PASS / INFO / SKIPPED. A FAIL outranks an ERROR so a confirmed problem is never
        reported as "check broken"; the summary line still shows the ERROR count.
    #>
    param([switch]$CouldNotRun)
    $c = Get-MSPSummaryCount
    if ($CouldNotRun) { return 3 }
    if ($c['FAIL'] -gt 0) { return 2 }
    if ($c['WARN'] -gt 0) { return 1 }
    if ($c['ERROR'] -gt 0) { return 3 }
    return 0
}

function Complete-MSPRun {
    <#
        Ends the run: prints the summary and ticket block, exports if -OutputPath was given,
        and writes the end time to the log. Findings never change the exit code; the exit
        code only says whether the script itself ran.
        RMM mode: also saves the JSON result to the results folder (Get-MSPResultFolder; the
        newest 10 per script are kept), prints the one-line summary "<CheckId> WARN=n FAIL=n
        ERROR=n" as the last line on stdout, and ENDS THE SCRIPT with the RMM exit code
        (Get-MSPRmmExitCode). -CouldNotRun marks a run that stopped before its checks.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [switch]$PassThru,
        [switch]$CouldNotRun
    )
    $run = $script:MSPRun
    $run.EndTime = Get-Date
    Write-MSPSummary
    if ($OutputPath) {
        try {
            $null = Export-MSPResult -OutputPath $OutputPath
        }
        catch {
            Write-Host (' Could not save results to "{0}": {1}' -f $OutputPath, $_.Exception.Message) -ForegroundColor Red
            Write-Host ' The console output and log above are still complete.' -ForegroundColor Red
            Write-MSPLog -Level ERROR -Message ('Export failed: {0}' -f $_.Exception.Message)
        }
    }
    $counts = Get-MSPSummaryCount
    $duration = [int]($run.EndTime - $run.StartTime).TotalSeconds
    Write-MSPLog -Message ('===== END {0} | duration {1}s | PASS {2} WARN {3} FAIL {4} INFO {5} SKIPPED {6} ERROR {7} =====' -f `
            $run.EndTime.ToString('yyyy-MM-dd HH:mm:ss'), $duration, $counts['PASS'], $counts['WARN'], $counts['FAIL'], $counts['INFO'], $counts['SKIPPED'], $counts['ERROR'])
    if ($run.LogPath -and -not $run.LogFailed) {
        Write-Host (' Log file: {0}' -f $run.LogPath) -ForegroundColor DarkGray
    }
    Write-Host ''
    if ($run.Rmm) {
        $code = Get-MSPRmmExitCode -CouldNotRun:$CouldNotRun
        try {
            $folder = Initialize-MSPResultFolder
            $saved = Export-MSPResult -OutputPath $folder -JsonOnly
            if ((Get-MSPPlatform) -ne 'Windows') { & chmod 600 $saved.Json }
            Limit-MSPResultHistory -Folder $folder -ScriptName $run.ScriptName
        }
        catch {
            Write-Host (' Could not save the RMM result to "{0}": {1}' -f (Get-MSPResultFolder), $_.Exception.Message)
            Write-MSPLog -Level ERROR -Message ('RMM result not saved: {0}' -f $_.Exception.Message)
            $code = 3
        }
        Write-MSPLog -Message ('RMM exit code {0}' -f $code)
        [Console]::Out.WriteLine(('{0} WARN={1} FAIL={2} ERROR={3}' -f $run.CheckId, $counts['WARN'], $counts['FAIL'], $counts['ERROR']))
        exit $code
    }
    if ($PassThru) { return (Get-MSPResultObject) }
}
#endregion MSPHelper:Core
#endregion MSPToolkit (generated)

$ScriptVersion = '1.2.1'
Initialize-MSPRun -ScriptName 'Get-DiskSpaceReport' -ScriptVersion $ScriptVersion -CheckId 'B5' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Disk space: volumes, largest folders, reclaimable space, disk health (read-only; deletes nothing)'
# Number ranges are checked here, not with [ValidateRange], so a wrong value gets a plain message
# and a clean exit 1 instead of a parameter-binding error.
if (-not (Test-MSPParameterRange -Bound $PSBoundParameters -Range ([ordered]@{ ScanSeconds = 10, 600; TopFolders = 5, 50 }))) {
    Complete-MSPRun -OutputPath $OutputPath -CouldNotRun
    exit 1
}

$now = Get-Date
$GB = [double]1GB
$sep = [System.IO.Path]::DirectorySeparatorChar
$systemDrive = [string]$env:SystemDrive
if (-not $systemDrive) { $systemDrive = 'C:' }
$systemRoot = $systemDrive.TrimEnd('\', '/') + $sep
$windir = [string]$env:windir
if (-not $windir) { $windir = Join-Path $systemRoot 'Windows' }
$steps = New-Object System.Collections.Generic.List[object]

function Join-PathPart {
    <# Joins path parts with this platform's separator (the tests run this script on macOS/Linux too). #>
    param([string]$Base, [string[]]$Part)
    $p = $Base
    foreach ($x in $Part) { $p = Join-Path -Path $p -ChildPath $x }
    return $p
}

function Get-VolumeStatus {
    <# PASS/WARN/FAIL for free space: under 5 % or 5 GB = FAIL, under 15 % or 20 GB = WARN; under 50 GB in size: percentage only. #>
    param([double]$SizeGB, [double]$FreeGB, [double]$PercentFree)
    $small = $SizeGB -lt 50
    if ($PercentFree -lt 5 -or (-not $small -and $FreeGB -lt 5)) { return 'FAIL' }
    if ($PercentFree -lt 15 -or (-not $small -and $FreeGB -lt 20)) { return 'WARN' }
    return 'PASS'
}

function Format-Size {
    <# "12.3 GB" / "850 MB" for a byte count. #>
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Measure-Folder {
    <#
        Total size of the files under PATH (or PATH itself when it is a file), walking until
        DEADLINE. Returns @{ Bytes; Partial; Denied }: Partial when the deadline stopped the walk,
        Denied when some folders could not be read. Junctions and symbolic links are not followed.
    #>
    param([string]$Path, [datetime]$Deadline)
    $result = @{ Bytes = [double]0; Partial = $false; Denied = $false }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { $result.Bytes = [double](New-Object System.IO.FileInfo($Path)).Length } catch { $result.Denied = $true }
        return $result
    }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        if ((Get-Date) -gt $Deadline) { $result.Partial = $true; break }
        $dir = New-Object System.IO.DirectoryInfo($stack.Pop())
        try {
            foreach ($f in $dir.GetFiles()) { $result.Bytes += $f.Length }
            foreach ($d in $dir.GetDirectories()) {
                if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($d.FullName) }
            }
        }
        catch { $result.Denied = $true }
    }
    return $result
}

function Get-LargestFolder {
    <#
        The folders one level under ROOT with the largest subfolders of each (two levels), by
        size, measured until DEADLINE. Returns rows: Place, Folder, Level, Bytes, Partial.
    #>
    param([string]$Root, [string]$Place, [datetime]$Deadline)
    $rows = New-Object System.Collections.Generic.List[object]
    $children = @()
    try { $children = @((New-Object System.IO.DirectoryInfo($Root)).GetDirectories() | Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 }) }
    catch { return $rows }
    foreach ($c in $children) {
        $total = [double]0
        $partial = $false
        try { foreach ($f in $c.GetFiles()) { $total += $f.Length } } catch { Write-MSPLog -Level WARN -Message ('Not readable: {0}' -f $c.FullName) }
        $grand = @()
        try { $grand = @($c.GetDirectories() | Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 }) } catch { $grand = @() }
        foreach ($g in $grand) {
            $m = Measure-Folder -Path $g.FullName -Deadline $Deadline
            $total += $m.Bytes
            if ($m.Partial) { $partial = $true }
            if ($m.Bytes -gt 0) { $rows.Add([pscustomobject]@{ Place = $Place; Folder = $g.FullName; Level = 2; Bytes = $m.Bytes; Partial = $m.Partial }) }
        }
        if ((Get-Date) -gt $Deadline) { $partial = $true }
        $rows.Add([pscustomobject]@{ Place = $Place; Folder = $c.FullName; Level = 1; Bytes = $total; Partial = $partial })
    }
    return $rows
}

# =========================================================================================
Write-MSPSection -Title 'Volumes'
# =========================================================================================
$volumeProblem = $null
Invoke-MSPCheck -Name 'Disk space' -Category 'Volumes' -ScriptBlock {
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | Where-Object { $_.Size -gt 0 })
    if ($disks.Count -eq 0) { throw 'No fixed volumes were reported.' }
    $rows = foreach ($d in $disks) {
        $size = [double]$d.Size / $GB
        $free = [double]$d.FreeSpace / $GB
        $pct = [math]::Round(100 * [double]$d.FreeSpace / [double]$d.Size, 1)
        $status = Get-VolumeStatus -SizeGB $size -FreeGB $free -PercentFree $pct
        $name = [string]$d.DeviceID
        $label = ''
        if ($d.VolumeName) { $label = ' "{0}"' -f $d.VolumeName }
        $text = '{0}{1}: {2:N1} GB free of {3:N1} GB ({4} % free).' -f $name, $label, $free, $size, $pct
        $check = 'Disk space {0}' -f $name
        $evidence = @{ Volume = $name; SizeGB = [math]::Round($size, 1); FreeGB = [math]::Round($free, 1); PercentFree = $pct }
        switch ($status) {
            'FAIL' {
                Add-MSPFinding -Check $check -Category 'Volumes' -Status FAIL -Severity High -Evidence $evidence -Detail $text `
                    -Recommendation 'Free space now (see What to do): Windows updates, Outlook and many programs fail when a volume is nearly full.'
            }
            'WARN' {
                Add-MSPFinding -Check $check -Category 'Volumes' -Status WARN -Severity Medium -Evidence $evidence -Detail $text `
                    -Recommendation 'Free space before it runs out (see What to do); feature updates need about 20 GB free.'
            }
            default { Add-MSPFinding -Check $check -Category 'Volumes' -Status PASS -Evidence $evidence -Detail $text }
        }
        if ($status -ne 'PASS' -and (-not $script:volumeProblem -or $name -eq $systemDrive)) { $script:volumeProblem = [pscustomobject]@{ Volume = $name; Status = $status; FreeGB = $free; SizeGB = $size } }
        [pscustomobject]@{ Volume = $name; Label = [string]$d.VolumeName; FileSystem = [string]$d.FileSystem; SizeGB = [math]::Round($size, 1); FreeGB = [math]::Round($free, 1); PercentFree = $pct; Status = $status }
    }
    Add-MSPData -Name 'Volumes' -Rows @($rows)
}

# =========================================================================================
Write-MSPSection -Title 'Where the space went'
# =========================================================================================
$folderRows = New-Object System.Collections.Generic.List[object]
$profileDir = [string]$env:USERPROFILE
$start = Get-Date
foreach ($place in @(
        @{ Name = 'User profile'; Path = $profileDir; Deadline = $start.AddSeconds($ScanSeconds / 2) },
        @{ Name = 'System drive'; Path = $systemRoot; Deadline = $start.AddSeconds($ScanSeconds) })) {
    Invoke-MSPCheck -Name ('Largest folders: {0}' -f $place.Name) -Category 'Folders' -ScriptBlock {
        if ($place.Name -eq 'User profile' -and $script:MSPRun.IsServiceAccount) {
            Skip-MSPCheck -Reason ('Running as {0}, which has no user profile of its own; the users'' folders are in the System drive list (Users).' -f $script:MSPRun.User)
        }
        if (-not $place.Path -or -not (Test-Path -LiteralPath $place.Path)) { Skip-MSPCheck -Reason ('{0} not found ({1}).' -f $place.Name, $place.Path) }
        $rows = @(Get-LargestFolder -Root $place.Path -Place $place.Name -Deadline $place.Deadline)
        foreach ($r in $rows) { $folderRows.Add($r) }
        $top = @($rows | Where-Object { $_.Level -eq 1 } | Sort-Object Bytes -Descending | Select-Object -First $TopFolders)
        if ($top.Count -eq 0) { Add-MSPFinding -Check ('Largest folders: {0}' -f $place.Name) -Category 'Folders' -Status INFO -Detail ('No folders could be measured under {0}.' -f $place.Path); return }
        $partial = @($rows | Where-Object { $_.Partial }).Count -gt 0
        $text = (@($top | ForEach-Object {
                    $f = $_
                    $sub = @($rows | Where-Object { $_.Level -eq 2 -and (Split-Path $_.Folder -Parent) -eq $f.Folder } | Sort-Object Bytes -Descending | Select-Object -First 1)
                    $inside = ''
                    if ($sub.Count -gt 0 -and $sub[0].Bytes -ge 1GB) { $inside = ' (most in {0}, {1})' -f (Split-Path $sub[0].Folder -Leaf), (Format-Size $sub[0].Bytes) }
                    '{0} {1}{2}{3}' -f (Split-Path $f.Folder -Leaf), $(if ($f.Partial) { 'at least ' } else { '' }), (Format-Size $f.Bytes), $inside
                })) -join '; '
        $note = ''
        if ($partial) { $note = (' The folder scan did not finish within -ScanSeconds {0}; sizes marked "at least" are minimums. Run it again with a higher -ScanSeconds (up to 600).' -f $ScanSeconds) }
        Add-MSPFinding -Check ('Largest folders: {0}' -f $place.Name) -Category 'Folders' -Status INFO -Detail ('{0}: {1}.{2}' -f $place.Path, $text, $note)
    }
}
$folderTable = @($folderRows | Sort-Object Place, @{ Expression = 'Bytes'; Descending = $true } | ForEach-Object {
        [pscustomobject]@{ Place = $_.Place; Folder = $_.Folder; Level = $_.Level; SizeGB = [math]::Round($_.Bytes / $GB, 2); AtLeast = [bool]$_.Partial }
    })
Add-MSPData -Name 'LargestFolders' -Rows $folderTable

# =========================================================================================
Write-MSPSection -Title 'Reclaimable space (measured, not deleted)'
# =========================================================================================
$reclaim = @(
    @{ Name = 'Temporary files (yours)'; Paths = @([string]$env:TEMP); Step = 'Delete the contents of %TEMP% (close programs first; files in use are skipped), or Settings > System > Storage > Temporary files.' }
    @{ Name = 'Temporary files (Windows)'; Paths = @((Join-PathPart $windir 'Temp')); Step = 'Settings > System > Storage > Temporary files > Temporary files (as administrator).' }
    @{ Name = 'Windows Update cache'; Paths = @((Join-PathPart $windir 'SoftwareDistribution', 'Download')); Step = 'Clear the Windows Update cache with D1: Clear-WindowsUpdateCache.ps1 (run it with -WhatIf first).' }
    @{ Name = 'Recycle Bin'; Paths = @((Join-PathPart $systemRoot '$Recycle.Bin')); Step = 'Empty the Recycle Bin after the user confirms nothing in it is needed.' }
    @{ Name = 'Previous Windows installation'; Paths = @((Join-PathPart $systemRoot 'Windows.old')); Step = 'Settings > System > Storage > Temporary files > Previous Windows installation(s), once the user is happy with the upgrade (Windows also removes it by itself after 10 days).' }
    @{ Name = 'Delivery Optimization cache'; Paths = @((Join-PathPart $windir 'ServiceProfiles', 'NetworkService', 'AppData', 'Local', 'Microsoft', 'Windows', 'DeliveryOptimization', 'Cache')); Step = 'Settings > System > Storage > Temporary files > Delivery Optimization Files.' }
    @{ Name = 'Crash dumps and error reports'; Paths = @((Join-PathPart $windir 'MEMORY.DMP'), (Join-PathPart $windir 'Minidump'), (Join-PathPart ([string]$env:LOCALAPPDATA) 'CrashDumps'), (Join-PathPart ([string]$env:ProgramData) 'Microsoft', 'Windows', 'WER', 'ReportArchive'), (Join-PathPart ([string]$env:ProgramData) 'Microsoft', 'Windows', 'WER', 'ReportQueue')); Step = 'Settings > System > Storage > Temporary files > System error memory dump files and Windows error reports (keep the newest dump if a crash is being investigated).' }
)
if ($script:MSPRun.IsServiceAccount) {
    # SYSTEM's own TEMP is the Windows one: measure every user's temporary files and crash dumps.
    $userHomes = @()
    try { $userHomes = @(Get-MSPUserProfile | ForEach-Object { $_.Path }) } catch { Write-MSPLog -Level WARN -Message ('User profiles not listed: {0}' -f $_.Exception.Message) }
    $reclaim[0] = @{ Name = 'Temporary files (all users)'; Paths = @($userHomes | ForEach-Object { Join-PathPart $_ 'AppData', 'Local', 'Temp' }); Step = 'With each user signed in: delete the contents of %TEMP% (close programs first; files in use are skipped), or Settings > System > Storage > Temporary files.' }
    $crash = $reclaim[$reclaim.Count - 1]
    $crash.Paths = @($crash.Paths | Where-Object { $_ -notlike '*CrashDumps' }) + @($userHomes | ForEach-Object { Join-PathPart $_ 'AppData', 'Local', 'CrashDumps' })
    Add-MSPFinding -Check 'Users covered' -Category 'Reclaimable' -Status INFO `
        -Detail ('Running as {0}: temporary files and crash dumps measured for {1} user profile(s).' -f $script:MSPRun.User, $userHomes.Count)
}
$reclaimRows = New-Object System.Collections.Generic.List[object]
Invoke-MSPCheck -Name 'Reclaimable space' -Category 'Reclaimable' -ScriptBlock {
    foreach ($item in $reclaim) {
        $bytes = [double]0
        $partial = $false
        $denied = $false
        $found = @()
        foreach ($p in @($item.Paths | Where-Object { $_ })) {
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $found += $p
            $m = Measure-Folder -Path $p -Deadline ((Get-Date).AddSeconds(20))
            $bytes += $m.Bytes
            if ($m.Partial) { $partial = $true }
            if ($m.Denied) { $denied = $true }
        }
        if ($found.Count -eq 0) { continue }
        $note = ''
        if ($partial) { $note += ' (at least: the time limit stopped the count)' }
        if ($denied -and -not $script:MSPRun.IsAdmin) { $note += (' (some of it is readable only as {0})' -f (Get-MSPAdminTerm)) }
        $reclaimRows.Add([pscustomobject]@{ Item = $item.Name; SizeGB = [math]::Round($bytes / $GB, 2); Bytes = $bytes; AtLeast = $partial; Paths = ($found -join '; '); Step = $item.Step; Note = $note.Trim() })
    }
    $sorted = @($reclaimRows | Sort-Object Bytes -Descending)
    Add-MSPData -Name 'Reclaimable' -Rows @($sorted | Select-Object Item, SizeGB, AtLeast, Paths, Note)
    $total = [double](($sorted | Measure-Object Bytes -Sum).Sum)
    if ($sorted.Count -eq 0) { Add-MSPFinding -Check 'Reclaimable space' -Category 'Reclaimable' -Status INFO -Detail 'None of the known cleanup locations exist here.'; return }
    Add-MSPFinding -Check 'Reclaimable space' -Category 'Reclaimable' -Status INFO -Evidence @{ TotalGB = [math]::Round($total / $GB, 2) } `
        -Detail ('{0} in known cleanup locations: {1}. Nothing was deleted.' -f (Format-Size $total), ((@($sorted | Where-Object { $_.Bytes -gt 0 } | ForEach-Object { '{0} {1}{2}' -f $_.Item, (Format-Size $_.Bytes), $(if ($_.Note) { ' ' + $_.Note } else { '' }) })) -join '; '))
    foreach ($r in @($sorted | Where-Object { $_.Bytes -ge 100MB })) { $script:steps.Add([pscustomobject]@{ Bytes = $r.Bytes; Text = ('{0} ({1}): {2}' -f $r.Item, (Format-Size $r.Bytes), $r.Step) }) }
}

# =========================================================================================
Write-MSPSection -Title 'Disk health'
# =========================================================================================
Invoke-MSPCheck -Name 'Disk health' -Category 'Health' -ScriptBlock {
    if (-not (Get-Command -Name Get-PhysicalDisk -ErrorAction SilentlyContinue)) { Skip-MSPCheck -Reason 'Get-PhysicalDisk is not available on this edition of Windows.' }
    $disks = @(Get-PhysicalDisk -ErrorAction Stop)
    $rows = @($disks | ForEach-Object { '{0} ({1}, {2:N0} GB): {3}, {4}' -f $_.FriendlyName, $_.MediaType, ([double]$_.Size / $GB), $_.HealthStatus, ((@($_.OperationalStatus) | ForEach-Object { [string]$_ }) -join '/') })
    $bad = @($disks | Where-Object { [string]$_.HealthStatus -eq 'Unhealthy' })
    $warn = @($disks | Where-Object { [string]$_.HealthStatus -eq 'Warning' -or (@($_.OperationalStatus) | Where-Object { [string]$_ -notin @('OK', '') }).Count -gt 0 })
    if ($bad.Count -gt 0) {
        Add-MSPFinding -Check 'Disk health' -Category 'Health' -Status FAIL -Severity Critical -Detail ($rows -join '; ') `
            -Recommendation 'Back up the data now and replace the disk; cleaning up space will not help a failing disk.'
        $script:steps.Add([pscustomobject]@{ Bytes = [double]::MaxValue; Text = 'Back up the data now: Windows reports a disk as unhealthy. Replace the disk before cleaning anything up.' })
    }
    elseif ($warn.Count -gt 0) {
        Add-MSPFinding -Check 'Disk health' -Category 'Health' -Status WARN -Severity High -Detail ($rows -join '; ') -Recommendation 'Make sure the backup is current and plan to replace the disk.'
    }
    else { Add-MSPFinding -Check 'Disk health' -Category 'Health' -Status PASS -Detail ($rows -join '; ') }
}

Invoke-MSPCheck -Name 'Reliability index' -Category 'Health' -ScriptBlock {
    $m = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction Stop | Sort-Object TimeGenerated -Descending | Select-Object -First 1)
    if ($m.Count -eq 0) { Skip-MSPCheck -Reason 'Windows has no reliability history yet (Reliability Monitor is empty or turned off).' }
    $index = [math]::Round([double]$m[0].SystemStabilityIndex, 1)
    $text = 'Reliability index {0} of 10 (Control Panel > Security and Maintenance > View reliability history).' -f $index
    if ($index -lt 5) { Add-MSPFinding -Check 'Reliability index' -Category 'Health' -Status WARN -Severity Low -Detail $text -Recommendation 'Look at Reliability Monitor for the crashes and failed updates behind it (B3 Get-RecentCriticalErrors.ps1 lists them).' }
    else { Add-MSPFinding -Check 'Reliability index' -Category 'Health' -Status INFO -Detail $text }
}

Invoke-MSPCheck -Name 'Disk errors' -Category 'Health' -ScriptBlock {
    $providers = @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'volmgr')
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $providers; Level = 1, 2, 3; StartTime = $now.AddDays(-7) } -ErrorAction Stop) }
    catch { if ([string]$_.Exception.Message -notmatch 'No events were found') { throw } }
    if ($events.Count -gt 0) {
        $byId = (@($events | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })) -join '; '
        Add-MSPFinding -Check 'Disk errors' -Category 'Health' -Status WARN -Severity High -Detail ('{0} disk or file system warning(s)/error(s) in the System log in 7 days: {1}.' -f $events.Count, $byId) `
            -Recommendation 'Bad blocks or a failing cable/controller: check the backup, run chkdsk /scan, and see B3 Get-RecentCriticalErrors.ps1 for the details.'
    }
    else { Add-MSPFinding -Check 'Disk errors' -Category 'Health' -Status PASS -Detail 'No disk or file system errors in the System log in 7 days.' }
}

# =========================================================================================
Write-MSPSection -Title 'What to do (by hand; this script deleted nothing)'
# =========================================================================================
$final = New-Object System.Collections.Generic.List[string]
if ($volumeProblem) {
    $need = [math]::Max(0, [math]::Ceiling([math]::Max(20 - $volumeProblem.FreeGB, $volumeProblem.SizeGB * 0.15 - $volumeProblem.FreeGB)))
    $final.Add(('{0} needs about {1} GB more free space to be out of the warning zone; work down this list until it has.' -f $volumeProblem.Volume, $need))
}
foreach ($s in @($steps | Sort-Object Bytes -Descending)) { $final.Add($s.Text) }
$big = @($folderRows | Where-Object { $_.Level -eq 1 -and $_.Place -eq 'User profile' } | Sort-Object Bytes -Descending | Select-Object -First 3)
if ($big.Count -gt 0) {
    $final.Add(('Go through the largest folders in the profile with the user (move old files to OneDrive or an external drive, delete what is not needed): {0}.' -f ((@($big | ForEach-Object { '{0} {1}' -f (Split-Path $_.Folder -Leaf), (Format-Size $_.Bytes) })) -join ', ')))
}
$final.Add('Settings > System > Storage > Storage Sense can keep temporary files and the Recycle Bin in check from now on.')
$i = 0
$stepRows = foreach ($s in $final) { $i++; Write-Host ('  {0,2}. {1}' -f $i, $s); [pscustomobject]@{ Step = $i; Action = $s } }
Add-MSPData -Name 'NextSteps' -Rows @($stepRows)
Add-MSPFinding -Check 'What to do' -Category 'Summary' -Status INFO -Detail ((@($stepRows | ForEach-Object { '{0}. {1}' -f $_.Step, $_.Action })) -join ' ')

Complete-MSPRun -OutputPath $OutputPath
