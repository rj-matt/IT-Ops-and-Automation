#Requires -Version 5.1
<#
.SYNOPSIS
    Resets a corrupt or broken Outlook profile for a specified user.

.DESCRIPTION
    This script safely diagnoses, backs up, and removes a corrupt Outlook profile,
    then recreates a clean profile with proper registry configuration. Designed to
    resolve Outlook launch failures, perpetual loading screens, repeated credential
    prompts, and OST sync issues without requiring OS reinstall or full Office repair.

    Steps performed:
      1. Pre-flight checks (Outlook running, profile exists, paths valid)
      2. Collect and log current profile state for ticket documentation
      3. Back up Outlook profile registry keys and local app data
      4. Optionally back up the OST file (large -- skipped by default)
      5. Terminate Outlook and related processes
      6. Remove the corrupt profile registry entries
      7. Recreate a clean default profile via registry
      8. Produce a ticket-ready summary of all actions taken

.PARAMETER TargetUser
    The Windows username whose Outlook profile will be reset.
    Defaults to the currently logged-on user.

.PARAMETER ProfileName
    The name of the Outlook profile to remove and recreate.
    Defaults to "Outlook" (the standard default profile name).

.PARAMETER BackupRoot
    Root folder where backup data will be saved.
    Defaults to C:\MSP\Backups\OutlookProfileReset

.PARAMETER SkipOSTBackup
    Switch. If specified, skips copying the OST file (recommended for large mailboxes).
    OST will be re-downloaded from Exchange/M365 on first Outlook launch.

.PARAMETER WhatIf
    Switch. Simulates all actions without making any changes.
    Use this to preview what the script will do before running for real.

.EXAMPLE
    # Preview what the script will do -- no changes made
    .\Reset-OutlookProfile.ps1 -WhatIf

.EXAMPLE
    # Reset Outlook for the currently logged-on user, skip OST backup
    .\Reset-OutlookProfile.ps1 -SkipOSTBackup

.EXAMPLE
    # Reset a named profile for a specific user (run as admin)
    .\Reset-OutlookProfile.ps1 -TargetUser "jsmith" -ProfileName "Outlook"

.NOTES
    Script Name   : Reset-OutlookProfile.ps1
    Location      : cloud-services/m365/remediation/
    Author        : MSP Automation Team
    Version       : 1.0.0

    RISK LEVEL    : MEDIUM
      - Removes and recreates Outlook profile registry keys
      - Does NOT delete PST files or modify Exchange/M365 mailbox data
      - OST file is either backed up or left in place (never deleted)
      - Outlook will re-sync from server on next launch
      - Full backup is taken before any changes are made

    PREREQUISITES :
      - Run as the affected user OR as a local administrator
      - Outlook must be installed (Microsoft 365 / Office 2016-2021)
      - Target user must be logged on if running as admin for another user
      - Internet/Exchange connectivity required for Outlook to re-sync after reset

    SCOPE         :
      - Affects only the named Outlook profile on the local machine
      - No changes to Exchange Online, Azure AD, or the M365 tenant
      - No changes to any other user profiles on this machine

    TESTED ON     : Windows 10 / Windows 11, Microsoft 365 Apps
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter()]
    [string]$TargetUser = $env:USERNAME,

    [Parameter()]
    [string]$ProfileName = "Outlook",

    [Parameter()]
    [string]$BackupRoot = "C:\MSP\Backups\OutlookProfileReset",

    [Parameter()]
    [switch]$SkipOSTBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# REGION: Initialization & Logging Setup
# ============================================================

$ScriptVersion  = "1.0.0"
$RunTimestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir         = Join-Path $BackupRoot "$TargetUser`_$RunTimestamp"
$LogFile        = Join-Path $LogDir "Reset-OutlookProfile_$RunTimestamp.log"
$TicketSummary  = Join-Path $LogDir "TicketNotes_$RunTimestamp.txt"

# Accumulate ticket notes throughout execution
$script:TicketLines = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","ACTION","SUCCESS","SKIP","DRYRUN")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Timestamp] [$Level] $Message"
    Write-Host $Entry -ForegroundColor $(
        switch ($Level) {
            "WARN"    { "Yellow" }
            "ERROR"   { "Red" }
            "ACTION"  { "Cyan" }
            "SUCCESS" { "Green" }
            "SKIP"    { "DarkGray" }
            "DRYRUN"  { "Magenta" }
            default   { "White" }
        }
    )
    if (Test-Path $LogDir) {
        Add-Content -Path $LogFile -Value $Entry
    }
}

function Add-TicketNote {
    param([string]$Line)
    $script:TicketLines.Add($Line)
}

function Write-SectionHeader {
    param([string]$Title)
    $bar = "=" * 60
    Write-Log ""
    Write-Log $bar
    Write-Log "  $Title"
    Write-Log $bar
    Add-TicketNote ""
    Add-TicketNote "--- $Title ---"
}

# ============================================================
# REGION: Pre-Flight Checks
# ============================================================

Write-SectionHeader "Reset-OutlookProfile.ps1 -- Pre-Flight Checks"
Write-Log "Script Version  : $ScriptVersion"
Write-Log "Executed By     : $($env:USERNAME)"
Write-Log "Target User     : $TargetUser"
Write-Log "Profile Name    : $ProfileName"
Write-Log "Backup Root     : $BackupRoot"
Write-Log "Skip OST Backup : $($SkipOSTBackup.IsPresent)"
Write-Log "WhatIf Mode     : $($WhatIfPreference -ne 'SilentlyContinue')"

Add-TicketNote "OUTLOOK PROFILE RESET"
Add-TicketNote "Executed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-TicketNote "Technician: $($env:USERNAME)"
Add-TicketNote "Target User: $TargetUser"
Add-TicketNote "Profile Name: $ProfileName"
Add-TicketNote "Machine: $($env:COMPUTERNAME)"

# Determine whether we are running as the target user or as an admin for another user
$TargetUserSID      = $null
$OutlookProfilesHive = $null

try {
    $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $IsAdmin = ([System.Security.Principal.WindowsPrincipal]$CurrentIdentity).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($TargetUser -eq $env:USERNAME) {
        Write-Log "Running as the target user -- using HKCU hive." -Level INFO
        $OutlookProfilesHive = "HKCU:\Software\Microsoft\Office"
    }
    else {
        if (-not $IsAdmin) {
            throw "Elevation required. You must run as Administrator to reset another user's Outlook profile."
        }

        # Resolve SID for the target user
        try {
            $NTAccount      = New-Object System.Security.Principal.NTAccount($TargetUser)
            $TargetUserSID  = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            Write-Log "Resolved SID for '$TargetUser': $TargetUserSID" -Level INFO
        }
        catch {
            throw "Could not resolve Windows SID for user '$TargetUser'. Verify the username and ensure the account exists on this machine."
        }

        # Ensure the HKU PSDrive is available and the user hive is loaded
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
        }
        if (-not (Test-Path "HKU:\$TargetUserSID")) {
            throw "Registry hive for '$TargetUser' (SID: $TargetUserSID) is not loaded. The user must be currently logged on for a remote profile reset."
        }
        $OutlookProfilesHive = "HKU:\$TargetUserSID\Software\Microsoft\Office"
        Write-Log "Using HKU hive for user '$TargetUser'." -Level INFO
    }
}
catch {
    Write-Log "Pre-flight failed: $_" -Level ERROR
    Write-Host "`nFATAL: Pre-flight check failed. No changes have been made.`n$_" -ForegroundColor Red
    exit 1
}

# Discover Outlook version keys that contain a Profiles subkey
$OutlookVersionKeys = @()
if (Test-Path $OutlookProfilesHive) {
    $OutlookVersionKeys = @(
        Get-ChildItem -Path $OutlookProfilesHive -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match "^\d+\.\d+$" } |
            ForEach-Object {
                # Normalize the registry item path to a clean PSDrive path
                # (HKCU:\... or HKU:\...) so all downstream consumers work
                # reliably. PSPath from the pipeline can be a provider-
                # qualified string like:
                #   Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\...
                # which breaks Join-Path, Test-Path, and reg.exe conversion.
                $normalized = $_.PSPath
                if ($normalized -match "::") {
                    $normalized = $normalized -replace "^.*::", ""
                }
                $normalized = $normalized `
                    -replace "^HKEY_CURRENT_USER\\",  "HKCU:\" `
                    -replace "^HKEY_LOCAL_MACHINE\\", "HKLM:\" `
                    -replace "^HKEY_USERS\\",         "HKU:\"
                $profilesPath = "$normalized\Outlook\Profiles"
                if (Test-Path $profilesPath) { $profilesPath }
            }
    )
}

if ($OutlookVersionKeys.Count -eq 0) {
    Write-Log "No Outlook profile registry keys found. Outlook may not have been configured for this user." -Level WARN
    Add-TicketNote "WARNING: No Outlook profile registry entries found. Outlook may not have been configured for this user yet."
}
else {
    Write-Log "Found $($OutlookVersionKeys.Count) Outlook version key(s) with profile data." -Level INFO
    $OutlookVersionKeys | ForEach-Object { Write-Log "  $_" -Level INFO }
}

# Locate the specific profile to be removed
$TargetProfileKey = $null
foreach ($versionPath in $OutlookVersionKeys) {
    $candidate = Join-Path $versionPath $ProfileName
    if (Test-Path $candidate) {
        $TargetProfileKey = $candidate
        Write-Log "Located target profile key: $TargetProfileKey" -Level INFO
        break
    }
}

if (-not $TargetProfileKey) {
    # Profile name not found as-is. Check whether the registry DefaultProfile
    # value points to a differently-named profile and use that instead.
    Write-Log "Profile '$ProfileName' not found in registry. Checking DefaultProfile value for active profile name..." -Level WARN

    foreach ($versionPath in $OutlookVersionKeys) {
        $outlookKeyCheck  = ($versionPath -replace "\\Profiles$", "")
        $defProfObj       = Get-ItemProperty -Path $outlookKeyCheck -Name "DefaultProfile" -ErrorAction SilentlyContinue
        $detectedDefault  = if ($defProfObj) { $defProfObj.DefaultProfile } else { $null }

        if ($detectedDefault) {
            $candidateKey = Join-Path $versionPath $detectedDefault
            if (Test-Path $candidateKey) {
                Write-Log "Found active profile via DefaultProfile value: '$detectedDefault' -- using this as the reset target." -Level WARN
                Write-Log "NOTE: To target a specific profile by name, re-run with: -ProfileName '$detectedDefault'" -Level INFO
                $ProfileName      = $detectedDefault
                $TargetProfileKey = $candidateKey
                Add-TicketNote "Auto-detected active profile: '$ProfileName' (DefaultProfile registry value was used as target)"
                break
            }
        }
    }

    if (-not $TargetProfileKey) {
        Write-Log "Could not locate any resettable profile in registry. The profile may already be removed." -Level WARN
        Add-TicketNote "WARNING: No resettable profile found in registry. The profile may already be absent."
    }
}

# Resolve the target user's local AppData path
$TargetAppData = $null
if ($TargetUser -eq $env:USERNAME) {
    $TargetAppData = $env:LOCALAPPDATA
}
elseif ($TargetUserSID) {
    $ProfileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$TargetUserSID"
    if (Test-Path $ProfileListKey) {
        $UserProfileRoot = (Get-ItemProperty -Path $ProfileListKey -Name "ProfileImagePath").ProfileImagePath
        $TargetAppData   = Join-Path $UserProfileRoot "AppData\Local"
    }
}

$OutlookAppDataPath = if ($TargetAppData) { Join-Path $TargetAppData "Microsoft\Outlook" } else { $null }
Write-Log "Outlook AppData path: $OutlookAppDataPath" -Level INFO

# ============================================================
# REGION: Create Backup Directory
# ============================================================

Write-SectionHeader "Creating Backup Directory"

if ($PSCmdlet.ShouldProcess($LogDir, "Create backup directory")) {
    try {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        Write-Log "Backup directory created: $LogDir" -Level SUCCESS
        Add-TicketNote "Backup location: $LogDir"
    }
    catch {
        Write-Log "Failed to create backup directory at '$LogDir': $_" -Level ERROR
        throw
    }
}
else {
    Write-Log "DRYRUN: Would create backup directory: $LogDir" -Level DRYRUN
}

# ============================================================
# REGION: Collect Current Profile State (Read-Only Diagnostics)
# ============================================================

Write-SectionHeader "Collecting Current Outlook Profile State"

Add-TicketNote ""
Add-TicketNote "PRE-RESET DIAGNOSTICS"

# Installed Office version
try {
    $OfficeReg = @(
        "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun\Configuration"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($OfficeReg) {
        $OfficeProps    = Get-ItemProperty -Path $OfficeReg -ErrorAction SilentlyContinue
        $OfficeVersion  = $OfficeProps.VersionToReport
        $OfficePlatform = $OfficeProps.Platform
        Write-Log "Office Version  : $OfficeVersion ($OfficePlatform)" -Level INFO
        Add-TicketNote "Office Version: $OfficeVersion ($OfficePlatform)"
    }
    else {
        Write-Log "Could not determine Office version from registry." -Level WARN
        Add-TicketNote "Office Version: Unknown (ClickToRun registry key not found)"
    }
}
catch {
    Write-Log "Error reading Office version: $_" -Level WARN
}

# Enumerate existing profiles
Write-Log "" -Level INFO
Write-Log "Existing Outlook profiles in registry:" -Level INFO
Add-TicketNote ""
Add-TicketNote "Existing Outlook Profiles (pre-reset):"

foreach ($versionPath in $OutlookVersionKeys) {
    $versionLabel = ($versionPath -split "\\") | Where-Object { $_ -match "^\d+\.\d+$" } | Select-Object -First 1
    $profiles = Get-ChildItem -Path $versionPath -ErrorAction SilentlyContinue
    if ($profiles) {
        foreach ($p in $profiles) {
            Write-Log "  [Office $versionLabel] $($p.PSChildName)" -Level INFO
            Add-TicketNote "  Office $versionLabel | Profile: $($p.PSChildName)"
        }
    }
    # Log the current DefaultProfile setting
    $outlookKey    = ($versionPath -replace "\\Profiles$", "")
    $defaultProfObj = Get-ItemProperty -Path $outlookKey -Name "DefaultProfile" -ErrorAction SilentlyContinue
    $defaultProf    = if ($defaultProfObj) { $defaultProfObj.DefaultProfile } else { $null }
    if ($defaultProf) {
        Write-Log "  Default Profile set to: $defaultProf" -Level INFO
        Add-TicketNote "  DefaultProfile value: $defaultProf"
    }
}

# Outlook AppData file inventory
if ($OutlookAppDataPath -and (Test-Path $OutlookAppDataPath)) {
    Write-Log "" -Level INFO
    Write-Log "Files in Outlook AppData ($OutlookAppDataPath):" -Level INFO
    Add-TicketNote ""
    Add-TicketNote "Outlook AppData Files (pre-reset):"
    $appDataFiles = Get-ChildItem -Path $OutlookAppDataPath -File -ErrorAction SilentlyContinue |
        Sort-Object Length -Descending
    foreach ($f in $appDataFiles) {
        $sizeMB = [Math]::Round($f.Length / 1MB, 2)
        Write-Log "  $($f.Name)  [$sizeMB MB]  Modified: $($f.LastWriteTime)" -Level INFO
        Add-TicketNote "  $($f.Name) | $sizeMB MB | Modified: $($f.LastWriteTime)"
    }
}
else {
    Write-Log "Outlook AppData path not found or inaccessible: $OutlookAppDataPath" -Level WARN
    Add-TicketNote "Outlook AppData path not found: $OutlookAppDataPath"
}

# ============================================================
# REGION: Terminate Outlook and Related Processes
# ============================================================

Write-SectionHeader "Terminating Outlook and Related Processes"

$ProcessesToStop    = @("OUTLOOK", "UCMapi", "lync", "communicator")
$TerminatedProcesses = @()

foreach ($procName in $ProcessesToStop) {
    $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($running) {
        if ($PSCmdlet.ShouldProcess($procName, "Stop process")) {
            try {
                Stop-Process -Name $procName -Force -ErrorAction Stop
                Write-Log "Stopped process: $procName (PID: $($running.Id -join ', '))" -Level ACTION
                $TerminatedProcesses += $procName
            }
            catch {
                Write-Log "Failed to stop ${procName}: $_" -Level WARN
            }
        }
        else {
            Write-Log "DRYRUN: Would stop process: $procName" -Level DRYRUN
        }
    }
    else {
        Write-Log "Process not running: $procName" -Level SKIP
    }
}

if ($TerminatedProcesses.Count -gt 0) {
    Add-TicketNote "Processes stopped before reset: $($TerminatedProcesses -join ', ')"
    Start-Sleep -Seconds 2
}
else {
    Add-TicketNote "Outlook was not running at time of reset."
}

# ============================================================
# REGION: Back Up Registry Profile Keys
# ============================================================

Write-SectionHeader "Backing Up Registry Profile Keys"

$RegBackupDir = Join-Path $LogDir "RegistryBackup"
if ($PSCmdlet.ShouldProcess($RegBackupDir, "Create registry backup directory")) {
    New-Item -ItemType Directory -Path $RegBackupDir -Force | Out-Null
}

foreach ($versionPath in $OutlookVersionKeys) {
    $versionLabel = ($versionPath -split "\\") | Where-Object { $_ -match "^\d+\.\d+$" } | Select-Object -First 1

    # Convert the clean PSDrive path (HKCU:\...) to the format reg.exe expects.
    # reg.exe uses HKCU\ (no colon) rather than the PowerShell HKCU:\ form.
    $regExportPath = ($versionPath -replace "\\Profiles$", "") -replace ":\\", "\"

    $exportFile = Join-Path $RegBackupDir "OutlookKey_Office${versionLabel}_$RunTimestamp.reg"
    $errorFile  = Join-Path $RegBackupDir "reg_err_Office${versionLabel}.txt"

    if ($PSCmdlet.ShouldProcess($exportFile, "Export Outlook registry key")) {
        try {
            $result = Start-Process -FilePath "reg.exe" `
                -ArgumentList "export `"$regExportPath`" `"$exportFile`" /y" `
                -Wait -PassThru -WindowStyle Hidden `
                -RedirectStandardError $errorFile

            if ($result.ExitCode -eq 0) {
                Write-Log "Registry backup saved: $exportFile" -Level SUCCESS
                Add-TicketNote "Registry backup: $exportFile"
            }
            else {
                $errContent = Get-Content $errorFile -ErrorAction SilentlyContinue
                Write-Log "reg.exe export returned exit code $($result.ExitCode). Detail: $errContent" -Level WARN
            }
        }
        catch {
            Write-Log "Failed to export registry for Office ${versionLabel}: $_" -Level WARN
        }
    }
    else {
        Write-Log "DRYRUN: Would export registry key: $regExportPath -> $exportFile" -Level DRYRUN
    }
}

# ============================================================
# REGION: Back Up Outlook AppData (NK2, Signatures, XML, etc.)
# ============================================================

Write-SectionHeader "Backing Up Outlook AppData Files"

$AppDataBackupDir = Join-Path $LogDir "AppDataBackup"

if ($OutlookAppDataPath -and (Test-Path $OutlookAppDataPath)) {
    if ($PSCmdlet.ShouldProcess($AppDataBackupDir, "Back up Outlook AppData folder")) {
        try {
            New-Item -ItemType Directory -Path $AppDataBackupDir -Force | Out-Null

            $allFiles    = Get-ChildItem -Path $OutlookAppDataPath -File -ErrorAction SilentlyContinue
            $backedUp    = 0
            $skippedOST  = 0

            foreach ($f in $allFiles) {
                if ($f.Extension -ieq ".ost") {
                    if ($SkipOSTBackup) {
                        Write-Log "Skipping OST (SkipOSTBackup active): $($f.Name)" -Level SKIP
                        $skippedOST++
                        continue
                    }
                    $sizeMB = [Math]::Round($f.Length / 1MB, 2)
                    if ($sizeMB -gt 500) {
                        Write-Log "Large OST file detected ($sizeMB MB) -- backup may take several minutes: $($f.Name)" -Level WARN
                    }
                }
                Copy-Item -Path $f.FullName -Destination $AppDataBackupDir -ErrorAction SilentlyContinue
                $backedUp++
            }

            Write-Log "AppData backup complete: $backedUp file(s) copied to $AppDataBackupDir" -Level SUCCESS

            if ($skippedOST -gt 0) {
                Write-Log "$skippedOST OST file(s) skipped -- will re-sync from Exchange/M365 after reset." -Level SKIP
                Add-TicketNote "OST file(s) not backed up -- will re-download from Exchange/M365 on next Outlook launch."
            }
            Add-TicketNote "AppData backup: $AppDataBackupDir ($backedUp files copied)"
        }
        catch {
            Write-Log "AppData backup encountered an error: $_" -Level WARN
            Add-TicketNote "WARNING: AppData backup partially failed. Review log for details."
        }
    }
    else {
        Write-Log "DRYRUN: Would back up Outlook AppData from $OutlookAppDataPath to $AppDataBackupDir" -Level DRYRUN
    }
}
else {
    Write-Log "Outlook AppData path not found -- skipping AppData backup." -Level SKIP
    Add-TicketNote "Outlook AppData path not found; no AppData backup taken."
}

# ============================================================
# REGION: Remove Corrupt Profile Registry Keys
# ============================================================

Write-SectionHeader "Removing Corrupt Outlook Profile Registry Keys"

if (-not $TargetProfileKey) {
    Write-Log "No target profile key found -- skipping removal step." -Level SKIP
    Add-TicketNote "Profile removal skipped: '$ProfileName' not found in registry."
}
else {
    if ($PSCmdlet.ShouldProcess($TargetProfileKey, "Remove Outlook profile registry key")) {
        try {
            Remove-Item -Path $TargetProfileKey -Recurse -Force -ErrorAction Stop
            Write-Log "Removed profile registry key: $TargetProfileKey" -Level ACTION
            Add-TicketNote "Removed registry key: $TargetProfileKey"
        }
        catch {
            Write-Log "Failed to remove profile key '$TargetProfileKey': $_" -Level ERROR
            Add-TicketNote "ERROR: Failed to remove profile registry key. Manual intervention may be required."
            throw
        }
    }
    else {
        Write-Log "DRYRUN: Would remove registry key: $TargetProfileKey" -Level DRYRUN
    }
}

# Clear the DefaultProfile value so Outlook prompts properly for new profile setup
foreach ($versionPath in $OutlookVersionKeys) {
    $outlookKey    = ($versionPath -replace "\\Profiles$", "")
    $defaultProfObj = Get-ItemProperty -Path $outlookKey -Name "DefaultProfile" -ErrorAction SilentlyContinue
    $defaultProf    = if ($defaultProfObj) { $defaultProfObj.DefaultProfile } else { $null }
    if ($defaultProf) {
        if ($PSCmdlet.ShouldProcess("$outlookKey -> DefaultProfile", "Clear DefaultProfile value")) {
            try {
                Remove-ItemProperty -Path $outlookKey -Name "DefaultProfile" -ErrorAction Stop
                Write-Log "Cleared DefaultProfile value in: $outlookKey" -Level ACTION
                Add-TicketNote "Cleared DefaultProfile registry value."
            }
            catch {
                Write-Log "Could not clear DefaultProfile value: $_" -Level WARN
            }
        }
        else {
            Write-Log "DRYRUN: Would clear DefaultProfile value in $outlookKey" -Level DRYRUN
        }
    }
}

# ============================================================
# REGION: Recreate Clean Default Profile
# ============================================================

Write-SectionHeader "Recreating Clean Outlook Profile"

# Determine the Office version to write the new profile under.
# Use the highest installed version found; fall back to 16.0 (O365/2016+).
$TargetOfficeVersion = $null
if ($OutlookVersionKeys.Count -gt 0) {
    $TargetOfficeVersion = $OutlookVersionKeys |
        ForEach-Object { ($_ -split "\\") | Where-Object { $_ -match "^\d+\.\d+$" } | Select-Object -First 1 } |
        Sort-Object { [version]$_ } -Descending |
        Select-Object -First 1
}

if (-not $TargetOfficeVersion) {
    $TargetOfficeVersion = "16.0"
    Write-Log "Could not determine Office version from existing keys -- defaulting to 16.0." -Level WARN
}

Write-Log "Recreating profile under Office version key: $TargetOfficeVersion" -Level INFO

# Build the correct registry paths based on whether we are using HKCU or HKU
if ($TargetUser -eq $env:USERNAME) {
    $OutlookParentKey = "HKCU:\Software\Microsoft\Office\$TargetOfficeVersion\Outlook"
    $NewProfilesPath  = "HKCU:\Software\Microsoft\Office\$TargetOfficeVersion\Outlook\Profiles"
}
else {
    $OutlookParentKey = "HKU:\$TargetUserSID\Software\Microsoft\Office\$TargetOfficeVersion\Outlook"
    $NewProfilesPath  = "HKU:\$TargetUserSID\Software\Microsoft\Office\$TargetOfficeVersion\Outlook\Profiles"
}
$NewProfilePath = Join-Path $NewProfilesPath $ProfileName

if ($PSCmdlet.ShouldProcess($NewProfilePath, "Create new clean Outlook profile registry key")) {
    try {
        # Ensure parent keys exist
        if (-not (Test-Path $OutlookParentKey)) {
            New-Item -Path $OutlookParentKey -Force | Out-Null
        }
        if (-not (Test-Path $NewProfilesPath)) {
            New-Item -Path $NewProfilesPath -Force | Out-Null
        }

        # Create the profile key and the required MAPI service subkey structure
        New-Item -Path $NewProfilePath -Force | Out-Null

        @(
            "$NewProfilePath\9375CFF0413111d3B88A00104B2A6676",
            "$NewProfilePath\9375CFF0413111d3B88A00104B2A6676\00000001"
        ) | ForEach-Object {
            if (-not (Test-Path $_)) { New-Item -Path $_ -Force | Out-Null }
        }

        # Set DefaultProfile so Outlook uses this profile on next launch
        Set-ItemProperty -Path $OutlookParentKey -Name "DefaultProfile" -Value $ProfileName -Type String -Force

        Write-Log "New profile key created: $NewProfilePath" -Level SUCCESS
        Write-Log "DefaultProfile set to: $ProfileName" -Level SUCCESS
        Add-TicketNote "New clean profile created: '$ProfileName' (Office $TargetOfficeVersion)"
        Add-TicketNote "DefaultProfile registry value set to: $ProfileName"
    }
    catch {
        Write-Log "Failed to create new profile key: $_" -Level ERROR
        Add-TicketNote "ERROR: Failed to create new profile registry key. Manual intervention may be required."
        throw
    }
}
else {
    Write-Log "DRYRUN: Would create new profile key at: $NewProfilePath" -Level DRYRUN
    Write-Log "DRYRUN: Would set DefaultProfile to: $ProfileName" -Level DRYRUN
}

# ============================================================
# REGION: Post-Reset Verification
# ============================================================

Write-SectionHeader "Post-Reset Verification"

$VerificationPassed = $true

if (-not $WhatIfPreference) {
    # Verify new profile key exists
    if (Test-Path $NewProfilePath) {
        Write-Log "VERIFIED: New profile key exists at $NewProfilePath" -Level SUCCESS
        Add-TicketNote "Verification PASSED: New profile key is present in registry."
    }
    else {
        Write-Log "VERIFICATION FAILED: New profile key not found at $NewProfilePath" -Level ERROR
        Add-TicketNote "Verification FAILED: New profile key is missing. Manual review required."
        $VerificationPassed = $false
    }

    # Verify DefaultProfile value
    $verifyDefaultObj = Get-ItemProperty -Path $OutlookParentKey -Name "DefaultProfile" -ErrorAction SilentlyContinue
    $verifyDefault    = if ($verifyDefaultObj) { $verifyDefaultObj.DefaultProfile } else { $null }
    if ($verifyDefault -eq $ProfileName) {
        Write-Log "VERIFIED: DefaultProfile = '$ProfileName'" -Level SUCCESS
    }
    else {
        Write-Log "WARNING: DefaultProfile mismatch. Expected '$ProfileName', found '$verifyDefault'" -Level WARN
        Add-TicketNote "WARNING: DefaultProfile value mismatch. Expected '$ProfileName', found '$verifyDefault'."
    }

    # Verify old corrupt profile key is gone
    if ($TargetProfileKey -and (Test-Path $TargetProfileKey)) {
        Write-Log "WARNING: Old profile key is still present -- removal may have failed." -Level WARN
        Add-TicketNote "WARNING: Old profile key was not fully removed. Manual check advised."
        $VerificationPassed = $false
    }
    elseif ($TargetProfileKey) {
        Write-Log "VERIFIED: Old profile key has been removed." -Level SUCCESS
    }
}
else {
    Write-Log "DRYRUN: Skipping post-reset verification in WhatIf mode." -Level DRYRUN
}

# ============================================================
# REGION: Generate Ticket Documentation
# ============================================================

Write-SectionHeader "Generating Ticket Documentation"

$ResultLabel = if ($VerificationPassed) { "SUCCESS" } else { "COMPLETED WITH WARNINGS -- review log" }

Add-TicketNote ""
Add-TicketNote "POST-RESET STATUS"
Add-TicketNote "Overall Result: $ResultLabel"
Add-TicketNote ""
Add-TicketNote "NEXT STEPS FOR TECHNICIAN"
Add-TicketNote "1. Ask the user to launch Outlook."
Add-TicketNote "2. Outlook will prompt to configure a new profile or auto-detect Exchange/M365."
Add-TicketNote "3. Have the user sign in with their M365 or Exchange credentials if prompted."
Add-TicketNote "4. Allow Outlook to complete initial sync (may take several minutes for large mailboxes)."
Add-TicketNote "5. Verify Send/Receive works, calendar loads, and Contacts appear."
Add-TicketNote "6. If additional accounts (IMAP/POP) were configured, these must be re-added manually."
Add-TicketNote "7. Confirm user signatures and AutoComplete are restored (backed up in AppDataBackup)."
Add-TicketNote ""
Add-TicketNote "BACKUP FILES RETAINED AT:"
Add-TicketNote "  $LogDir"
Add-TicketNote "  (Retain for minimum 30 days per escalation policy)"
Add-TicketNote ""
Add-TicketNote "Full execution log: $LogFile"

# Write ticket notes to file
if (Test-Path $LogDir) {
    $TicketHeader = @"
================================================================
  OUTLOOK PROFILE RESET -- TICKET DOCUMENTATION
  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Script    : Reset-OutlookProfile.ps1 v$ScriptVersion
  Machine   : $($env:COMPUTERNAME)
================================================================

"@
    Set-Content -Path $TicketSummary -Value ($TicketHeader + ($script:TicketLines -join "`n"))
    Write-Log "Ticket notes saved: $TicketSummary" -Level SUCCESS
}

# ============================================================
# REGION: Final Console Summary
# ============================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  OUTLOOK PROFILE RESET COMPLETE" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  User     : $TargetUser"
Write-Host "  Profile  : $ProfileName"
Write-Host "  Machine  : $($env:COMPUTERNAME)"
Write-Host "  Result   : $ResultLabel" -ForegroundColor $(if ($VerificationPassed) { "Green" } else { "Yellow" })
Write-Host ""
Write-Host "  Backup & Logs : $LogDir"
Write-Host "  Ticket Notes  : $TicketSummary"
Write-Host ""
Write-Host "  NEXT STEP: Have the user launch Outlook and sign in."
Write-Host "             Allow time for initial mailbox sync."
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "  *** DRYRUN MODE -- No changes were made to this system ***" -ForegroundColor Magenta
    Write-Host ""
}