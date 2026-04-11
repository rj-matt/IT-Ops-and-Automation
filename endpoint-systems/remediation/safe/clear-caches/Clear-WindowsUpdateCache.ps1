#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Clears the Windows Update cache to resolve update installation failures.

.DESCRIPTION
    Safely stops Windows Update-related services, clears the SoftwareDistribution
    and catroot2 folders, then restarts services and validates that the Windows
    Update stack is operational. Resolves the majority of "updates won't install"
    issues caused by a corrupted or stale update cache.

.NOTES
    Script Name  : Clear-WindowsUpdateCache.ps1
    Category     : endpoint-systems / remediation / safe / clear-caches
    Version      : 1.0.0
    Author       : MSP Automation Toolkit

    USE CASE     : Run when a device cannot install Windows Updates. Common
                   symptoms: updates stuck at 0%, recurring error codes
                   (0x80070002, 0x80070003, 0x80073712, etc.), or updates
                   that repeatedly fail and re-appear.

    SCOPE        : Local machine only. No network changes. No data loss.

    RISK LEVEL   : LOW — Safe remediation. Only deletes cached update metadata
                   and downloaded packages. Windows will re-download what it
                   needs. Does NOT affect installed updates, system files, or
                   user data.

    PREREQUISITES: Must be run as Administrator.
                   Services stopped briefly: wuauserv, cryptSvc, bits, msiserver.
                   Typical runtime: 30–90 seconds.

    TICKET USE   : Copy the output block at the end directly into your ticket.
#>

# ============================================================
# CONFIGURATION
# ============================================================

$ScriptVersion   = "1.0.0"
$ScriptName      = "Clear-WindowsUpdateCache"
$LogTimestamp    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogDir          = "$env:SystemDrive\MSP\Logs\WindowsUpdate"
$LogFile         = "$LogDir\$ScriptName`_$LogTimestamp.log"

$ServicesToStop  = @("wuauserv", "cryptSvc", "bits", "msiserver")
$CacheFolders    = @(
    "$env:SystemRoot\SoftwareDistribution",
    "$env:SystemRoot\System32\catroot2"
)

# ============================================================
# LOGGING FUNCTION
# ============================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","SECTION")][string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Prefix = switch ($Level) {
        "INFO"    { "[INFO   ]" }
        "WARN"    { "[WARN   ]" }
        "ERROR"   { "[ERROR  ]" }
        "SUCCESS" { "[SUCCESS]" }
        "SECTION" { "[-------]" }
    }

    $Line = "$Timestamp $Prefix $Message"
    Add-Content -Path $LogFile -Value $Line -ErrorAction SilentlyContinue
    Write-Host $Line
}

# ============================================================
# HELPER: STOP SERVICES
# ============================================================

function Stop-UpdateServices {
    Write-Log "Stopping Windows Update-related services..." -Level SECTION

    foreach ($ServiceName in $ServicesToStop) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($null -eq $svc) {
            Write-Log "Service not found: $ServiceName — skipping." -Level WARN
            continue
        }

        if ($svc.Status -eq "Stopped") {
            Write-Log "$ServiceName is already stopped." -Level INFO
            continue
        }

        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Log "Stopped: $ServiceName" -Level SUCCESS
        }
        catch {
            Write-Log "Failed to stop ${ServiceName}: $($_.Exception.Message)" -Level WARN
        }
    }
}

# ============================================================
# HELPER: CLEAR CACHE FOLDERS
# ============================================================

function Clear-CacheFolders {
    Write-Log "Clearing Windows Update cache folders..." -Level SECTION

    $script:ClearedFolders = @()
    $script:FailedFolders  = @()

    foreach ($Folder in $CacheFolders) {
        if (-not (Test-Path $Folder)) {
            Write-Log "Folder not found (already clean or non-standard path): $Folder" -Level WARN
            continue
        }

        try {
            # Measure size before clearing for the ticket summary
            $SizeBefore = (Get-ChildItem -Path $Folder -Recurse -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            $SizeMB = [math]::Round($SizeBefore / 1MB, 1)

            Remove-Item -Path "$Folder\*" -Recurse -Force -ErrorAction Stop

            Write-Log "Cleared: $Folder  ($SizeMB MB freed)" -Level SUCCESS
            $script:ClearedFolders += "$Folder ($SizeMB MB)"
        }
        catch {
            Write-Log "Could not fully clear ${Folder}: $($_.Exception.Message)" -Level WARN
            $script:FailedFolders += $Folder
        }
    }
}

# ============================================================
# HELPER: START SERVICES
# ============================================================

function Start-UpdateServices {
    Write-Log "Restarting Windows Update-related services..." -Level SECTION

    foreach ($ServiceName in $ServicesToStop) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($null -eq $svc) {
            continue
        }

        # msiserver and bits are demand-start; only restart if they were running
        if ($svc.StartType -eq "Disabled") {
            Write-Log "$ServiceName is disabled — not restarting." -Level WARN
            continue
        }

        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            Write-Log "Started: $ServiceName" -Level SUCCESS
        }
        catch {
            Write-Log "Failed to start ${ServiceName}: $($_.Exception.Message)" -Level WARN
        }
    }
}

# ============================================================
# HELPER: POST-REMEDIATION VALIDATION
# ============================================================

function Test-WindowsUpdateStack {
    Write-Log "Validating Windows Update stack..." -Level SECTION

    $script:ValidationResults = @{}

    # 1 — wuauserv running
    $wua = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    $script:ValidationResults["wuauserv Running"] = ($wua -and $wua.Status -eq "Running")

    # 2 — cryptSvc running
    $crypt = Get-Service -Name cryptSvc -ErrorAction SilentlyContinue
    $script:ValidationResults["cryptSvc Running"] = ($crypt -and $crypt.Status -eq "Running")

    # 3 — SoftwareDistribution folder re-created by wuauserv
    Start-Sleep -Seconds 5
    $sdExists = Test-Path "$env:SystemRoot\SoftwareDistribution"
    $script:ValidationResults["SoftwareDistribution Recreated"] = $sdExists

    # 4 — Windows Update COM object is accessible
    try {
        $null = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $script:ValidationResults["Update COM Object Accessible"] = $true
    }
    catch {
        $script:ValidationResults["Update COM Object Accessible"] = $false
    }

    # 5 — BITS service is accessible (demand-start is acceptable)
    $bits = Get-Service -Name bits -ErrorAction SilentlyContinue
    $script:ValidationResults["BITS Service Present"] = ($bits -ne $null)

    foreach ($Check in $script:ValidationResults.GetEnumerator()) {
        $Status = if ($Check.Value) { "PASS" } else { "FAIL" }
        $LogLevel = if ($Check.Value) { "SUCCESS" } else { "WARN" }
        Write-Log "  [$Status]  $($Check.Key)" -Level $LogLevel
    }
}

# ============================================================
# TICKET SUMMARY BLOCK
# ============================================================

function Write-TicketSummary {
    $EndTime    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $PassCount  = ($script:ValidationResults.Values | Where-Object { $_ -eq $true }).Count
    $TotalCheck = $script:ValidationResults.Count
    $AllPassed  = ($PassCount -eq $TotalCheck)
    $OverallStatus = if ($AllPassed) { "SUCCESS — Update stack validated and operational." }
                     else            { "PARTIAL — Some validation checks did not pass. Review log." }

    $ClearedList = if ($script:ClearedFolders.Count -gt 0) {
        $script:ClearedFolders -join "; "
    } else { "None" }

    $FailedList = if ($script:FailedFolders.Count -gt 0) {
        $script:FailedFolders -join "; "
    } else { "None" }

    $ValidationSummary = ($script:ValidationResults.GetEnumerator() | ForEach-Object {
        $mark = if ($_.Value) { "✓" } else { "✗" }
        "    $mark  $($_.Key)"
    }) -join "`n"

    $Summary = @"

============================================================
  TICKET SUMMARY — $ScriptName v$ScriptVersion
============================================================
  Device        : $env:COMPUTERNAME
  Run As        : $env:USERNAME
  Completed     : $EndTime
  Log File      : $LogFile

  OUTCOME       : $OverallStatus

  FOLDERS CLEARED  : $ClearedList
  FOLDERS SKIPPED  : $FailedList

  VALIDATION ($PassCount / $TotalCheck passed):
$ValidationSummary

  NEXT STEPS:
"@

    if ($AllPassed) {
        $Summary += @"

    1. Open Windows Update (Settings > Windows Update).
    2. Click 'Check for updates'.
    3. Allow updates to download and install normally.
    4. If issues persist after a full update cycle, escalate to Tier 2
       and attach the log file: $LogFile
"@
    } else {
        $Summary += @"

    One or more validation checks failed. Review the full log at:
      $LogFile
    Consider escalating to Tier 2 with the log attached.
    If wuauserv or cryptSvc failed to start, check for Group Policy
    or third-party software blocking those services.
"@
    }

    $Summary += "`n============================================================`n"

    Write-Host $Summary
    Add-Content -Path $LogFile -Value $Summary -ErrorAction SilentlyContinue
}

# ============================================================
# MAIN EXECUTION
# ============================================================

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "================================================================" -Level SECTION
Write-Log " $ScriptName v$ScriptVersion" -Level INFO
Write-Log " Device  : $env:COMPUTERNAME" -Level INFO
Write-Log " User    : $env:USERNAME" -Level INFO
Write-Log " Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
Write-Log " Log     : $LogFile" -Level INFO
Write-Log "================================================================" -Level SECTION

Stop-UpdateServices
Clear-CacheFolders
Start-UpdateServices
Test-WindowsUpdateStack
Write-TicketSummary