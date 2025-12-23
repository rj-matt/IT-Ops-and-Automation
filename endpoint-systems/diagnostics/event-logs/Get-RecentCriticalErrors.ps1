<#
.SYNOPSIS
    Retrieves recent critical and error events from System and Application logs.

.DESCRIPTION
    This diagnostic script queries Windows Event Logs for critical and error-level 
    events from the past 24-48 hours. It filters out common noise and presents 
    actionable events in a format suitable for ticket documentation.
    
    Domain: endpoint-systems/diagnostics/event-logs
    Risk Level: SAFE (Read-Only)
    
.PARAMETER Hours
    Number of hours to look back. Default is 24 hours.
    Valid range: 1-168 (1 week maximum)

.PARAMETER IncludeWarnings
    Include Warning-level events in addition to Critical and Error events.

.PARAMETER ExcludeCommonNoise
    Filter out commonly recurring non-actionable events. Default is $true.

.PARAMETER ExportPath
    Optional. Path to export results as CSV for ticket attachment.

.EXAMPLE
    .\Get-RecentCriticalErrors.ps1
    Retrieves critical and error events from the last 24 hours.

.EXAMPLE
    .\Get-RecentCriticalErrors.ps1 -Hours 48
    Retrieves events from the last 48 hours.

.EXAMPLE
    .\Get-RecentCriticalErrors.ps1 -Hours 24 -IncludeWarnings -ExportPath "C:\Temp\errors.csv"
    Retrieves errors and warnings from last 24 hours and exports to CSV.

.NOTES
    Author: MSP Automation Team
    Version: 1.0
    Prerequisites: 
        - Local Administrator rights (required for full event log access)
        - PowerShell 5.1 or later
    
    Use Case:
        - Troubleshooting system instability
        - Investigating application crashes
        - Pre-emptive health checks
        - Incident response documentation
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 168)]
    [int]$Hours = 24,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeWarnings,

    [Parameter(Mandatory = $false)]
    [bool]$ExcludeCommonNoise = $true,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -match '\.(csv|txt)$') { $true }
        else { throw "ExportPath must end with .csv or .txt" }
    })]
    [string]$ExportPath
)

#Requires -Version 5.1

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = "Continue"
$ScriptVersion = "1.0"
$StartTime = Get-Date

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Recent Critical Errors Diagnostic" -ForegroundColor Cyan
Write-Host "  Version: $ScriptVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some event logs may not be accessible."
    Write-Host "For complete results, run this script with elevated privileges." -ForegroundColor Yellow
    Write-Host ""
}

# Display parameters
Write-Host "Configuration:" -ForegroundColor Green
Write-Host "  Time Range: Last $Hours hours" -ForegroundColor Gray
Write-Host "  Start Time: $($StartTime.AddHours(-$Hours).ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "  End Time: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "  Include Warnings: $IncludeWarnings" -ForegroundColor Gray
Write-Host "  Filter Common Noise: $ExcludeCommonNoise" -ForegroundColor Gray
if ($ExportPath) {
    Write-Host "  Export Path: $ExportPath" -ForegroundColor Gray
}
Write-Host ""

# ============================================================================
# NOISE FILTER DEFINITIONS
# ============================================================================

# Common non-actionable Event IDs to filter out
$NoiseFilter = @{
    'System' = @(
        1014,  # DNS Client - Name resolution timeout (often transient)
        1500,  # Group Policy - Shortcut processing
        10016, # DistributedCOM - Permission issues (often cosmetic)
        10010  # DistributedCOM - Server timeout (often cosmetic)
    )
    'Application' = @(
        1000,  # Application Error - handled by specific app logs
        1002   # Application Hang - often false positives
    )
}

# ============================================================================
# EVENT LOG QUERY FUNCTION
# ============================================================================

function Get-FilteredEvents {
    param (
        [string]$LogName,
        [datetime]$StartTime,
        [array]$LevelFilter
    )

    Write-Host "Querying $LogName log..." -ForegroundColor Cyan

    try {
        # Build filter hashtable
        $filterHash = @{
            LogName   = $LogName
            StartTime = $StartTime
            Level     = $LevelFilter
        }

        # Query events
        $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

        if ($null -eq $events) {
            Write-Host "  No events found in $LogName log." -ForegroundColor Gray
            return @()
        }

        Write-Host "  Found $($events.Count) events before filtering." -ForegroundColor Gray

        # Apply noise filter if enabled
        if ($ExcludeCommonNoise -and $NoiseFilter.ContainsKey($LogName)) {
            $events = $events | Where-Object { 
                $_.Id -notin $NoiseFilter[$LogName] 
            }
            Write-Host "  $($events.Count) events after noise filtering." -ForegroundColor Gray
        }

        return $events

    } catch {
        Write-Warning "Error querying $LogName log: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================================
# MAIN EVENT COLLECTION
# ============================================================================

$queryStartTime = $StartTime.AddHours(-$Hours)

# Define event levels to query
# 1 = Critical, 2 = Error, 3 = Warning
$levelFilter = @(1, 2)  # Critical and Error
if ($IncludeWarnings) {
    $levelFilter += 3
}

# Query System and Application logs
$systemEvents = Get-FilteredEvents -LogName "System" -StartTime $queryStartTime -LevelFilter $levelFilter
$applicationEvents = Get-FilteredEvents -LogName "Application" -StartTime $queryStartTime -LevelFilter $levelFilter

# Combine and sort all events
$allEvents = @($systemEvents) + @($applicationEvents) | 
    Sort-Object TimeCreated -Descending

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($allEvents.Count -eq 0) {
    Write-Host "No critical or error events found in the specified time range." -ForegroundColor Green
    Write-Host "This is a good sign - the system appears stable." -ForegroundColor Green
    exit 0
}

# ============================================================================
# EVENT ANALYSIS AND GROUPING
# ============================================================================

Write-Host "Total Events Found: $($allEvents.Count)" -ForegroundColor Yellow
Write-Host ""

# Group by Source/Provider for summary
$eventsBySource = $allEvents | Group-Object ProviderName | 
    Sort-Object Count -Descending

Write-Host "Events by Source:" -ForegroundColor Green
foreach ($group in $eventsBySource | Select-Object -First 10) {
    $criticalCount = ($group.Group | Where-Object LevelDisplayName -eq "Critical").Count
    $errorCount = ($group.Group | Where-Object LevelDisplayName -eq "Error").Count
    $warningCount = ($group.Group | Where-Object LevelDisplayName -eq "Warning").Count
    
    Write-Host "  $($group.Name): $($group.Count) events" -ForegroundColor White
    if ($criticalCount -gt 0) { Write-Host "    - Critical: $criticalCount" -ForegroundColor Red }
    if ($errorCount -gt 0) { Write-Host "    - Error: $errorCount" -ForegroundColor Yellow }
    if ($warningCount -gt 0) { Write-Host "    - Warning: $warningCount" -ForegroundColor Gray }
}

if ($eventsBySource.Count -gt 10) {
    Write-Host "  ... and $($eventsBySource.Count - 10) more sources" -ForegroundColor Gray
}

Write-Host ""

# ============================================================================
# DETAILED EVENT OUTPUT
# ============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DETAILED EVENT LIST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Prepare data for display and export
$eventOutput = foreach ($event in $allEvents | Select-Object -First 100) {
    
    # Determine severity color
    $severityColor = switch ($event.LevelDisplayName) {
        "Critical" { "Red" }
        "Error" { "Yellow" }
        "Warning" { "Gray" }
        default { "White" }
    }

    # Display event
    Write-Host "[$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))]" -NoNewline -ForegroundColor Cyan
    Write-Host " $($event.LevelDisplayName.ToUpper())" -NoNewline -ForegroundColor $severityColor
    Write-Host " - Event ID: $($event.Id)" -ForegroundColor White
    Write-Host "  Log: $($event.LogName)" -ForegroundColor Gray
    Write-Host "  Source: $($event.ProviderName)" -ForegroundColor Gray
    
    # Clean up message (remove excess whitespace)
    $cleanMessage = $event.Message -replace '\s+', ' ' -replace '^\s+|\s+$', ''
    if ($cleanMessage.Length -gt 200) {
        $cleanMessage = $cleanMessage.Substring(0, 200) + "..."
    }
    Write-Host "  Message: $cleanMessage" -ForegroundColor White
    Write-Host ""

    # Create output object for export
    [PSCustomObject]@{
        Timestamp    = $event.TimeCreated
        Level        = $event.LevelDisplayName
        Log          = $event.LogName
        Source       = $event.ProviderName
        EventID      = $event.Id
        Message      = $event.Message
        MachineName  = $event.MachineName
    }
}

if ($allEvents.Count -gt 100) {
    Write-Host "... showing first 100 events only (total: $($allEvents.Count))" -ForegroundColor Yellow
    Write-Host "Use -ExportPath to save all events to a file." -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# EXPORT RESULTS
# ============================================================================

if ($ExportPath) {
    try {
        # Create export directory if it doesn't exist
        $exportDir = Split-Path -Path $ExportPath -Parent
        if ($exportDir -and -not (Test-Path $exportDir)) {
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        }

        # Export all events (not just first 100)
        $allEventOutput = foreach ($event in $allEvents) {
            [PSCustomObject]@{
                Timestamp    = $event.TimeCreated
                Level        = $event.LevelDisplayName
                Log          = $event.LogName
                Source       = $event.ProviderName
                EventID      = $event.Id
                Message      = $event.Message
                MachineName  = $event.MachineName
            }
        }

        $allEventOutput | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
        Write-Host "Total events exported: $($allEventOutput.Count)" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Warning "Failed to export results: $($_.Exception.Message)"
    }
}

# ============================================================================
# ACTIONABLE RECOMMENDATIONS
# ============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$criticalCount = ($allEvents | Where-Object LevelDisplayName -eq "Critical").Count
$errorCount = ($allEvents | Where-Object LevelDisplayName -eq "Error").Count

if ($criticalCount -gt 0) {
    Write-Host "CRITICAL: $criticalCount critical events detected." -ForegroundColor Red
    Write-Host "  Action Required: Investigate critical events immediately." -ForegroundColor Red
    Write-Host ""
}

if ($errorCount -gt 10) {
    Write-Host "HIGH: $errorCount error events detected." -ForegroundColor Yellow
    Write-Host "  Action: Review recurring errors and address root causes." -ForegroundColor Yellow
    Write-Host ""
}

# Check for specific patterns that warrant attention
$diskErrors = $allEvents | Where-Object { $_.ProviderName -like "*disk*" -or $_.Message -like "*disk*" }
$networkErrors = $allEvents | Where-Object { $_.ProviderName -like "*network*" -or $_.Message -like "*network*" }
$serviceErrors = $allEvents | Where-Object { $_.Message -like "*service*" -and $_.Message -like "*failed*" }

if ($diskErrors.Count -gt 0) {
    Write-Host "NOTE: $($diskErrors.Count) disk-related errors detected." -ForegroundColor Yellow
    Write-Host "  Consider running storage diagnostics." -ForegroundColor Yellow
    Write-Host ""
}

if ($networkErrors.Count -gt 5) {
    Write-Host "NOTE: $($networkErrors.Count) network-related errors detected." -ForegroundColor Yellow
    Write-Host "  Consider running network diagnostics." -ForegroundColor Yellow
    Write-Host ""
}

if ($serviceErrors.Count -gt 0) {
    Write-Host "NOTE: $($serviceErrors.Count) service failure events detected." -ForegroundColor Yellow
    Write-Host "  Review services that failed to start." -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# COMPLETION
# ============================================================================

$duration = (Get-Date) - $StartTime

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Diagnostic completed in $([math]::Round($duration.TotalSeconds, 2)) seconds" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Green
Write-Host "  1. Review events above for recurring patterns" -ForegroundColor White
Write-Host "  2. Document findings in support ticket" -ForegroundColor White
Write-Host "  3. Address critical and high-priority errors" -ForegroundColor White
Write-Host "  4. Consider running targeted diagnostics based on error types" -ForegroundColor White
Write-Host ""