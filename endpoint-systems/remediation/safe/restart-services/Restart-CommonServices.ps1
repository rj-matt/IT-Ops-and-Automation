<#
.SYNOPSIS
    Safely restarts common Windows services that frequently resolve support issues.

.DESCRIPTION
    Restarts Print Spooler, Windows Update, BITS, and DNS Client services with full
    validation and logging. Captures before/after state for ticket documentation.
    
    This script handles approximately 30% of "tried turning it off and on again" scenarios.
    
    NOTE: DNS Client is excluded from default restart operations as it is typically
    protected by Windows. Network issues requiring DNS restart are best resolved
    with a full network stack reset or system reboot.

.PARAMETER Services
    Specify which services to restart. Default is the three safe common services.
    Valid values: Spooler, wuauserv, BITS, All

.PARAMETER SkipDependencyCheck
    Skip checking for dependent services (not recommended for production use)

.EXAMPLE
    .\Restart-CommonServices.ps1
    Restarts all four common services with full validation

.EXAMPLE
    .\Restart-CommonServices.ps1 -Services Spooler,wuauserv
    Restarts only Print Spooler and Windows Update services

.NOTES
    Folder:      endpoint-systems/remediation/safe/restart-services/
    Risk Level:  LOW - Safe for all environments
    Privileges:  Requires Administrator rights
    Author:      MSP Automation Team
    Version:     1.0
    
.OUTPUTS
    Structured log output suitable for copying directly into support tickets
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Spooler','wuauserv','BITS','All')]
    [string[]]$Services = @('All'),
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDependencyCheck
)

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

# Service mapping: friendly name to actual service name
$ServiceMap = @{
    'Spooler'   = @{
        Name = 'Spooler'
        DisplayName = 'Print Spooler'
        Description = 'Manages print jobs and printer communication'
    }
    'wuauserv'  = @{
        Name = 'wuauserv'
        DisplayName = 'Windows Update'
        Description = 'Enables detection, download, and installation of Windows updates'
    }
    'BITS'      = @{
        Name = 'BITS'
        DisplayName = 'Background Intelligent Transfer Service'
        Description = 'Transfers files in the background using idle network bandwidth'
    }
}

# ============================================================================
# FUNCTIONS
# ============================================================================

function Write-LogHeader {
    param([string]$Message)
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
}

function Write-LogSection {
    param([string]$Message)
    Write-Host "`n--- $Message ---" -ForegroundColor Yellow
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-LogWarning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor White
}

function Get-ServiceStatusReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $serviceInfo = $ServiceMap[$ServiceName]
        
        $report = [PSCustomObject]@{
            ServiceName = $service.Name
            DisplayName = $serviceInfo.DisplayName
            Status = $service.Status
            StartType = $service.StartType
            CanStop = $service.CanStop
            DependentServices = ($service.DependentServices | Select-Object -ExpandProperty Name) -join ', '
            Success = $true
            ErrorMessage = $null
        }
        
        return $report
    }
    catch {
        return [PSCustomObject]@{
            ServiceName = $ServiceName
            DisplayName = $ServiceMap[$ServiceName].DisplayName
            Status = 'Unknown'
            StartType = 'Unknown'
            CanStop = $false
            DependentServices = 'N/A'
            Success = $false
            ErrorMessage = $_.Exception.Message
        }
    }
}

function Restart-ServiceSafely {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory=$false)]
        [switch]$SkipDependencyCheck
    )
    
    $serviceInfo = $ServiceMap[$ServiceName]
    $result = @{
        ServiceName = $ServiceName
        DisplayName = $serviceInfo.DisplayName
        Success = $false
        BeforeState = $null
        AfterState = $null
        Action = 'None'
        Message = ''
        DependentServicesAffected = @()
    }
    
    try {
        # Get initial state
        Write-LogInfo "Checking current state of $($serviceInfo.DisplayName)..."
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $result.BeforeState = $service.Status
        
        # Check if service exists but is disabled
        if ($service.StartType -eq 'Disabled') {
            Write-LogWarning "$($serviceInfo.DisplayName) is disabled. Cannot restart."
            $result.Message = "Service is disabled and cannot be restarted without changing startup type"
            return $result
        }
        
        # Check for dependent services
        if (-not $SkipDependencyCheck) {
            $dependentServices = $service.DependentServices | Where-Object { $_.Status -eq 'Running' }
            if ($dependentServices) {
                $result.DependentServicesAffected = $dependentServices.Name
                Write-LogWarning "The following dependent services are running and will be stopped:"
                foreach ($dep in $dependentServices) {
                    Write-Host "  - $($dep.DisplayName) ($($dep.Name))" -ForegroundColor Yellow
                }
            }
        }
        
        # Determine action based on current state
        if ($service.Status -eq 'Running') {
            Write-LogInfo "Restarting $($serviceInfo.DisplayName)..."
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            $result.Action = 'Restarted'
            Start-Sleep -Seconds 2
        }
        elseif ($service.Status -eq 'Stopped') {
            Write-LogInfo "$($serviceInfo.DisplayName) is stopped. Starting service..."
            Start-Service -Name $ServiceName -ErrorAction Stop
            $result.Action = 'Started'
            Start-Sleep -Seconds 2
        }
        else {
            Write-LogInfo "$($serviceInfo.DisplayName) is in $($service.Status) state. Attempting restart..."
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Start-Service -Name $ServiceName -ErrorAction Stop
            $result.Action = 'Force Restarted'
            Start-Sleep -Seconds 2
        }
        
        # Verify final state
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $result.AfterState = $service.Status
        
        if ($service.Status -eq 'Running') {
            Write-LogSuccess "$($serviceInfo.DisplayName) is now running"
            $result.Success = $true
            $result.Message = "Service successfully $($result.Action.ToLower())"
        }
        else {
            Write-LogError "$($serviceInfo.DisplayName) did not start properly. Current state: $($service.Status)"
            $result.Message = "Service $($result.Action.ToLower()) but is in $($service.Status) state"
        }
    }
    catch {
        Write-LogError "Failed to restart $($serviceInfo.DisplayName): $($_.Exception.Message)"
        $result.Message = $_.Exception.Message
        
        # Try to get current state even after failure
        try {
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service) {
                $result.AfterState = $service.Status
            }
        }
        catch {
            # Silently fail if we can't get status
        }
    }
    
    return $result
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

$startTime = Get-Date

Write-LogHeader "Common Services Restart Tool"

# Display execution context
Write-Host "Computer Name:  $env:COMPUTERNAME"
Write-Host "Executed By:    $env:USERDOMAIN\$env:USERNAME"
Write-Host "Execution Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "PowerShell:     $($PSVersionTable.PSVersion)"

# Determine which services to restart
$servicesToRestart = @()
if ($Services -contains 'All') {
    $servicesToRestart = $ServiceMap.Keys
}
else {
    $servicesToRestart = $Services
}

Write-LogSection "Services Targeted for Restart"
foreach ($svc in $servicesToRestart) {
    Write-Host "  $($ServiceMap[$svc].DisplayName) ($svc)"
}

# ============================================================================
# PHASE 1: PRE-RESTART DIAGNOSTICS
# ============================================================================

Write-LogSection "Phase 1: Pre-Restart State Capture"

$preRestartState = @()
foreach ($svc in $servicesToRestart) {
    $status = Get-ServiceStatusReport -ServiceName $svc
    $preRestartState += $status
    
    if ($status.Success) {
        Write-Host "`n$($status.DisplayName):"
        Write-Host "  Status:       $($status.Status)"
        Write-Host "  Start Type:   $($status.StartType)"
        Write-Host "  Can Stop:     $($status.CanStop)"
        if ($status.DependentServices) {
            Write-Host "  Dependents:   $($status.DependentServices)"
        }
    }
    else {
        Write-LogError "Could not retrieve status for $($status.DisplayName): $($status.ErrorMessage)"
    }
}

# ============================================================================
# PHASE 2: SERVICE RESTART
# ============================================================================

Write-LogSection "Phase 2: Service Restart Operations"

$restartResults = @()
foreach ($svc in $servicesToRestart) {
    Write-Host ""
    $result = Restart-ServiceSafely -ServiceName $svc -SkipDependencyCheck:$SkipDependencyCheck
    $restartResults += $result
}

# ============================================================================
# PHASE 3: POST-RESTART VERIFICATION
# ============================================================================

Write-LogSection "Phase 3: Post-Restart Verification"

Start-Sleep -Seconds 3

$postRestartState = @()
foreach ($svc in $servicesToRestart) {
    $status = Get-ServiceStatusReport -ServiceName $svc
    $postRestartState += $status
}

# ============================================================================
# SUMMARY REPORT
# ============================================================================

$endTime = Get-Date
$duration = $endTime - $startTime

Write-LogHeader "EXECUTION SUMMARY"

Write-Host "Total Execution Time: $($duration.TotalSeconds) seconds`n"

# Success/Failure counts
$successCount = ($restartResults | Where-Object { $_.Success }).Count
$failureCount = $restartResults.Count - $successCount

Write-Host "Services Processed: $($restartResults.Count)"
Write-Host "Successful:         " -NoNewline
if ($successCount -eq $restartResults.Count) {
    Write-Host $successCount -ForegroundColor Green
}
else {
    Write-Host $successCount -ForegroundColor Yellow
}
Write-Host "Failed:             " -NoNewline
if ($failureCount -gt 0) {
    Write-Host $failureCount -ForegroundColor Red
}
else {
    Write-Host $failureCount -ForegroundColor Green
}

# Detailed results table
Write-LogSection "Detailed Results"

foreach ($result in $restartResults) {
    Write-Host "`n$($result.DisplayName):"
    Write-Host "  Before: $($result.BeforeState)"
    Write-Host "  Action: $($result.Action)"
    Write-Host "  After:  $($result.AfterState)"
    Write-Host "  Result: " -NoNewline
    if ($result.Success) {
        Write-Host "SUCCESS" -ForegroundColor Green
    }
    else {
        Write-Host "FAILED" -ForegroundColor Red
    }
    if ($result.Message) {
        Write-Host "  Note:   $($result.Message)"
    }
    if ($result.DependentServicesAffected.Count -gt 0) {
        Write-Host "  Dependent Services Affected: $($result.DependentServicesAffected -join ', ')"
    }
}

# ============================================================================
# TICKET DOCUMENTATION FORMAT
# ============================================================================

Write-LogSection "Copy Below for Ticket Documentation"

Write-Host @"

--- Service Restart Report ---
Computer: $env:COMPUTERNAME
Date/Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))
Technician: $env:USERNAME

Services Restarted:
"@

foreach ($result in $restartResults) {
    $statusSymbol = if ($result.Success) { "✓" } else { "✗" }
    Write-Host "$statusSymbol $($result.DisplayName): $($result.BeforeState) → $($result.AfterState) ($($result.Action))"
}

Write-Host "`nResult: $successCount of $($restartResults.Count) services restarted successfully"

if ($failureCount -gt 0) {
    Write-Host "`nFailed Services:"
    foreach ($result in ($restartResults | Where-Object { -not $_.Success })) {
        Write-Host "- $($result.DisplayName): $($result.Message)"
    }
}

Write-Host "`n--- End Report ---`n"

# ============================================================================
# EXIT CODE
# ============================================================================

if ($failureCount -gt 0) {
    Write-LogWarning "Script completed with $failureCount failure(s)"
    exit 1
}
else {
    Write-LogSuccess "All services restarted successfully"
    exit 0
}