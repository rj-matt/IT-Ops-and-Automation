<#
.SYNOPSIS
    Collects comprehensive system health snapshot for client troubleshooting.

.DESCRIPTION
    Gathers critical system information in a ticket-friendly format:
    - Operating system details and version
    - System uptime
    - Disk space utilization
    - Memory usage
    - CPU information and current load
    - Windows Update status and last install date
    - Pending reboot status
    
    Output is formatted for direct copy-paste into support tickets.

.USAGE
    Run from elevated PowerShell prompt (recommended) or standard prompt.
    Standard users can run this - UAC elevation is not required.

.SCOPE
    Read-only diagnostics. No system changes are made.

.RISK LEVEL
    Minimal - Read-only operations only

.PREREQUISITES
    - Windows 7/Server 2008 R2 or later
    - PowerShell 3.0 or later

.EXAMPLES
    .\Get-ClientHealthSnapshot.ps1
    
    .\Get-ClientHealthSnapshot.ps1 | Out-File C:\Temp\health-snapshot.txt

.NOTES
    Domain: endpoint-systems
    Category: diagnostics/system-info
    Author: MSP Automation Team
    Version: 1.0
#>

[CmdletBinding()]
param()

#Requires -Version 3.0

# ============================================================================
# FUNCTIONS
# ============================================================================

function Get-SystemUptime {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime
        
        $days = $uptime.Days
        $hours = $uptime.Hours
        $minutes = $uptime.Minutes
        
        return "$days days, $hours hours, $minutes minutes"
    }
    catch {
        return "Unable to determine (Error: $($_.Exception.Message))"
    }
}

function Get-DiskSpaceInfo {
    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        
        $diskInfo = [System.Collections.ArrayList]@()
        foreach ($disk in $disks) {
            $sizeGB = [math]::Round($disk.Size / 1GB, 2)
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $usedGB = $sizeGB - $freeGB
            $percentFree = [math]::Round(($freeGB / $sizeGB) * 100, 1)
            
            $status = if ($percentFree -lt 10) { "CRITICAL" }
                     elseif ($percentFree -lt 20) { "WARNING" }
                     else { "OK" }
            
            [void]$diskInfo.Add([PSCustomObject]@{
                Drive = $disk.DeviceID
                Label = if ($disk.VolumeName) { $disk.VolumeName } else { "(No Label)" }
                TotalGB = $sizeGB
                UsedGB = $usedGB
                FreeGB = $freeGB
                PercentFree = $percentFree
                Status = $status
            })
        }
        
        return @($diskInfo)
    }
    catch {
        return "Unable to retrieve disk information (Error: $($_.Exception.Message))"
    }
}

function Get-MemoryInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedGB = $totalGB - $freeGB
        $percentUsed = [math]::Round(($usedGB / $totalGB) * 100, 1)
        
        $status = if ($percentUsed -gt 90) { "CRITICAL" }
                 elseif ($percentUsed -gt 80) { "WARNING" }
                 else { "OK" }
        
        return [PSCustomObject]@{
            TotalGB = $totalGB
            UsedGB = $usedGB
            FreeGB = $freeGB
            PercentUsed = $percentUsed
            Status = $status
        }
    }
    catch {
        return "Unable to retrieve memory information (Error: $($_.Exception.Message))"
    }
}

function Get-CPUInfo {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        
        # Get current CPU usage
        $cpuLoad = (Get-CimInstance -ClassName Win32_Processor | 
                   Measure-Object -Property LoadPercentage -Average).Average
        
        $status = if ($cpuLoad -gt 90) { "HIGH" }
                 elseif ($cpuLoad -gt 70) { "ELEVATED" }
                 else { "NORMAL" }
        
        return [PSCustomObject]@{
            Name = $cpu.Name
            Cores = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
            CurrentLoad = "$cpuLoad%"
            Status = $status
        }
    }
    catch {
        return "Unable to retrieve CPU information (Error: $($_.Exception.Message))"
    }
}

function Get-WindowsUpdateInfo {
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        # Get last successful update install date
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        
        if ($historyCount -gt 0) {
            $history = $updateSearcher.QueryHistory(0, 100) | 
                      Where-Object { $_.ResultCode -eq 2 } | 
                      Sort-Object Date -Descending | 
                      Select-Object -First 1
            
            $lastUpdate = if ($history) { 
                $history.Date.ToString("yyyy-MM-dd HH:mm:ss") 
            } else { 
                "No successful updates found in recent history" 
            }
        }
        else {
            $lastUpdate = "No update history available"
        }
        
        # Check for pending updates
        $searchResult = $updateSearcher.Search("IsInstalled=0")
        $pendingCount = $searchResult.Updates.Count
        
        return [PSCustomObject]@{
            LastUpdate = $lastUpdate
            PendingUpdates = $pendingCount
        }
    }
    catch {
        # Fallback method using registry
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
            $lastSuccess = Get-ItemProperty -Path $regPath -ErrorAction Stop
            $lastUpdate = $lastSuccess.LastSuccessTime
            
            return [PSCustomObject]@{
                LastUpdate = $lastUpdate
                PendingUpdates = "Unable to check (use Windows Update UI)"
            }
        }
        catch {
            return [PSCustomObject]@{
                LastUpdate = "Unable to determine"
                PendingUpdates = "Unable to check"
            }
        }
    }
}

function Test-PendingReboot {
    try {
        $pendingReboot = $false
        $reasons = @()
        
        # Check CBS (Component Based Servicing)
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $pendingReboot = $true
            $reasons += "Component Based Servicing"
        }
        
        # Check Windows Update
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $pendingReboot = $true
            $reasons += "Windows Update"
        }
        
        # Check PendingFileRenameOperations
        $pfro = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pfro) {
            $pendingReboot = $true
            $reasons += "Pending File Rename Operations"
        }
        
        # Check for CCM Client reboot
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData") {
            $pendingReboot = $true
            $reasons += "SCCM/ConfigMgr"
        }
        
        if ($pendingReboot) {
            return "YES - Reasons: $($reasons -join ', ')"
        }
        else {
            return "No"
        }
    }
    catch {
        return "Unable to determine (Error: $($_.Exception.Message))"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CLIENT HEALTH SNAPSHOT" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Collect all information
Write-Host "Collecting system information..." -ForegroundColor Yellow

try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    
    # Build output
    $output = @"

SYSTEM INFORMATION
───────────────────────────────────────────────────────────────
Computer Name:      $($computerSystem.Name)
Manufacturer:       $($computerSystem.Manufacturer)
Model:              $($computerSystem.Model)
Serial Number:      $($bios.SerialNumber)
Domain/Workgroup:   $(if ($computerSystem.PartOfDomain) { $computerSystem.Domain } else { $computerSystem.Workgroup + " (Workgroup)" })
Current User:       $env:USERNAME

OPERATING SYSTEM
───────────────────────────────────────────────────────────────
OS:                 $($os.Caption)
Version:            $($os.Version)
Build:              $($os.BuildNumber)
Architecture:       $($os.OSArchitecture)
Install Date:       $($os.InstallDate.ToString("yyyy-MM-dd"))
System Uptime:      $(Get-SystemUptime)

"@

    # Memory Information
    Write-Host "Analyzing memory usage..." -ForegroundColor Yellow
    $memInfo = Get-MemoryInfo
    
    if ($memInfo -is [PSCustomObject]) {
        $output += @"
MEMORY
───────────────────────────────────────────────────────────────
Total Memory:       $($memInfo.TotalGB) GB
Used:               $($memInfo.UsedGB) GB ($($memInfo.PercentUsed)%)
Available:          $($memInfo.FreeGB) GB
Status:             $($memInfo.Status)

"@
    }
    else {
        $output += "MEMORY: $memInfo`n`n"
    }
    
    # CPU Information
    Write-Host "Checking CPU performance..." -ForegroundColor Yellow
    $cpuInfo = Get-CPUInfo
    
    if ($cpuInfo -is [PSCustomObject]) {
        $output += @"
CPU
───────────────────────────────────────────────────────────────
Processor:          $($cpuInfo.Name)
Cores:              $($cpuInfo.Cores) physical / $($cpuInfo.LogicalProcessors) logical
Current Load:       $($cpuInfo.CurrentLoad)
Status:             $($cpuInfo.Status)

"@
    }
    else {
        $output += "CPU: $cpuInfo`n`n"
    }
    
    # Disk Space Information
    Write-Host "Scanning disk space..." -ForegroundColor Yellow
    $diskInfo = Get-DiskSpaceInfo
    
    $output += "DISK SPACE`n"
    $output += "───────────────────────────────────────────────────────────────`n"
    
    if ($diskInfo -is [string]) {
        $output += "$diskInfo`n"
    }
    else {
        foreach ($disk in $diskInfo) {
            $output += "$($disk.Drive) [$($disk.Label)]`n"
            $output += "  Total: $($disk.TotalGB) GB | Used: $($disk.UsedGB) GB | Free: $($disk.FreeGB) GB ($($disk.PercentFree)%)`n"
            $output += "  Status: $($disk.Status)`n"
        }
    }
    $output += "`n"
    
    # Windows Update Information
    Write-Host "Checking Windows Update status..." -ForegroundColor Yellow
    $updateInfo = Get-WindowsUpdateInfo
    
    $output += @"
WINDOWS UPDATES
───────────────────────────────────────────────────────────────
Last Update:        $($updateInfo.LastUpdate)
Pending Updates:    $($updateInfo.PendingUpdates)

"@
    
    # Pending Reboot Check
    Write-Host "Checking for pending reboots..." -ForegroundColor Yellow
    $rebootStatus = Test-PendingReboot
    
    $output += @"
REBOOT STATUS
───────────────────────────────────────────────────────────────
Pending Reboot:     $rebootStatus

"@
    
    # Add timestamp
    $output += "───────────────────────────────────────────────────────────────`n"
    $output += "Report Generated:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
    $output += "═══════════════════════════════════════════════════════════════`n"
    
    # Display output
    Write-Host $output
    
    Write-Host ""
    Write-Host "✓ Health snapshot completed successfully" -ForegroundColor Green
    Write-Host "  Copy the above output into your ticket" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "✗ ERROR: Failed to collect system information" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}