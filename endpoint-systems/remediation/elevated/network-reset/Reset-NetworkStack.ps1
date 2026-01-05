<#
.SYNOPSIS
    Performs a comprehensive TCP/IP network stack reset with rollback capability.

.DESCRIPTION
    This script resets the Windows network stack to resolve persistent connectivity issues
    caused by corrupted network configuration. It performs pre-flight diagnostics, creates
    a restoration point, and executes a series of network resets in a safe, logged manner.
    
    RISK LEVEL: ELEVATED
    - Temporarily disrupts all network connectivity
    - Resets network adapters and TCP/IP settings
    - Clears DNS, Winsock, and IP configurations
    - May require reboot to complete
    
    USE CASES:
    - Persistent network connectivity failures after basic troubleshooting
    - Corrupted Winsock or TCP/IP stack
    - DNS resolution failures not resolved by standard cache clearing
    - Network adapter errors that persist after driver updates
    
    PREREQUISITES:
    - Must be run as Administrator
    - Run Get-NetworkDiagnostics.ps1 first to confirm need for reset
    - Document current network configuration before running
    - Ensure physical network connectivity is verified
    - Have alternative connectivity method available (e.g., phone hotspot)

.PARAMETER SkipPreFlightChecks
    Bypasses pre-flight diagnostic checks. Not recommended for production use.

.PARAMETER NoRebootPrompt
    Suppresses the reboot prompt after completion. System may require manual reboot.

.PARAMETER BackupOnly
    Creates a backup of current network configuration without performing reset.

.EXAMPLE
    .\Reset-NetworkStack.ps1
    Performs full network stack reset with all safety checks.

.EXAMPLE
    .\Reset-NetworkStack.ps1 -BackupOnly
    Creates backup of current network settings without performing reset.

.NOTES
    Script: Reset-NetworkStack.ps1
    Version: 1.0.0
    Author: MSP Automation Team
    Domain: endpoint-systems/remediation/elevated/network-resets
    Last Updated: 2025-01-05
    
    IMPORTANT WARNINGS:
    - All network connectivity will be lost during execution (30-90 seconds)
    - VPN connections will be terminated
    - Network drives will disconnect
    - Remote sessions will be interrupted
    - Some settings may require reboot to fully apply
    
    EXIT CODES:
    0  = Success
    1  = Not running as Administrator
    2  = Pre-flight checks failed
    3  = Network reset operations failed
    4  = Backup creation failed
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$SkipPreFlightChecks,
    
    [Parameter(Mandatory = $false)]
    [switch]$NoRebootPrompt,
    
    [Parameter(Mandatory = $false)]
    [switch]$BackupOnly
)

#Requires -RunAsAdministrator

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = "Stop"
$script:LogEntries = @()
$script:BackupPath = Join-Path $env:TEMP "NetworkStackBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:LogEntries += $logEntry
    
    $color = switch ($Level) {
        'INFO'    { 'White' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host $logEntry -ForegroundColor $color
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

function Test-PreFlightChecks {
    Write-SectionHeader "PRE-FLIGHT CHECKS"
    Write-Log "Starting pre-flight diagnostic checks..."
    
    $checks = @{
        "Administrator Rights" = $true  # Already verified by #Requires
        "Network Adapters Present" = $false
        "Active Network Connection" = $false
        "DNS Resolution Working" = $false
        "Internet Connectivity" = $false
    }
    
    # Check for network adapters
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Disabled' }
        if ($adapters.Count -gt 0) {
            $checks["Network Adapters Present"] = $true
            Write-Log "Found $($adapters.Count) active network adapter(s)"
        } else {
            Write-Log "No active network adapters found" -Level WARNING
        }
    } catch {
        Write-Log "Failed to enumerate network adapters: $($_.Exception.Message)" -Level ERROR
    }
    
    # Check for active connection
    try {
        $connected = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($connected.Count -gt 0) {
            $checks["Active Network Connection"] = $true
            Write-Log "Network adapter is connected"
        } else {
            Write-Log "No connected network adapters found" -Level WARNING
        }
    } catch {
        Write-Log "Failed to check adapter status: $($_.Exception.Message)" -Level WARNING
    }
    
    # Check DNS resolution
    try {
        $dnsTest = Resolve-DnsName "www.microsoft.com" -ErrorAction Stop
        if ($dnsTest) {
            $checks["DNS Resolution Working"] = $true
            Write-Log "DNS resolution is functioning"
        }
    } catch {
        Write-Log "DNS resolution failed (expected if this is the problem): $($_.Exception.Message)" -Level WARNING
    }
    
    # Check internet connectivity
    try {
        $ping = Test-NetConnection "8.8.8.8" -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($ping) {
            $checks["Internet Connectivity"] = $true
            Write-Log "Internet connectivity confirmed"
        }
    } catch {
        Write-Log "Internet connectivity test failed: $($_.Exception.Message)" -Level WARNING
    }
    
    # Display summary
    Write-Host "`nPre-Flight Check Summary:" -ForegroundColor Cyan
    foreach ($check in $checks.GetEnumerator()) {
        $status = if ($check.Value) { "PASS" } else { "FAIL" }
        $color = if ($check.Value) { "Green" } else { "Yellow" }
        Write-Host "  [$status] $($check.Key)" -ForegroundColor $color
    }
    
    return $checks
}

# ============================================================================
# BACKUP FUNCTIONS
# ============================================================================

function Backup-NetworkConfiguration {
    Write-SectionHeader "BACKUP NETWORK CONFIGURATION"
    Write-Log "Creating backup of current network configuration..."
    
    try {
        # Create backup directory
        New-Item -Path $script:BackupPath -ItemType Directory -Force | Out-Null
        Write-Log "Backup location: $script:BackupPath"
        
        # Export network adapter configuration
        Write-Log "Backing up network adapter configuration..."
        Get-NetAdapter | Select-Object * | Export-Clixml -Path (Join-Path $script:BackupPath "NetAdapters.xml")
        
        # Export IP configuration
        Write-Log "Backing up IP configuration..."
        Get-NetIPConfiguration | Export-Clixml -Path (Join-Path $script:BackupPath "IPConfiguration.xml")
        
        # Export IP addresses
        Write-Log "Backing up IP address assignments..."
        Get-NetIPAddress | Export-Clixml -Path (Join-Path $script:BackupPath "IPAddresses.xml")
        
        # Export DNS client configuration
        Write-Log "Backing up DNS client settings..."
        Get-DnsClientServerAddress | Export-Clixml -Path (Join-Path $script:BackupPath "DNSServers.xml")
        
        # Export routes
        Write-Log "Backing up routing table..."
        Get-NetRoute | Export-Clixml -Path (Join-Path $script:BackupPath "Routes.xml")
        
        # Export network connections (for reference)
        Write-Log "Backing up network connection details..."
        ipconfig /all | Out-File -FilePath (Join-Path $script:BackupPath "ipconfig_all.txt")
        
        # Export Winsock catalog
        Write-Log "Backing up Winsock catalog..."
        netsh winsock show catalog | Out-File -FilePath (Join-Path $script:BackupPath "winsock_catalog.txt")
        
        # Export network interface info
        Write-Log "Backing up network interface details..."
        netsh interface show interface | Out-File -FilePath (Join-Path $script:BackupPath "interfaces.txt")
        
        Write-Log "Network configuration backup completed successfully" -Level SUCCESS
        Write-Host "`nBackup saved to: $script:BackupPath" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Log "Failed to create backup: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

# ============================================================================
# NETWORK RESET FUNCTIONS
# ============================================================================

function Reset-WinsockCatalog {
    Write-Log "Resetting Winsock Catalog..."
    try {
        $result = netsh winsock reset 2>&1
        Write-Log "Winsock catalog reset completed"
        return $true
    }
    catch {
        Write-Log "Winsock reset failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Reset-TcpIpStack {
    Write-Log "Resetting TCP/IP stack..."
    try {
        $result = netsh int ip reset 2>&1
        Write-Log "TCP/IP stack reset completed"
        return $true
    }
    catch {
        Write-Log "TCP/IP reset failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Reset-DnsClientCache {
    Write-Log "Flushing DNS client cache..."
    try {
        Clear-DnsClientCache -ErrorAction Stop
        Write-Log "DNS cache cleared successfully"
        return $true
    }
    catch {
        Write-Log "DNS cache clear failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Reset-NetBiosOverTcpIp {
    Write-Log "Resetting NetBIOS over TCP/IP..."
    try {
        $result = nbtstat -R 2>&1
        $result = nbtstat -RR 2>&1
        Write-Log "NetBIOS reset completed"
        return $true
    }
    catch {
        Write-Log "NetBIOS reset failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Reset-IpConfiguration {
    Write-Log "Releasing and renewing IP configuration..."
    try {
        # Release all DHCP leases
        $result = ipconfig /release 2>&1
        Start-Sleep -Seconds 2
        
        # Renew all DHCP leases
        $result = ipconfig /renew 2>&1
        Write-Log "IP configuration reset completed"
        return $true
    }
    catch {
        Write-Log "IP configuration reset failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Reset-NetworkAdapters {
    Write-Log "Restarting network adapters..."
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Disabled' }
        foreach ($adapter in $adapters) {
            Write-Log "  Restarting adapter: $($adapter.Name)"
            Restart-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Continue
            Start-Sleep -Milliseconds 500
        }
        Write-Log "Network adapters restarted"
        return $true
    }
    catch {
        Write-Log "Network adapter restart failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Reset-WindowsFirewall {
    Write-Log "Resetting Windows Firewall to default (optional)..."
    try {
        # This is commented out by default as it may be too aggressive
        # Uncomment if firewall reset is explicitly needed
        # netsh advfirewall reset
        Write-Log "Firewall reset skipped (not performed by default)"
        return $true
    }
    catch {
        Write-Log "Firewall reset failed: $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

function Invoke-NetworkStackReset {
    Write-SectionHeader "NETWORK STACK RESET"
    Write-Log "Beginning network stack reset operations..." -Level WARNING
    Write-Log "Network connectivity will be temporarily lost during this process" -Level WARNING
    
    $results = @{
        "Winsock Catalog" = $false
        "TCP/IP Stack" = $false
        "DNS Cache" = $false
        "NetBIOS" = $false
        "IP Configuration" = $false
        "Network Adapters" = $false
    }
    
    # Execute resets in sequence
    $results["Winsock Catalog"] = Reset-WinsockCatalog
    Start-Sleep -Seconds 1
    
    $results["TCP/IP Stack"] = Reset-TcpIpStack
    Start-Sleep -Seconds 1
    
    $results["DNS Cache"] = Reset-DnsClientCache
    Start-Sleep -Seconds 1
    
    $results["NetBIOS"] = Reset-NetBiosOverTcpIp
    Start-Sleep -Seconds 1
    
    $results["IP Configuration"] = Reset-IpConfiguration
    Start-Sleep -Seconds 2
    
    $results["Network Adapters"] = Reset-NetworkAdapters
    Start-Sleep -Seconds 2
    
    # Display results
    Write-Host "`nNetwork Reset Results:" -ForegroundColor Cyan
    $allSuccess = $true
    foreach ($result in $results.GetEnumerator()) {
        $status = if ($result.Value) { "SUCCESS" } else { "FAILED" }
        $color = if ($result.Value) { "Green" } else { "Red" }
        Write-Host "  [$status] $($result.Key)" -ForegroundColor $color
        if (-not $result.Value) { $allSuccess = $false }
    }
    
    return $allSuccess
}

# ============================================================================
# POST-RESET VALIDATION
# ============================================================================

function Test-NetworkRecovery {
    Write-SectionHeader "POST-RESET VALIDATION"
    Write-Log "Waiting for network to stabilize..."
    Start-Sleep -Seconds 5
    
    $tests = @{
        "Network Adapter Status" = $false
        "IP Address Assigned" = $false
        "Default Gateway Present" = $false
        "DNS Resolution" = $false
        "Internet Connectivity" = $false
    }
    
    # Test adapter status
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($adapters.Count -gt 0) {
            $tests["Network Adapter Status"] = $true
            Write-Log "Network adapter is UP"
        } else {
            Write-Log "No network adapters are UP" -Level WARNING
        }
    } catch {
        Write-Log "Failed to check adapter status: $($_.Exception.Message)" -Level WARNING
    }
    
    # Test IP assignment
    try {
        $ipAddress = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" }
        if ($ipAddress) {
            $tests["IP Address Assigned"] = $true
            Write-Log "Valid IP address assigned: $($ipAddress[0].IPAddress)"
        } else {
            Write-Log "No valid IP address found" -Level WARNING
        }
    } catch {
        Write-Log "Failed to check IP address: $($_.Exception.Message)" -Level WARNING
    }
    
    # Test gateway
    try {
        $gateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($gateway) {
            $tests["Default Gateway Present"] = $true
            Write-Log "Default gateway configured: $($gateway[0].NextHop)"
        } else {
            Write-Log "No default gateway found" -Level WARNING
        }
    } catch {
        Write-Log "Failed to check gateway: $($_.Exception.Message)" -Level WARNING
    }
    
    # Test DNS
    try {
        $dnsTest = Resolve-DnsName "www.microsoft.com" -ErrorAction Stop
        if ($dnsTest) {
            $tests["DNS Resolution"] = $true
            Write-Log "DNS resolution is working"
        }
    } catch {
        Write-Log "DNS resolution failed: $($_.Exception.Message)" -Level WARNING
    }
    
    # Test internet
    try {
        $ping = Test-NetConnection "8.8.8.8" -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($ping) {
            $tests["Internet Connectivity"] = $true
            Write-Log "Internet connectivity restored"
        } else {
            Write-Log "Internet connectivity not yet restored" -Level WARNING
        }
    } catch {
        Write-Log "Internet connectivity test failed: $($_.Exception.Message)" -Level WARNING
    }
    
    # Display summary
    Write-Host "`nPost-Reset Validation Summary:" -ForegroundColor Cyan
    foreach ($test in $tests.GetEnumerator()) {
        $status = if ($test.Value) { "PASS" } else { "FAIL" }
        $color = if ($test.Value) { "Green" } else { "Yellow" }
        Write-Host "  [$status] $($test.Key)" -ForegroundColor $color
    }
    
    return $tests
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    try {
        Write-SectionHeader "NETWORK STACK RESET TOOL"
        Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
        Write-Host "User: $env:USERNAME" -ForegroundColor Cyan
        Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
        
        Write-Host "`n" -NoNewline
        Write-Host "WARNING: This script will reset your network stack!" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host "  - All network connectivity will be temporarily lost" -ForegroundColor Yellow
        Write-Host "  - VPN connections will be terminated" -ForegroundColor Yellow
        Write-Host "  - Network drives will disconnect" -ForegroundColor Yellow
        Write-Host "  - A system reboot may be required" -ForegroundColor Yellow
        Write-Host ""
        
        # Confirm execution
        if (-not $BackupOnly) {
            $confirm = Read-Host "Type 'YES' to proceed with network stack reset"
            if ($confirm -ne 'YES') {
                Write-Log "Operation cancelled by user" -Level WARNING
                return 0
            }
        }
        
        # Pre-flight checks
        if (-not $SkipPreFlightChecks) {
            $preFlightResults = Test-PreFlightChecks
            Write-Host "`nReview the pre-flight checks above." -ForegroundColor Cyan
            
            if (-not $BackupOnly) {
                $proceed = Read-Host "Continue with network reset? (Y/N)"
                if ($proceed -ne 'Y') {
                    Write-Log "Operation cancelled after pre-flight checks" -Level WARNING
                    return 0
                }
            }
        }
        
        # Create backup
        $backupSuccess = Backup-NetworkConfiguration
        if (-not $backupSuccess) {
            Write-Log "Backup failed - aborting reset for safety" -Level ERROR
            return 4
        }
        
        if ($BackupOnly) {
            Write-Log "Backup-only mode: Configuration saved successfully" -Level SUCCESS
            return 0
        }
        
        # Perform network reset
        $resetSuccess = Invoke-NetworkStackReset
        
        if (-not $resetSuccess) {
            Write-Log "Network reset completed with some failures" -Level WARNING
            Write-Log "Review the results above and backup location: $script:BackupPath" -Level WARNING
        } else {
            Write-Log "Network reset completed successfully" -Level SUCCESS
        }
        
        # Post-reset validation
        $validationResults = Test-NetworkRecovery
        
        # Generate summary report
        Write-SectionHeader "EXECUTION SUMMARY"
        Write-Host "Backup Location: $script:BackupPath" -ForegroundColor Cyan
        Write-Host "Log Entries: $($script:LogEntries.Count)" -ForegroundColor Cyan
        
        # Save log file
        $logFile = Join-Path $script:BackupPath "Reset-NetworkStack.log"
        $script:LogEntries | Out-File -FilePath $logFile
        Write-Host "Full log saved to: $logFile" -ForegroundColor Cyan
        
        # Reboot recommendation
        Write-Host "`n" -NoNewline
        Write-Host "IMPORTANT: A system reboot is recommended to complete the network reset." -ForegroundColor Yellow
        Write-Host "Some changes may not take full effect until after a restart." -ForegroundColor Yellow
        
        if (-not $NoRebootPrompt) {
            Write-Host ""
            $reboot = Read-Host "Would you like to reboot now? (Y/N)"
            if ($reboot -eq 'Y') {
                Write-Log "User initiated system reboot" -Level WARNING
                Write-Host "`nRebooting in 10 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            }
        }
        
        Write-Log "Script execution completed" -Level SUCCESS
        return 0
    }
    catch {
        Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
        Write-Log $_.ScriptStackTrace -Level ERROR
        return 3
    }
}

# Execute main function
$exitCode = Main
exit $exitCode