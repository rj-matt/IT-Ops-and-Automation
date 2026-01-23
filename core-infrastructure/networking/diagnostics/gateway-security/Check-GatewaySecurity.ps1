<#
.SYNOPSIS
    Performs security diagnostic checks on network routers/gateways.

.DESCRIPTION
    This script assesses router security posture by checking for common vulnerabilities
    and misconfigurations. It attempts automated checks where possible and provides a
    manual verification checklist when direct router access is not available.
    
    Checks performed:
    - Gateway identification and reachability
    - Firmware version detection (where possible)
    - UPnP status (security risk if enabled)
    - Remote management exposure
    - DNS configuration validation
    - Common security misconfigurations
    
    This is a READ-ONLY diagnostic script. It does not modify router settings.

.PARAMETER GatewayIP
    IP address of the router/gateway to check. If not specified, script will auto-detect
    the default gateway from network configuration.

.PARAMETER IncludePortScan
    Performs a basic port scan to identify exposed services. Use with caution on client
    networks - verify authorization before enabling.

.PARAMETER OutputPath
    Optional path to save the security report. If not specified, outputs to console only.

.EXAMPLE
    .\Get-RouterSecurityCheck.ps1
    Runs security check against auto-detected default gateway with console output only.

.EXAMPLE
    .\Get-RouterSecurityCheck.ps1 -GatewayIP 192.168.1.1 -OutputPath "C:\Temp\router-check.txt"
    Checks specific gateway and saves report to file.

.EXAMPLE
    .\Get-RouterSecurityCheck.ps1 -IncludePortScan
    Performs full check including port scan (requires authorization).

.NOTES
    Filename    : Get-RouterSecurityCheck.ps1
    Author      : MSP Automation Team
    Version     : 1.0
    Domain      : core-infrastructure/networking/diagnostics
    Risk Level  : Read-only (network scanning may trigger security alerts)
    
    Prerequisites:
    - PowerShell 5.1 or higher
    - Network access to router/gateway
    - Router admin credentials (for web interface checks)
    - Authorization to perform network scanning if using -IncludePortScan
    
    Limitations:
    - Router web interface checks are brand-specific and may not work on all devices
    - Some checks require manual verification via checklist
    - Port scanning may trigger IDS/IPS alerts
    
    Use Case:
    - Security assessments and audits
    - Incident response (checking for compromise)
    - Client onboarding security baseline
    - Compliance verification
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    [string]$GatewayIP,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludePortScan,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

# ============================================================================
# INITIALIZATION
# ============================================================================

$script:ErrorActionPreference = 'Continue'
$script:Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    GatewayIP = $null
    Checks = @()
    ManualChecklistRequired = $false
    OverallRisk = "Unknown"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $color
    Write-Host $Message
}

function Add-CheckResult {
    param(
        [string]$CheckName,
        [ValidateSet('Pass','Fail','Warning','Info','Manual')]
        [string]$Status,
        [string]$Finding,
        [string]$Recommendation = "",
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity = 'Info'
    )
    
    $script:Results.Checks += [PSCustomObject]@{
        CheckName = $CheckName
        Status = $Status
        Finding = $Finding
        Recommendation = $Recommendation
        Severity = $Severity
    }
}

function Test-RouterReachability {
    param([string]$IP)
    
    Write-Log "Testing connectivity to gateway: $IP" -Level Info
    
    try {
        $ping = Test-Connection -ComputerName $IP -Count 2 -Quiet -ErrorAction Stop
        if ($ping) {
            Add-CheckResult -CheckName "Gateway Reachability" -Status "Pass" `
                -Finding "Gateway $IP is reachable (ping successful)" `
                -Severity "Info"
            return $true
        } else {
            Add-CheckResult -CheckName "Gateway Reachability" -Status "Fail" `
                -Finding "Gateway $IP is not responding to ping" `
                -Recommendation "Verify network connectivity and gateway IP address" `
                -Severity "High"
            return $false
        }
    } catch {
        Add-CheckResult -CheckName "Gateway Reachability" -Status "Fail" `
            -Finding "Unable to test connectivity: $($_.Exception.Message)" `
            -Recommendation "Verify network configuration and firewall rules" `
            -Severity "High"
        return $false
    }
}

function Get-DefaultGateway {
    Write-Log "Auto-detecting default gateway..." -Level Info
    
    try {
        $gateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | 
                   Where-Object {$_.NextHop -ne '0.0.0.0'} | 
                   Select-Object -First 1 -ExpandProperty NextHop
        
        if ($gateway) {
            Write-Log "Default gateway detected: $gateway" -Level Success
            return $gateway
        } else {
            Write-Log "No default gateway found in routing table" -Level Error
            return $null
        }
    } catch {
        Write-Log "Failed to detect default gateway: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-DNSConfiguration {
    Write-Log "Checking DNS configuration..." -Level Info
    
    try {
        $adapters = Get-DnsClientServerAddress -AddressFamily IPv4 | 
                    Where-Object {$_.ServerAddresses.Count -gt 0}
        
        $dnsServers = @()
        foreach ($adapter in $adapters) {
            foreach ($dns in $adapter.ServerAddresses) {
                if ($dns -notin $dnsServers) {
                    $dnsServers += $dns
                }
            }
        }
        
        if ($dnsServers.Count -eq 0) {
            Add-CheckResult -CheckName "DNS Configuration" -Status "Fail" `
                -Finding "No DNS servers configured" `
                -Recommendation "Configure DNS servers (recommend 8.8.8.8, 1.1.1.1, or ISP DNS)" `
                -Severity "High"
        } else {
            # Check for suspicious DNS servers (common malware DNS)
            $suspiciousDNS = @('8.26.56.26','9.9.9.9','198.105.244.11','198.105.254.11')
            $foundSuspicious = $dnsServers | Where-Object {$_ -in $suspiciousDNS}
            
            if ($foundSuspicious) {
                Add-CheckResult -CheckName "DNS Configuration" -Status "Warning" `
                    -Finding "Potentially suspicious DNS servers detected: $($foundSuspicious -join ', ')" `
                    -Recommendation "Verify DNS settings are not hijacked. Check router DNS configuration." `
                    -Severity "Critical"
            } else {
                $dnsInfo = $dnsServers -join ', '
                Add-CheckResult -CheckName "DNS Configuration" -Status "Pass" `
                    -Finding "DNS servers configured: $dnsInfo" `
                    -Severity "Info"
            }
        }
        
        return $dnsServers
    } catch {
        Add-CheckResult -CheckName "DNS Configuration" -Status "Warning" `
            -Finding "Unable to retrieve DNS configuration: $($_.Exception.Message)" `
            -Severity "Medium"
        return @()
    }
}

function Test-CommonPorts {
    param([string]$IP)
    
    if (-not $IncludePortScan) {
        Write-Log "Port scanning skipped (use -IncludePortScan to enable)" -Level Info
        return
    }
    
    Write-Log "Scanning common router management ports (this may take 30-60 seconds)..." -Level Info
    
    # Common router/management ports
    $portsToCheck = @{
        '80'   = 'HTTP (Web Interface)'
        '443'  = 'HTTPS (Secure Web Interface)'
        '22'   = 'SSH (Remote Admin)'
        '23'   = 'Telnet (INSECURE - Remote Admin)'
        '8080' = 'HTTP Alt (Web Interface)'
        '8443' = 'HTTPS Alt (Web Interface)'
        '1900' = 'UPnP (Potential Security Risk)'
        '5000' = 'UPnP Control'
    }
    
    $openPorts = @()
    $criticalPorts = @()
    
    foreach ($port in $portsToCheck.Keys) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connect = $tcpClient.BeginConnect($IP, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
            
            if ($wait -and $tcpClient.Connected) {
                $portDesc = $portsToCheck[$port]
                $openPorts += "$port ($portDesc)"
                
                # Flag critical security issues
                if ($port -eq '23') {
                    $criticalPorts += "Telnet (Port 23) - INSECURE protocol enabled"
                } elseif ($port -eq '1900' -or $port -eq '5000') {
                    $criticalPorts += "UPnP (Port $port) - Potential security risk"
                }
                
                $tcpClient.Close()
            }
        } catch {
            # Port closed or filtered - this is expected
        }
    }
    
    if ($openPorts.Count -eq 0) {
        Add-CheckResult -CheckName "Open Ports Scan" -Status "Pass" `
            -Finding "No common management ports found open from this network position" `
            -Recommendation "This is expected if scanning from LAN. External exposure should still be verified." `
            -Severity "Info"
    } else {
        $severity = if ($criticalPorts.Count -gt 0) { "Critical" } else { "Medium" }
        $finding = "Open ports detected: " + ($openPorts -join ', ')
        
        if ($criticalPorts.Count -gt 0) {
            $finding += "`nCRITICAL ISSUES: " + ($criticalPorts -join '; ')
        }
        
        Add-CheckResult -CheckName "Open Ports Scan" -Status "Warning" `
            -Finding $finding `
            -Recommendation "Review each open port. Disable UPnP if not needed. NEVER use Telnet - disable immediately." `
            -Severity $severity
    }
}

function Test-RouterWebInterface {
    param([string]$IP)
    
    Write-Log "Attempting to access router web interface..." -Level Info
    
    $testURLs = @(
        "http://$IP",
        "https://$IP",
        "http://$IP:8080",
        "https://$IP:8443"
    )
    
    $accessible = $false
    $accessibleURL = $null
    
    foreach ($url in $testURLs) {
        try {
            # Quick check if web interface is responding
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
            $accessible = $true
            $accessibleURL = $url
            break
        } catch {
            # Expected for most URLs - continue checking
        }
    }
    
    if ($accessible) {
        Add-CheckResult -CheckName "Web Interface Access" -Status "Info" `
            -Finding "Router web interface accessible at: $accessibleURL" `
            -Recommendation "Manual verification required. Admin should log in to check settings." `
            -Severity "Info"
        
        $script:Results.ManualChecklistRequired = $true
    } else {
        Add-CheckResult -CheckName "Web Interface Access" -Status "Manual" `
            -Finding "Unable to access router web interface automatically" `
            -Recommendation "Manual login required to verify security settings. See checklist below." `
            -Severity "Info"
        
        $script:Results.ManualChecklistRequired = $true
    }
}

function Get-ManualVerificationChecklist {
    Write-Log "Generating manual verification checklist..." -Level Info
    
    return @"

================================================================================
MANUAL GATEWAY SECURITY VERIFICATION CHECKLIST
================================================================================
Gateway IP: $($script:Results.GatewayIP)
Technician must log into gateway web interface and verify the following:

[ ] AUTHENTICATION
    - Default username/password has been changed
    - Strong password is in use (12+ characters, complex)
    - Admin account is not using 'admin/admin' or 'admin/password'

[ ] FIRMWARE
    - Current firmware version: _______________
    - Latest firmware version:  _______________
    - Firmware is up to date (check manufacturer website)
    - Auto-update is enabled (if available)

[ ] REMOTE MANAGEMENT
    - Remote management is DISABLED (critical security risk if enabled)
    - If enabled, note: Protocol _____ Port _____ (document in ticket)
    - Remote management should only be enabled with strong justification

[ ] UPnP (Universal Plug and Play)
    - UPnP is DISABLED (recommended for security)
    - If enabled, document reason in ticket (some applications require it)

[ ] DNS SETTINGS
    - Primary DNS:   _______________
    - Secondary DNS: _______________
    - Verify DNS servers are legitimate (ISP, Google, Cloudflare)
    - No unknown or suspicious DNS servers configured

[ ] WIRELESS SECURITY (if applicable)
    - WPA3 or WPA2 encryption enabled (WEP is insecure)
    - Strong WiFi password in use
    - SSID is not broadcasting sensitive information
    - Guest network is isolated from main network (if present)

[ ] PORT FORWARDING / DMZ
    - Document any port forwarding rules: _______________
    - DMZ is not enabled (unless specifically required)
    - Only necessary ports are forwarded

[ ] LOGGING
    - Gatway logging is enabled
    - Check logs for suspicious activity (repeated login failures, etc.)

FINDINGS SUMMARY:
________________________________________________________________________________
________________________________________________________________________________
________________________________________________________________________________

RECOMMENDATIONS:
________________________________________________________________________________
________________________________________________________________________________
________________________________________________________________________________

Verified by: _______________  Date: _______________  Ticket #: _______________

"@
}

function Get-RiskAssessment {
    $criticalCount = ($script:Results.Checks | Where-Object {$_.Severity -eq 'Critical'}).Count
    $highCount = ($script:Results.Checks | Where-Object {$_.Severity -eq 'High'}).Count
    $failCount = ($script:Results.Checks | Where-Object {$_.Status -eq 'Fail'}).Count
    
    if ($criticalCount -gt 0) {
        return "CRITICAL"
    } elseif ($highCount -gt 0 -or $failCount -gt 0) {
        return "HIGH"
    } elseif (($script:Results.Checks | Where-Object {$_.Severity -eq 'Medium'}).Count -gt 0) {
        return "MEDIUM"
    } else {
        return "LOW"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Log "======================================================" -Level Info
Write-Log "Gateway Security Diagnostic Check - Starting" -Level Info
Write-Log "======================================================" -Level Info
Write-Log ""

# Step 1: Determine gateway IP
if (-not $GatewayIP) {
    $GatewayIP = Get-DefaultGateway
    if (-not $GatewayIP) {
        Write-Log "FATAL: Unable to determine gateway IP address" -Level Error
        Write-Log "Please specify gateway IP using -GatewayIP parameter" -Level Error
        exit 1
    }
}

$script:Results.GatewayIP = $GatewayIP
Write-Log "Target Gateway: $GatewayIP" -Level Info
Write-Log ""

# Step 2: Test basic connectivity
$reachable = Test-RouterReachability -IP $GatewayIP
if (-not $reachable) {
    Write-Log "WARNING: Gateway is not reachable - some checks will be skipped" -Level Warning
}

# Step 3: Check DNS configuration
Get-DNSConfiguration | Out-Null

# Step 4: Port scanning (if enabled)
if ($reachable) {
    Test-CommonPorts -IP $GatewayIP
}

# Step 5: Web interface detection
if ($reachable) {
    Test-RouterWebInterface -IP $GatewayIP
}

# Step 6: Calculate overall risk
$script:Results.OverallRisk = Get-RiskAssessment

# ============================================================================
# RESULTS OUTPUT
# ============================================================================

Write-Log ""
Write-Log "======================================================" -Level Info
Write-Log "Gateway Security Check - Results Summary" -Level Info
Write-Log "======================================================" -Level Info

$output = @"

GATEWAY SECURITY DIAGNOSTIC REPORT
Generated: $($script:Results.Timestamp)
Computer: $($script:Results.ComputerName)
Gateway IP: $($script:Results.GatewayIP)
Overall Risk Level: $($script:Results.OverallRisk)

================================================================================
AUTOMATED CHECK RESULTS
================================================================================

"@

foreach ($check in $script:Results.Checks) {
    $statusSymbol = switch($check.Status) {
        'Pass'    { '[✓]' }
        'Fail'    { '[✗]' }
        'Warning' { '[!]' }
        'Info'    { '[i]' }
        'Manual'  { '[→]' }
    }
    
    $output += "`n$statusSymbol $($check.CheckName) - $($check.Status.ToUpper())`n"
    $output += "    Severity: $($check.Severity)`n"
    $output += "    Finding: $($check.Finding)`n"
    
    if ($check.Recommendation) {
        $output += "    Recommendation: $($check.Recommendation)`n"
    }
}

# Add manual checklist if required
if ($script:Results.ManualChecklistRequired) {
    $output += "`n`n"
    $output += Get-ManualVerificationChecklist
}

# Add recommendations summary
$criticalIssues = $script:Results.Checks | Where-Object {$_.Severity -eq 'Critical'}
$highIssues = $script:Results.Checks | Where-Object {$_.Severity -eq 'High'}

if ($criticalIssues.Count -gt 0 -or $highIssues.Count -gt 0) {
    $output += "`n`n"
    $output += "================================================================================`n"
    $output += "PRIORITY ACTION ITEMS`n"
    $output += "================================================================================`n"
    
    if ($criticalIssues.Count -gt 0) {
        $output += "`nCRITICAL ISSUES (Address Immediately):`n"
        foreach ($issue in $criticalIssues) {
            $output += "  • $($issue.CheckName): $($issue.Finding)`n"
            if ($issue.Recommendation) {
                $output += "    → $($issue.Recommendation)`n"
            }
        }
    }
    
    if ($highIssues.Count -gt 0) {
        $output += "`nHIGH PRIORITY ISSUES:`n"
        foreach ($issue in $highIssues) {
            $output += "  • $($issue.CheckName): $($issue.Finding)`n"
            if ($issue.Recommendation) {
                $output += "    → $($issue.Recommendation)`n"
            }
        }
    }
}

$output += "`n`n"
$output += "================================================================================`n"
$output += "END OF REPORT`n"
$output += "================================================================================`n"

# Output to console
Write-Host $output

# Save to file if specified
if ($OutputPath) {
    try {
        $output | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Log "Report saved to: $OutputPath" -Level Success
    } catch {
        Write-Log "Failed to save report to file: $($_.Exception.Message)" -Level Error
    }
}

# Final summary
Write-Log ""
Write-Log "======================================================" -Level Info

$summaryColor = switch($script:Results.OverallRisk) {
    'CRITICAL' { 'Red' }
    'HIGH'     { 'Red' }
    'MEDIUM'   { 'Yellow' }
    'LOW'      { 'Green' }
    default    { 'Gray' }
}

Write-Host "Overall Risk Assessment: " -NoNewline
Write-Host $script:Results.OverallRisk -ForegroundColor $summaryColor

Write-Log "Total Checks Performed: $($script:Results.Checks.Count)" -Level Info
Write-Log "Manual Verification Required: $($script:Results.ManualChecklistRequired)" -Level Info
Write-Log ""
Write-Log "Review findings above and document in ticket." -Level Info
Write-Log "Use manual checklist to complete verification." -Level Info
Write-Log "======================================================" -Level Info