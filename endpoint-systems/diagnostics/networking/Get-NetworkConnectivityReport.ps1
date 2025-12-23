<#
.SYNOPSIS
    Comprehensive network connectivity diagnostic report for troubleshooting client connectivity issues.

.DESCRIPTION
    This script performs layered network diagnostics to identify where connectivity failures occur.
    Tests are performed in logical order from physical layer up through application layer.
    
    Tests performed:
    - Network adapter status and configuration
    - Default gateway connectivity
    - DNS resolution and server connectivity
    - Internet connectivity (multiple methods)
    - Proxy configuration and connectivity
    - VPN connection status
    - Common service endpoint tests (Microsoft 365, Google, etc.)
    
    Output is formatted for direct inclusion in support tickets.

.PARAMETER IncludeDetailedAdapter
    Include detailed network adapter configuration (IP, subnet, MAC, etc.)

.PARAMETER TestEndpoints
    Specify custom endpoints to test. Defaults to common cloud services.

.PARAMETER SkipSlowTests
    Skip tests that may take longer (traceroute, extended timeout tests)

.EXAMPLE
    .\Get-NetworkConnectivityReport.ps1
    Run standard connectivity diagnostics

.EXAMPLE
    .\Get-NetworkConnectivityReport.ps1 -IncludeDetailedAdapter
    Include full adapter configuration details

.EXAMPLE
    .\Get-NetworkConnectivityReport.ps1 -TestEndpoints "portal.azure.com","github.com"
    Test connectivity to specific endpoints

.NOTES
    Filename    : Get-NetworkConnectivityReport.ps1
    Domain      : endpoint-systems/diagnostics/networking
    Risk Level  : SAFE (Read-only diagnostic)
    Use Case    : Troubleshooting connectivity issues during support tickets
    
    Prerequisites:
    - Windows PowerShell 5.1 or PowerShell 7+
    - No elevation required for basic tests
    - Some VPN details may require elevation
    
    Author      : MSP Automation Team
    Version     : 1.0
    Last Updated: 2025-01-22
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDetailedAdapter,
    
    [Parameter(Mandatory=$false)]
    [string[]]$TestEndpoints = @(
        "outlook.office365.com",
        "login.microsoftonline.com",
        "google.com",
        "1.1.1.1"
    ),
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSlowTests
)

#Requires -Version 5.1

# Script initialization
$ErrorActionPreference = "Continue"
$script:FailureLayer = "None"
$script:TestResults = @()

#region Helper Functions

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details,
        [string]$Layer = "Unknown"
    )
    
    $statusColor = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "Gray" }
    }
    
    $result = [PSCustomObject]@{
        Test = $TestName
        Status = $Status
        Details = $Details
        Layer = $Layer
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:TestResults += $result
    
    Write-Host "[$Status] " -ForegroundColor $statusColor -NoNewline
    Write-Host "$TestName" -ForegroundColor White
    if ($Details) {
        Write-Host "      → $Details" -ForegroundColor Gray
    }
    
    # Track first failure
    if ($Status -eq "FAIL" -and $script:FailureLayer -eq "None") {
        $script:FailureLayer = $Layer
    }
}

function Test-NetworkAdapter {
    Write-SectionHeader "1. NETWORK ADAPTER STATUS"
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        
        if ($adapters.Count -eq 0) {
            Write-TestResult -TestName "Network Adapters" -Status "FAIL" `
                -Details "No active network adapters found" -Layer "Physical"
            return $false
        }
        
        foreach ($adapter in $adapters) {
            $adapterType = if ($adapter.MediaType) { $adapter.MediaType } else { "Unknown" }
            Write-TestResult -TestName "Adapter: $($adapter.Name)" -Status "PASS" `
                -Details "Status: Up | Type: $adapterType | Speed: $($adapter.LinkSpeed)" -Layer "Physical"
        }
        
        if ($IncludeDetailedAdapter) {
            Write-Host "`n   Detailed Configuration:" -ForegroundColor Yellow
            foreach ($adapter in $adapters) {
                $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | 
                    Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
                
                if ($ipConfig) {
                    Write-Host "   Interface: $($adapter.Name)" -ForegroundColor Gray
                    Write-Host "      IP Address: $($ipConfig.IPAddress)" -ForegroundColor Gray
                    Write-Host "      Prefix: /$($ipConfig.PrefixLength)" -ForegroundColor Gray
                    Write-Host "      MAC: $($adapter.MacAddress)" -ForegroundColor Gray
                }
            }
        }
        
        return $true
    }
    catch {
        Write-TestResult -TestName "Network Adapters" -Status "FAIL" `
            -Details "Error checking adapters: $($_.Exception.Message)" -Layer "Physical"
        return $false
    }
}

function Test-IPConfiguration {
    Write-SectionHeader "2. IP CONFIGURATION"
    
    try {
        $ipv4Addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | 
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" }
        
        if ($ipv4Addresses.Count -eq 0) {
            Write-TestResult -TestName "IP Configuration" -Status "FAIL" `
                -Details "No valid IPv4 address (APIPA or no IP assigned)" -Layer "Physical"
            return $false
        }
        
        foreach ($ip in $ipv4Addresses) {
            Write-TestResult -TestName "IP Address" -Status "PASS" `
                -Details "$($ip.IPAddress)/$($ip.PrefixLength) on interface $($ip.InterfaceAlias)" -Layer "Physical"
        }
        
        return $true
    }
    catch {
        Write-TestResult -TestName "IP Configuration" -Status "FAIL" `
            -Details "Error retrieving IP configuration: $($_.Exception.Message)" -Layer "Physical"
        return $false
    }
}

function Test-DefaultGateway {
    Write-SectionHeader "3. DEFAULT GATEWAY CONNECTIVITY"
    
    try {
        $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop
        
        if ($routes.Count -eq 0) {
            Write-TestResult -TestName "Default Gateway" -Status "FAIL" `
                -Details "No default gateway configured" -Layer "Routing"
            return $false
        }
        
        $gatewayReachable = $false
        foreach ($route in $routes) {
            $gateway = $route.NextHop
            
            if ($gateway -eq "0.0.0.0") { continue }
            
            $pingResult = Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue
            
            if ($pingResult) {
                Write-TestResult -TestName "Gateway Ping" -Status "PASS" `
                    -Details "Gateway $gateway is reachable" -Layer "Routing"
                $gatewayReachable = $true
            }
            else {
                Write-TestResult -TestName "Gateway Ping" -Status "FAIL" `
                    -Details "Gateway $gateway is not responding to ping" -Layer "Routing"
            }
        }
        
        return $gatewayReachable
    }
    catch {
        Write-TestResult -TestName "Default Gateway" -Status "FAIL" `
            -Details "Error testing gateway: $($_.Exception.Message)" -Layer "Routing"
        return $false
    }
}

function Test-DNSResolution {
    Write-SectionHeader "4. DNS RESOLUTION"
    
    try {
        # Get configured DNS servers
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | 
            Where-Object { $_.ServerAddresses.Count -gt 0 } | 
            Select-Object -First 1
        
        if ($null -eq $dnsServers -or $dnsServers.ServerAddresses.Count -eq 0) {
            Write-TestResult -TestName "DNS Configuration" -Status "FAIL" `
                -Details "No DNS servers configured" -Layer "DNS"
            return $false
        }
        
        Write-TestResult -TestName "DNS Configuration" -Status "PASS" `
            -Details "DNS Servers: $($dnsServers.ServerAddresses -join ', ')" -Layer "DNS"
        
        # Test DNS resolution
        $testDomains = @("google.com", "microsoft.com")
        $resolutionSuccess = $false
        
        foreach ($domain in $testDomains) {
            try {
                $resolved = Resolve-DnsName -Name $domain -ErrorAction Stop -DnsOnly
                Write-TestResult -TestName "DNS Resolution: $domain" -Status "PASS" `
                    -Details "Resolved to $($resolved[0].IPAddress)" -Layer "DNS"
                $resolutionSuccess = $true
                break
            }
            catch {
                Write-TestResult -TestName "DNS Resolution: $domain" -Status "FAIL" `
                    -Details "Failed to resolve: $($_.Exception.Message)" -Layer "DNS"
            }
        }
        
        return $resolutionSuccess
    }
    catch {
        Write-TestResult -TestName "DNS Resolution" -Status "FAIL" `
            -Details "Error testing DNS: $($_.Exception.Message)" -Layer "DNS"
        return $false
    }
}

function Test-InternetConnectivity {
    Write-SectionHeader "5. INTERNET CONNECTIVITY"
    
    $connectivityTests = @(
        @{ Host = "8.8.8.8"; Name = "Google DNS (IP)" },
        @{ Host = "1.1.1.1"; Name = "Cloudflare DNS (IP)" },
        @{ Host = "www.msftconnecttest.com"; Name = "Microsoft Connectivity Test" }
    )
    
    $hasInternet = $false
    
    foreach ($test in $connectivityTests) {
        try {
            $pingResult = Test-Connection -ComputerName $test.Host -Count 2 -Quiet -ErrorAction Stop
            
            if ($pingResult) {
                Write-TestResult -TestName $test.Name -Status "PASS" `
                    -Details "Successfully reached $($test.Host)" -Layer "Internet"
                $hasInternet = $true
            }
            else {
                Write-TestResult -TestName $test.Name -Status "FAIL" `
                    -Details "Cannot reach $($test.Host)" -Layer "Internet"
            }
        }
        catch {
            Write-TestResult -TestName $test.Name -Status "FAIL" `
                -Details "Error: $($_.Exception.Message)" -Layer "Internet"
        }
    }
    
    # HTTP/HTTPS connectivity test
    try {
        $httpTest = Invoke-WebRequest -Uri "http://www.msftconnecttest.com/connecttest.txt" `
            -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        
        if ($httpTest.StatusCode -eq 200) {
            Write-TestResult -TestName "HTTP Connectivity" -Status "PASS" `
                -Details "HTTP request successful" -Layer "Application"
            $hasInternet = $true
        }
    }
    catch {
        Write-TestResult -TestName "HTTP Connectivity" -Status "FAIL" `
            -Details "HTTP request failed: $($_.Exception.Message)" -Layer "Application"
    }
    
    return $hasInternet
}

function Test-ProxyConfiguration {
    Write-SectionHeader "6. PROXY CONFIGURATION"
    
    try {
        # Check system proxy settings
        $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop
        
        if ($proxySettings.ProxyEnable -eq 1) {
            Write-TestResult -TestName "Proxy Status" -Status "WARN" `
                -Details "Proxy enabled: $($proxySettings.ProxyServer)" -Layer "Proxy"
            
            # Test if proxy is reachable
            if ($proxySettings.ProxyServer -match "^(.+):(\d+)$") {
                $proxyHost = $Matches[1]
                $proxyPort = $Matches[2]
                
                try {
                    $tcpTest = Test-NetConnection -ComputerName $proxyHost -Port $proxyPort -WarningAction SilentlyContinue
                    if ($tcpTest.TcpTestSucceeded) {
                        Write-TestResult -TestName "Proxy Connectivity" -Status "PASS" `
                            -Details "Proxy server is reachable" -Layer "Proxy"
                    }
                    else {
                        Write-TestResult -TestName "Proxy Connectivity" -Status "FAIL" `
                            -Details "Proxy server is not reachable" -Layer "Proxy"
                    }
                }
                catch {
                    Write-TestResult -TestName "Proxy Connectivity" -Status "WARN" `
                        -Details "Could not test proxy connectivity" -Layer "Proxy"
                }
            }
        }
        else {
            Write-TestResult -TestName "Proxy Status" -Status "PASS" `
                -Details "No proxy configured (direct connection)" -Layer "Proxy"
        }
        
        return $true
    }
    catch {
        Write-TestResult -TestName "Proxy Configuration" -Status "WARN" `
            -Details "Could not read proxy settings: $($_.Exception.Message)" -Layer "Proxy"
        return $true
    }
}

function Test-VPNStatus {
    Write-SectionHeader "7. VPN CONNECTION STATUS"
    
    try {
        # Check for VPN connections
        $vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
        
        if ($null -eq $vpnConnections -or $vpnConnections.Count -eq 0) {
            Write-TestResult -TestName "VPN Status" -Status "PASS" `
                -Details "No VPN connections configured" -Layer "VPN"
            return $true
        }
        
        foreach ($vpn in $vpnConnections) {
            $status = $vpn.ConnectionStatus
            $statusResult = if ($status -eq "Connected") { "PASS" } else { "WARN" }
            
            Write-TestResult -TestName "VPN: $($vpn.Name)" -Status $statusResult `
                -Details "Status: $status | Server: $($vpn.ServerAddress)" -Layer "VPN"
        }
        
        return $true
    }
    catch {
        Write-TestResult -TestName "VPN Status" -Status "WARN" `
            -Details "Could not check VPN status (may require elevation): $($_.Exception.Message)" -Layer "VPN"
        return $true
    }
}

function Test-ServiceEndpoints {
    Write-SectionHeader "8. SERVICE ENDPOINT CONNECTIVITY"
    
    foreach ($endpoint in $TestEndpoints) {
        try {
            # Try DNS resolution first
            $resolved = Resolve-DnsName -Name $endpoint -ErrorAction Stop
            
            # Try HTTPS connection
            $httpTest = Invoke-WebRequest -Uri "https://$endpoint" -UseBasicParsing `
                -TimeoutSec 10 -ErrorAction Stop
            
            Write-TestResult -TestName "Endpoint: $endpoint" -Status "PASS" `
                -Details "HTTPS connection successful (Status: $($httpTest.StatusCode))" -Layer "Application"
        }
        catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -like "*resolve*" -or $errorMsg -like "*DNS*") {
                Write-TestResult -TestName "Endpoint: $endpoint" -Status "FAIL" `
                    -Details "DNS resolution failed" -Layer "DNS"
            }
            else {
                Write-TestResult -TestName "Endpoint: $endpoint" -Status "WARN" `
                    -Details "Connection issue: $errorMsg" -Layer "Application"
            }
        }
    }
}

function Write-Summary {
    Write-SectionHeader "DIAGNOSTIC SUMMARY"
    
    $passCount = ($script:TestResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($script:TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($script:TestResults | Where-Object { $_.Status -eq "WARN" }).Count
    
    Write-Host "Total Tests Run: $($script:TestResults.Count)" -ForegroundColor White
    Write-Host "Passed: $passCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "Warnings: $warnCount" -ForegroundColor Yellow
    
    if ($script:FailureLayer -ne "None") {
        Write-Host "`nFirst Failure Detected At: $($script:FailureLayer) Layer" -ForegroundColor Red
        Write-Host "Focus troubleshooting efforts on the $($script:FailureLayer) layer and below." -ForegroundColor Yellow
    }
    else {
        Write-Host "`nAll Critical Tests Passed" -ForegroundColor Green
    }
    
    # Troubleshooting recommendations
    if ($failCount -gt 0) {
        Write-Host "`nTroubleshooting Recommendations:" -ForegroundColor Yellow
        
        $failures = $script:TestResults | Where-Object { $_.Status -eq "FAIL" }
        $layers = $failures | Select-Object -ExpandProperty Layer -Unique
        
        foreach ($layer in $layers) {
            switch ($layer) {
                "Physical" {
                    Write-Host "  • Physical/Adapter: Check cables, adapter status, driver updates" -ForegroundColor Gray
                }
                "Routing" {
                    Write-Host "  • Routing: Verify gateway configuration, check router/firewall" -ForegroundColor Gray
                }
                "DNS" {
                    Write-Host "  • DNS: Check DNS server settings, try 8.8.8.8 or 1.1.1.1" -ForegroundColor Gray
                }
                "Internet" {
                    Write-Host "  • Internet: Check firewall rules, ISP issues, external connectivity" -ForegroundColor Gray
                }
                "Proxy" {
                    Write-Host "  • Proxy: Verify proxy server status, check proxy authentication" -ForegroundColor Gray
                }
                "Application" {
                    Write-Host "  • Application: Check application-specific firewall rules, certificates" -ForegroundColor Gray
                }
            }
        }
    }
}

#endregion

#region Main Execution

# Script header
Write-Host "`n" -NoNewline
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║        NETWORK CONNECTIVITY DIAGNOSTIC REPORT              ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:      $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Username:      $env:USERNAME" -ForegroundColor White
Write-Host "Date/Time:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "PowerShell:    $($PSVersionTable.PSVersion)" -ForegroundColor White
Write-Host ""

# Run diagnostic tests in order
Test-NetworkAdapter
Test-IPConfiguration
Test-DefaultGateway
Test-DNSResolution
Test-InternetConnectivity
Test-ProxyConfiguration
Test-VPNStatus
Test-ServiceEndpoints

# Display summary
Write-Summary

# Export results option
Write-Host "`n"
Write-Host "Export Options:" -ForegroundColor Cyan
Write-Host "  Results are stored in `$script:TestResults variable" -ForegroundColor Gray
Write-Host "  Export to CSV: `$script:TestResults | Export-Csv -Path 'NetworkDiagnostics.csv' -NoTypeInformation" -ForegroundColor Gray
Write-Host "  Copy to clipboard: `$script:TestResults | ConvertTo-Json | Set-Clipboard" -ForegroundColor Gray
Write-Host "`n"

#endregion