<#
.SYNOPSIS
    Scans for open listening ports on local or remote Windows endpoints and identifies potentially risky exposures.

.DESCRIPTION
    This diagnostic script enumerates all listening TCP/UDP ports on Windows systems and identifies the 
    associated processes and services. It flags potentially dangerous exposures (RDP, SMB, administrative 
    interfaces) and validates against local firewall rules.
    
    Designed for MSP security assessments, incident response, and routine security posture validation.

.PARAMETER ComputerName
    Target computer(s) to scan. Defaults to local machine.
    Accepts single computer, comma-separated list, or array from pipeline.

.PARAMETER IncludeFirewallRules
    When specified, retrieves Windows Firewall rules and compares against listening ports.
    Helps identify ports open without explicit firewall rules.

.PARAMETER ExportPath
    Optional path to export results as CSV for ticket documentation.
    If not specified, results are displayed to console only.

.EXAMPLE
    .\Get-OpenPortScan.ps1
    Scans the local machine for listening ports.

.EXAMPLE
    .\Get-OpenPortScan.ps1 -ComputerName SERVER01 -IncludeFirewallRules
    Scans SERVER01 and includes firewall rule analysis.

.EXAMPLE
    .\Get-OpenPortScan.ps1 -ComputerName WS01,WS02,WS03 -ExportPath "C:\Temp\PortScan.csv"
    Scans multiple workstations and exports results to CSV.

.NOTES
    Filename    : Get-OpenPortScan.ps1
    Domain      : security-operations/diagnostics/endpoint-posture/
    Risk Level  : READ-ONLY / SAFE
    Requirements: 
        - PowerShell 5.1 or higher
        - Administrator rights (for firewall rule access and remote scanning)
        - WinRM enabled for remote computers
        - Network connectivity to target systems
    
    Author      : MSP Automation Toolkit
    Version     : 1.1
    
.LINK
    https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter()]
    [switch]$IncludeFirewallRules,
    
    [Parameter()]
    [string]$ExportPath
)

BEGIN {
    # Define high-risk ports commonly exploited or exposed inappropriately
    $RiskyPorts = @{
        20    = "FTP Data"
        21    = "FTP Control"
        22    = "SSH"
        23    = "Telnet"
        25    = "SMTP"
        53    = "DNS"
        80    = "HTTP"
        110   = "POP3"
        135   = "RPC Endpoint Mapper"
        139   = "NetBIOS Session"
        143   = "IMAP"
        389   = "LDAP"
        443   = "HTTPS"
        445   = "SMB/CIFS"
        636   = "LDAPS"
        1433  = "SQL Server"
        1434  = "SQL Server Browser"
        3306  = "MySQL"
        3389  = "RDP"
        5432  = "PostgreSQL"
        5900  = "VNC"
        5985  = "WinRM HTTP"
        5986  = "WinRM HTTPS"
        8080  = "HTTP Proxy"
        8443  = "HTTPS Alt"
    }

    # Initialize results collection
    $AllResults = @()
    
    Write-Host "`n=== MSP Open Port Scan - Security Posture Check ===" -ForegroundColor Cyan
    Write-Host "Scan Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Target Systems: $($ComputerName -join ', ')`n" -ForegroundColor Gray
}

PROCESS {
    foreach ($Computer in $ComputerName) {
        Write-Host "[SCANNING] $Computer..." -ForegroundColor Yellow
        
        try {
            # Test connectivity first
            if ($Computer -ne $env:COMPUTERNAME) {
                if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
                    Write-Warning "[$Computer] Unreachable - skipping"
                    continue
                }
            }

            # Scriptblock to run on target system
            $ScanScript = {
                param($RiskyPortsList, $IncludeFW)
                
                $Results = @()
                
                # Get TCP listening ports
                $TcpConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
                    Select-Object LocalAddress, LocalPort, OwningProcess, State
                
                # Get UDP listening ports
                $UdpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | 
                    Select-Object LocalAddress, LocalPort, OwningProcess
                
                # Process TCP ports
                foreach ($conn in $TcpConnections) {
                    try {
                        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                        $serviceName = (Get-WmiObject Win32_Service -Filter "ProcessId=$($conn.OwningProcess)" -ErrorAction SilentlyContinue).Name
                        
                        # Check if port is in risky list
                        $isRisky = $false
                        $serviceDesc = ""
                        if ($RiskyPortsList.ContainsKey([int]$conn.LocalPort)) {
                            $isRisky = $true
                            $serviceDesc = $RiskyPortsList[[int]$conn.LocalPort]
                        }
                        
                        $portInfo = [PSCustomObject]@{
                            Protocol      = "TCP"
                            LocalAddress  = $conn.LocalAddress
                            LocalPort     = $conn.LocalPort
                            State         = $conn.State
                            ProcessID     = $conn.OwningProcess
                            ProcessName   = if ($process) { $process.Name } else { "Unknown" }
                            ServiceName   = if ($serviceName) { $serviceName } else { "N/A" }
                            ServiceDesc   = $serviceDesc
                            IsRisky       = $isRisky
                        }
                        $Results += $portInfo
                    }
                    catch {
                        Write-Warning "Error processing TCP port $($conn.LocalPort): $_"
                    }
                }
                
                # Process UDP ports
                foreach ($endpoint in $UdpEndpoints) {
                    try {
                        $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
                        $serviceName = (Get-WmiObject Win32_Service -Filter "ProcessId=$($endpoint.OwningProcess)" -ErrorAction SilentlyContinue).Name
                        
                        # Check if port is in risky list
                        $isRisky = $false
                        $serviceDesc = ""
                        if ($RiskyPortsList.ContainsKey([int]$endpoint.LocalPort)) {
                            $isRisky = $true
                            $serviceDesc = $RiskyPortsList[[int]$endpoint.LocalPort]
                        }
                        
                        $portInfo = [PSCustomObject]@{
                            Protocol      = "UDP"
                            LocalAddress  = $endpoint.LocalAddress
                            LocalPort     = $endpoint.LocalPort
                            State         = "Listening"
                            ProcessID     = $endpoint.OwningProcess
                            ProcessName   = if ($process) { $process.Name } else { "Unknown" }
                            ServiceName   = if ($serviceName) { $serviceName } else { "N/A" }
                            ServiceDesc   = $serviceDesc
                            IsRisky       = $isRisky
                        }
                        $Results += $portInfo
                    }
                    catch {
                        Write-Warning "Error processing UDP port $($endpoint.LocalPort): $_"
                    }
                }
                
                # Get firewall rules if requested
                $FirewallData = $null
                if ($IncludeFW) {
                    try {
                        $FirewallData = Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue | 
                            Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty LocalPort -Unique
                    }
                    catch {
                        Write-Warning "Could not retrieve firewall rules: $_"
                    }
                }
                
                return @{
                    Ports = $Results
                    FirewallPorts = $FirewallData
                }
            }

            # Execute scan
            if ($Computer -eq $env:COMPUTERNAME) {
                $ScanResult = & $ScanScript -RiskyPortsList $RiskyPorts -IncludeFW $IncludeFirewallRules
            }
            else {
                $ScanResult = Invoke-Command -ComputerName $Computer -ScriptBlock $ScanScript `
                    -ArgumentList $RiskyPorts, $IncludeFirewallRules -ErrorAction Stop
            }

            # Add computer name to results
            foreach ($port in $ScanResult.Ports) {
                $port | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $Computer -Force
                $AllResults += $port
            }

            # Display results for this computer
            Write-Host "`n[$Computer] Listening Ports Found: $($ScanResult.Ports.Count)" -ForegroundColor Green
            
            $RiskyFound = $ScanResult.Ports | Where-Object { $_.IsRisky -eq $true }
            if ($RiskyFound) {
                Write-Host "[$Computer] ⚠️  HIGH-RISK PORTS DETECTED: $($RiskyFound.Count)" -ForegroundColor Red
                Write-Host "" # Blank line
                $RiskyFound | ForEach-Object {
                    Write-Host "  🔴 $($_.Protocol)/$($_.LocalPort) - $($_.ServiceDesc)" -ForegroundColor Red
                    Write-Host "     Process: $($_.ProcessName) (PID: $($_.ProcessID))" -ForegroundColor Yellow
                    Write-Host "     Binding: $($_.LocalAddress)" -ForegroundColor Gray
                    Write-Host "" # Blank line between entries
                }
            }
            else {
                Write-Host "[$Computer] ✅ No high-risk ports exposed" -ForegroundColor Green
            }

            # Firewall analysis
            if ($IncludeFirewallRules -and $ScanResult.FirewallPorts) {
                $ListeningPorts = $ScanResult.Ports.LocalPort | Sort-Object -Unique
                $FWPorts = $ScanResult.FirewallPorts | Sort-Object -Unique
                
                $PortsWithoutFWRule = $ListeningPorts | Where-Object { $_ -notin $FWPorts }
                
                if ($PortsWithoutFWRule) {
                    Write-Host "`n[$Computer] ALERT: Ports listening without explicit firewall rules:" -ForegroundColor Yellow
                    $PortsWithoutFWRule | ForEach-Object {
                        $portDetail = $ScanResult.Ports | Where-Object { $_.LocalPort -eq $_ } | Select-Object -First 1
                        Write-Host "  ℹ️  $($portDetail.Protocol)/$_ - $($portDetail.ProcessName)" -ForegroundColor Yellow
                    }
                }
            }

            Write-Host "" # Blank line for readability
        }
        catch {
            Write-Error "[$Computer] Scan failed: $($_.Exception.Message)"
            Write-Host "[$Computer] This may be due to:" -ForegroundColor Yellow
            Write-Host "  - WinRM not enabled" -ForegroundColor Yellow
            Write-Host "  - Firewall blocking remote access" -ForegroundColor Yellow
            Write-Host "  - Insufficient permissions" -ForegroundColor Yellow
            Write-Host "  - Network connectivity issues`n" -ForegroundColor Yellow
        }
    }
}

END {
    Write-Host "`n=== Scan Summary ===" -ForegroundColor Cyan
    Write-Host "Total Systems Scanned: $($ComputerName.Count)" -ForegroundColor Gray
    Write-Host "Total Listening Ports: $($AllResults.Count)" -ForegroundColor Gray
    
    $RiskyCount = ($AllResults | Where-Object { $_.IsRisky }).Count
    if ($RiskyCount -gt 0) {
        Write-Host "High-Risk Exposures: $RiskyCount" -ForegroundColor Red
    }
    else {
        Write-Host "High-Risk Exposures: 0" -ForegroundColor Green
    }
    Write-Host "Scan Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

    # Export if requested
    if ($ExportPath -and $AllResults.Count -gt 0) {
        try {
            $AllResults | Select-Object ComputerName, Protocol, LocalAddress, LocalPort, State, ProcessName, ServiceName, ServiceDesc, IsRisky, ProcessID |
                Export-Csv -Path $ExportPath -NoTypeInformation -Force
            Write-Host "✅ Results exported to: $ExportPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export results: $($_.Exception.Message)"
        }
    }

    # Display detailed table to console
    if ($AllResults.Count -gt 0) {
        Write-Host "`n=== Detailed Port Listing ===" -ForegroundColor Cyan
        
        # Sort with risky ports first, then by computer name and port number
        $AllResults | 
            Sort-Object @{Expression = "IsRisky"; Descending = $true}, 
                        @{Expression = "ComputerName"; Descending = $false}, 
                        @{Expression = "LocalPort"; Descending = $false} |
            Format-Table ComputerName, Protocol, LocalPort, ProcessName, ServiceDesc, IsRisky -AutoSize
    }
    else {
        Write-Warning "No results collected. All scans may have failed."
    }

    Write-Host "`n=== Ticket Documentation Notes ===" -ForegroundColor Cyan
    Write-Host "High-risk ports identified (if any) should be reviewed for:" -ForegroundColor White
    Write-Host "  1. Business justification for the service" -ForegroundColor Gray
    Write-Host "  2. Network segmentation and access controls" -ForegroundColor Gray
    Write-Host "  3. Whether the service should be exposed externally" -ForegroundColor Gray
    Write-Host "  4. Patching and hardening status of the service`n" -ForegroundColor Gray
    
    if ($IncludeFirewallRules) {
        Write-Host "Ports without firewall rules may indicate:" -ForegroundColor White
        Write-Host "  - Services bound to 0.0.0.0 (all interfaces)" -ForegroundColor Gray
        Write-Host "  - Default Windows services with implicit rules" -ForegroundColor Gray
        Write-Host "  - Potential security misconfigurations`n" -ForegroundColor Gray
    }
    
    # Display high-risk summary if any found
    $RiskyPorts = $AllResults | Where-Object { $_.IsRisky } | 
        Select-Object ComputerName, Protocol, LocalPort, ServiceDesc, ProcessName -Unique
    
    if ($RiskyPorts) {
        Write-Host "`n⚠️  HIGH-RISK PORT SUMMARY ⚠️" -ForegroundColor Red
        $RiskyPorts | Format-Table -AutoSize
        Write-Host "RECOMMENDATION: Review these exposed services immediately." -ForegroundColor Red
        Write-Host "Consider if these ports need to be accessible on the network.`n" -ForegroundColor Yellow
    }
}