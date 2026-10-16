<#
.SYNOPSIS
    Maps all devices on the local network for diagnostics and security review.

.DESCRIPTION
    Discovers and catalogs all devices on the local network using ARP cache and 
    active ICMP scanning. Identifies device types, vendors, and flags unknown devices.
    
    This is a READ-ONLY diagnostic script safe for production environments.

.USAGE CONTEXT
    - Network troubleshooting during support tickets
    - Security audits to identify unauthorized devices
    - Documentation of network topology for client records
    - IoT device discovery and inventory

.PREREQUISITES
    - Windows PowerShell 5.1 or later
    - Local network connectivity
    - Elevated privileges recommended (for complete ARP table access)

.RISK LEVEL
    Low - Read-only operations, no system changes

.OUTPUTS
    - Console report with device summary
    - CSV export: HomeNetworkMap_<timestamp>.csv
    - Formatted text report suitable for ticket documentation

.EXAMPLE
    .\Get-HomeNetworkMap.ps1
    
    Scans the local network and displays all discovered devices.

.EXAMPLE
    .\Get-HomeNetworkMap.ps1 | Export-Csv -Path "C:\Temp\network-scan.csv" -NoTypeInformation
    
    Exports results to custom location.

.NOTES
    Author: MSP Automation Team
    Version: 1.0
    Last Updated: 2025-01-05
    
    Limitations:
    - Devices with firewalls may not respond to ICMP ping
    - MAC vendor lookup requires internet connectivity (optional)
    - Scan time increases with network size (typically 1-3 minutes)
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SkipPing,
    
    [Parameter()]
    [switch]$QuickScan
)

#Requires -Version 5.1

# Script initialization
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'Continue'
$StartTime = Get-Date

Write-Host "`n=== Network Mapping Tool ===" -ForegroundColor Cyan
Write-Host "Started: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "Risk Level: READ-ONLY (Safe)`n" -ForegroundColor Green

# Initialize results collection
$DiscoveredDevices = [System.Collections.ArrayList]::new()

#region Helper Functions

function Get-LocalSubnet {
    <#
    .SYNOPSIS
        Determines the local subnet to scan.
    #>
    try {
        $NetworkAdapters = Get-NetIPConfiguration | Where-Object {
            $_.IPv4DefaultGateway -ne $null -and
            $_.NetAdapter.Status -eq 'Up'
        }
        
        if (-not $NetworkAdapters) {
            Write-Warning "No active network connection with default gateway found"
            return $null
        }
        
        # Prefer Ethernet over Wi-Fi
        $ActiveAdapter = $NetworkAdapters | 
            Sort-Object @{Expression={if($_.InterfaceAlias -like '*Ethernet*'){0}else{1}}} |
            Select-Object -First 1
        
        $IPAddress = $ActiveAdapter.IPv4Address.IPAddress
        $PrefixLength = $ActiveAdapter.IPv4Address.PrefixLength
        $Gateway = $ActiveAdapter.IPv4DefaultGateway.NextHop
        
        Write-Host "[INFO] Active Network Adapter: $($ActiveAdapter.InterfaceAlias)" -ForegroundColor Cyan
        Write-Host "[INFO] Local IP: $IPAddress/$PrefixLength" -ForegroundColor Cyan
        Write-Host "[INFO] Gateway: $Gateway`n" -ForegroundColor Cyan
        
        return @{
            IPAddress = $IPAddress
            PrefixLength = $PrefixLength
            Gateway = $Gateway
            Interface = $ActiveAdapter.InterfaceAlias
        }
    }
    catch {
        Write-Warning "Failed to determine local subnet: $_"
        return $null
    }
}

function Get-IPRange {
    <#
    .SYNOPSIS
        Calculates IP range from subnet information.
    #>
    param(
        [string]$IPAddress,
        [int]$PrefixLength
    )
    
    try {
        $IP = [System.Net.IPAddress]::Parse($IPAddress)
        $MaskBytes = [System.Net.IPAddress]::Parse("255.255.255.255").GetAddressBytes()
        
        # Calculate subnet mask
        $MaskBits = ('1' * $PrefixLength).PadRight(32, '0')
        for ($i = 0; $i -lt 4; $i++) {
            $MaskBytes[$i] = [Convert]::ToByte($MaskBits.Substring($i * 8, 8), 2)
        }
        
        $Mask = [System.Net.IPAddress]::new($MaskBytes)
        $IPBytes = $IP.GetAddressBytes()
        
        # Calculate network address
        $NetworkBytes = 0..3 | ForEach-Object { $IPBytes[$_] -band $MaskBytes[$_] }
        
        # Calculate broadcast address
        $BroadcastBytes = 0..3 | ForEach-Object { $IPBytes[$_] -bor (-bnot $MaskBytes[$_] -band 0xFF) }
        
        # Generate IP range
        $Start = [System.Net.IPAddress]::new($NetworkBytes)
        $End = [System.Net.IPAddress]::new($BroadcastBytes)
        
        # Calculate host range (exclude network and broadcast)
        $StartInt = [System.BitConverter]::ToUInt32($Start.GetAddressBytes()[3..0], 0)
        $EndInt = [System.BitConverter]::ToUInt32($End.GetAddressBytes()[3..0], 0)
        
        $IPList = @()
        for ($i = $StartInt + 1; $i -lt $EndInt; $i++) {
            $Bytes = [System.BitConverter]::GetBytes([UInt32]$i)[3..0]
            $IPList += [System.Net.IPAddress]::new($Bytes).ToString()
        }
        
        return $IPList
    }
    catch {
        Write-Warning "Failed to calculate IP range: $_"
        return @()
    }
}

function Get-ARPCache {
    <#
    .SYNOPSIS
        Retrieves ARP cache entries.
    #>
    try {
        Write-Host "[STEP 1/4] Reading ARP cache..." -ForegroundColor Yellow
        
        $ARPEntries = @()
        $ARPOutput = arp -a
        
        foreach ($Line in $ARPOutput) {
            if ($Line -match '^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f-]{17})\s+(\w+)') {
                $ARPEntries += [PSCustomObject]@{
                    IPAddress = $Matches[1]
                    MACAddress = $Matches[2].Replace('-', ':').ToUpper()
                    Type = $Matches[3]
                }
            }
        }
        
        Write-Host "  Found $($ARPEntries.Count) devices in ARP cache" -ForegroundColor Gray
        return $ARPEntries
    }
    catch {
        Write-Warning "Failed to read ARP cache: $_"
        return @()
    }
}

function Test-DeviceReachable {
    <#
    .SYNOPSIS
        Tests if a device responds to ping.
    #>
    param([string]$IPAddress)
    
    try {
        $Ping = Test-Connection -ComputerName $IPAddress -Count 1 -Quiet -TimeoutSeconds 1
        return $Ping
    }
    catch {
        return $false
    }
}

function Get-MACVendor {
    <#
    .SYNOPSIS
        Looks up MAC address vendor from OUI database.
    #>
    param([string]$MACAddress)
    
    if ([string]::IsNullOrWhiteSpace($MACAddress)) {
        return "Unknown"
    }
    
    try {
        $OUI = ($MACAddress -replace '[:-]', '').Substring(0, 6).ToUpper()
        
        # Call macvendors.com API (free, no key required)
        $Uri = "https://api.macvendors.com/$OUI"
        $Response = Invoke-RestMethod -Uri $Uri -TimeoutSec 3 -ErrorAction Stop
        return $Response
    }
    catch {
        # Common vendors based on OUI prefix
        $CommonVendors = @{
            '00:50:56' = 'VMware'
            '00:0C:29' = 'VMware'
            '00:05:69' = 'VMware'
            '08:00:27' = 'Oracle VirtualBox'
            '52:54:00' = 'QEMU/KVM'
            '00:15:5D' = 'Microsoft Hyper-V'
            'DC:A6:32' = 'Raspberry Pi'
            'B8:27:EB' = 'Raspberry Pi'
            'E4:5F:01' = 'Raspberry Pi'
            '00:1B:63' = 'Apple'
            '00:03:93' = 'Apple'
            '00:17:F2' = 'Apple'
        }
        
        foreach ($Prefix in $CommonVendors.Keys) {
            if ($MACAddress.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
                return $CommonVendors[$Prefix]
            }
        }
        
        return "Unknown"
    }
}

function Get-DeviceHostname {
    <#
    .SYNOPSIS
        Attempts to resolve hostname for IP address.
    #>
    param([string]$IPAddress)
    
    try {
        $Hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        return $Hostname
    }
    catch {
        return "Unknown"
    }
}

function Get-DeviceType {
    <#
    .SYNOPSIS
        Guesses device type based on hostname, MAC vendor, and other indicators.
    #>
    param(
        [string]$Hostname,
        [string]$Vendor,
        [string]$IPAddress,
        [string]$Gateway
    )
    
    # Router/Gateway detection
    if ($IPAddress -eq $Gateway) {
        return "Router/Gateway"
    }
    
    # Hostname-based detection
    if ($Hostname -match 'router|gateway|modem') { return "Router/Gateway" }
    if ($Hostname -match 'switch|ap-|access-point') { return "Network Device" }
    if ($Hostname -match 'printer|print|hp-|canon-|epson-') { return "Printer" }
    if ($Hostname -match 'nas|storage|synology|qnap') { return "NAS/Storage" }
    if ($Hostname -match 'camera|cam|dvr|nvr') { return "Security Camera" }
    if ($Hostname -match 'phone|android|iphone|mobile') { return "Mobile Device" }
    if ($Hostname -match 'desktop|pc|workstation|laptop') { return "Computer" }
    if ($Hostname -match 'server|srv') { return "Server" }
    if ($Hostname -match 'iot|smart|alexa|google-home|nest') { return "IoT Device" }
    
    # Vendor-based detection
    if ($Vendor -match 'Apple') { return "Apple Device" }
    if ($Vendor -match 'Raspberry Pi') { return "Raspberry Pi / IoT" }
    if ($Vendor -match 'VMware|VirtualBox|QEMU|Hyper-V') { return "Virtual Machine" }
    if ($Vendor -match 'Cisco|Ubiquiti|Netgear|TP-Link|Linksys') { return "Network Device" }
    if ($Vendor -match 'HP|Canon|Epson|Brother|Xerox') { return "Printer" }
    if ($Vendor -match 'Samsung|LG|Sony') { return "Smart TV / IoT" }
    if ($Vendor -match 'Ring|Nest|Arlo|Wyze') { return "Security Device" }
    
    return "Unknown"
}

#endregion

#region Main Execution

try {
    # Step 1: Get local network information
    $SubnetInfo = Get-LocalSubnet
    if (-not $SubnetInfo) {
        Write-Error "Cannot determine local network configuration. Ensure you are connected to a network."
        exit 1
    }
    
    # Step 2: Get ARP cache
    $ARPCache = Get-ARPCache
    
    # Step 3: Generate IP range and perform active scan
    if (-not $QuickScan) {
        Write-Host "`n[STEP 2/4] Calculating IP range..." -ForegroundColor Yellow
        $IPRange = Get-IPRange -IPAddress $SubnetInfo.IPAddress -PrefixLength $SubnetInfo.PrefixLength
        Write-Host "  Scan range: $($IPRange[0]) - $($IPRange[-1]) ($($IPRange.Count) addresses)" -ForegroundColor Gray
        
        if (-not $SkipPing) {
            Write-Host "`n[STEP 3/4] Performing active network scan (this may take 1-3 minutes)..." -ForegroundColor Yellow
            
            $Counter = 0
            $IPRange | ForEach-Object {
                $Counter++
                if ($Counter % 10 -eq 0) {
                    Write-Progress -Activity "Scanning network" -Status "Checking $_ ($Counter/$($IPRange.Count))" -PercentComplete (($Counter / $IPRange.Count) * 100)
                }
                
                # Quick ping test
                if (Test-DeviceReachable -IPAddress $_) {
                    # Add to ARP cache if not already present
                    if ($ARPCache.IPAddress -notcontains $_) {
                        $null = Test-Connection -ComputerName $_ -Count 1 -ErrorAction SilentlyContinue
                    }
                }
            }
            Write-Progress -Activity "Scanning network" -Completed
            
            # Re-read ARP cache after scan
            $ARPCache = Get-ARPCache
        }
    }
    
    # Step 4: Process discovered devices
    Write-Host "`n[STEP 4/4] Gathering device information..." -ForegroundColor Yellow
    
    $DeviceCounter = 0
    foreach ($Device in $ARPCache) {
        $DeviceCounter++
        Write-Progress -Activity "Processing devices" -Status "Device $DeviceCounter/$($ARPCache.Count)" -PercentComplete (($DeviceCounter / $ARPCache.Count) * 100)
        
        # Get additional information
        $Hostname = Get-DeviceHostname -IPAddress $Device.IPAddress
        $Vendor = Get-MACVendor -MACAddress $Device.MACAddress
        $DeviceType = Get-DeviceType -Hostname $Hostname -Vendor $Vendor -IPAddress $Device.IPAddress -Gateway $SubnetInfo.Gateway
        
        # Determine if device is known or unknown
        $IsUnknown = ($Hostname -eq "Unknown" -and $Vendor -eq "Unknown") -or ($DeviceType -eq "Unknown")
        
        $DeviceInfo = [PSCustomObject]@{
            IPAddress = $Device.IPAddress
            MACAddress = $Device.MACAddress
            Hostname = $Hostname
            Vendor = $Vendor
            DeviceType = $DeviceType
            ARPType = $Device.Type
            IsUnknown = $IsUnknown
            LastSeen = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Gateway = if ($Device.IPAddress -eq $SubnetInfo.Gateway) { "Yes" } else { "No" }
        }
        
        $null = $DiscoveredDevices.Add($DeviceInfo)
    }
    Write-Progress -Activity "Processing devices" -Completed
    
    # Sort devices: Gateway first, then by IP
    $DiscoveredDevices = $DiscoveredDevices | Sort-Object {
        if ($_.Gateway -eq "Yes") { 0 } else { 1 }
    }, { [System.Version]::Parse($_.IPAddress) }
    
    # Display results
    Write-Host "`n`n=== NETWORK MAP RESULTS ===" -ForegroundColor Cyan
    Write-Host "Total Devices Found: $($DiscoveredDevices.Count)" -ForegroundColor Green
    Write-Host "Unknown/Unidentified: $($DiscoveredDevices.Where({$_.IsUnknown}).Count)" -ForegroundColor $(if ($DiscoveredDevices.Where({$_.IsUnknown}).Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""
    
    # Display summary table
    $DiscoveredDevices | Format-Table -AutoSize -Property @(
        @{Label="IP Address"; Expression={$_.IPAddress}; Width=15}
        @{Label="MAC Address"; Expression={$_.MACAddress}; Width=17}
        @{Label="Hostname"; Expression={$_.Hostname}; Width=25}
        @{Label="Vendor"; Expression={$_.Vendor}; Width=20}
        @{Label="Device Type"; Expression={$_.DeviceType}; Width=20}
        @{Label="Gateway"; Expression={$_.Gateway}; Width=7}
    )
    
    # Highlight unknown devices
    if ($DiscoveredDevices.Where({$_.IsUnknown}).Count -gt 0) {
        Write-Host "`n⚠ UNKNOWN DEVICES DETECTED:" -ForegroundColor Yellow
        $DiscoveredDevices.Where({$_.IsUnknown}) | ForEach-Object {
            Write-Host "  - $($_.IPAddress) [$($_.MACAddress)]" -ForegroundColor Yellow
        }
        Write-Host "`nReview & identify these devices.`n" -ForegroundColor Yellow
    }
    
    # Export to CSV
    $ExportPath = Join-Path -Path $PSScriptRoot -ChildPath "HomeNetworkMap_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $DiscoveredDevices | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
    
    # Display device type breakdown
    Write-Host "`n=== DEVICE TYPE BREAKDOWN ===" -ForegroundColor Cyan
    $DiscoveredDevices | Group-Object DeviceType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
    }
    
    # Execution summary
    $Duration = (Get-Date) - $StartTime
    Write-Host "`n=== SCAN COMPLETE ===" -ForegroundColor Cyan
    Write-Host "Duration: $($Duration.ToString('mm\:ss'))" -ForegroundColor Gray
    Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
}
catch {
    Write-Error "Script execution failed: $_"
    Write-Host "`nError Details:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "`nStack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

#endregion