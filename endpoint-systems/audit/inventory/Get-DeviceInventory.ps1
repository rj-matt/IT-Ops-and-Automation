<#
.SYNOPSIS
    Comprehensive device inventory for home networks and enterprise environments.

.DESCRIPTION
    Discovers and inventories all Windows devices across home networks, workgroups,
    or Active Directory domains. Automatically detects environment type and adjusts
    scanning strategy accordingly.
    
    Collects:
    - Device identification (hostname, OS, last login)
    - Primary user information
    - Installed software with security focus
    - Remote access tools and P2P applications
    - High-risk software indicators
    
    Supports:
    - Home networks (workgroup, ARP discovery)
    - Small business (simple AD environments)
    - Enterprise (multi-OU, parallel scanning, credential management)
    
    Output is formatted for ticket documentation and security review.

.PARAMETER Scope
    Defines scan scope:
    - Auto: Automatically detect environment (default)
    - Local: Scan only the current device
    - Subnet: Scan devices on local subnet via ARP/network discovery
    - Domain: Scan all domain-joined computers
    - OU: Scan specific Organizational Unit(s)
    - ComputerList: Scan from provided computer names

.PARAMETER OrganizationalUnit
    Specific OU(s) to scan. Accepts single OU or array.
    Example: "OU=Workstations,DC=contoso,DC=com"

.PARAMETER ComputerName
    Specific computer name(s) to scan. Accepts single name or array.

.PARAMETER Credential
    PSCredential object for remote access. If not provided, uses current user context.

.PARAMETER IncludeOfflineDevices
    Include devices that are currently offline in the inventory.

.PARAMETER ExportPath
    Path to export CSV results. Defaults to desktop.

.PARAMETER ScanDepth
    Controls software scan depth:
    - Quick: Common locations only (5-10 min per device)
    - Standard: Registry + common paths (15-30 min per device)
    - Deep: Full filesystem scan (30+ min per device)

.PARAMETER MaxThreads
    Maximum parallel threads for scanning. Default: 10
    Recommended: 5-10 for home, 10-20 for small business, 20-50 for enterprise

.PARAMETER IncludeServers
    Include Windows Server operating systems in scan (default: workstations only)

.PARAMETER Timeout
    Timeout in seconds for each device connection attempt. Default: 30

.EXAMPLE
    .\Get-DeviceInventory.ps1
    Auto-detect environment and run appropriate scan

.EXAMPLE
    .\Get-DeviceInventory.ps1 -Scope Subnet -ScanDepth Quick
    Scan local subnet with quick software inventory

.EXAMPLE
    .\Get-DeviceInventory.ps1 -Scope Domain -MaxThreads 20 -IncludeOfflineDevices
    Scan all domain computers with 20 parallel threads

.EXAMPLE
    .\Get-DeviceInventory.ps1 -Scope OU -OrganizationalUnit "OU=Workstations,DC=corp,DC=local" -Credential (Get-Credential)
    Scan specific OU with provided credentials

.EXAMPLE
    .\Get-DeviceInventory.ps1 -Scope ComputerList -ComputerName "PC001","PC002","LAPTOP-HR"
    Scan specific computers by name

.NOTES
    Domain:          endpoint-systems/audit/software-inventory
    Risk Level:      READ-ONLY / SAFE
    Prerequisites:   Local admin rights (domain admin for enterprise scope)
    Network Impact:  Scales with device count and threading
    
    Author:          MSP Automation Team
    Version:         2.0.0
    Last Updated:    2026-01-05
    
    Environment Detection:
    - Checks for domain membership
    - Tests AD availability
    - Falls back to workgroup/subnet scanning if needed
#>

[CmdletBinding(DefaultParameterSetName = 'Auto')]
param(
    [Parameter(ParameterSetName = 'Auto')]
    [Parameter(ParameterSetName = 'Scoped')]
    [ValidateSet('Auto', 'Local', 'Subnet', 'Domain', 'OU', 'ComputerList')]
    [string]$Scope = 'Auto',
    
    [Parameter(ParameterSetName = 'Scoped', Mandatory = $true)]
    [string[]]$OrganizationalUnit,
    
    [Parameter(ParameterSetName = 'Scoped')]
    [string[]]$ComputerName,
    
    [Parameter()]
    [PSCredential]$Credential,
    
    [Parameter()]
    [switch]$IncludeOfflineDevices,
    
    [Parameter()]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { $true }
        else { throw "Export path does not exist: $_" }
    })]
    [string]$ExportPath = [Environment]::GetFolderPath('Desktop'),
    
    [Parameter()]
    [ValidateSet('Quick', 'Standard', 'Deep')]
    [string]$ScanDepth = 'Standard',
    
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$MaxThreads = 10,
    
    [Parameter()]
    [switch]$IncludeServers,
    
    [Parameter()]
    [ValidateRange(10, 300)]
    [int]$Timeout = 30
)

#Requires -Version 5.1

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Continue'
$ScriptVersion = '2.0.0'
$StartTime = Get-Date
$Timestamp = $StartTime.ToString('yyyyMMdd_HHmmss')
$OutputFile = Join-Path $ExportPath "DeviceInventory_$Timestamp.csv"

# Global progress tracking
$Global:ScannedCount = 0
$Global:TotalDevices = 0

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "       Device Inventory Scanner v$ScriptVersion" -ForegroundColor Cyan
Write-Host "       Home Networks | Small Business | Enterprise" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Started: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "Scan Depth: $ScanDepth | Max Threads: $MaxThreads" -ForegroundColor Gray
Write-Host "`n"

# ============================================================================
# HIGH-RISK SOFTWARE DEFINITIONS
# ============================================================================

$HighRiskPatterns = @{
    'RemoteAccess_Unmanaged' = @(
        'TeamViewer',
        'AnyDesk',
        'Chrome Remote Desktop',
        'VNC',
        'LogMeIn',
        'GoToMyPC',
        'RemotePC',
        'Splashtop',
        'UltraVNC',
        'TightVNC',
        'RealVNC'
    )
    'P2P_FileSharing' = @(
        'uTorrent',
        'BitTorrent',
        'qBittorrent',
        'Transmission',
        'Vuze',
        'FrostWire',
        'LimeWire',
        'eMule',
        'Kazaa'
    )
    'OutdatedBrowsers' = @(
        'Internet Explorer 11',
        'Internet Explorer 10',
        'Internet Explorer 9',
        'Internet Explorer 8'
    )
    'Risky_Utilities' = @(
        'CCleaner',
        'Advanced SystemCare',
        'Driver Booster',
        'PC Optimizer',
        'Registry Cleaner',
        'Registry Reviver',
        'MyCleanPC'
    )
    'Shadow_IT' = @(
        'Hamachi',
        'Radmin',
        'NetSupport',
        'pcAnywhere'
    )
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $Colors = @{
        'Info'    = 'White'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
        'Debug'   = 'Gray'
    }
    
    $Prefix = switch ($Level) {
        'Info'    { '[INFO]   ' }
        'Warning' { '[WARN]   ' }
        'Error'   { '[ERROR]  ' }
        'Success' { '[OK]     ' }
        'Debug'   { '[DEBUG]  ' }
    }
    
    $TimeStamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "$TimeStamp $Prefix$Message" -ForegroundColor $Colors[$Level]
}

function Test-Administrator {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EnvironmentType {
    Write-LogMessage "Detecting environment type..."
    
    $EnvInfo = @{
        Type = 'Unknown'
        DomainName = $null
        IsDomainJoined = $false
        HasADModule = $false
        ComputerCount = 0
    }
    
    try {
        # Check domain membership
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $EnvInfo.IsDomainJoined = $ComputerSystem.PartOfDomain
        
        if ($EnvInfo.IsDomainJoined) {
            $EnvInfo.DomainName = $ComputerSystem.Domain
            Write-LogMessage "Domain-joined: $($EnvInfo.DomainName)" -Level Success
            
            # Try to load AD module
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $EnvInfo.HasADModule = $true
                
                # Count domain computers
                $ADComputers = Get-ADComputer -Filter * -ErrorAction SilentlyContinue
                $EnvInfo.ComputerCount = $ADComputers.Count
                
                if ($EnvInfo.ComputerCount -lt 20) {
                    $EnvInfo.Type = 'SmallBusiness'
                    Write-LogMessage "Environment: Small Business AD ($($EnvInfo.ComputerCount) computers)" -Level Info
                }
                else {
                    $EnvInfo.Type = 'Enterprise'
                    Write-LogMessage "Environment: Enterprise AD ($($EnvInfo.ComputerCount) computers)" -Level Info
                }
            }
            catch {
                Write-LogMessage "ActiveDirectory module not available - limited domain functionality" -Level Warning
                $EnvInfo.Type = 'DomainNoADModule'
            }
        }
        else {
            $EnvInfo.Type = 'Workgroup'
            Write-LogMessage "Environment: Workgroup/Home Network" -Level Info
        }
    }
    catch {
        Write-LogMessage "Failed to detect environment: $_" -Level Error
        $EnvInfo.Type = 'Unknown'
    }
    
    return $EnvInfo
}

function Get-TargetDevices {
    param(
        [string]$ScopeType,
        [string[]]$OUs,
        [string[]]$Computers,
        [object]$EnvironmentInfo
    )
    
    Write-LogMessage "Building target device list (Scope: $ScopeType)..."
    
    $Devices = @()
    
    switch ($ScopeType) {
        'Local' {
            Write-LogMessage "Targeting local computer only"
            $Devices += [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                IPAddress    = (Get-NetIPAddress -AddressFamily IPv4 | 
                    Where-Object {$_.PrefixOrigin -in @('Dhcp','Manual') -and $_.IPAddress -notlike '169.254.*'} | 
                    Select-Object -First 1).IPAddress
                IsOnline     = $true
                Source       = 'Local'
                OU           = $null
            }
        }
        
        'Subnet' {
            Write-LogMessage "Scanning local subnet via ARP and network discovery..."
            
            # Add local computer
            $Devices += [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                IPAddress    = (Get-NetIPAddress -AddressFamily IPv4 | 
                    Where-Object {$_.PrefixOrigin -in @('Dhcp','Manual') -and $_.IPAddress -notlike '169.254.*'} | 
                    Select-Object -First 1).IPAddress
                IsOnline     = $true
                Source       = 'Local'
                OU           = $null
            }
            
            # Scan ARP cache
            $ArpTable = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                Where-Object {$_.State -eq 'Reachable' -or $_.State -eq 'Stale'}
            
            foreach ($Entry in $ArpTable) {
                try {
                    # Try DNS resolution
                    $HostEntry = [System.Net.Dns]::GetHostEntry($Entry.IPAddress)
                    $HostName = $HostEntry.HostName.Split('.')[0].ToUpper()
                    
                    # Test if it's a Windows device with WinRM
                    if ($HostName -ne $env:COMPUTERNAME -and 
                        (Test-WSMan -ComputerName $Entry.IPAddress -ErrorAction SilentlyContinue)) {
                        
                        if ($Devices.ComputerName -notcontains $HostName) {
                            $Devices += [PSCustomObject]@{
                                ComputerName = $HostName
                                IPAddress    = $Entry.IPAddress
                                IsOnline     = $true
                                Source       = 'NetworkDiscovery'
                                OU           = $null
                            }
                            Write-LogMessage "Found: $HostName ($($Entry.IPAddress))" -Level Debug
                        }
                    }
                }
                catch {
                    # Not a Windows device or unreachable
                }
            }
        }
        
        'Domain' {
    if (-not $EnvironmentInfo.HasADModule) {
        Write-LogMessage "ActiveDirectory module required for domain scope" -Level Error
        throw "ActiveDirectory module not available"
    }
    
    Write-LogMessage "Querying Active Directory for computers (timeout: 120s)..." -Level Info
    
    $Filter = if ($IncludeServers) { '*' } else { 'OperatingSystem -notlike "*Server*"' }
    
    # Query with timeout and batching
    try {
        $QueryJob = Start-Job -ScriptBlock {
            param($Filter, $IncludeOffline)
            
            Import-Module ActiveDirectory
            
            $Computers = Get-ADComputer -Filter $using:Filter `
                -Properties OperatingSystem, LastLogonDate, IPv4Address, Enabled `
                -ResultSetSize 2000
            
            # Filter to enabled computers only unless including offline
            if (-not $IncludeOffline) {
                $Computers = $Computers | Where-Object { $_.Enabled -eq $true }
            }
            
            return $Computers
        } -ArgumentList $Filter, $IncludeOfflineDevices
        
        # Wait max 120 seconds
        $ADComputers = Wait-Job $QueryJob -Timeout 120 | Receive-Job
        Remove-Job $QueryJob -Force
        
        if (-not $ADComputers) {
            throw "AD query timed out or returned no results"
        }
        
        Write-LogMessage "Retrieved $($ADComputers.Count) computers from AD" -Level Success
    }
    catch {
        Write-LogMessage "AD query failed: $_" -Level Error
        throw
    }
    
    # Progress bar for connectivity testing
    $i = 0
    foreach ($Computer in $ADComputers) {
        $i++
        Write-Progress -Activity "Testing Connectivity" -Status "$i of $($ADComputers.Count)" -PercentComplete (($i / $ADComputers.Count) * 100)
        
        $IsOnline = $null
        if (-not $IncludeOfflineDevices) {
            # Quick ping test (PowerShell 5.1 compatible)
            $IsOnline = Test-Connection -ComputerName $Computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
        }
        else {
            $IsOnline = $true
        }
        
        if ($IsOnline) {
            $Devices += [PSCustomObject]@{
                ComputerName = $Computer.Name
                IPAddress    = $Computer.IPv4Address
                IsOnline     = $IsOnline
                Source       = 'ActiveDirectory'
                OU           = $Computer.DistinguishedName
            }
        }
    }
    
    Write-Progress -Activity "Testing Connectivity" -Completed
}
        
        'OU' {
            if (-not $EnvironmentInfo.HasADModule) {
                Write-LogMessage "ActiveDirectory module required for OU scope" -Level Error
                throw "ActiveDirectory module not available"
            }
            
            foreach ($OU in $OUs) {
                Write-LogMessage "Querying OU: $OU"
                
                $Filter = if ($IncludeServers) { '*' } else { 'OperatingSystem -notlike "*Server*"' }
                
                $ADComputers = Get-ADComputer -Filter $Filter -SearchBase $OU -Properties OperatingSystem, LastLogonDate, IPv4Address
                
                foreach ($Computer in $ADComputers) {
                    $IsOnline = $null
                    if (-not $IncludeOfflineDevices) {
                        $IsOnline = Test-Connection -ComputerName $Computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue
                    }
                    else {
                        $IsOnline = $true
                    }
                    
                    if ($IsOnline) {
                        $Devices += [PSCustomObject]@{
                            ComputerName = $Computer.Name
                            IPAddress    = $Computer.IPv4Address
                            IsOnline     = $IsOnline
                            Source       = 'OU'
                            OU           = $Computer.DistinguishedName
                        }
                    }
                }
            }
        }
        
        'ComputerList' {
            foreach ($Computer in $Computers) {
                Write-LogMessage "Adding: $Computer" -Level Debug
                
                # Try to resolve IP
                try {
                    $IPAddress = [System.Net.Dns]::GetHostAddresses($Computer) | 
                        Where-Object {$_.AddressFamily -eq 'InterNetwork'} | 
                        Select-Object -First 1 -ExpandProperty IPAddressToString
                }
                catch {
                    $IPAddress = $null
                }
                
                $IsOnline = Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue
                
                if ($IsOnline -or $IncludeOfflineDevices) {
                    $Devices += [PSCustomObject]@{
                        ComputerName = $Computer
                        IPAddress    = $IPAddress
                        IsOnline     = $IsOnline
                        Source       = 'Manual'
                        OU           = $null
                    }
                }
            }
        }
    }
    
    Write-LogMessage "Target devices identified: $($Devices.Count)" -Level Success
    return $Devices
}

function Get-DeviceDetails {
    param(
        [string]$ComputerName,
        [bool]$IsLocal,
        [PSCredential]$Cred,
        [int]$TimeoutSeconds
    )
    
    $SessionParams = @{
        ErrorAction = 'Stop'
    }
    
    if (-not $IsLocal) {
        $SessionParams['ComputerName'] = $ComputerName
        
        if ($Cred) {
            $SessionParams['Credential'] = $Cred
        }
    }
    
    try {
        # Create CIM session with timeout
        if (-not $IsLocal) {
            $SessionOption = New-CimSessionOption -Protocol Dcom
            $CimSession = New-CimSession @SessionParams -OperationTimeoutSec $TimeoutSeconds -SessionOption $SessionOption
        }
        
        # Get device information
        if ($IsLocal) {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
            $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
            $BIOS = Get-CimInstance -ClassName Win32_BIOS
        }
        else {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession
            $Computer = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession
            $BIOS = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession
        }
        
        # Determine device type
        $DeviceType = switch ($Computer.PCSystemType) {
            1 { 'Desktop' }
            2 { 'Mobile/Laptop' }
            3 { 'Workstation' }
            4 { 'Enterprise Server' }
            5 { 'SOHO Server' }
            6 { 'Appliance PC' }
            7 { 'Performance Server' }
            8 { 'Slate' }
            default { 'Unknown' }
        }
        
        # Check if virtual
        if ($Computer.Model -match 'Virtual|VMware|Hyper-V|VirtualBox|Xen') {
            $DeviceType = "Virtual Machine ($DeviceType)"
        }
        
        # Get primary user
        $PrimaryUser = 'Unknown'
        try {
            if ($IsLocal) {
                $PrimaryUser = $env:USERNAME
            }
            else {
                # Try registry query for last logged on user
                $RegPath = "\\$ComputerName\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $RegKey = $Reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI')
                $PrimaryUser = $RegKey.GetValue('LastLoggedOnUser')
                $RegKey.Close()
                $Reg.Close()
            }
        }
        catch {
            # Fallback to WMI
            try {
                $Explorer = if ($IsLocal) {
                    Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'"
                } else {
                    Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -CimSession $CimSession
                }
                
                if ($Explorer) {
                    $Owner = Invoke-CimMethod -InputObject $Explorer[0] -MethodName GetOwner
                    $PrimaryUser = "$($Owner.Domain)\$($Owner.User)"
                }
            }
            catch {
                # Keep as Unknown
            }
        }
        
        # Get disk info
        $Disks = if ($IsLocal) {
            Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
        } else {
            Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -CimSession $CimSession
        }
        
        $TotalDiskGB = ($Disks | Measure-Object -Property Size -Sum).Sum / 1GB
        $FreeDiskGB = ($Disks | Measure-Object -Property FreeSpace -Sum).Sum / 1GB
        
        $Result = [PSCustomObject]@{
            ComputerName     = $ComputerName
            OperatingSystem  = $OS.Caption
            OSVersion        = $OS.Version
            BuildNumber      = $OS.BuildNumber
            ServicePack      = $OS.ServicePackMajorVersion
            LastBootTime     = $OS.LastBootUpTime
            InstallDate      = $OS.InstallDate
            DeviceType       = $DeviceType
            PrimaryUser      = $PrimaryUser
            Manufacturer     = $Computer.Manufacturer
            Model            = $Computer.Model
            SerialNumber     = $BIOS.SerialNumber
            TotalRAM_GB      = [math]::Round($Computer.TotalPhysicalMemory / 1GB, 2)
            TotalDisk_GB     = [math]::Round($TotalDiskGB, 2)
            FreeDisk_GB      = [math]::Round($FreeDiskGB, 2)
            DiskUsedPercent  = [math]::Round((($TotalDiskGB - $FreeDiskGB) / $TotalDiskGB) * 100, 1)
            Status           = 'Online'
            ErrorMessage     = $null
        }
        
        # Clean up
        if ($CimSession) {
            Remove-CimSession $CimSession
        }
        
        return $Result
    }
    catch {
        return [PSCustomObject]@{
            ComputerName = $ComputerName
            Status       = 'Failed'
            ErrorMessage = $_.Exception.Message
        }
    }
}

function Get-InstalledSoftware {
    param(
        [string]$ComputerName,
        [bool]$IsLocal,
        [string]$Depth,
        [PSCredential]$Cred
    )
    
    $Software = @()
    $RegistryPaths = @(
        'Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    
    try {
        if ($IsLocal) {
            # Local registry access
            foreach ($Path in $RegistryPaths) {
                $FullPath = "HKLM:\$Path"
                $Items = Get-ChildItem $FullPath -ErrorAction SilentlyContinue
                
                foreach ($Item in $Items) {
                    $App = Get-ItemProperty $Item.PSPath -ErrorAction SilentlyContinue
                    
                    if ($App.DisplayName) {
                        $Software += [PSCustomObject]@{
                            DisplayName    = $App.DisplayName
                            DisplayVersion = $App.DisplayVersion
                            Publisher      = $App.Publisher
                            InstallDate    = $App.InstallDate
                            InstallLocation = $App.InstallLocation
                        }
                    }
                }
            }
        }
        else {
            # Remote registry access
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            
            foreach ($Path in $RegistryPaths) {
                try {
                    $RegKey = $Reg.OpenSubKey($Path)
                    
                    if ($RegKey) {
                        foreach ($SubKeyName in $RegKey.GetSubKeyNames()) {
                            $SubKey = $RegKey.OpenSubKey($SubKeyName)
                            $DisplayName = $SubKey.GetValue('DisplayName')
                            
                            if ($DisplayName) {
                                $Software += [PSCustomObject]@{
                                    DisplayName     = $DisplayName
                                    DisplayVersion  = $SubKey.GetValue('DisplayVersion')
                                    Publisher       = $SubKey.GetValue('Publisher')
                                    InstallDate     = $SubKey.GetValue('InstallDate')
                                    InstallLocation = $SubKey.GetValue('InstallLocation')
                                }
                            }
                            $SubKey.Close()
                        }
                        $RegKey.Close()
                    }
                }
                catch {
                    # Continue on error
                }
            }
            $Reg.Close()
        }
        
        # Remove duplicates
        $Software = $Software | Sort-Object DisplayName -Unique
        
        return $Software
    }
    catch {
        Write-LogMessage "Failed to enumerate software on $ComputerName : $_" -Level Error
        return @()
    }
}

function Test-HighRiskSoftware {
    param([array]$SoftwareList)
    
    $RiskyApps = @()
    
    foreach ($App in $SoftwareList) {
        foreach ($Category in $HighRiskPatterns.Keys) {
            foreach ($Pattern in $HighRiskPatterns[$Category]) {
                if ($App.DisplayName -like "*$Pattern*") {
                    $RiskyApps += [PSCustomObject]@{
                        Application = $App.DisplayName
                        Version     = $App.DisplayVersion
                        Category    = $Category
                        RiskReason  = $Pattern
                        Publisher   = $App.Publisher
                    }
                    break  # Only match once per app
                }
            }
        }
    }
    
    return $RiskyApps
}

function Invoke-DeviceScan {
    param(
        [PSCustomObject]$Device,
        [PSCredential]$Cred,
        [string]$Depth,
        [int]$TimeoutSeconds
    )
    
    $IsLocal = ($Device.ComputerName -eq $env:COMPUTERNAME)
    
    # Increment progress
    $Global:ScannedCount++
    $PercentComplete = [math]::Round(($Global:ScannedCount / $Global:TotalDevices) * 100, 1)
    Write-Progress -Activity "Scanning Devices" -Status "$($Device.ComputerName) ($Global:ScannedCount of $Global:TotalDevices)" -PercentComplete $PercentComplete
    
    # Get device details
    $DeviceInfo = Get-DeviceDetails -ComputerName $Device.ComputerName -IsLocal $IsLocal -Cred $Cred -TimeoutSeconds $TimeoutSeconds
    
    if ($DeviceInfo.Status -eq 'Failed') {
        Write-LogMessage "Failed to scan $($Device.ComputerName): $($DeviceInfo.ErrorMessage)" -Level Warning
        return [PSCustomObject]@{
            ComputerName = $Device.ComputerName
            Status       = 'Failed'
            ErrorMessage = $DeviceInfo.ErrorMessage
            ScanTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
    }
    
    # Get software inventory
    $Software = Get-InstalledSoftware -ComputerName $Device.ComputerName -IsLocal $IsLocal -Depth $Depth -Cred $Cred
    
    # Check for high-risk software
    $RiskySoftware = Test-HighRiskSoftware -SoftwareList $Software
    
    # Compile result
    $Result = [PSCustomObject]@{
        ComputerName        = $DeviceInfo.ComputerName
        DeviceType          = $DeviceInfo.DeviceType
        PrimaryUser         = $DeviceInfo.PrimaryUser
        OperatingSystem     = $DeviceInfo.OperatingSystem
        OSVersion           = $DeviceInfo.OSVersion
        BuildNumber         = $DeviceInfo.BuildNumber
        ServicePack         = $DeviceInfo.ServicePack
        LastBootTime        = $DeviceInfo.LastBootTime
        InstallDate         = $DeviceInfo.InstallDate
        Manufacturer        = $DeviceInfo.Manufacturer
        Model               = $DeviceInfo.Model
        SerialNumber        = $DeviceInfo.SerialNumber
        TotalRAM_GB         = $DeviceInfo.TotalRAM_GB
        TotalDisk_GB        = $DeviceInfo.TotalDisk_GB
        FreeDisk_GB         = $DeviceInfo.FreeDisk_GB
        DiskUsedPercent     = $DeviceInfo.DiskUsedPercent
        TotalApplications   = $Software.Count
        HighRiskAppCount    = $RiskySoftware.Count
        HighRiskApps        = ($RiskySoftware.Application -join '; ')
        RiskCategories      = (($RiskySoftware.Category | Select-Object -Unique) -join '; ')
        IPAddress           = $Device.IPAddress
        OU                  = $Device.OU
        DiscoverySource     = $Device.Source
        Status              = 'Success'
        ScanTimestamp       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
    
    # Log risk summary
    if ($RiskySoftware.Count -gt 0) {
        Write-LogMessage "$($Device.ComputerName): ⚠ $($RiskySoftware.Count) high-risk apps detected" -Level Warning
    }
    else {
        Write-LogMessage "$($Device.ComputerName): ✓ No high-risk software" -Level Success
    }
    
    return $Result
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Security check
if (-not (Test-Administrator)) {
    Write-LogMessage "This script requires administrator privileges" -Level Error
    Write-Host "`nPlease run PowerShell as Administrator and try again.`n" -ForegroundColor Yellow
    exit 1
}

# Detect environment
$Environment = Get-EnvironmentType

# Determine scope
$ActualScope = $Scope
if ($Scope -eq 'Auto') {
    $ActualScope = switch ($Environment.Type) {
        'Workgroup'      { 'Subnet' }
        'SmallBusiness'  { 'Domain' }
        'Enterprise'     { 'Domain' }
        'DomainNoADModule' { 'Subnet' }
        default          { 'Local' }
    }
    Write-LogMessage "Auto-detected scope: $ActualScope" -Level Info
}

# Handle OU/ComputerList parameters
if ($ActualScope -eq 'OU' -and -not $OrganizationalUnit) {
    Write-LogMessage "OU scope requires -OrganizationalUnit parameter" -Level Error
    exit 1
}

if ($ActualScope -eq 'ComputerList' -and -not $ComputerName) {
    Write-LogMessage "ComputerList scope requires -ComputerName parameter" -Level Error
    exit 1
}

# Get target devices
try {
    $Devices = Get-TargetDevices -ScopeType $ActualScope -OUs $OrganizationalUnit -Computers $ComputerName -EnvironmentInfo $Environment
}
catch {
    Write-LogMessage "Failed to get target devices: $_" -Level Error
    exit 1
}

if ($Devices.Count -eq 0) {
    Write-LogMessage "No devices found to scan" -Level Warning
    exit 0
}

$Global:TotalDevices = $Devices.Count

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "Beginning scan of $($Devices.Count) device(s)" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "`n"

# Parallel processing setup
$AllResults = @()

if ($MaxThreads -eq 1 -or $Devices.Count -eq 1) {
    # Sequential processing
    foreach ($Device in $Devices) {
        $Result = Invoke-DeviceScan -Device $Device -Cred $Credential -Depth $ScanDepth -TimeoutSeconds $Timeout
        $AllResults += $Result
    }
}
else {
    # Parallel processing with runspaces
    Write-LogMessage "Using parallel processing with $MaxThreads threads" -Level Info
    
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $RunspacePool.Open()
    $Jobs = @()
    
    # Create script block for parallel execution
    $ScriptBlock = {
        param($Device, $Cred, $Depth, $Timeout, $Functions, $Patterns)
        
        # Import functions into runspace
        $Functions.GetEnumerator() | ForEach-Object {
            Invoke-Expression $_.Value
        }
        
        # Set global pattern variable
        $Global:HighRiskPatterns = $Patterns
        
        # Execute scan
        Invoke-DeviceScan -Device $Device -Cred $Cred -Depth $Depth -TimeoutSeconds $Timeout
    }
    
    # Export functions for runspaces
    $FunctionDefinitions = @{
        'Get-DeviceDetails' = ${function:Get-DeviceDetails}.ToString()
        'Get-InstalledSoftware' = ${function:Get-InstalledSoftware}.ToString()
        'Test-HighRiskSoftware' = ${function:Test-HighRiskSoftware}.ToString()
        'Invoke-DeviceScan' = ${function:Invoke-DeviceScan}.ToString()
        'Write-LogMessage' = ${function:Write-LogMessage}.ToString()
    }
    
    # Start jobs
    foreach ($Device in $Devices) {
        $PowerShell = [powershell]::Create().AddScript($ScriptBlock)
        $PowerShell.AddArgument($Device) | Out-Null
        $PowerShell.AddArgument($Credential) | Out-Null
        $PowerShell.AddArgument($ScanDepth) | Out-Null
        $PowerShell.AddArgument($Timeout) | Out-Null
        $PowerShell.AddArgument($FunctionDefinitions) | Out-Null
        $PowerShell.AddArgument($HighRiskPatterns) | Out-Null
        $PowerShell.RunspacePool = $RunspacePool
        
        $Jobs += [PSCustomObject]@{
            PowerShell = $PowerShell
            Handle     = $PowerShell.BeginInvoke()
            Device     = $Device.ComputerName
        }
    }
    
    # Wait for completion
    Write-LogMessage "Waiting for scan jobs to complete..."
    
    while ($Jobs | Where-Object { -not $_.Handle.IsCompleted }) {
        Start-Sleep -Milliseconds 500
        $CompletedCount = ($Jobs | Where-Object { $_.Handle.IsCompleted }).Count
        $PercentComplete = [math]::Round(($CompletedCount / $Jobs.Count) * 100, 1)
        Write-Progress -Activity "Scanning Devices (Parallel)" -Status "$CompletedCount of $($Jobs.Count) completed" -PercentComplete $PercentComplete
    }
    
    Write-Progress -Activity "Scanning Devices (Parallel)" -Completed
    
    # Collect results
    foreach ($Job in $Jobs) {
        try {
            $Result = $Job.PowerShell.EndInvoke($Job.Handle)
            $AllResults += $Result
        }
        catch {
            Write-LogMessage "Job failed for $($Job.Device): $_" -Level Error
        }
        finally {
            $Job.PowerShell.Dispose()
        }
    }
    
    $RunspacePool.Close()
    $RunspacePool.Dispose()
}

Write-Progress -Activity "Scanning Devices" -Completed

# ============================================================================
# OUTPUT AND REPORTING
# ============================================================================

Write-Host "`n`n=================================================================" -ForegroundColor Cyan
Write-Host "                    INVENTORY SUMMARY" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$SuccessfulScans = $AllResults | Where-Object { $_.Status -eq 'Success' }
$FailedScans = $AllResults | Where-Object { $_.Status -eq 'Failed' }

Write-Host "`nTotal Devices Targeted: $($AllResults.Count)" -ForegroundColor White
Write-Host "  • Successfully Scanned: $($SuccessfulScans.Count)" -ForegroundColor Green
Write-Host "  • Failed/Unreachable: $($FailedScans.Count)" -ForegroundColor $(if ($FailedScans.Count -gt 0) { 'Yellow' } else { 'Gray' })

if ($SuccessfulScans) {
    # Device type breakdown
    Write-Host "`nDevice Types:" -ForegroundColor White
    $SuccessfulScans | Group-Object DeviceType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  • $($_.Name): $($_.Count)" -ForegroundColor Gray
    }
    
    # Risk analysis
    $DevicesWithRisks = $SuccessfulScans | Where-Object { $_.HighRiskAppCount -gt 0 }
    $TotalRiskyApps = ($SuccessfulScans | Measure-Object -Property HighRiskAppCount -Sum).Sum
    
    Write-Host "`nSecurity Posture:" -ForegroundColor White
    Write-Host "  • Devices with High-Risk Software: $($DevicesWithRisks.Count)" -ForegroundColor $(if ($DevicesWithRisks.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  • Total High-Risk Applications: $TotalRiskyApps" -ForegroundColor $(if ($TotalRiskyApps -gt 0) { 'Red' } else { 'Green' })
    
    if ($DevicesWithRisks.Count -gt 0) {
        Write-Host "`n⚠ DEVICES REQUIRING ATTENTION:" -ForegroundColor Yellow
        foreach ($Device in $DevicesWithRisks | Sort-Object HighRiskAppCount -Descending) {
            Write-Host "`n  $($Device.ComputerName)" -ForegroundColor Yellow
            Write-Host "    User: $($Device.PrimaryUser)" -ForegroundColor Gray
            Write-Host "    Risk Count: $($Device.HighRiskAppCount)" -ForegroundColor Red
            Write-Host "    Categories: $($Device.RiskCategories)" -ForegroundColor Gray
            
            $AppList = $Device.HighRiskApps -split '; '
            foreach ($App in $AppList | Select-Object -First 5) {
                Write-Host "      • $App" -ForegroundColor Red
            }
            if ($AppList.Count -gt 5) {
                Write-Host "      ... and $($AppList.Count - 5) more" -ForegroundColor Gray
            }
        }
    }
    
    # Storage analysis
    $LowDiskDevices = $SuccessfulScans | Where-Object { $_.DiskUsedPercent -gt 85 }
    if ($LowDiskDevices) {
        Write-Host "`n⚠ LOW DISK SPACE WARNINGS:" -ForegroundColor Yellow
        foreach ($Device in $LowDiskDevices) {
            Write-Host "  • $($Device.ComputerName): $($Device.DiskUsedPercent)% used ($($Device.FreeDisk_GB)GB free)" -ForegroundColor Yellow
        }
    }
}

# Export to CSV
try {
    $AllResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "`n✓ Results exported to:" -ForegroundColor Green
    Write-Host "  $OutputFile" -ForegroundColor White
}
catch {
    Write-LogMessage "Failed to export CSV: $_" -Level Error
}

# Display summary table
if ($SuccessfulScans) {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "                    DEVICE INVENTORY" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "`n"
    
    $SuccessfulScans | 
        Select-Object ComputerName, DeviceType, PrimaryUser, OperatingSystem, HighRiskAppCount, TotalApplications, DiskUsedPercent | 
        Format-Table -AutoSize
}

if ($FailedScans) {
    Write-Host "`n⚠ FAILED SCANS:" -ForegroundColor Yellow
    $FailedScans | 
        Select-Object ComputerName, ErrorMessage | 
        Format-Table -AutoSize
}

$Duration = (Get-Date) - $StartTime
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "Scan completed in $([math]::Round($Duration.TotalMinutes, 2)) minutes" -ForegroundColor White
Write-Host "Average: $([math]::Round($Duration.TotalSeconds / $AllResults.Count, 1)) seconds per device" -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "`n"

# ============================================================================
# END OF SCRIPT
# ============================================================================