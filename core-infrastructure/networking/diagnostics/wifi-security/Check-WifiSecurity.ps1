<#
.SYNOPSIS
    Audits WiFi security configuration and saved network profiles.

.DESCRIPTION
    Performs a comprehensive WiFi security audit including:
    - Current connection details (SSID, encryption, signal strength)
    - All saved WiFi profiles with security settings
    - Encryption type analysis (flags weak encryption)
    - Neighboring networks for interference and security threats
    - Guest network detection and isolation status
    
    Designed for MSP technicians performing network security assessments.

.USAGE
    Run during security audits, network troubleshooting, or onboarding assessments.
    Output is formatted for direct inclusion in support tickets.

.SCOPE
    Read-only diagnostic script. Makes no configuration changes.

.RISK LEVEL
    SAFE - Read-only operations only. No modifications made to system.

.PREREQUISITES
    - Windows 10/11 or Windows Server with WiFi capability
    - Must be run on a system with wireless adapter (including USB dongles)
    - No elevation required for basic diagnostics
    - Administrative rights required for detailed profile inspection

.NOTES
    Author: MSP Automation Team
    Version: 1.1
    Last Updated: 2025-01-05
    
.EXAMPLE
    .\Get-WiFiSecurityAudit.ps1
    Performs complete WiFi security audit and displays results
#>

#Requires -Version 5.1

# Script metadata
$ScriptVersion = "1.1"
$ScriptPath = $MyInvocation.MyCommand.Path
$ExecutionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Initialize result collection
$AuditResults = @{
    ExecutionTime = $ExecutionTime
    ComputerName = $env:COMPUTERNAME
    CurrentUser = $env:USERNAME
    Warnings = @()
    Errors = @()
}

#region Helper Functions

function Write-AuditSection {
    param(
        [string]$Title,
        [ConsoleColor]$Color = 'Cyan'
    )
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host ("=" * 80) -ForegroundColor $Color
}

function Write-AuditWarning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
    $AuditResults.Warnings += $Message
}

function Write-AuditError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    $AuditResults.Errors += $Message
}

function Get-SecurityRating {
    param([string]$AuthType)
    
    switch -Regex ($AuthType) {
        'WPA3' { return @{ Rating = 'EXCELLENT'; Color = 'Green'; Score = 5 } }
        'WPA2-Personal|WPA2-Enterprise' { return @{ Rating = 'GOOD'; Color = 'Green'; Score = 4 } }
        'WPA-Personal|WPA-Enterprise' { return @{ Rating = 'FAIR'; Color = 'Yellow'; Score = 3 } }
        'WEP' { return @{ Rating = 'CRITICAL - INSECURE'; Color = 'Red'; Score = 1 } }
        'Open|None' { return @{ Rating = 'CRITICAL - NO ENCRYPTION'; Color = 'Red'; Score = 0 } }
        default { return @{ Rating = 'UNKNOWN'; Color = 'Yellow'; Score = 2 } }
    }
}

function Test-WirelessCapability {
    <#
    .SYNOPSIS
        Comprehensive check for wireless capability using multiple detection methods
    #>
    
    # Method 1: Check using netsh (most reliable for WiFi capability)
    try {
        $NetshCheck = netsh wlan show interfaces 2>&1
        if ($NetshCheck -notmatch 'There is no wireless interface|not running|AutoConfig') {
            return $true
        }
    }
    catch {
        # Continue to next check
    }
    
    # Method 2: Check if WLAN AutoConfig service exists and can be queried
    try {
        $WlanService = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
        if ($WlanService) {
            # Service exists, try to query driver
            $DriverCheck = netsh wlan show drivers 2>&1
            if ($DriverCheck -notmatch 'not running|There is no wireless') {
                return $true
            }
        }
    }
    catch {
        # Continue to next check
    }
    
    # Method 3: Check for saved profiles (indicates WiFi was used before)
    try {
        $ProfileCheck = netsh wlan show profiles 2>&1
        if ($ProfileCheck -match 'User profiles|All User Profile') {
            return $true
        }
    }
    catch {
        # Continue to next check
    }
    
    # Method 4: Check network adapters via CIM/WMI
    try {
        $WirelessAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { 
            $_.InterfaceDescription -match 'wireless|wifi|802\.11|wlan|wi-fi' -or
            $_.Name -match 'wi-fi|wlan|wireless'
        }
        
        if ($WirelessAdapters) {
            return $true
        }
    }
    catch {
        # Continue to next check
    }
    
    # Method 5: Check WMI for network adapters
    try {
        $WmiAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue | 
            Where-Object { 
                $_.Name -match 'wireless|wifi|802\.11|wlan|wi-fi' -or
                $_.Description -match 'wireless|wifi|802\.11|wlan|wi-fi'
            }
        
        if ($WmiAdapters) {
            return $true
        }
    }
    catch {
        # No wireless capability detected
    }
    
    return $false
}

#endregion

#region Main Audit Logic

try {
    # Header
    Write-AuditSection "WiFi SECURITY AUDIT REPORT" -Color Green
    Write-Host "Computer: $($AuditResults.ComputerName)"
    Write-Host "User: $($AuditResults.CurrentUser)"
    Write-Host "Scan Time: $ExecutionTime"
    Write-Host "Script Version: $ScriptVersion"
    
    # Comprehensive wireless capability check
    Write-AuditSection "1. WIRELESS CAPABILITY DETECTION"
    
    Write-Host "`nPerforming comprehensive wireless capability check..."
    
    $HasWirelessCapability = Test-WirelessCapability
    
    if (-not $HasWirelessCapability) {
        Write-AuditError "No wireless capability detected on this system."
        Write-Host "`nThis system does not appear to have:"
        Write-Host "  - Any wireless network adapters (built-in or USB)"
        Write-Host "  - WLAN AutoConfig service capability"
        Write-Host "  - Any saved WiFi profiles"
        Write-Host "`nPossible reasons:"
        Write-Host "  1. This is a desktop/server without WiFi hardware"
        Write-Host "  2. WiFi adapter drivers are not installed"
        Write-Host "  3. WiFi adapter is physically disabled"
        Write-Host "  4. WLAN AutoConfig service is disabled"
        Write-Host "`nIf you believe this system should have WiFi capability:"
        Write-Host "  - Check Device Manager for disabled wireless adapters"
        Write-Host "  - Verify WLAN AutoConfig service is running (services.msc)"
        Write-Host "  - Install appropriate wireless adapter drivers"
        
        Write-AuditSection "AUDIT SUMMARY" -Color Yellow
        Write-Host "`nAudit Status: NOT APPLICABLE - No wireless capability detected"
        Write-Host "This report can be included in tickets to document lack of WiFi capability."
        exit 0
    }
    
    Write-Host "`n[SUCCESS] Wireless capability detected" -ForegroundColor Green
    
    # Check WLAN AutoConfig service
    Write-AuditSection "2. WLAN SERVICE STATUS"
    
    try {
        $WlanService = Get-Service -Name WlanSvc -ErrorAction Stop
        
        Write-Host "`nWLAN AutoConfig Service:"
        Write-Host "  Status: $($WlanService.Status)" -ForegroundColor $(if ($WlanService.Status -eq 'Running') { 'Green' } else { 'Yellow' })
        Write-Host "  Start Type: $($WlanService.StartType)"
        
        if ($WlanService.Status -ne 'Running') {
            Write-AuditWarning "WLAN AutoConfig service is not running. Some features may be limited."
            Write-Host "  Note: Service must be running for full WiFi functionality." -ForegroundColor Yellow
        }
    }
    catch {
        Write-AuditError "Could not query WLAN AutoConfig service: $($_.Exception.Message)"
    }
    
    # Enumerate wireless adapters
    Write-AuditSection "3. WIRELESS ADAPTER INVENTORY"
    
    try {
        # Try multiple methods to find wireless adapters
        $WirelessAdapters = @()
        
        # Method 1: Get-NetAdapter (most detailed)
        $NetAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { 
            $_.InterfaceDescription -match 'wireless|wifi|802\.11|wlan|wi-fi' -or
            $_.Name -match 'wi-fi|wlan|wireless'
        }
        
        if ($NetAdapters) {
            $WirelessAdapters += $NetAdapters
        }
        
        # Method 2: WMI/CIM fallback
        if ($WirelessAdapters.Count -eq 0) {
            $WmiAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue | 
                Where-Object { 
                    ($_.Name -match 'wireless|wifi|802\.11|wlan|wi-fi' -or
                     $_.Description -match 'wireless|wifi|802\.11|wlan|wi-fi') -and
                    $_.NetEnabled -eq $true
                }
            
            if ($WmiAdapters) {
                foreach ($Adapter in $WmiAdapters) {
                    $WirelessAdapters += [PSCustomObject]@{
                        Name = $Adapter.NetConnectionID
                        InterfaceDescription = $Adapter.Description
                        Status = if ($Adapter.NetConnectionStatus -eq 2) { 'Up' } else { 'Disconnected' }
                        MacAddress = $Adapter.MACAddress
                        LinkSpeed = 'N/A'
                    }
                }
            }
        }
        
        if ($WirelessAdapters.Count -eq 0) {
            Write-Host "`nNo wireless adapters found via PowerShell."
            Write-Host "Attempting detection via netsh command..." -ForegroundColor Yellow
            
            # Method 3: Parse netsh output
            $NetshDrivers = netsh wlan show drivers
            if ($NetshDrivers -notmatch 'not running|There is no wireless') {
                Write-Host "`nWireless driver detected via netsh:"
                $NetshDrivers | Where-Object { $_ -match 'Interface name|Description|Driver' } | ForEach-Object {
                    Write-Host "  $_"
                }
                Write-Host "`nNote: Detailed adapter properties unavailable via netsh." -ForegroundColor Yellow
                
                # Create minimal adapter object
                $WirelessAdapters += [PSCustomObject]@{
                    Name = 'Detected via netsh'
                    InterfaceDescription = 'Wireless adapter (details limited)'
                    Status = 'Unknown'
                    MacAddress = 'N/A'
                    LinkSpeed = 'N/A'
                }
            }
        }
        
        if ($WirelessAdapters.Count -eq 0) {
            Write-AuditWarning "Wireless capability detected but no active adapters found."
            Write-Host "`nThis may indicate:"
            Write-Host "  - Adapter is disabled in Device Manager"
            Write-Host "  - Driver issues"
            Write-Host "  - Hardware is present but not functioning"
            Write-Host "`nContinuing audit with saved profile analysis..."
        }
        else {
            Write-Host "`nFound $($WirelessAdapters.Count) wireless adapter(s):"
            
            foreach ($Adapter in $WirelessAdapters) {
                Write-Host "`nAdapter: $($Adapter.InterfaceDescription)" -ForegroundColor Cyan
                Write-Host "  Interface Name: $($Adapter.Name)"
                Write-Host "  Status: $($Adapter.Status)" -ForegroundColor $(if ($Adapter.Status -eq 'Up') { 'Green' } else { 'Yellow' })
                
                if ($Adapter.MacAddress -and $Adapter.MacAddress -ne 'N/A') {
                    Write-Host "  MAC Address: $($Adapter.MacAddress)"
                }
                
                if ($Adapter.LinkSpeed -and $Adapter.LinkSpeed -ne 'N/A') {
                    Write-Host "  Link Speed: $($Adapter.LinkSpeed)"
                }
                
                # Identify adapter type
                if ($Adapter.InterfaceDescription -match 'USB|Wireless-AC|Wireless-N') {
                    if ($Adapter.InterfaceDescription -match 'USB') {
                        Write-Host "  Type: USB WiFi Adapter" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "  Type: Built-in WiFi Adapter" -ForegroundColor Cyan
                    }
                }
            }
            
            $AuditResults.AdapterCount = $WirelessAdapters.Count
        }
    }
    catch {
        Write-AuditError "Error enumerating wireless adapters: $($_.Exception.Message)"
        Write-Host "Continuing with profile-based audit..."
    }
    
    # Current connection details
    Write-AuditSection "4. CURRENT WiFi CONNECTION"
    
    try {
        $CurrentConnection = netsh wlan show interfaces 2>&1
        
        if ($CurrentConnection -match 'There is no wireless interface|not running') {
            Write-Host "`nNot currently connected to any WiFi network." -ForegroundColor Yellow
            Write-Host "(Or adapter is disabled/not available)"
        }
        else {
            # Parse current connection
            $SSID = ($CurrentConnection | Select-String "^\s*SSID\s*:" | Select-Object -First 1) -replace '.*:\s+', ''
            $BSSID = ($CurrentConnection | Select-String "^\s*BSSID\s*:" | Select-Object -First 1) -replace '.*:\s+', ''
            $NetworkType = ($CurrentConnection | Select-String "Network type" | Select-Object -First 1) -replace '.*:\s+', ''
            $Authentication = ($CurrentConnection | Select-String "^\s*Authentication\s*:" | Select-Object -First 1) -replace '.*:\s+', ''
            $Cipher = ($CurrentConnection | Select-String "^\s*Cipher\s*:" | Select-Object -First 1) -replace '.*:\s+', ''
            $Signal = ($CurrentConnection | Select-String "Signal" | Select-Object -First 1) -replace '.*:\s+', ''
            
            if ($SSID) {
                $SecurityRating = Get-SecurityRating -AuthType $Authentication
                
                Write-Host "`nConnected Network Details:"
                Write-Host "  SSID: $SSID" -ForegroundColor Cyan
                Write-Host "  BSSID (Access Point): $BSSID"
                Write-Host "  Network Type: $NetworkType"
                Write-Host "  Authentication: $Authentication" -ForegroundColor $SecurityRating.Color
                Write-Host "  Cipher: $Cipher"
                Write-Host "  Signal Strength: $Signal"
                Write-Host "  Security Rating: $($SecurityRating.Rating)" -ForegroundColor $SecurityRating.Color
                
                # Security warnings
                if ($SecurityRating.Score -lt 3) {
                    Write-AuditWarning "Current network uses weak or no encryption: $Authentication"
                    Write-Host "  RECOMMENDATION: Connect to a WPA2 or WPA3 protected network immediately." -ForegroundColor Yellow
                }
                
                $AuditResults.CurrentConnection = @{
                    SSID = $SSID
                    Authentication = $Authentication
                    SecurityRating = $SecurityRating.Rating
                    Signal = $Signal
                }
            }
            else {
                Write-Host "`nNo active WiFi connection detected." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-AuditError "Failed to retrieve current connection details: $($_.Exception.Message)"
    }
    
    # Saved WiFi profiles
    Write-AuditSection "5. SAVED WiFi PROFILES"
    
    try {
        $ProfileList = netsh wlan show profiles 2>&1 | Select-String "All User Profile" | ForEach-Object {
            ($_ -split ':')[1].Trim()
        }
        
        if ($ProfileList) {
            Write-Host "`nFound $($ProfileList.Count) saved WiFi profile(s):"
            Write-Host "Analyzing security settings for each profile...`n"
            
            $ProfileDetails = @()
            $InsecureProfiles = @()
            
            foreach ($ProfileName in $ProfileList) {
                try {
                    $ProfileInfo = netsh wlan show profile name="$ProfileName" key=clear 2>&1
                    
                    # Extract key details
                    $AuthType = ($ProfileInfo | Select-String "^\s*Authentication\s*:" | Select-Object -First 1) -replace '.*:\s+', ''
                    $CipherType = ($ProfileInfo | Select-String "^\s*Cipher\s*:" | Select-Object -First 1) -replace '.*:\s+', ''
                    $SecurityKey = ($ProfileInfo | Select-String "Key Content" | Select-Object -First 1) -replace '.*:\s+', ''
                    $ConnectionMode = ($ProfileInfo | Select-String "Connection mode" | Select-Object -First 1) -replace '.*:\s+', ''
                    
                    $SecurityRating = Get-SecurityRating -AuthType $AuthType
                    
                    $ProfileDetail = [PSCustomObject]@{
                        ProfileName = $ProfileName
                        Authentication = if ($AuthType) { $AuthType } else { "Unknown" }
                        Cipher = if ($CipherType) { $CipherType } else { "Unknown" }
                        SecurityRating = $SecurityRating.Rating
                        SecurityScore = $SecurityRating.Score
                        ConnectionMode = if ($ConnectionMode) { $ConnectionMode } else { "Unknown" }
                        HasSavedPassword = if ($SecurityKey -and $SecurityKey -ne 'Absent') { 'Yes' } else { 'No' }
                    }
                    
                    $ProfileDetails += $ProfileDetail
                    
                    # Display profile
                    Write-Host "Profile: $ProfileName" -ForegroundColor Cyan
                    Write-Host "  Authentication: $($ProfileDetail.Authentication)"
                    Write-Host "  Cipher: $($ProfileDetail.Cipher)"
                    Write-Host "  Security Rating: $($ProfileDetail.SecurityRating)" -ForegroundColor $SecurityRating.Color
                    Write-Host "  Connection Mode: $($ProfileDetail.ConnectionMode)"
                    Write-Host "  Saved Password: $($ProfileDetail.HasSavedPassword)"
                    
                    # Flag security issues
                    if ($SecurityRating.Score -lt 3) {
                        Write-AuditWarning "Insecure profile detected: $ProfileName ($($ProfileDetail.Authentication))"
                        $InsecureProfiles += $ProfileName
                    }
                    
                    # Check for public/guest network patterns
                    if ($ProfileName -match 'guest|public|free|wifi|hotel|airport|cafe|coffee|starbucks|mcdonalds') {
                        Write-Host "  [!] Potential public/guest network - review if still needed" -ForegroundColor Yellow
                    }
                    
                    Write-Host ""
                }
                catch {
                    Write-Host "  [ERROR] Could not retrieve details for: $ProfileName" -ForegroundColor Red
                    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host ""
                }
            }
            
            $AuditResults.SavedProfiles = $ProfileDetails
            $AuditResults.InsecureProfileCount = $InsecureProfiles.Count
            
            # Summary of insecure profiles
            if ($InsecureProfiles.Count -gt 0) {
                Write-Host "`n[SECURITY CONCERN] $($InsecureProfiles.Count) insecure profile(s) found:" -ForegroundColor Red
                foreach ($Profile in $InsecureProfiles) {
                    Write-Host "  - $Profile" -ForegroundColor Red
                }
                Write-Host "`nRECOMMENDATION: Remove insecure profiles or avoid connecting to them." -ForegroundColor Yellow
                Write-Host "To remove: netsh wlan delete profile name=`"ProfileName`"" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "`nNo saved WiFi profiles found." -ForegroundColor Yellow
            Write-Host "This system may never have connected to WiFi networks."
        }
    }
    catch {
        Write-AuditError "Failed to enumerate WiFi profiles: $($_.Exception.Message)"
    }
    
    # Scan for nearby networks
    Write-AuditSection "6. NEARBY WIRELESS NETWORKS"
    
    try {
        Write-Host "`nScanning for nearby networks (this may take 5-10 seconds)..."
        
        # Check if we can scan
        $ScanResults = netsh wlan show networks mode=bssid 2>&1
        
        if ($ScanResults -match 'There is no wireless interface|not running|The Wireless AutoConfig Service') {
            Write-Host "`n[SKIPPED] Cannot scan for networks - adapter unavailable or service not running" -ForegroundColor Yellow
            Write-Host "This feature requires:"
            Write-Host "  - Active wireless adapter"
            Write-Host "  - WLAN AutoConfig service running"
            Write-Host "  - Adapter not in use by another connection"
        }
        else {
            # Parse available networks
            $NetworkList = @()
            $CurrentNetwork = @{}
            
            foreach ($Line in $ScanResults) {
                if ($Line -match '^SSID \d+ : (.+)') {
                    if ($CurrentNetwork.Count -gt 0) {
                        $NetworkList += [PSCustomObject]$CurrentNetwork
                    }
                    $CurrentNetwork = @{ SSID = $Matches[1].Trim() }
                }
                elseif ($Line -match '^\s*Network type\s+:\s+(.+)') {
                    $CurrentNetwork.NetworkType = $Matches[1].Trim()
                }
                elseif ($Line -match '^\s*Authentication\s+:\s+(.+)') {
                    $CurrentNetwork.Authentication = $Matches[1].Trim()
                }
                elseif ($Line -match '^\s*Encryption\s+:\s+(.+)') {
                    $CurrentNetwork.Encryption = $Matches[1].Trim()
                }
                elseif ($Line -match '^\s*BSSID \d+\s+:\s+(.+)') {
                    if (-not $CurrentNetwork.ContainsKey('BSSIDs')) {
                        $CurrentNetwork.BSSIDs = @()
                    }
                    $CurrentNetwork.BSSIDs += $Matches[1].Trim()
                }
                elseif ($Line -match '^\s*Signal\s+:\s+(.+)') {
                    $CurrentNetwork.Signal = $Matches[1].Trim()
                }
                elseif ($Line -match '^\s*Radio type\s+:\s+(.+)') {
                    $CurrentNetwork.RadioType = $Matches[1].Trim()
                }
                elseif ($Line -match '^\s*Channel\s+:\s+(.+)') {
                    $CurrentNetwork.Channel = $Matches[1].Trim()
                }
            }
            
            if ($CurrentNetwork.Count -gt 0) {
                $NetworkList += [PSCustomObject]$CurrentNetwork
            }
            
            if ($NetworkList.Count -gt 0) {
                Write-Host "`nFound $($NetworkList.Count) nearby wireless network(s):`n"
                
                $OpenNetworks = @()
                $WeakNetworks = @()
                
                foreach ($Network in $NetworkList | Sort-Object Signal -Descending) {
                    $SecurityRating = Get-SecurityRating -AuthType $Network.Authentication
                    
                    Write-Host "SSID: $($Network.SSID)" -ForegroundColor Cyan
                    
                    if ($Network.NetworkType) {
                        Write-Host "  Network Type: $($Network.NetworkType)"
                    }
                    
                    Write-Host "  Authentication: $($Network.Authentication)"
                    Write-Host "  Encryption: $($Network.Encryption)"
                    
                    if ($Network.Signal) {
                        Write-Host "  Signal: $($Network.Signal)"
                    }
                    
                    if ($Network.Channel) {
                        Write-Host "  Channel: $($Network.Channel)"
                    }
                    
                    if ($Network.RadioType) {
                        Write-Host "  Radio Type: $($Network.RadioType)"
                    }
                    
                    if ($Network.BSSIDs -and $Network.BSSIDs.Count -gt 1) {
                        Write-Host "  Access Points: $($Network.BSSIDs.Count) (multiple APs detected)"
                    }
                    
                    Write-Host "  Security: $($SecurityRating.Rating)" -ForegroundColor $SecurityRating.Color
                    
                    # Flag security concerns
                    if ($SecurityRating.Score -eq 0) {
                        Write-Host "  [!] OPEN NETWORK - No encryption" -ForegroundColor Red
                        $OpenNetworks += $Network.SSID
                    }
                    elseif ($SecurityRating.Score -lt 3) {
                        Write-Host "  [!] Weak encryption detected" -ForegroundColor Yellow
                        $WeakNetworks += $Network.SSID
                    }
                    
                    # Check for suspicious SSIDs (evil twin detection)
                    if ($Network.SSID -match '^\s*$|^free|^public|xfinitywifi|attwifi') {
                        if ($SecurityRating.Score -eq 0) {
                            Write-Host "  [!] Potential rogue access point - generic/provider SSID with no security" -ForegroundColor Red
                        }
                    }
                    
                    Write-Host ""
                }
                
                $AuditResults.NearbyNetworks = $NetworkList.Count
                $AuditResults.OpenNetworks = $OpenNetworks.Count
                
                # Warnings summary
                if ($OpenNetworks.Count -gt 0) {
                    Write-Host "`n[WARNING] $($OpenNetworks.Count) open network(s) detected in area:" -ForegroundColor Yellow
                    foreach ($Network in $OpenNetworks) {
                        Write-Host "  - $Network" -ForegroundColor Yellow
                    }
                    Write-Host "RECOMMENDATION: Avoid connecting to open networks. Use VPN if necessary." -ForegroundColor Yellow
                }
                
                # Channel interference analysis
                if ($NetworkList.Where({ $_.Channel }).Count -gt 0) {
                    Write-AuditSection "7. CHANNEL INTERFERENCE ASSESSMENT"
                    
                    $ChannelUsage = $NetworkList | Where-Object { $_.Channel } | 
                        Group-Object -Property Channel | 
                        Sort-Object Count -Descending
                    
                    Write-Host "`nChannel usage summary:"
                    foreach ($Channel in $ChannelUsage) {
                        $CongestionLevel = if ($Channel.Count -ge 5) { " [HIGH CONGESTION]" } 
                                          elseif ($Channel.Count -ge 3) { " [MODERATE]" }
                                          else { "" }
                        
                        $Color = if ($Channel.Count -ge 5) { 'Red' }
                                 elseif ($Channel.Count -ge 3) { 'Yellow' }
                                 else { 'Green' }
                        
                        Write-Host "  Channel $($Channel.Name): $($Channel.Count) network(s)$CongestionLevel" -ForegroundColor $Color
                    }
                    
                    if ($ChannelUsage[0].Count -ge 5) {
                        Write-AuditWarning "High channel congestion detected on Channel $($ChannelUsage[0].Name)"
                        Write-Host "`nRECOMMENDATION: Consider configuring router to use less congested channel." -ForegroundColor Yellow
                        Write-Host "Optimal channels for 2.4GHz: 1, 6, 11 (non-overlapping)" -ForegroundColor Gray
                        Write-Host "Consider 5GHz for less interference" -ForegroundColor Gray
                    }
                }
            }
            else {
                Write-Host "`nNo nearby networks detected." -ForegroundColor Yellow
                Write-Host "This may indicate:"
                Write-Host "  - No WiFi networks in range"
                Write-Host "  - Adapter scanning capability limited"
                Write-Host "  - Interference or hardware issues"
            }
        }
    }
    catch {
        Write-AuditError "Failed to scan nearby networks: $($_.Exception.Message)"
    }
    
    # Guest network detection
    Write-AuditSection "8. GUEST NETWORK ANALYSIS"
    
    Write-Host "`nAnalyzing for guest network configurations..."
    
    if ($ProfileDetails.Count -gt 0) {
        $GuestNetworks = $ProfileDetails | Where-Object { 
            $_.ProfileName -match 'guest|visitor|public' 
        }
        
        if ($GuestNetworks) {
            Write-Host "`nFound $($GuestNetworks.Count) potential guest network profile(s):"
            foreach ($Guest in $GuestNetworks) {
                Write-Host "  - $($Guest.ProfileName) (Security: $($Guest.SecurityRating))"
            }
            Write-Host "`nNOTE: Guest network isolation cannot be verified from client side."
            Write-Host "Recommendation: Verify router configuration to ensure guest network isolation is enabled."
        }
        else {
            Write-Host "`nNo obvious guest network profiles detected in saved profiles."
        }
    }
    else {
        Write-Host "`nNo saved profiles available for guest network analysis."
    }
    
    # Final summary
    Write-AuditSection "AUDIT SUMMARY" -Color Green
    
    Write-Host "`nAudit Statistics:"
    
    if ($AuditResults.ContainsKey('AdapterCount')) {
        Write-Host "  Wireless Adapters: $($AuditResults.AdapterCount)" -ForegroundColor $(if ($AuditResults.AdapterCount -gt 0) { 'Green' } else { 'Yellow' })
    }
    else {
        Write-Host "  Wireless Adapters: 0 (or unavailable)" -ForegroundColor Yellow
}
Write-Host "  Saved Profiles: $($ProfileDetails.Count)"
Write-Host "  Insecure Profiles: $($AuditResults.InsecureProfileCount)" -ForegroundColor $(if ($AuditResults.InsecureProfileCount -gt 0) { 'Red' } else { 'Green' })

if ($AuditResults.ContainsKey('NearbyNetworks')) {
    Write-Host "  Nearby Networks: $($AuditResults.NearbyNetworks)"
    Write-Host "  Open Networks Detected: $($AuditResults.OpenNetworks)" -ForegroundColor $(if ($AuditResults.OpenNetworks -gt 0) { 'Yellow' } else { 'Green' })
}

Write-Host "  Warnings: $($AuditResults.Warnings.Count)" -ForegroundColor $(if ($AuditResults.Warnings.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Errors: $($AuditResults.Errors.Count)" -ForegroundColor $(if ($AuditResults.Errors.Count -gt 0) { 'Red' } else { 'Green' })

if ($AuditResults.Warnings.Count -gt 0) {
    Write-Host "`nWarnings Summary:" -ForegroundColor Yellow
    foreach ($Warning in $AuditResults.Warnings) {
        Write-Host "  - $Warning" -ForegroundColor Yellow
    }
}

# Security recommendations
Write-AuditSection "SECURITY RECOMMENDATIONS"

Write-Host "`nBased on this audit, consider the following actions:`n"

$RecommendationPriority = 0

if ($AuditResults.InsecureProfileCount -gt 0) {
    Write-Host "[$($RecommendationPriority + 1)] HIGH PRIORITY: Remove or avoid insecure WiFi profiles" -ForegroundColor Red
    $RecommendationPriority++
}

if ($AuditResults.ContainsKey('OpenNetworks') -and $AuditResults.OpenNetworks -gt 0) {
    Write-Host "[$($RecommendationPriority + 1)] MEDIUM PRIORITY: Open networks detected - ensure VPN usage if connecting" -ForegroundColor Yellow
    $RecommendationPriority++
}

if ($ProfileDetails | Where-Object { $_.ProfileName -match 'guest|public|free|hotel|airport' }) {
    Write-Host "[$($RecommendationPriority + 1)] MEDIUM PRIORITY: Review and remove old public WiFi profiles" -ForegroundColor Yellow
    $RecommendationPriority++
}

if ((-not $AuditResults.ContainsKey('AdapterCount') -or $AuditResults.AdapterCount -eq 0) -and $ProfileDetails.Count -gt 0) {
    Write-Host "[$($RecommendationPriority + 1)] MEDIUM PRIORITY: WiFi profiles exist but no adapter detected - check Device Manager" -ForegroundColor Yellow
    $RecommendationPriority++
}

Write-Host "[$($RecommendationPriority + 1)] BEST PRACTICE: Prefer WPA3 networks when available"
Write-Host "[$($RecommendationPriority + 2)] BEST PRACTICE: Enable router guest network isolation"
Write-Host "[$($RecommendationPriority + 3)] BEST PRACTICE: Regularly audit saved WiFi profiles"
Write-Host "[$($RecommendationPriority + 4)] BEST PRACTICE: Use VPN on untrusted networks"

Write-Host "`n" + ("=" * 80)
Write-Host "Audit completed successfully at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green
Write-Host ("=" * 80)
Write-Host ""
}
catch {
    Write-AuditError "Critical error during audit execution: ((
(_.Exception.Message)"
    Write-Host "
nStack Trace:" -ForegroundColor Red     Write-Host $_.ScriptStackTrace -ForegroundColor Red     exit 1 } finally {     # Cleanup     Write-Host "nNote: This audit report can be copied directly into support tickets."
Write-Host "For remediation assistance, consult the remediation scripts in the toolkit."
}
#endregion