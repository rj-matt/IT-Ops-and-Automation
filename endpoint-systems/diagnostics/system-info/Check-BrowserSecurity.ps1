<#
.SYNOPSIS
    Comprehensive browser security and configuration diagnostic tool.

.DESCRIPTION
    Scans all installed browsers (Chrome, Edge, Firefox) and reports:
    - Browser versions with update status
    - Installed extensions with risk assessment
    - Saved password counts (privacy concern indicator)
    - Auto-update configuration
    - Security and privacy settings
    
    Output is formatted for direct inclusion in support tickets.

.USAGE
    Run manually during security audits or when investigating browser-related issues.
    
.SCOPE
    - Reads browser configuration files and registry keys
    - Does NOT access actual saved passwords or extension data
    - Does NOT modify any browser settings
    
.RISK LEVEL
    READ-ONLY / SAFE
    No modifications are made to the system.

.PREREQUISITES
    - PowerShell 5.1 or later
    - Run as current user (admin not required for basic checks)
    - Works best when browsers are closed

.OUTPUTS
    Console output suitable for ticket documentation
    Highlights security concerns in RED
    Warnings in YELLOW
    Good configurations in GREEN

.NOTES
    Author: MSP Automation Team
    Version: 1.0
    Last Updated: 2025-01-05
    
.EXAMPLE
    .\Get-BrowserSecurityCheck.ps1
    
    Runs full browser security diagnostic on local machine.
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# Initialize output collection
$Script:Findings = @()
$Script:SecurityConcerns = @()

#region Helper Functions

function Write-Header {
    param([string]$Text)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Finding {
    param(
        [string]$Category,
        [string]$Item,
        [string]$Status,
        [string]$Details = "",
        [ValidateSet('Good','Warning','Concern','Info')]
        [string]$Severity = 'Info'
    )
    
    $color = switch ($Severity) {
        'Good'    { 'Green' }
        'Warning' { 'Yellow' }
        'Concern' { 'Red' }
        'Info'    { 'White' }
    }
    
    $prefix = switch ($Severity) {
        'Good'    { '[✓]' }
        'Warning' { '[!]' }
        'Concern' { '[X]' }
        'Info'    { '[i]' }
    }
    
    Write-Host "$prefix $Item`: " -NoNewline -ForegroundColor $color
    Write-Host $Status -ForegroundColor $color
    
    if ($Details) {
        Write-Host "    $Details" -ForegroundColor Gray
    }
    
    $Script:Findings += [PSCustomObject]@{
        Category = $Category
        Item = $Item
        Status = $Status
        Details = $Details
        Severity = $Severity
    }
    
    if ($Severity -eq 'Concern') {
        $Script:SecurityConcerns += "$Category - $Item`: $Status"
    }
}

function Get-FileVersion {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            $version = (Get-Item $Path).VersionInfo.FileVersion
            return $version
        }
        catch {
            return "Unknown"
        }
    }
    return $null
}

function Test-VersionOutdated {
    param(
        [string]$CurrentVersion,
        [int]$MajorVersionBehindThreshold = 2
    )
    
    # This is a simplified check - in production you'd compare against known current versions
    # For now, we flag if version is more than X major versions behind a reasonable baseline
    
    if ($CurrentVersion -match '(\d+)\.') {
        $majorVersion = [int]$Matches[1]
        
        # Baseline "current" major versions as of Jan 2025
        $baselines = @{
            'Chrome' = 131
            'Edge' = 131
            'Firefox' = 133
        }
        
        foreach ($browser in $baselines.Keys) {
            if ($CurrentVersion -like "*$browser*" -or $majorVersion -gt 50) {
                $baseline = $baselines[$browser]
                if ($majorVersion -lt ($baseline - $MajorVersionBehindThreshold)) {
                    return $true
                }
            }
        }
    }
    
    return $false
}

#endregion

#region Chrome Functions

function Get-ChromeInfo {
    Write-Header "Google Chrome"
    
    $chromePath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
    $chromePathx86 = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    $chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    
    # Check if Chrome is installed
    $chromeExe = $null
    if (Test-Path $chromePath) {
        $chromeExe = $chromePath
    }
    elseif (Test-Path $chromePathx86) {
        $chromeExe = $chromePathx86
    }
    
    if (-not $chromeExe) {
        Write-Finding -Category "Chrome" -Item "Installation" -Status "Not installed" -Severity Info
        return
    }
    
    # Version check
    $version = Get-FileVersion -Path $chromeExe
    if ($version) {
        $outdated = Test-VersionOutdated -CurrentVersion $version
        if ($outdated) {
            Write-Finding -Category "Chrome" -Item "Version" -Status $version `
                -Details "Version may be outdated - recommend checking for updates" -Severity Warning
        }
        else {
            Write-Finding -Category "Chrome" -Item "Version" -Status $version -Severity Good
        }
    }
    
    # Auto-update check (via registry)
    try {
        $updatePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "AutoUpdateCheckPeriodMinutes" -ErrorAction SilentlyContinue
        if ($updatePolicy) {
            if ($updatePolicy.AutoUpdateCheckPeriodMinutes -eq 0) {
                Write-Finding -Category "Chrome" -Item "Auto-Update" -Status "DISABLED" `
                    -Details "Updates are blocked by policy" -Severity Concern
            }
            else {
                Write-Finding -Category "Chrome" -Item "Auto-Update" -Status "Enabled (Policy controlled)" -Severity Good
            }
        }
        else {
            Write-Finding -Category "Chrome" -Item "Auto-Update" -Status "Enabled (Default)" -Severity Good
        }
    }
    catch {
        Write-Finding -Category "Chrome" -Item "Auto-Update" -Status "Unable to verify" -Severity Info
    }
    
    # Check user profile
    if (Test-Path $chromeUserData) {
        # Extensions
        $defaultProfile = "$chromeUserData\Default\Extensions"
        if (Test-Path $defaultProfile) {
            $extensions = Get-ChildItem -Path $defaultProfile -Directory | Measure-Object
            $extCount = $extensions.Count
            
            if ($extCount -eq 0) {
                Write-Finding -Category "Chrome" -Item "Extensions" -Status "None installed" -Severity Good
            }
            elseif ($extCount -le 5) {
                Write-Finding -Category "Chrome" -Item "Extensions" -Status "$extCount installed" `
                    -Details "Reasonable number - review periodically" -Severity Info
            }
            else {
                Write-Finding -Category "Chrome" -Item "Extensions" -Status "$extCount installed" `
                    -Details "Large number of extensions increases attack surface" -Severity Warning
            }
        }
        
        # Saved passwords (check if Login Data exists)
        $loginData = "$chromeUserData\Default\Login Data"
        if (Test-Path $loginData) {
            try {
                $fileSize = (Get-Item $loginData).Length
                if ($fileSize -gt 50KB) {
                    Write-Finding -Category "Chrome" -Item "Saved Passwords" -Status "Password database present (significant size)" `
                        -Details "Consider using a dedicated password manager" -Severity Warning
                }
                else {
                    Write-Finding -Category "Chrome" -Item "Saved Passwords" -Status "Few or no saved passwords" -Severity Good
                }
            }
            catch {
                Write-Finding -Category "Chrome" -Item "Saved Passwords" -Status "Unable to check" -Severity Info
            }
        }
        
        # Preferences (security settings)
        $prefsFile = "$chromeUserData\Default\Preferences"
        if (Test-Path $prefsFile) {
            try {
                $prefs = Get-Content $prefsFile -Raw | ConvertFrom-Json
                
                # Safe Browsing
                if ($prefs.profile.safe_browsing_enabled -eq $false) {
                    Write-Finding -Category "Chrome" -Item "Safe Browsing" -Status "DISABLED" `
                        -Details "Critical security feature is turned off" -Severity Concern
                }
                else {
                    Write-Finding -Category "Chrome" -Item "Safe Browsing" -Status "Enabled" -Severity Good
                }
                
                # Password manager
                if ($prefs.credentials_enable_service -eq $false) {
                    Write-Finding -Category "Chrome" -Item "Password Manager" -Status "Disabled" -Severity Info
                }
                else {
                    Write-Finding -Category "Chrome" -Item "Password Manager" -Status "Enabled" `
                        -Details "Built-in password manager active" -Severity Info
                }
            }
            catch {
                Write-Finding -Category "Chrome" -Item "Security Settings" -Status "Unable to parse preferences" -Severity Info
            }
        }
    }
}

#endregion

#region Edge Functions

function Get-EdgeInfo {
    Write-Header "Microsoft Edge"
    
    $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $edgeUserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    
    # Check if Edge is installed
    if (-not (Test-Path $edgePath)) {
        Write-Finding -Category "Edge" -Item "Installation" -Status "Not found at expected location" -Severity Info
        return
    }
    
    # Version check
    $version = Get-FileVersion -Path $edgePath
    if ($version) {
        $outdated = Test-VersionOutdated -CurrentVersion $version
        if ($outdated) {
            Write-Finding -Category "Edge" -Item "Version" -Status $version `
                -Details "Version may be outdated - recommend checking for updates" -Severity Warning
        }
        else {
            Write-Finding -Category "Edge" -Item "Version" -Status $version -Severity Good
        }
    }
    
    # Auto-update check
    try {
        $updatePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "AutoUpdateCheckPeriodMinutes" -ErrorAction SilentlyContinue
        if ($updatePolicy) {
            if ($updatePolicy.AutoUpdateCheckPeriodMinutes -eq 0) {
                Write-Finding -Category "Edge" -Item "Auto-Update" -Status "DISABLED" `
                    -Details "Updates are blocked by policy" -Severity Concern
            }
            else {
                Write-Finding -Category "Edge" -Item "Auto-Update" -Status "Enabled (Policy controlled)" -Severity Good
            }
        }
        else {
            Write-Finding -Category "Edge" -Item "Auto-Update" -Status "Enabled (Default)" -Severity Good
        }
    }
    catch {
        Write-Finding -Category "Edge" -Item "Auto-Update" -Status "Unable to verify" -Severity Info
    }
    
    # Check user profile
    if (Test-Path $edgeUserData) {
        # Extensions
        $defaultProfile = "$edgeUserData\Default\Extensions"
        if (Test-Path $defaultProfile) {
            $extensions = Get-ChildItem -Path $defaultProfile -Directory | Measure-Object
            $extCount = $extensions.Count
            
            if ($extCount -eq 0) {
                Write-Finding -Category "Edge" -Item "Extensions" -Status "None installed" -Severity Good
            }
            elseif ($extCount -le 5) {
                Write-Finding -Category "Edge" -Item "Extensions" -Status "$extCount installed" `
                    -Details "Reasonable number - review periodically" -Severity Info
            }
            else {
                Write-Finding -Category "Edge" -Item "Extensions" -Status "$extCount installed" `
                    -Details "Large number of extensions increases attack surface" -Severity Warning
            }
        }
        
        # Saved passwords
        $loginData = "$edgeUserData\Default\Login Data"
        if (Test-Path $loginData) {
            try {
                $fileSize = (Get-Item $loginData).Length
                if ($fileSize -gt 50KB) {
                    Write-Finding -Category "Edge" -Item "Saved Passwords" -Status "Password database present (significant size)" `
                        -Details "Consider using a dedicated password manager" -Severity Warning
                }
                else {
                    Write-Finding -Category "Edge" -Item "Saved Passwords" -Status "Few or no saved passwords" -Severity Good
                }
            }
            catch {
                Write-Finding -Category "Edge" -Item "Saved Passwords" -Status "Unable to check" -Severity Info
            }
        }
        
        # Preferences
        $prefsFile = "$edgeUserData\Default\Preferences"
        if (Test-Path $prefsFile) {
            try {
                $prefs = Get-Content $prefsFile -Raw | ConvertFrom-Json
                
                # SmartScreen
                if ($prefs.browser.safebrowsing.enabled -eq $false) {
                    Write-Finding -Category "Edge" -Item "SmartScreen" -Status "DISABLED" `
                        -Details "Critical security feature is turned off" -Severity Concern
                }
                else {
                    Write-Finding -Category "Edge" -Item "SmartScreen" -Status "Enabled" -Severity Good
                }
                
                # Tracking prevention
                if ($prefs.profile.edge_tracking_prevention_level) {
                    $level = $prefs.profile.edge_tracking_prevention_level
                    $levelName = switch ($level) {
                        0 { "Basic" }
                        1 { "Balanced" }
                        2 { "Strict" }
                        default { "Unknown ($level)" }
                    }
                    
                    if ($level -eq 0) {
                        Write-Finding -Category "Edge" -Item "Tracking Prevention" -Status $levelName `
                            -Details "Consider using 'Balanced' or 'Strict' for better privacy" -Severity Warning
                    }
                    else {
                        Write-Finding -Category "Edge" -Item "Tracking Prevention" -Status $levelName -Severity Good
                    }
                }
            }
            catch {
                Write-Finding -Category "Edge" -Item "Security Settings" -Status "Unable to parse preferences" -Severity Info
            }
        }
    }
}

#endregion

#region Firefox Functions

function Get-FirefoxInfo {
    Write-Header "Mozilla Firefox"
    
    $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
    $firefoxPathx86 = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    $firefoxProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    
    # Check if Firefox is installed
    $firefoxExe = $null
    if (Test-Path $firefoxPath) {
        $firefoxExe = $firefoxPath
    }
    elseif (Test-Path $firefoxPathx86) {
        $firefoxExe = $firefoxPathx86
    }
    
    if (-not $firefoxExe) {
        Write-Finding -Category "Firefox" -Item "Installation" -Status "Not installed" -Severity Info
        return
    }
    
    # Version check
    $version = Get-FileVersion -Path $firefoxExe
    if ($version) {
        $outdated = Test-VersionOutdated -CurrentVersion $version
        if ($outdated) {
            Write-Finding -Category "Firefox" -Item "Version" -Status $version `
                -Details "Version may be outdated - recommend checking for updates" -Severity Warning
        }
        else {
            Write-Finding -Category "Firefox" -Item "Version" -Status $version -Severity Good
        }
    }
    
    # Auto-update check
    try {
        $updatePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableAppUpdate" -ErrorAction SilentlyContinue
        if ($updatePolicy -and $updatePolicy.DisableAppUpdate -eq 1) {
            Write-Finding -Category "Firefox" -Item "Auto-Update" -Status "DISABLED" `
                -Details "Updates are blocked by policy" -Severity Concern
        }
        else {
            Write-Finding -Category "Firefox" -Item "Auto-Update" -Status "Enabled (Default)" -Severity Good
        }
    }
    catch {
        Write-Finding -Category "Firefox" -Item "Auto-Update" -Status "Unable to verify" -Severity Info
    }
    
    # Check profiles
    if (Test-Path $firefoxProfiles) {
        $profiles = Get-ChildItem -Path $firefoxProfiles -Directory
        
        if ($profiles.Count -eq 0) {
            Write-Finding -Category "Firefox" -Item "Profile" -Status "No profiles found" -Severity Info
            return
        }
        
        # Use the default or most recently modified profile
        $activeProfile = $profiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        
        # Extensions
        $extensionsJson = "$($activeProfile.FullName)\extensions.json"
        if (Test-Path $extensionsJson) {
            try {
                $extData = Get-Content $extensionsJson -Raw | ConvertFrom-Json
                $addons = $extData.addons | Where-Object { $_.type -eq 'extension' -and $_.visible -eq $true }
                $extCount = ($addons | Measure-Object).Count
                
                if ($extCount -eq 0) {
                    Write-Finding -Category "Firefox" -Item "Extensions" -Status "None installed" -Severity Good
                }
                elseif ($extCount -le 5) {
                    Write-Finding -Category "Firefox" -Item "Extensions" -Status "$extCount installed" `
                        -Details "Reasonable number - review periodically" -Severity Info
                }
                else {
                    Write-Finding -Category "Firefox" -Item "Extensions" -Status "$extCount installed" `
                        -Details "Large number of extensions increases attack surface" -Severity Warning
                }
            }
            catch {
                Write-Finding -Category "Firefox" -Item "Extensions" -Status "Unable to parse extensions data" -Severity Info
            }
        }
        
        # Saved passwords
        $loginsJson = "$($activeProfile.FullName)\logins.json"
        if (Test-Path $loginsJson) {
            try {
                $logins = Get-Content $loginsJson -Raw | ConvertFrom-Json
                $loginCount = ($logins.logins | Measure-Object).Count
                
                if ($loginCount -eq 0) {
                    Write-Finding -Category "Firefox" -Item "Saved Passwords" -Status "None saved" -Severity Good
                }
                elseif ($loginCount -le 10) {
                    Write-Finding -Category "Firefox" -Item "Saved Passwords" -Status "$loginCount passwords saved" `
                        -Details "Consider using a dedicated password manager" -Severity Info
                }
                else {
                    Write-Finding -Category "Firefox" -Item "Saved Passwords" -Status "$loginCount passwords saved" `
                        -Details "Recommend migrating to a dedicated password manager" -Severity Warning
                }
            }
            catch {
                Write-Finding -Category "Firefox" -Item "Saved Passwords" -Status "Unable to parse login data" -Severity Info
            }
        }
        
        # Preferences (prefs.js)
        $prefsFile = "$($activeProfile.FullName)\prefs.js"
        if (Test-Path $prefsFile) {
            try {
                $prefsContent = Get-Content $prefsFile
                
                # HTTPS-Only Mode
                $httpsOnly = $prefsContent | Select-String 'dom.security.https_only_mode", true'
                if ($httpsOnly) {
                    Write-Finding -Category "Firefox" -Item "HTTPS-Only Mode" -Status "Enabled" -Severity Good
                }
                else {
                    Write-Finding -Category "Firefox" -Item "HTTPS-Only Mode" -Status "Disabled" `
                        -Details "Recommend enabling for better security" -Severity Warning
                }
                
                # Enhanced Tracking Protection
                $etp = $prefsContent | Select-String 'browser.contentblocking.category", "(\w+)"'
                if ($etp) {
                    $etpLevel = $etp.Matches.Groups[1].Value
                    if ($etpLevel -eq 'standard') {
                        Write-Finding -Category "Firefox" -Item "Enhanced Tracking Protection" -Status "Standard" -Severity Good
                    }
                    elseif ($etpLevel -eq 'strict') {
                        Write-Finding -Category "Firefox" -Item "Enhanced Tracking Protection" -Status "Strict" -Severity Good
                    }
                    else {
                        Write-Finding -Category "Firefox" -Item "Enhanced Tracking Protection" -Status $etpLevel `
                            -Details "Consider using 'Standard' or 'Strict'" -Severity Warning
                    }
                }
                
                # Safe Browsing
                $safeBrowsing = $prefsContent | Select-String 'browser.safebrowsing.malware.enabled", false'
                if ($safeBrowsing) {
                    Write-Finding -Category "Firefox" -Item "Safe Browsing" -Status "DISABLED" `
                        -Details "Critical security feature is turned off" -Severity Concern
                }
                else {
                    Write-Finding -Category "Firefox" -Item "Safe Browsing" -Status "Enabled" -Severity Good
                }
            }
            catch {
                Write-Finding -Category "Firefox" -Item "Security Settings" -Status "Unable to parse preferences" -Severity Info
            }
        }
    }
}

#endregion

#region Main Execution

try {
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║          Browser Security & Configuration Check                ║" -ForegroundColor Cyan
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`nScan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "User: $env:USERNAME`n" -ForegroundColor Gray
    
    # Run browser checks
    Get-ChromeInfo
    Get-EdgeInfo
    Get-FirefoxInfo
    
    # Summary
    Write-Header "Summary"
    
    $totalFindings = $Script:Findings.Count
    $concerns = ($Script:Findings | Where-Object { $_.Severity -eq 'Concern' }).Count
    $warnings = ($Script:Findings | Where-Object { $_.Severity -eq 'Warning' }).Count
    $good = ($Script:Findings | Where-Object { $_.Severity -eq 'Good' }).Count
    
    Write-Host "Total Findings: $totalFindings" -ForegroundColor White
    Write-Host "Security Concerns: $concerns" -ForegroundColor $(if ($concerns -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Warnings: $warnings" -ForegroundColor $(if ($warnings -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "Good Configurations: $good" -ForegroundColor Green
    
    if ($Script:SecurityConcerns.Count -gt 0) {
        Write-Host "`n⚠ PRIORITY ITEMS TO ADDRESS:" -ForegroundColor Red
        foreach ($concern in $Script:SecurityConcerns) {
            Write-Host "  • $concern" -ForegroundColor Red
        }
    }
    
    # Recommendations
    Write-Header "Recommendations"
    
    Write-Host "✓ Ensure all browsers are set to auto-update" -ForegroundColor Gray
    Write-Host "✓ Review and remove unnecessary browser extensions" -ForegroundColor Gray
    Write-Host "✓ Consider using a dedicated password manager (e.g., Bitwarden, 1Password)" -ForegroundColor Gray
    Write-Host "✓ Enable HTTPS-Only mode and enhanced tracking protection" -ForegroundColor Gray
    Write-Host "✓ Regularly clear browsing data and cached credentials" -ForegroundColor Gray
    Write-Host "✓ Avoid saving sensitive passwords in browser password managers" -ForegroundColor Gray
    
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Scan completed successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan
    
}
catch {
    Write-Host "`n[ERROR] Script execution failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "At line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    
    Write-Host "`nPlease copy this error and include it in your support ticket." -ForegroundColor Yellow
    exit 1
}

#endregion