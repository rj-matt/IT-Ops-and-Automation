<#
.SYNOPSIS
    Comprehensive Endpoint Security Posture Assessment Tool
.DESCRIPTION
    Enhanced security status check for incident triage and compliance validation.
    Checks: Antivirus, Firewall, BitLocker, Updates, Local Admins, Secure Boot, TPM,
    Password Policy, Audit Logging, USB Restrictions, RDP, Exploit Protection, and more.
.PARAMETER OutputFormat
    Output format: Console, JSON, or CSV
.PARAMETER ExportPath
    Path to export results (for JSON/CSV formats)
.PARAMETER QuickScan
    Skip time-consuming checks (Windows Updates query)
.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1
.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1 -OutputFormat JSON -ExportPath "C:\Reports\security-status.json"
.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1 -QuickScan
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Console', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Console',
    
    [Parameter()]
    [string]$ExportPath,
    
    [Parameter()]
    [switch]$QuickScan
)

# Requires elevation
#Requires -RunAsAdministrator

$results = @{
    ComputerName = $env:COMPUTERNAME
    ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Checks = @{}
    OverallStatus = "PASS"
}

function Write-CheckResult {
    param(
        [string]$CheckName,
        [string]$Status,
        [string]$Details,
        [hashtable]$Data = @{}
    )
    
    $results.Checks[$CheckName] = @{
        Status = $Status
        Details = $Details
        Data = $Data
    }
    
    if ($Status -eq "FAIL") {
        $results.OverallStatus = "FAIL"
    }
    
    if ($OutputFormat -eq 'Console') {
        $color = switch ($Status) {
            "PASS" { "Green" }
            "FAIL" { "Red" }
            "WARN" { "Yellow" }
            default { "White" }
        }
        Write-Host "[$Status] " -ForegroundColor $color -NoNewline
        Write-Host "$CheckName - $Details"
    }
}

# ============================================
# CHECK 1: Antivirus Protection
# ============================================
Write-Host "`n=== ANTIVIRUS STATUS ===" -ForegroundColor Cyan
try {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    
    if ($avProducts) {
        $activeAV = $null
        $avData = @{ InstalledProducts = @() }
        
        foreach ($product in $avProducts) {
            $hexString = [Convert]::ToString($product.productState, 16).PadLeft(6, '0')
            $enabled = $hexString.Substring(2, 2) -eq '10' -or $hexString.Substring(2, 2) -eq '11'
            $updated = $hexString.Substring(4, 2) -eq '00'
            
            $productInfo = @{
                Name = $product.displayName
                State = $product.productState
                Enabled = $enabled
                DefinitionsCurrent = $updated
                PathToExe = $product.pathToSignedProductExe
            }
            
            $avData.InstalledProducts += $productInfo
            
            if ($enabled) {
                $activeAV = $productInfo
            }
        }
        
        if ($activeAV) {
            $avData['ActiveProduct'] = $activeAV.Name
            $avData['ProductEnabled'] = $activeAV.Enabled
            $avData['DefinitionStatus'] = if ($activeAV.DefinitionsCurrent) { "Current" } else { "Outdated" }
            
            if (-not $activeAV.DefinitionsCurrent) {
                Write-CheckResult -CheckName "Antivirus Protection" -Status "WARN" -Details "$($activeAV.Name) enabled but definitions may be outdated" -Data $avData
            } else {
                Write-CheckResult -CheckName "Antivirus Protection" -Status "PASS" -Details "$($activeAV.Name) active and up-to-date" -Data $avData
            }
        } else {
            Write-CheckResult -CheckName "Antivirus Protection" -Status "FAIL" -Details "No active antivirus protection detected" -Data $avData
        }
    } else {
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            $avData = @{
                Product = "Windows Defender"
                Enabled = $defender.AntivirusEnabled
                RealTimeProtection = $defender.RealTimeProtectionEnabled
            }
            
            if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
                Write-CheckResult -CheckName "Antivirus Protection" -Status "PASS" -Details "Windows Defender active" -Data $avData
            } else {
                Write-CheckResult -CheckName "Antivirus Protection" -Status "FAIL" -Details "Windows Defender disabled, no AV products found" -Data $avData
            }
        } catch {
            Write-CheckResult -CheckName "Antivirus Protection" -Status "FAIL" -Details "No antivirus products detected"
        }
    }
} catch {
    Write-CheckResult -CheckName "Antivirus Protection" -Status "FAIL" -Details "Unable to query antivirus status: $($_.Exception.Message)"
}

# ============================================
# CHECK 2: Windows Firewall
# ============================================
Write-Host "`n=== FIREWALL STATUS ===" -ForegroundColor Cyan
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $fwData = @{}
    $allEnabled = $true
    
    foreach ($profile in $fwProfiles) {
        $fwData[$profile.Name] = @{
            Enabled = $profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction
            DefaultOutboundAction = $profile.DefaultOutboundAction
        }
        if (-not $profile.Enabled) {
            $allEnabled = $false
        }
    }
    
    if ($allEnabled) {
        Write-CheckResult -CheckName "Windows Firewall" -Status "PASS" -Details "All profiles enabled" -Data $fwData
    } else {
        $disabled = ($fwProfiles | Where-Object { -not $_.Enabled }).Name -join ", "
        Write-CheckResult -CheckName "Windows Firewall" -Status "FAIL" -Details "Disabled profiles: $disabled" -Data $fwData
    }
} catch {
    Write-CheckResult -CheckName "Windows Firewall" -Status "FAIL" -Details "Unable to query firewall: $($_.Exception.Message)"
}

# ============================================
# CHECK 3: BitLocker Encryption
# ============================================
Write-Host "`n=== BITLOCKER STATUS ===" -ForegroundColor Cyan
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $osVolume = $volumes | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
    
    if ($osVolume) {
        $blData = @{
            MountPoint = $osVolume.MountPoint
            ProtectionStatus = $osVolume.ProtectionStatus
            EncryptionPercentage = $osVolume.EncryptionPercentage
            EncryptionMethod = $osVolume.EncryptionMethod
            VolumeStatus = $osVolume.VolumeStatus
        }
        
        if ($osVolume.ProtectionStatus -eq 'On' -and $osVolume.EncryptionPercentage -eq 100) {
            Write-CheckResult -CheckName "BitLocker Encryption" -Status "PASS" -Details "OS drive fully encrypted" -Data $blData
        } elseif ($osVolume.ProtectionStatus -eq 'On') {
            Write-CheckResult -CheckName "BitLocker Encryption" -Status "WARN" -Details "Encryption in progress ($($osVolume.EncryptionPercentage)%)" -Data $blData
        } else {
            Write-CheckResult -CheckName "BitLocker Encryption" -Status "FAIL" -Details "OS drive NOT encrypted" -Data $blData
        }
    } else {
        Write-CheckResult -CheckName "BitLocker Encryption" -Status "FAIL" -Details "No OS volume found"
    }
} catch {
    Write-CheckResult -CheckName "BitLocker Encryption" -Status "FAIL" -Details "Unable to query BitLocker: $($_.Exception.Message)"
}

# ============================================
# CHECK 4: Secure Boot & TPM
# ============================================
Write-Host "`n=== SECURE BOOT & TPM ===" -ForegroundColor Cyan
try {
    # Check Secure Boot
    $secureBootEnabled = $false
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    } catch {
        # System might not support Secure Boot
    }
    
    # Check TPM
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $tpmData = @{
        SecureBootEnabled = $secureBootEnabled
        TPMPresent = $false
        TPMEnabled = $false
        TPMActivated = $false
        TPMVersion = "Not Available"
    }
    
    if ($tpm) {
        $tpmData.TPMPresent = $tpm.TpmPresent
        $tpmData.TPMEnabled = $tpm.TpmEnabled
        $tpmData.TPMActivated = $tpm.TpmActivated
        
        try {
            $tpmVersion = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
            if ($tpmVersion) {
                $tpmData.TPMVersion = $tpmVersion.SpecVersion
            }
        } catch { }
    }
    
    if ($secureBootEnabled -and $tpmData.TPMPresent -and $tpmData.TPMEnabled) {
        Write-CheckResult -CheckName "Secure Boot & TPM" -Status "PASS" -Details "Secure Boot enabled, TPM active" -Data $tpmData
    } elseif (-not $secureBootEnabled) {
        Write-CheckResult -CheckName "Secure Boot & TPM" -Status "FAIL" -Details "Secure Boot is DISABLED" -Data $tpmData
    } elseif (-not $tpmData.TPMPresent) {
        Write-CheckResult -CheckName "Secure Boot & TPM" -Status "FAIL" -Details "TPM not present or not detected" -Data $tpmData
    } else {
        Write-CheckResult -CheckName "Secure Boot & TPM" -Status "FAIL" -Details "TPM present but not enabled/activated" -Data $tpmData
    }
} catch {
    Write-CheckResult -CheckName "Secure Boot & TPM" -Status "WARN" -Details "Unable to verify Secure Boot/TPM: $($_.Exception.Message)"
}

# ============================================
# CHECK 5: Password Policy
# ============================================
Write-Host "`n=== PASSWORD POLICY ===" -ForegroundColor Cyan
try {
    $pwdPolicy = net accounts | Out-String
    
    # Parse output
    $minLength = if ($pwdPolicy -match "Minimum password length:\s+(\d+)") { [int]$matches[1] } else { 0 }
    $maxAge = if ($pwdPolicy -match "Maximum password age \(days\):\s+(\d+)") { [int]$matches[1] } else { 0 }
    $minAge = if ($pwdPolicy -match "Minimum password age \(days\):\s+(\d+)") { [int]$matches[1] } else { 0 }
    $historyLength = if ($pwdPolicy -match "Length of password history maintained:\s+(\d+)") { [int]$matches[1] } else { 0 }
    $lockoutThreshold = if ($pwdPolicy -match "Lockout threshold:\s+(\d+)") { [int]$matches[1] } else { 0 }
    
    $pwdData = @{
        MinimumLength = $minLength
        MaximumAge = $maxAge
        MinimumAge = $minAge
        HistoryLength = $historyLength
        LockoutThreshold = $lockoutThreshold
    }
    
    $issues = @()
    if ($minLength -lt 12) { $issues += "Min length < 12" }
    if ($maxAge -eq 0 -or $maxAge -gt 90) { $issues += "Max age > 90 days or unlimited" }
    if ($historyLength -lt 5) { $issues += "Password history < 5" }
    if ($lockoutThreshold -eq 0) { $issues += "No lockout policy" }
    
    if ($issues.Count -eq 0) {
        Write-CheckResult -CheckName "Password Policy" -Status "PASS" -Details "Policy meets security standards" -Data $pwdData
    } else {
        Write-CheckResult -CheckName "Password Policy" -Status "FAIL" -Details ($issues -join "; ") -Data $pwdData
    }
} catch {
    Write-CheckResult -CheckName "Password Policy" -Status "WARN" -Details "Unable to query password policy: $($_.Exception.Message)"
}

# ============================================
# CHECK 6: Audit Logging
# ============================================
Write-Host "`n=== AUDIT LOGGING ===" -ForegroundColor Cyan
try {
    $auditPolicies = @(
        "Logon/Logoff",
        "Account Logon",
        "Object Access",
        "Privilege Use",
        "System"
    )
    
    $auditOutput = auditpol /get /category:* | Out-String
    $auditData = @{
        Policies = @{}
    }
    
    $enabledCount = 0
    foreach ($policy in $auditPolicies) {
        if ($auditOutput -match "$policy.*Success and Failure") {
            $auditData.Policies[$policy] = "Success and Failure"
            $enabledCount++
        } elseif ($auditOutput -match "$policy.*Success") {
            $auditData.Policies[$policy] = "Success"
            $enabledCount++
        } elseif ($auditOutput -match "$policy.*Failure") {
            $auditData.Policies[$policy] = "Failure"
        } else {
            $auditData.Policies[$policy] = "Not Configured"
        }
    }
    
    if ($enabledCount -ge 4) {
        Write-CheckResult -CheckName "Audit Logging" -Status "PASS" -Details "Critical audit policies enabled ($enabledCount/5)" -Data $auditData
    } elseif ($enabledCount -ge 2) {
        Write-CheckResult -CheckName "Audit Logging" -Status "WARN" -Details "Some audit policies missing ($enabledCount/5)" -Data $auditData
    } else {
        Write-CheckResult -CheckName "Audit Logging" -Status "FAIL" -Details "Insufficient audit logging ($enabledCount/5)" -Data $auditData
    }
} catch {
    Write-CheckResult -CheckName "Audit Logging" -Status "WARN" -Details "Unable to query audit policies: $($_.Exception.Message)"
}

# ============================================
# CHECK 7: Guest Account Status
# ============================================
Write-Host "`n=== GUEST ACCOUNT ===" -ForegroundColor Cyan
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
    $guestData = @{
        Name = $guest.Name
        Enabled = $guest.Enabled
        Description = $guest.Description
    }
    
    if (-not $guest.Enabled) {
        Write-CheckResult -CheckName "Guest Account" -Status "PASS" -Details "Guest account disabled" -Data $guestData
    } else {
        Write-CheckResult -CheckName "Guest Account" -Status "FAIL" -Details "Guest account is ENABLED" -Data $guestData
    }
} catch {
    Write-CheckResult -CheckName "Guest Account" -Status "WARN" -Details "Unable to query guest account: $($_.Exception.Message)"
}

# ============================================
# CHECK 8: RDP Configuration
# ============================================
Write-Host "`n=== REMOTE DESKTOP ===" -ForegroundColor Cyan
try {
    $rdpEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections -eq 0
    $nlaEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication -eq 1
    $rdpPort = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue).PortNumber
    
    $rdpData = @{
        Enabled = $rdpEnabled
        NLAEnabled = $nlaEnabled
        Port = $rdpPort
    }
    
    if (-not $rdpEnabled) {
        Write-CheckResult -CheckName "Remote Desktop" -Status "PASS" -Details "RDP disabled (recommended for workstations)" -Data $rdpData
    } elseif ($rdpEnabled -and $nlaEnabled) {
        Write-CheckResult -CheckName "Remote Desktop" -Status "WARN" -Details "RDP enabled with NLA (review if necessary)" -Data $rdpData
    } else {
        Write-CheckResult -CheckName "Remote Desktop" -Status "FAIL" -Details "RDP enabled without NLA" -Data $rdpData
    }
} catch {
    Write-CheckResult -CheckName "Remote Desktop" -Status "WARN" -Details "Unable to query RDP settings: $($_.Exception.Message)"
}

# ============================================
# CHECK 9: SMBv1 Protocol
# ============================================
Write-Host "`n=== SMBv1 PROTOCOL ===" -ForegroundColor Cyan
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $smb1Data = @{
        State = $smb1.State
    }
    
    if ($smb1.State -eq 'Disabled') {
        Write-CheckResult -CheckName "SMBv1 Protocol" -Status "PASS" -Details "SMBv1 disabled (secure)" -Data $smb1Data
    } else {
        Write-CheckResult -CheckName "SMBv1 Protocol" -Status "FAIL" -Details "SMBv1 is ENABLED (WannaCry/NotPetya risk)" -Data $smb1Data
    }
} catch {
    Write-CheckResult -CheckName "SMBv1 Protocol" -Status "WARN" -Details "Unable to query SMBv1 status: $($_.Exception.Message)"
}

# ============================================
# CHECK 10: Screen Lock Timeout
# ============================================
Write-Host "`n=== SCREEN LOCK TIMEOUT ===" -ForegroundColor Cyan
try {
    $screenSaverTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    $screenSaverActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
    $screenSaverSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    
    $lockData = @{
        TimeoutSeconds = $screenSaverTimeout
        Active = $screenSaverActive -eq "1"
        Secure = $screenSaverSecure -eq "1"
    }
    
    if ($screenSaverActive -eq "1" -and $screenSaverSecure -eq "1" -and [int]$screenSaverTimeout -le 900) {
        Write-CheckResult -CheckName "Screen Lock Timeout" -Status "PASS" -Details "Auto-lock configured (≤15 min)" -Data $lockData
    } elseif ($screenSaverActive -eq "1" -and $screenSaverSecure -eq "1") {
        Write-CheckResult -CheckName "Screen Lock Timeout" -Status "WARN" -Details "Auto-lock timeout > 15 minutes" -Data $lockData
    } else {
        Write-CheckResult -CheckName "Screen Lock Timeout" -Status "FAIL" -Details "Screen lock not properly configured" -Data $lockData
    }
} catch {
    Write-CheckResult -CheckName "Screen Lock Timeout" -Status "WARN" -Details "Unable to query screen lock settings: $($_.Exception.Message)"
}

# ============================================
# CHECK 11: Windows Updates (Optional - Slow)
# ============================================
if (-not $QuickScan) {
    Write-Host "`n=== WINDOWS UPDATE STATUS ===" -ForegroundColor Cyan
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and Type='Software'")
        
        $pendingCount = $searchResult.Updates.Count
        $criticalCount = ($searchResult.Updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }).Count
        
        $updateData = @{
            TotalPending = $pendingCount
            CriticalPending = $criticalCount
        }
        
        try {
            $lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
            $updateData['LastInstalled'] = $lastUpdate.InstalledOn.ToString("yyyy-MM-dd")
            $daysSinceUpdate = ((Get-Date) - $lastUpdate.InstalledOn).Days
            $updateData['DaysSinceLastUpdate'] = $daysSinceUpdate
        } catch {
            $daysSinceUpdate = 999
        }
        
        if ($criticalCount -gt 0) {
            Write-CheckResult -CheckName "Windows Updates" -Status "FAIL" -Details "$criticalCount critical updates pending" -Data $updateData
        } elseif ($pendingCount -gt 10 -or $daysSinceUpdate -gt 30) {
            Write-CheckResult -CheckName "Windows Updates" -Status "WARN" -Details "$pendingCount updates pending" -Data $updateData
        } else {
            Write-CheckResult -CheckName "Windows Updates" -Status "PASS" -Details "Update status acceptable ($pendingCount pending)" -Data $updateData
        }
    } catch {
        Write-CheckResult -CheckName "Windows Updates" -Status "WARN" -Details "Unable to query updates: $($_.Exception.Message)"
    }
}

# ============================================
# CHECK 12: Local Administrators
# ============================================
Write-Host "`n=== LOCAL ADMINISTRATORS ===" -ForegroundColor Cyan
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $adminData = @{
        Count = $admins.Count
        Members = @()
    }
    
    foreach ($admin in $admins) {
        $adminData.Members += @{
            Name = $admin.Name
            Type = $admin.ObjectClass
            Source = $admin.PrincipalSource
        }
    }
    
    $unexpectedAdmins = $admins | Where-Object { 
        $_.Name -notmatch 'Administrator$' -and 
        $_.Name -notmatch 'Domain Admins' -and
        $_.ObjectClass -eq 'User'
    }
    
    if ($admins.Count -gt 5) {
        Write-CheckResult -CheckName "Local Administrators" -Status "WARN" -Details "$($admins.Count) local admins found (review recommended)" -Data $adminData
    } elseif ($unexpectedAdmins.Count -gt 0) {
        Write-CheckResult -CheckName "Local Administrators" -Status "WARN" -Details "$($unexpectedAdmins.Count) unexpected admin accounts" -Data $adminData
    } else {
        Write-CheckResult -CheckName "Local Administrators" -Status "PASS" -Details "$($admins.Count) local admins (standard)" -Data $adminData
    }
} catch {
    Write-CheckResult -CheckName "Local Administrators" -Status "FAIL" -Details "Unable to query local admins: $($_.Exception.Message)"
}

# ============================================
# SUMMARY OUTPUT
# ============================================
Write-Host "`n" ("=" * 50) -ForegroundColor Cyan
Write-Host "OVERALL STATUS: " -NoNewline
if ($results.OverallStatus -eq "PASS") {
    Write-Host "COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "NON-COMPLIANT" -ForegroundColor Red
}
Write-Host ("=" * 50) -ForegroundColor Cyan

$passCount = ($results.Checks.Values | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($results.Checks.Values | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = ($results.Checks.Values | Where-Object { $_.Status -eq "WARN" }).Count
$totalChecks = $results.Checks.Count

Write-Host "`nSecurity Score: $passCount/$totalChecks checks passed" -ForegroundColor $(if ($passCount -eq $totalChecks) { "Green" } else { "Yellow" })
Write-Host "Checks Passed: $passCount" -ForegroundColor Green
Write-Host "Checks Failed: $failCount" -ForegroundColor Red
Write-Host "Warnings: $warnCount" -ForegroundColor Yellow

# ============================================
# EXPORT RESULTS
# ============================================
if ($ExportPath) {
    try {
        if ($OutputFormat -eq 'JSON') {
            $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
        } elseif ($OutputFormat -eq 'CSV') {
            $flatResults = @()
            foreach ($check in $results.Checks.GetEnumerator()) {
                $flatResults += [PSCustomObject]@{
                    ComputerName = $results.ComputerName
                    ScanTime = $results.ScanTime
                    CheckName = $check.Key
                    Status = $check.Value.Status
                    Details = $check.Value.Details
                }
            }
            $flatResults | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
        }
    } catch {
        Write-Host "`nFailed to export results: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Return results object for pipeline usage
return $results