<#
.SYNOPSIS
    Retrieves comprehensive mailbox status and configuration for a Microsoft 365 user.

.DESCRIPTION
    Diagnostic script for IT administrators to check mailbox health indicators including:
    - Mailbox size and quota status
    - Connected mobile devices and sync status
    - Email forwarding rules and configurations
    - Mailbox permissions and delegates
    - Common misconfigurations

    This is a READ-ONLY diagnostic tool. No changes are made to the mailbox.
    Run this script with your admin credentials - it will query the specified user's mailbox.

.PARAMETER EmailAddress
    The email address of the mailbox to check.

.PARAMETER IncludeDeviceDetails
    Include detailed mobile device information (OS, model, last sync).

.PARAMETER CheckForwardingRules
    Perform deep scan of inbox rules for forwarding configurations.

.EXAMPLE
    .\Get-UserMailboxStatus.ps1 -EmailAddress john.doe@contoso.com

.EXAMPLE
    .\Get-UserMailboxStatus.ps1 -EmailAddress jane.smith@contoso.com -IncludeDeviceDetails -CheckForwardingRules

.NOTES
    Filename    : Get-UserMailboxStatus.ps1
    Domain      : cloud-services/m365/diagnostics
    Risk Level  : LOW (Read-only diagnostic)
    
    Prerequisites:
    - Exchange Online PowerShell Module (ExchangeOnlineManagement)
    - Admin account with appropriate M365 permissions:
      * Exchange Administrator (full diagnostics)
      * Global Reader (view-only diagnostics)
      * Helpdesk Administrator (basic diagnostics)
    - Active connection to Exchange Online (script will attempt to connect)

    Typical Use Cases:
    - "Email not working" tickets
    - Mailbox full issues
    - Mobile device sync problems
    - Suspected email forwarding/compromise
    - Pre-migration mailbox assessment

    Admin Workflow:
    1. Sign in with your admin account (Connect-ExchangeOnline or let script connect)
    2. Run script and specify target user's email address
    3. Review diagnostics and copy report to ticket

    Version: 1.3
    Author: MSP Automation Team
    Last Updated: 2025-12-22
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Enter the target user's email address to diagnose")]
    [ValidateNotNullOrEmpty()]
    [Alias("Email","UPN","UserPrincipalName","TargetEmail")]
    [string]$EmailAddress,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeDeviceDetails,

    [Parameter(Mandatory=$false)]
    [switch]$CheckForwardingRules
)

#Requires -Modules ExchangeOnlineManagement

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = "Stop"
$scriptStartTime = Get-Date
$outputSections = @()

# Color coding for console output
function Write-StatusGood { 
    param([string]$Message)
    Write-Host "  [✓] $Message" -ForegroundColor Green 
}

function Write-StatusWarning { 
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Yellow 
}

function Write-StatusBad { 
    param([string]$Message)
    Write-Host "  [✗] $Message" -ForegroundColor Red 
}

function Write-StatusInfo { 
    param([string]$Message)
    Write-Host "  [i] $Message" -ForegroundColor Cyan 
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# Helper function to convert ByteQuantifiedSize to bytes
function Convert-ByteQuantifiedSizeToBytes {
    param($Size)
    
    if ($null -eq $Size) { return 0 }
    
    # Parse string representation (e.g., "1.5 GB (1,610,612,736 bytes)")
    $sizeString = $Size.ToString()
    
    # Try to extract bytes from parentheses first (most reliable)
    if ($sizeString -match '\(([0-9,]+) bytes\)') {
        return [long]($matches[1] -replace ',', '')
    }
    
    # Fallback: parse the size unit
    if ($sizeString -match '([\d\.]+)\s*(B|KB|MB|GB|TB)') {
        $value = [double]$matches[1]
        $unit = $matches[2]
        
        switch ($unit) {
            'B'  { return [long]$value }
            'KB' { return [long]($value * 1KB) }
            'MB' { return [long]($value * 1MB) }
            'GB' { return [long]($value * 1GB) }
            'TB' { return [long]($value * 1TB) }
        }
    }
    
    return 0
}

# ============================================================================
# BANNER
# ============================================================================

Write-Host "`n" -NoNewline
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "║      M365 MAILBOX DIAGNOSTIC TOOL - ADMIN MODE             ║" -ForegroundColor Cyan
Write-Host "║                                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
# ============================================================================
# STEP 1: ADMIN CONNECTION
# ============================================================================

Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host " STEP 1: ADMINISTRATOR AUTHENTICATION" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

try {
    $connectionStatus = Get-ConnectionInformation -ErrorAction SilentlyContinue
    
    if ($null -eq $connectionStatus) {
        Write-Host "  Status: Not connected to Exchange Online" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor White
        Write-Host "  │  You will now be prompted to sign in as an             │" -ForegroundColor White
        Write-Host "  │  ADMINISTRATOR with Exchange permissions               │" -ForegroundColor White
        Write-Host "  │                                                        │" -ForegroundColor White
        Write-Host "  │  Use YOUR admin account (e.g., admin@company.com)     │" -ForegroundColor White
        Write-Host "  │  NOT the user's mailbox you want to diagnose          │" -ForegroundColor White
        Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor White
        Write-Host ""
        Write-Host "  Initiating admin sign-in..." -ForegroundColor Cyan
        Write-Host ""
        
        try {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            $connectionStatus = Get-ConnectionInformation
            Write-Host ""
            Write-StatusGood "Successfully authenticated as administrator"
        }
        catch {
            Write-Host ""
            Write-StatusBad "Failed to authenticate to Exchange Online"
            Write-Host "`n  Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
            Write-Host "    • Verify you're using an admin account" -ForegroundColor Yellow
            Write-Host "    • Check that you have Exchange admin permissions" -ForegroundColor Yellow
            Write-Host "    • Ensure MFA is configured if required" -ForegroundColor Yellow
            Write-Host "    • Try manually: Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host ""
            exit 1
        }
    }
    else {
        Write-StatusGood "Already authenticated to Exchange Online"
    }
    
    # Display connection details
    Write-Host ""
    Write-Host "  Admin Connection Details:" -ForegroundColor Cyan
    Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor White
    Write-Host "  │  Signed in as: " -NoNewline -ForegroundColor White
    Write-Host "$($connectionStatus.UserPrincipalName)".PadRight(38) -NoNewline -ForegroundColor Green
    Write-Host "│" -ForegroundColor White
    Write-Host "  │  Tenant ID:    " -NoNewline -ForegroundColor White
    Write-Host "$($connectionStatus.TenantId)".Substring(0, [Math]::Min(38, $connectionStatus.TenantId.Length)).PadRight(38) -NoNewline -ForegroundColor Gray
    Write-Host "│" -ForegroundColor White
    Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor White
    Write-Host ""
    
    # Verify admin can query mailboxes
    Write-Host "  Verifying admin permissions..." -ForegroundColor Gray
    try {
        $testMailbox = Get-Mailbox -ResultSize 1 -ErrorAction Stop | Select-Object -First 1
        Write-StatusGood "Admin has mailbox query permissions"
        Write-Host ""
    }
    catch {
        Write-StatusWarning "Limited permissions detected - some diagnostics may be unavailable"
        Write-Host ""
    }
}
catch {
    Write-StatusBad "Unable to verify Exchange Online connection"
    Write-Host "`nError: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ============================================================================
# STEP 2: TARGET MAILBOX SELECTION
# ============================================================================

Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host " STEP 2: SELECT TARGET USER'S MAILBOX TO DIAGNOSE" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

# If EmailAddress wasn't provided as parameter, prompt for it
if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
    Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor White
    Write-Host "  │  Enter the EMAIL ADDRESS of the user's mailbox        │" -ForegroundColor White
    Write-Host "  │  you want to diagnose (not your admin email)          │" -ForegroundColor White
    Write-Host "  │                                                        │" -ForegroundColor White
    Write-Host "  │  Example: john.doe@company.com                         │" -ForegroundColor White
    Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor White
    Write-Host ""
    
    do {
        Write-Host "  Target user's email address: " -NoNewline -ForegroundColor Cyan
        $EmailAddress = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
            Write-Host ""
            Write-StatusWarning "Email address cannot be empty. Please try again."
            Write-Host ""
        }
        elseif ($EmailAddress -notmatch '^[^@]+@[^@]+\.[^@]+$') {
            Write-Host ""
            Write-StatusWarning "Invalid email format. Please enter a valid email address."
            Write-Host ""
            $EmailAddress = $null
        }
    } while ([string]::IsNullOrWhiteSpace($EmailAddress))
    
    Write-Host ""
}

Write-Host "  Target Mailbox Selected:" -ForegroundColor Cyan
Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor White
Write-Host "  │  " -NoNewline -ForegroundColor White
Write-Host "$EmailAddress".PadRight(54) -NoNewline -ForegroundColor Yellow
Write-Host "│" -ForegroundColor White
Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor White
Write-Host ""

# ============================================================================
# MAILBOX LOOKUP
# ============================================================================

Write-SectionHeader "Mailbox Lookup"

Write-Host "  Querying Exchange Online for mailbox: $EmailAddress" -ForegroundColor Gray

try {
    $mailbox = Get-Mailbox -Identity $EmailAddress -ErrorAction Stop
    Write-Host ""
    Write-StatusGood "Mailbox found: $($mailbox.DisplayName)"
    Write-StatusInfo "Mailbox type: $($mailbox.RecipientTypeDetails)"
    
    $outputSections += @"

========================================
MAILBOX IDENTITY
========================================
Display Name        : $($mailbox.DisplayName)
Email Address       : $($mailbox.PrimarySmtpAddress)
User Principal Name : $($mailbox.UserPrincipalName)
Mailbox Type        : $($mailbox.RecipientTypeDetails)
Exchange GUID       : $($mailbox.ExchangeGuid)
Database            : $($mailbox.Database)

"@
}
catch {
    Write-Host ""
    Write-StatusBad "Mailbox not found or inaccessible"
    Write-Host "`n  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n  Possible Reasons:" -ForegroundColor Yellow
    Write-Host "    • Email address is incorrect or typo" -ForegroundColor Yellow
    Write-Host "    • User doesn't have a mailbox (unlicensed)" -ForegroundColor Yellow
    Write-Host "    • Recently created mailbox (provisioning delay)" -ForegroundColor Yellow
    Write-Host "    • Your admin account lacks permissions for this mailbox" -ForegroundColor Yellow
    Write-Host "`n  Troubleshooting Steps:" -ForegroundColor Cyan
    Write-Host "    1. Verify email address in M365 Admin Center" -ForegroundColor Gray
    Write-Host "    2. Check if user has Exchange Online license assigned" -ForegroundColor Gray
    Write-Host "    3. Confirm your admin role has sufficient permissions" -ForegroundColor Gray
    Write-Host "    4. Wait 15-30 minutes if mailbox was just created" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

# ============================================================================
# MAILBOX SIZE AND QUOTA
# ============================================================================

Write-SectionHeader "Mailbox Size & Quota Status"

try {
    $mailboxStats = Get-MailboxStatistics -Identity $EmailAddress -ErrorAction Stop
    
    # Extract size values using our helper function
    $totalItemSizeBytes = Convert-ByteQuantifiedSizeToBytes -Size $mailboxStats.TotalItemSize
    $totalItemSizeGB = [math]::Round($totalItemSizeBytes / 1GB, 2)
    
    $deletedItemSizeBytes = Convert-ByteQuantifiedSizeToBytes -Size $mailboxStats.TotalDeletedItemSize
    $deletedItemSizeGB = [math]::Round($deletedItemSizeBytes / 1GB, 2)
    
    # Get quota settings
    $prohibitSendQuota = $mailbox.ProhibitSendQuota
    $issueWarningQuota = $mailbox.IssueWarningQuota
    
    # Determine quota status
    $quotaStatus = "HEALTHY"
    $quotaColor = "Green"
    $percentUsed = 0
    $prohibitSendGB = "Unlimited"
    
    if ($prohibitSendQuota -ne "Unlimited") {
        $prohibitSendBytes = Convert-ByteQuantifiedSizeToBytes -Size $prohibitSendQuota
        $prohibitSendGB = [math]::Round($prohibitSendBytes / 1GB, 2)
        
        if ($prohibitSendGB -gt 0) {
            $percentUsed = [math]::Round(($totalItemSizeGB / $prohibitSendGB) * 100, 1)
            
            if ($percentUsed -ge 95) {
                $quotaStatus = "CRITICAL - Near Send Limit"
                $quotaColor = "Red"
            }
            elseif ($percentUsed -ge 85) {
                $quotaStatus = "WARNING - Approaching Limit"
                $quotaColor = "Yellow"
            }
        }
    }
    
    Write-Host "  Current Size: " -NoNewline -ForegroundColor Gray
    Write-Host "$totalItemSizeGB GB" -ForegroundColor White
    Write-Host "  Item Count: " -NoNewline -ForegroundColor Gray
    Write-Host "$($mailboxStats.ItemCount) items" -ForegroundColor White
    
    if ($prohibitSendGB -ne "Unlimited") {
        Write-Host "  Quota Limit: " -NoNewline -ForegroundColor Gray
        Write-Host "$prohibitSendGB GB" -ForegroundColor White
        Write-Host "  Usage: " -NoNewline -ForegroundColor Gray
        Write-Host "$percentUsed%" -ForegroundColor $quotaColor
        Write-Host "  Status: " -NoNewline -ForegroundColor Gray
        Write-Host "$quotaStatus" -ForegroundColor $quotaColor
    }
    else {
        Write-Host "  Quota: " -NoNewline -ForegroundColor Gray
        Write-Host "Unlimited" -ForegroundColor Green
    }
    
    $quotaDisplayText = if ($prohibitSendGB -ne "Unlimited") { 
        "$prohibitSendGB GB ($percentUsed% used)" 
    } else { 
        "Unlimited" 
    }
    
    $outputSections += @"

========================================
MAILBOX SIZE & QUOTA
========================================
Total Size          : $totalItemSizeGB GB
Item Count          : $($mailboxStats.ItemCount)
Deleted Item Size   : $deletedItemSizeGB GB
Deleted Item Count  : $($mailboxStats.DeletedItemCount)

Prohibit Send Quota : $quotaDisplayText
Issue Warning Quota : $issueWarningQuota
Quota Status        : $quotaStatus

Last Logon          : $($mailboxStats.LastLogonTime)
Last Logoff         : $($mailboxStats.LastLogoffTime)

"@

    # Alert on high usage
    if ($quotaStatus -like "*CRITICAL*") {
        Write-Host ""
        Write-StatusBad "CRITICAL: Mailbox at $percentUsed% capacity"
        Write-Host "    ⚠️  USER CANNOT SEND EMAIL" -ForegroundColor Red
        Write-Host "    Action: Archive or delete items immediately" -ForegroundColor Yellow
    }
    elseif ($quotaStatus -like "*WARNING*") {
        Write-Host ""
        Write-StatusWarning "Mailbox at $percentUsed% capacity"
        Write-Host "    Recommend: Schedule cleanup or enable archive" -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-StatusGood "Mailbox size is healthy"
    }
}
catch {
    Write-StatusBad "Unable to retrieve mailbox statistics"
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Note: Admin may lack permissions for statistics" -ForegroundColor Yellow
    
    # Set defaults for use later
    $totalItemSizeGB = "Unknown"
}

# ============================================================================
# MOBILE DEVICES
# ============================================================================

Write-SectionHeader "Connected Mobile Devices"

try {
    $mobileDevices = Get-MobileDevice -Mailbox $EmailAddress -ErrorAction Stop
    
    if ($mobileDevices.Count -eq 0) {
        Write-StatusInfo "No mobile devices connected to this mailbox"
        $outputSections += @"

========================================
MOBILE DEVICES
========================================
Status: No mobile devices found
Note: User may not have configured mobile email sync

"@
    }
    else {
        Write-StatusInfo "Found $($mobileDevices.Count) device(s) connected to this mailbox"
        
        $deviceOutput = @"

========================================
MOBILE DEVICES ($($mobileDevices.Count) found)
========================================

"@
        
        $staleDeviceCount = 0
        
        foreach ($device in $mobileDevices) {
            # Get detailed stats
            $deviceStats = Get-MobileDeviceStatistics -Identity $device.Guid -ErrorAction SilentlyContinue
            
            $deviceName = if ($device.FriendlyName) { $device.FriendlyName } else { "Unnamed Device" }
            $deviceType = if ($device.DeviceType) { $device.DeviceType } else { "Unknown" }
            $deviceOS = if ($device.DeviceOS) { $device.DeviceOS } else { "Unknown" }
            $lastSync = if ($deviceStats -and $deviceStats.LastSuccessSync) { $deviceStats.LastSuccessSync } else { "Unknown" }
            $syncStatus = if ($deviceStats -and $deviceStats.Status) { $deviceStats.Status } else { "Unknown" }
            
            Write-Host "`n  Device: " -NoNewline -ForegroundColor Gray
            Write-Host "$deviceName" -ForegroundColor White
            Write-Host "    Type: $deviceType" -ForegroundColor Gray
            Write-Host "    OS: $deviceOS" -ForegroundColor Gray
            Write-Host "    Last Sync: $lastSync" -ForegroundColor Gray
            Write-Host "    Status: " -NoNewline -ForegroundColor Gray
            Write-Host "$syncStatus" -ForegroundColor $(if ($syncStatus -eq "Succeeded" -or $syncStatus -eq "DeviceOk") { "Green" } else { "Yellow" })
            
            # Check for stale syncs (more than 7 days)
            $daysSinceSync = 0
            if ($lastSync -ne "Unknown" -and $lastSync -is [DateTime]) {
                $daysSinceSync = (Get-Date) - $lastSync
                if ($daysSinceSync.TotalDays -gt 7) {
                    $staleDeviceCount++
                    Write-StatusWarning "Stale device: No sync in $([math]::Round($daysSinceSync.TotalDays)) days"
                    Write-Host "      Possible Issue: Device offline, password change, or sync error" -ForegroundColor Yellow
                }
            }
            
            $deviceOutput += @"
Device Name         : $deviceName
Device Type         : $deviceType
Device OS           : $deviceOS
Device Model        : $($device.DeviceModel)
Device ID           : $($device.DeviceId)
Last Sync           : $lastSync$(if ($daysSinceSync.TotalDays -gt 7) { " (STALE - $([math]::Round($daysSinceSync.TotalDays)) days)" })
Sync Status         : $syncStatus
First Sync          : $($deviceStats.FirstSyncTime)

"@
            
            if ($IncludeDeviceDetails -and $deviceStats) {
                $deviceOutput += @"
Device IMEI         : $($device.DeviceImei)
Device User Agent   : $($device.DeviceUserAgent)

"@
            }
        }
        
        $outputSections += $deviceOutput
        
        # Summary alert for stale devices
        if ($staleDeviceCount -gt 0) {
            Write-Host ""
            Write-StatusWarning "$staleDeviceCount device(s) haven't synced recently"
            Write-Host "    Admin Action: Verify with user or consider removing stale devices" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-StatusWarning "Unable to retrieve mobile device information"
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Note: Admin may lack mobile device permissions" -ForegroundColor Gray
    
    # Set default for summary
    $mobileDevices = @()
}

# ============================================================================
# EMAIL FORWARDING CONFIGURATION
# ============================================================================

Write-SectionHeader "Email Forwarding Configuration"

try {
    $forwardingIssues = @()
    
    # Check mailbox-level forwarding
    if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) {
        Write-StatusWarning "Forwarding is ENABLED on this mailbox"
        
        if ($mailbox.ForwardingAddress) {
            Write-Host "    Forward To (Internal): " -NoNewline -ForegroundColor Yellow
            Write-Host "$($mailbox.ForwardingAddress)" -ForegroundColor White
            $forwardingIssues += "Internal forwarding to: $($mailbox.ForwardingAddress)"
        }
        
        if ($mailbox.ForwardingSmtpAddress) {
            Write-Host "    Forward To (External): " -NoNewline -ForegroundColor Yellow
            Write-Host "$($mailbox.ForwardingSmtpAddress)" -ForegroundColor White
            $forwardingIssues += "External forwarding to: $($mailbox.ForwardingSmtpAddress)"
        }
        
        Write-Host "    Keep Copy in Mailbox: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($mailbox.DeliverToMailboxAndForward)" -ForegroundColor White
    }
    else {
        Write-StatusGood "No mailbox-level forwarding configured"
    }
    
    $outputSections += @"

========================================
FORWARDING CONFIGURATION
========================================
Mailbox Forwarding  : $(if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) { 'ENABLED' } else { 'None' })
Forward To (Int)    : $(if ($mailbox.ForwardingAddress) { $mailbox.ForwardingAddress } else { 'N/A' })
Forward To (Ext)    : $(if ($mailbox.ForwardingSmtpAddress) { $mailbox.ForwardingSmtpAddress } else { 'N/A' })
Keep Copy           : $($mailbox.DeliverToMailboxAndForward)

"@
    
    # Check inbox rules for forwarding
    if ($CheckForwardingRules) {
        Write-Host "`n  Scanning inbox rules for forwarding/redirection..." -ForegroundColor Gray
        
        $inboxRules = Get-InboxRule -Mailbox $EmailAddress -ErrorAction SilentlyContinue
        $suspiciousRules = $inboxRules | Where-Object { 
            $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage
        }
        
        if ($suspiciousRules) {
            Write-StatusWarning "Found $($suspiciousRules.Count) suspicious inbox rule(s)"
            
            $ruleOutput = "INBOX RULES WITH FORWARDING/DELETION:`n`n"
            
            foreach ($rule in $suspiciousRules) {
                Write-Host "`n    Rule: " -NoNewline -ForegroundColor Yellow
                Write-Host "$($rule.Name)" -ForegroundColor White
                Write-Host "      Enabled: $($rule.Enabled)" -ForegroundColor Gray
                
                if ($rule.ForwardTo) {
                    Write-Host "      Forwards To: $($rule.ForwardTo -join ', ')" -ForegroundColor Yellow
                    $forwardingIssues += "Inbox rule '$($rule.Name)' forwards to: $($rule.ForwardTo -join ', ')"
                }
                
                if ($rule.RedirectTo) {
                    Write-Host "      Redirects To: $($rule.RedirectTo -join ', ')" -ForegroundColor Yellow
                    $forwardingIssues += "Inbox rule '$($rule.Name)' redirects to: $($rule.RedirectTo -join ', ')"
                }
                
                if ($rule.DeleteMessage) {
                    Write-Host "      Deletes Messages: YES" -ForegroundColor Red
                    $forwardingIssues += "Inbox rule '$($rule.Name)' deletes messages"
                }
                
                $ruleOutput += @"
Rule Name           : $($rule.Name)
Enabled             : $($rule.Enabled)
Forward To          : $(if ($rule.ForwardTo) { $rule.ForwardTo -join ', ' } else { 'N/A' })
Redirect To         : $(if ($rule.RedirectTo) { $rule.RedirectTo -join ', ' } else { 'N/A' })
Delete Message      : $(if ($rule.DeleteMessage) { 'YES' } else { 'No' })
Description         : $($rule.Description)

"@
            }
            
            $outputSections += $ruleOutput
        }
        else {
            Write-StatusGood "No suspicious inbox rules found"
        }
    }
    
    # Alert on forwarding issues
    if ($forwardingIssues.Count -gt 0) {
        Write-Host ""
        Write-Host "  ════════════════════════════════════════" -ForegroundColor Red
        Write-Host "  ⚠️  SECURITY ALERT - FORWARDING DETECTED" -ForegroundColor Red
        Write-Host "  ════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Admin Action Required:" -ForegroundColor Yellow
        Write-Host "    • Verify this forwarding is authorized by user/management" -ForegroundColor Yellow
        Write-Host "    • Common indicator of compromised account" -ForegroundColor Yellow
        Write-Host "    • Check recent sign-in activity for suspicious logins" -ForegroundColor Yellow
        Write-Host "    • Consider running additional security diagnostics" -ForegroundColor Yellow
    }
}
catch {
    Write-StatusWarning "Unable to check forwarding configuration"
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ============================================================================
# MAILBOX PERMISSIONS
# ============================================================================

Write-SectionHeader "Mailbox Permissions & Delegates"

try {
    # Check mailbox permissions
    $permissions = Get-MailboxPermission -Identity $EmailAddress | 
        Where-Object { 
            $_.User -notlike "NT AUTHORITY\*" -and 
            $_.User -notlike "S-1-5-*" -and
            $_.IsInherited -eq $false
        }
    
    if ($permissions) {
        Write-StatusInfo "Found $($permissions.Count) explicitly granted permission(s)"
        
        $permOutput = @"

========================================
MAILBOX PERMISSIONS
========================================

"@
        
        foreach ($perm in $permissions) {
            Write-Host "  User: " -NoNewline -ForegroundColor Gray
            Write-Host "$($perm.User)" -ForegroundColor White
            Write-Host "    Rights: $($perm.AccessRights -join ', ')" -ForegroundColor Gray
            
            $permOutput += @"
User                : $($perm.User)
Access Rights       : $($perm.AccessRights -join ', ')
Deny               : $($perm.Deny)

"@
        }
        
        $outputSections += $permOutput
    }
    else {
        Write-StatusGood "No additional mailbox permissions found"
        Write-Host "    Only mailbox owner has access" -ForegroundColor Gray
}

# Check SendAs permissions
$sendAsPerms = Get-RecipientPermission -Identity $EmailAddress -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.Trustee -notlike "NT AUTHORITY\*" -and 
        $_.Trustee -notlike "S-1-5-*" -and
        $_.AccessRights -contains "SendAs"
    }

if ($sendAsPerms) {
    Write-Host "`n  Send-As Permissions:" -ForegroundColor Yellow
    $sendAsOutput = "`nSEND AS PERMISSIONS:`n`n"
    
    foreach ($sendAs in $sendAsPerms) {
        Write-Host "    • $($sendAs.Trustee)" -ForegroundColor Gray
        $sendAsOutput += "Trustee: $($sendAs.Trustee) - Rights: $($sendAs.AccessRights -join ', ')`n"
    }
    
    $outputSections += $sendAsOutput
    
    Write-Host "`n    Note: These users can send email as $($mailbox.DisplayName)" -ForegroundColor Yellow
}

} catch { Write-StatusWarning "Unable to retrieve mailbox permissions" Write-Host " Error: ((_.Exception.Message)" -ForegroundColor Yellow }
# ============================================================================
# COMMON MISCONFIGURATIONS CHECK
# ============================================================================

Write-SectionHeader "Common Misconfigurations Check"

$issues = @()

# Check litigation hold
if ($mailbox.LitigationHoldEnabled) {
    Write-StatusInfo "Litigation Hold is ENABLED"
    Write-Host "    Items cannot be permanently deleted (legal/compliance hold)" -ForegroundColor Gray
    $issues += "Litigation Hold enabled - emails cannot be permanently deleted"
}

# Check if mailbox is on hold
if ($mailbox.InPlaceHolds) {
    Write-StatusWarning "Mailbox has In-Place Holds"
    Write-Host "    Holds: $($mailbox.InPlaceHolds -join ', ')" -ForegroundColor Yellow
    $issues += "In-Place Holds detected: $($mailbox.InPlaceHolds -join ', ')"
}

# Check archive status
if ($mailbox.ArchiveStatus -eq "Active") {
    Write-StatusGood "Archive mailbox is active"
    Write-Host "    User can move old items to archive" -ForegroundColor Gray
}
else {
    Write-StatusInfo "No archive mailbox"
    Write-Host "    Consider enabling if user needs more storage" -ForegroundColor Gray
}

# Check if mailbox is hidden from GAL
if ($mailbox.HiddenFromAddressListsEnabled) {
    Write-StatusWarning "Mailbox is HIDDEN from Global Address List"
    Write-Host "    Others cannot find this user in address book" -ForegroundColor Yellow
    $issues += "Hidden from GAL - may cause address book issues"
}

# Check if audit is enabled
if (-not $mailbox.AuditEnabled) {
    Write-StatusWarning "Mailbox auditing is DISABLED"
    Write-Host "    No audit logs for mailbox access/changes" -ForegroundColor Yellow
    $issues += "Auditing disabled - cannot track mailbox access"
}

$outputSections += @"

========================================
ADDITIONAL CONFIGURATION
========================================
Litigation Hold     : $($mailbox.LitigationHoldEnabled)
In-Place Holds      : $(if ($mailbox.InPlaceHolds) { $mailbox.InPlaceHolds -join ', ' } else { 'None' })
Archive Status      : $($mailbox.ArchiveStatus)
Hidden from GAL     : $($mailbox.HiddenFromAddressListsEnabled)
Audit Enabled       : $($mailbox.AuditEnabled)
Mailbox Enabled     : $($mailbox.IsMailboxEnabled)

"@

if ($issues.Count -gt 0) {
    Write-Host "`n  Configuration Notes:" -ForegroundColor Yellow
    foreach ($issue in $issues) {
        Write-Host "    • $issue" -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-StatusGood "No common misconfigurations detected"
}
# ============================================================================
# SUMMARY AND OUTPUT
# ============================================================================

$scriptEndTime = Get-Date
$executionTime = ($scriptEndTime - $scriptStartTime).TotalSeconds

Write-SectionHeader "Diagnostic Summary"

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │ MAILBOX: " -NoNewline -ForegroundColor Cyan
Write-Host "$($mailbox.DisplayName)".PadRight(45) -NoNewline -ForegroundColor White
Write-Host "│" -ForegroundColor Cyan
Write-Host "  │ EMAIL:   " -NoNewline -ForegroundColor Cyan
Write-Host "$EmailAddress".PadRight(45) -NoNewline -ForegroundColor White
Write-Host "│" -ForegroundColor Cyan
Write-Host "  ├─────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "  │ Size:            " -NoNewline -ForegroundColor Cyan
Write-Host "$totalItemSizeGB GB".PadRight(39) -NoNewline -ForegroundColor White
Write-Host "│" -ForegroundColor Cyan
Write-Host "  │ Mobile Devices:  " -NoNewline -ForegroundColor Cyan
Write-Host "$($mobileDevices.Count)".PadRight(39) -NoNewline -ForegroundColor White
Write-Host "│" -ForegroundColor Cyan
Write-Host "  │ Forwarding:      " -NoNewline -ForegroundColor Cyan
$forwardingText = if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) { "YES (!!)" } else { "No" }
$forwardingColor = if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) { "Yellow" } else { "Green" }
Write-Host $forwardingText.PadRight(39) -NoNewline -ForegroundColor $forwardingColor
Write-Host "│" -ForegroundColor Cyan
Write-Host "  │ Config Issues:   " -NoNewline -ForegroundColor Cyan
$issueColor = if ($issues.Count -gt 0) { "Yellow" } else { "Green" }
Write-Host "$($issues.Count)".PadRight(39) -NoNewline -ForegroundColor $issueColor
Write-Host "│" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

# Build complete output for ticket documentation
$completeOutput = @"
========================================
MAILBOX STATUS REPORT
========================================
Target User       : $($mailbox.DisplayName)
Email Address     : $EmailAddress
Generated         : $scriptStartTime
Queried By Admin  : $env:USERNAME (connected as $($connectionStatus.UserPrincipalName))
Workstation       : $env:COMPUTERNAME
Execution Time    : $([math]::Round($executionTime, 2)) seconds

$($outputSections -join "`n")
========================================
DIAGNOSTIC COMPLETE
========================================

Admin Notes:
- Review any warnings or security alerts above
- Verify forwarding is authorized if present
- Address quota issues if critical
- Document findings in support ticket

"@

Write-Host "`n✓ Diagnostic complete" -ForegroundColor Green

# Copy to clipboard for easy pasting into tickets
try {
    $completeOutput | Set-Clipboard -ErrorAction Stop
    Write-Host "✓ Full report copied to clipboard" -ForegroundColor Green
    Write-Host "`n  Paste into your ticket documentation (Ctrl+V)" -ForegroundColor Cyan
}
catch {
    Write-StatusWarning "Could not copy to clipboard (may not be supported in this session)"
    Write-Host "`n  Report available in variable: `$completeOutput" -ForegroundColor Yellow
    Write-Host "  Run: `$completeOutput | Out-File report.txt" -ForegroundColor Gray
}

Write-Host ""