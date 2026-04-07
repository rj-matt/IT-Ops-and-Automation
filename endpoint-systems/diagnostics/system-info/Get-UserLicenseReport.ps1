#Requires -Version 5.1
<#
.SYNOPSIS
    Generates a detailed Microsoft 365 user license report for one or more users.

.DESCRIPTION
    Connects to Microsoft Graph and retrieves assigned license SKUs, per-service plan
    status, account enabled state, and last interactive sign-in timestamp for each
    target user. Output is formatted for direct copy-paste into a support ticket.

    USE CASE:
        - Investigating access issues related to licensing
        - Catching deprovisioning gaps (departed users still holding paid licenses)
        - Identifying license conflicts or disabled service plans
        - Monthly billing audits and license reconciliation
        - Verifying license assignment after onboarding/offboarding tasks

    SCOPE:
        Read-only. No changes are made to any user, license, or tenant setting.

    RISK LEVEL:
        LOW — Diagnostic only. Requires Microsoft Graph read permissions.

    PREREQUISITES:
        - Microsoft.Graph PowerShell SDK installed:
              Install-Module Microsoft.Graph -Scope CurrentUser
        - Permissions required (delegated or app):
              User.Read.All
              Organization.Read.All
              AuditLog.Read.All  (for last sign-in data; optional but recommended)
        - The running account must be able to consent to or already have those scopes.

.PARAMETER UserPrincipalName
    One or more UPNs to report on. Accepts pipeline input.
    Example: -UserPrincipalName "alice@contoso.com","bob@contoso.com"

.PARAMETER All
    Switch. When specified, pulls ALL licensed users in the tenant.
    Use with caution in large tenants — may take several minutes.

.PARAMETER IncludeServicePlans
    Switch. When specified, expands each license to show individual service plan
    states (e.g., EXCHANGE_S_ENTERPRISE: Success, TEAMS1: Disabled).
    Adds detail useful for diagnosing partial-access issues.

.PARAMETER ExportCsv
    Optional file path. When provided, results are also saved to a CSV file
    in addition to being printed to the console.
    Example: -ExportCsv "C:\Temp\LicenseReport.csv"

.EXAMPLE
    # Report on a single user
    .\Get-UserLicenseReport.ps1 -UserPrincipalName "alice@contoso.com"

.EXAMPLE
    # Report on multiple users with service plan detail
    .\Get-UserLicenseReport.ps1 -UserPrincipalName "alice@contoso.com","bob@contoso.com" -IncludeServicePlans

.EXAMPLE
    # Full tenant audit, exported to CSV
    .\Get-UserLicenseReport.ps1 -All -ExportCsv "C:\Temp\LicenseAudit.csv"

.NOTES
    Script Path:    cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1
    Version:        1.0.0
    Last Updated:   2025-07-01
    Author:         MSP Automation Engineering
    Intended For:   Tier 1–3 Technicians
#>

Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All' -UseDeviceCode

[CmdletBinding(DefaultParameterSetName = 'AllUsers')]
param (
    [Parameter(ParameterSetName = 'ByUPN', ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]]$UserPrincipalName,

    [Parameter(ParameterSetName = 'AllUsers')]
    [switch]$All,

    [switch]$IncludeServicePlans,

    [string]$ExportCsv
)

begin {
    #region --- Helpers ---

    function Write-Log {
        param([string]$Message, [ValidateSet('INFO','WARN','ERROR')]$Level = 'INFO')
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $prefix = switch ($Level) {
            'INFO'  { '[INFO ]' }
            'WARN'  { '[WARN ]' }
            'ERROR' { '[ERROR]' }
        }
        Write-Host "$timestamp $prefix $Message" -ForegroundColor $(
            switch ($Level) { 'INFO' { 'Cyan' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } }
        )
    }

    function Get-FriendlySkuName {
        param([string]$SkuPartNumber)
        # Common SKU display names. Unmapped SKUs fall back to the raw part number.
        $map = @{
            'SPE_E3'                  = 'Microsoft 365 E3'
            'SPE_E5'                  = 'Microsoft 365 E5'
            'ENTERPRISEPACK'          = 'Office 365 E3'
            'ENTERPRISEPREMIUM'       = 'Office 365 E5'
            'O365_BUSINESS_PREMIUM'   = 'Microsoft 365 Business Premium'
            'O365_BUSINESS_ESSENTIALS'= 'Microsoft 365 Business Basic'
            'SMB_BUSINESS_PREMIUM'    = 'Microsoft 365 Business Standard'
            'EXCHANGESTANDARD'        = 'Exchange Online (Plan 1)'
            'EXCHANGEENTERPRISE'      = 'Exchange Online (Plan 2)'
            'TEAMS_EXPLORATORY'       = 'Microsoft Teams Exploratory'
            'MCOSTANDARD'             = 'Skype for Business Online (Plan 2)'
            'POWER_BI_STANDARD'       = 'Power BI (free)'
            'POWER_BI_PRO'            = 'Power BI Pro'
            'PROJECTPREMIUM'          = 'Project Plan 5'
            'PROJECTESSENTIALS'       = 'Project Plan 1'
            'VISIOCLIENT'             = 'Visio Plan 2'
            'AAD_PREMIUM'             = 'Azure AD Premium P1'
            'AAD_PREMIUM_P2'          = 'Azure AD Premium P2'
            'INTUNE_A'                = 'Microsoft Intune'
            'EMS'                     = 'Enterprise Mobility + Security E3'
            'EMSPREMIUM'              = 'Enterprise Mobility + Security E5'
            'DEVELOPERPACK_E5'        = 'Microsoft 365 E5 Developer'
            'FLOW_FREE'               = 'Power Automate Free'
        }
        if ($map.ContainsKey($SkuPartNumber)) { return $map[$SkuPartNumber] }
        return $SkuPartNumber
    }

    function Format-LastSignIn {
        param($SignInDateTime)
        if ($null -eq $SignInDateTime) { return 'Never / No data (requires AuditLog.Read.All)' }
        $ago = (Get-Date) - $SignInDateTime
        $friendly = switch ($true) {
            ($ago.TotalMinutes -lt 60)  { "$([int]$ago.TotalMinutes) minutes ago" }
            ($ago.TotalHours   -lt 24)  { "$([int]$ago.TotalHours) hours ago" }
            ($ago.TotalDays    -lt 30)  { "$([int]$ago.TotalDays) days ago" }
            ($ago.TotalDays    -lt 365) { "$([int]($ago.TotalDays / 30)) months ago" }
            default                     { "$([int]($ago.TotalDays / 365)) year(s) ago" }
        }
        return "$($SignInDateTime.ToString('yyyy-MM-dd HH:mm')) UTC  ($friendly)"
    }

    #endregion

    #region --- Graph Connection ---

    # Scopes for delegated Device Code auth.
    # AuditLog.Read.All is requested separately — some tenants restrict it
    # and its absence only affects last-sign-in data, not core license output.
    $requiredScopes   = @('User.Read.All', 'Directory.Read.All')
    $auditScope       = 'AuditLog.Read.All'

    Write-Log 'Checking Microsoft Graph connection...'
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($null -eq $ctx) { throw 'Not connected.' }

        # Validate that core scopes are present
        $missing = $requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($missing) {
            throw "Missing required Graph scopes: $($missing -join ', '). Re-run the script to reconnect."
        }
        if ($auditScope -notin $ctx.Scopes) {
            Write-Log 'AuditLog.Read.All scope not present. Last sign-in data will not be available.' WARN
        }
        Write-Log "Connected to tenant: $($ctx.TenantId) as $($ctx.Account)"
    }
    catch {
        Write-Log 'Not connected to Microsoft Graph. Starting sign-in...' WARN
        Write-Log 'Using Device Code auth. A code will appear below — go to https://aka.ms/devicelogin and enter it.' INFO
        Write-Host ''
        try {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -ErrorAction Stop
            Write-Log 'Connected to Microsoft Graph successfully.'

            # Attempt AuditLog scope for last sign-in data — non-fatal if tenant restricts it
            try {
                Connect-MgGraph -Scopes $auditScope -UseDeviceCode -ErrorAction Stop
                Write-Log 'AuditLog.Read.All granted. Last sign-in data will be included.'
            }
            catch {
                Write-Log 'AuditLog.Read.All not granted — last sign-in data will be unavailable. Continuing.' WARN
            }
        }
        catch {
            Write-Log "Failed to connect to Microsoft Graph: $_" ERROR
            Write-Log 'Ensure the Microsoft.Graph module is installed: Install-Module Microsoft.Graph -Scope CurrentUser' ERROR
            exit 1
        }
    }

    #endregion

    #region --- Tenant SKU Map (for friendly names and pool sizes) ---

    Write-Log 'Loading tenant license SKU data...'
    try {
        $tenantSkus = Get-MgSubscribedSku -All -ErrorAction Stop
        $skuLookup  = @{}
        foreach ($sku in $tenantSkus) {
            $skuLookup[$sku.SkuId] = $sku
        }
        Write-Log "Found $($tenantSkus.Count) SKU(s) in tenant."
    }
    catch {
        Write-Log "Could not retrieve tenant SKU data: $_" WARN
        $skuLookup = @{}
    }

    #endregion

    # Accumulator for CSV export
    $reportRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Separator width for console output
    $separator = '=' * 72

    Write-Host ''
    Write-Host $separator -ForegroundColor DarkGray
    Write-Host '  M365 USER LICENSE REPORT' -ForegroundColor White
    Write-Host "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" -ForegroundColor Gray
    Write-Host "  Tenant    : $((Get-MgContext).TenantId)" -ForegroundColor Gray
    Write-Host $separator -ForegroundColor DarkGray
    Write-Host ''

}

process {
    # Intentionally empty — UPN collection is handled in begin{} (interactive)
    # or directly from the parameter in end{}.
}

end {
    #region --- Build User List ---

    # Collect UPNs from parameter (command-line) or from the interactive prompt
    # both of which populate $UserPrincipalName before this block runs.
    $allUpns = [System.Collections.Generic.List[string]]::new()
    if ($PSCmdlet.ParameterSetName -eq 'ByUPN' -and $null -ne $UserPrincipalName) {
        foreach ($upn in $UserPrincipalName) { $allUpns.Add($upn) }
    }

    $targetUsers = [System.Collections.Generic.List[object]]::new()

    if ($PSCmdlet.ParameterSetName -eq 'AllUsers') {
        Write-Log 'Retrieving all licensed users from tenant (this may take a moment)...'
        try {
            $fetchedUsers = Get-MgUser -All `
                -Filter 'assignedLicenses/$count ne 0' `
                -ConsistencyLevel eventual `
                -CountVariable userCount `
                -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses,SignInActivity,UserType' `
                -ErrorAction Stop
            foreach ($u in $fetchedUsers) { $targetUsers.Add($u) }
            Write-Log "Found $userCount licensed user(s)."
        }
        catch {
            Write-Log "Failed to retrieve all users: $_" ERROR
            exit 1
        }
    }
    else {
        foreach ($upn in $allUpns) {
            Write-Log "Looking up user: $upn"
            try {
                $u = Get-MgUser -UserId $upn `
                    -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses,SignInActivity,UserType' `
                    -ErrorAction Stop
                $targetUsers.Add($u)
            }
            catch {
                Write-Log "User not found or access denied: $upn — $_" ERROR
            }
        }
    }

    if ($targetUsers.Count -eq 0) {
        Write-Log 'No users to process. Exiting.' WARN
        exit 0
    }

    #endregion

    #region --- Process Each User ---

    $userIndex = 0
    foreach ($user in $targetUsers) {
        $userIndex++
        Write-Log "Processing ($userIndex/$($targetUsers.Count)): $($user.UserPrincipalName)"

        $accountState = if ($user.AccountEnabled) { 'ENABLED' } else { 'DISABLED ⚠' }
        $signInActivity = $user.SignInActivity
        $lastSignInDt   = if ($null -ne $signInActivity) { $signInActivity.LastSignInDateTime } else { $null }
        $lastSignIn     = Format-LastSignIn -SignInDateTime $lastSignInDt

        # Flags for attention items
        $warnings = [System.Collections.Generic.List[string]]::new()
        if (-not $user.AccountEnabled)            { $warnings.Add('Account is disabled but may hold active licenses') }
        if ($user.AssignedLicenses.Count -eq 0)   { $warnings.Add('No licenses assigned') }
        if ($user.UserType -eq 'Guest')            { $warnings.Add('Guest account — verify license entitlement') }

        # Check last sign-in staleness (>90 days = flag)
        $signInAge = if ($null -ne $lastSignInDt) {
            ((Get-Date) - $lastSignInDt).TotalDays
        } else { $null }
        if ($null -ne $signInAge -and $signInAge -gt 90) {
            $warnings.Add("No sign-in for $([int]$signInAge) days — possible stale/deprovisioned account")
        }

        # Console output — user block
        Write-Host $separator -ForegroundColor DarkGray
        Write-Host "  USER: $($user.DisplayName)" -ForegroundColor White
        Write-Host "  UPN          : $($user.UserPrincipalName)" -ForegroundColor Gray
        Write-Host "  Account ID   : $($user.Id)" -ForegroundColor Gray
        Write-Host "  Account State: $accountState" -ForegroundColor $(if ($user.AccountEnabled) { 'Green' } else { 'Yellow' })
        Write-Host "  User Type    : $($user.UserType)" -ForegroundColor Gray
        Write-Host "  Last Sign-In : $lastSignIn" -ForegroundColor Gray

        if ($warnings.Count -gt 0) {
            Write-Host ''
            Write-Host '  ⚠ ATTENTION:' -ForegroundColor Yellow
            foreach ($w in $warnings) { Write-Host "    - $w" -ForegroundColor Yellow }
        }

        Write-Host ''

        # --- Licenses ---
        if ($user.AssignedLicenses.Count -eq 0) {
            Write-Host '  LICENSES: None assigned' -ForegroundColor DarkYellow
        }
        else {
            Write-Host "  LICENSES ($($user.AssignedLicenses.Count)):" -ForegroundColor White

            foreach ($lic in $user.AssignedLicenses) {
                $sku        = $skuLookup[$lic.SkuId]
                $skuName    = if ($sku) { Get-FriendlySkuName -SkuPartNumber $sku.SkuPartNumber } else { $lic.SkuId }
                $skuPart    = if ($sku) { $sku.SkuPartNumber } else { 'Unknown' }
                $consumed   = if ($sku) { $sku.ConsumedUnits } else { '?' }
                $total      = if ($sku) { $sku.PrepaidUnits.Enabled } else { '?' }

                Write-Host "    [$skuName]" -ForegroundColor Cyan
                Write-Host "      SKU Part   : $skuPart" -ForegroundColor Gray
                Write-Host "      SKU ID     : $($lic.SkuId)" -ForegroundColor Gray
                Write-Host "      Pool Usage : $consumed / $total seats consumed" -ForegroundColor Gray

                if ($lic.DisabledPlans.Count -gt 0) {
                    Write-Host "      Disabled Plans ($($lic.DisabledPlans.Count)):" -ForegroundColor DarkYellow
                    foreach ($planId in $lic.DisabledPlans) {
                        $matchedPlan = $null
                        if ($null -ne $sku) {
                            $matchedPlan = $sku.ServicePlans | Where-Object { $_.ServicePlanId -eq $planId } | Select-Object -First 1
                        }
                        $planName = if ($null -ne $matchedPlan) { $matchedPlan.ServicePlanName } else { $planId }
                        Write-Host "        - $planName" -ForegroundColor DarkYellow
                    }
                }

                if ($IncludeServicePlans -and $sku) {
                    Write-Host "      Service Plans:" -ForegroundColor Gray
                    foreach ($plan in ($sku.ServicePlans | Sort-Object ServicePlanName)) {
                        $isDisabled = $lic.DisabledPlans -contains $plan.ServicePlanId
                        $planState  = if ($isDisabled) { 'Disabled' } else { $plan.ProvisioningStatus }
                        $color      = switch ($planState) {
                            'Success'   { 'Green' }
                            'Disabled'  { 'DarkGray' }
                            default     { 'Yellow' }
                        }
                        Write-Host ("        {0,-45} {1}" -f $plan.ServicePlanName, $planState) -ForegroundColor $color
                    }
                }

                Write-Host ''

                # Accumulate CSV row per license
                $reportRows.Add([PSCustomObject]@{
                    DisplayName        = $user.DisplayName
                    UserPrincipalName  = $user.UserPrincipalName
                    AccountEnabled     = $user.AccountEnabled
                    UserType           = $user.UserType
                    LastSignIn         = $lastSignInDt
                    LicenseName        = $skuName
                    SkuPartNumber      = $skuPart
                    SkuId              = $lic.SkuId
                    DisabledPlanCount  = $lic.DisabledPlans.Count
                    DisabledPlans      = ($lic.DisabledPlans -join '; ')
                    PoolConsumed       = $consumed
                    PoolTotal          = $total
                    Warnings           = ($warnings -join '; ')
                })
            }
        }

        if ($user.AssignedLicenses.Count -eq 0) {
            # Still write a row for unlicensed users when -All is used
            $reportRows.Add([PSCustomObject]@{
                DisplayName        = $user.DisplayName
                UserPrincipalName  = $user.UserPrincipalName
                AccountEnabled     = $user.AccountEnabled
                UserType           = $user.UserType
                LastSignIn         = $lastSignInDt
                LicenseName        = '(No license assigned)'
                SkuPartNumber      = ''
                SkuId              = ''
                DisabledPlanCount  = 0
                DisabledPlans      = ''
                PoolConsumed       = ''
                PoolTotal          = ''
                Warnings           = ($warnings -join '; ')
            })
        }
    }

    #endregion

    #region --- Summary ---

    $totalLicenseAssignments = ($targetUsers | Measure-Object -Property { $_.AssignedLicenses.Count } -Sum).Sum
    $disabledWithLicenses    = $targetUsers | Where-Object { -not $_.AccountEnabled -and $_.AssignedLicenses.Count -gt 0 }
    $unlicensedUsers         = $targetUsers | Where-Object { $_.AssignedLicenses.Count -eq 0 }
    $staleUsers              = $targetUsers | Where-Object {
        $sa = $_.SignInActivity
        $null -ne $sa -and $null -ne $sa.LastSignInDateTime -and
        ((Get-Date) - $sa.LastSignInDateTime).TotalDays -gt 90
    }

    Write-Host $separator -ForegroundColor DarkGray
    Write-Host '  SUMMARY' -ForegroundColor White
    Write-Host "  Users Evaluated           : $($targetUsers.Count)" -ForegroundColor Gray
    Write-Host "  Total License Assignments : $totalLicenseAssignments" -ForegroundColor Gray
    Write-Host "  Unlicensed Users          : $($unlicensedUsers.Count)" -ForegroundColor $(if ($unlicensedUsers.Count -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host "  Disabled Accts w/ Licenses: $($disabledWithLicenses.Count)" -ForegroundColor $(if ($disabledWithLicenses.Count -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host "  Stale Accounts (>90 days) : $($staleUsers.Count)" -ForegroundColor $(if ($staleUsers.Count -gt 0) { 'Yellow' } else { 'Gray' })

    if ($disabledWithLicenses.Count -gt 0) {
        Write-Host ''
        Write-Host '  ⚠ DISABLED ACCOUNTS HOLDING LICENSES (review for deprovisioning):' -ForegroundColor Yellow
        foreach ($u in $disabledWithLicenses) {
            Write-Host "    - $($u.UserPrincipalName)  ($($u.AssignedLicenses.Count) license(s))" -ForegroundColor Yellow
        }
    }

    Write-Host $separator -ForegroundColor DarkGray
    Write-Host ''

    #endregion

    #region --- CSV Export ---

    if ($ExportCsv) {
        try {
            $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportCsv)
            $reportRows | Export-Csv -Path $resolvedPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Log "Report exported to CSV: $resolvedPath"
        }
        catch {
            Write-Log "Failed to export CSV to '$ExportCsv': $_" ERROR
        }
    }

    #endregion

    Write-Log 'License report complete.'
}