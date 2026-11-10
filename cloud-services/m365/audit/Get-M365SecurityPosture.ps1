<#
.SYNOPSIS
    Read-only security check of a whole Microsoft 365 tenant for onboarding and quarterly
    reviews: MFA, security defaults / Conditional Access, legacy authentication, admin roles,
    external forwarding, guests, mailbox auditing and Secure Score.

.DESCRIPTION
    Uses Microsoft Graph with read-only delegated scopes and Exchange Online with read cmdlets
    only. Nothing in the tenant is changed. Every check that the tenant's licenses or the
    signed-in account's role do not allow is SKIPPED with the reason; the others still run.

    Checks (Target = the tenant ID)                                      Needs Entra ID P1/P2
      MFA registration     Users without a registered MFA method (Graph       yes
                           authentication methods report). Admins without
                           MFA = FAIL High; other users = WARN Medium.
      Security defaults /  Which one protects the tenant. Neither = FAIL       CA: yes
      Conditional Access   High; CA without any policy requiring MFA for
                           all users = WARN.
      Legacy auth blocked  Security defaults on, or an enabled CA policy       CA: yes
                           that blocks Exchange ActiveSync and other legacy
                           clients for all users. Report-only = WARN; not
                           blocked = WARN High.
      Legacy sign-ins      Successful sign-ins over legacy protocols (IMAP,    yes
                           POP, SMTP AUTH, ActiveSync, EWS, ...) in the last
                           -LegacySignInDays days.
      Admin roles          Who holds Global Administrator and the other        no
                           privileged roles. More than 4 or fewer than 2
                           Global Admins = WARN; admins who are also
                           licensed day-to-day mailboxes = WARN.
      Outbound forwarding  Outbound spam policies: automatic forwarding        no (Exchange)
      policy               "On" = WARN High.
      Mailbox forwarding   Mailboxes forwarding to an address outside the      no (Exchange)
                           tenant's domains = WARN High.
      Forwarding rules     Enabled inbox rules that forward or redirect        no (Exchange)
                           outside the tenant = WARN High (skip with
                           -SkipInboxRules in very large tenants).
      Guest users          Count; guests without a sign-in for               last sign-in: yes
                           -InactiveGuestDays (default 90) = WARN Low.
      Mailbox auditing     Organization-wide mailbox auditing off = FAIL.      no (Exchange)
      Secure Score         Current score and the top improvement actions.     no
      Entra ID P1/P2       One summary line: which of the checks above could
                           run in this tenant.

    Sign-in: uses existing Microsoft Graph and Exchange Online connections when there are any.
    Otherwise it signs in (browser, or -DeviceCode) to Graph with only these scopes:
      User.Read.All                  guests and admins' licenses and last sign-in
      AuditLog.Read.All              MFA registration report and sign-in logs
      Policy.Read.All                security defaults and Conditional Access policies
      RoleManagement.Read.Directory  admin role members
      SecurityEvents.Read.All        Secure Score and its improvement actions
    The Graph token is kept for this PowerShell process only (-ContextScope Process). Exchange
    Online loads only the read cmdlets this script calls (Connect-ExchangeOnline -CommandName);
    Exchange has no read-only sign-in scope, so use a Global Reader account. Both connections
    are closed at the end unless -KeepConnection is given.

    FIRST SIGN-IN = TENANT-WIDE ADMIN CONSENT. The first time these scopes are used in a
    tenant, Microsoft asks an administrator to consent "on behalf of your organization" for
    Microsoft's own "Microsoft Graph Command Line Tools" app. That consent covers the whole
    tenant and stays until an admin removes it: anyone in the tenant who signs in to that app
    can then use these read scopes, within the limits of their own role. In a client's tenant,
    get the client's approval before consenting and note it in the ticket (who approved,
    when, which scopes). To remove it later: Entra admin center > Enterprise applications >
    Microsoft Graph Command Line Tools > Permissions (or delete the app's service principal).

.PARAMETER InactiveGuestDays
    Guests without a sign-in for this many days are flagged (30-365, default 90).

.PARAMETER LegacySignInDays
    How many days of sign-in logs to search for legacy-protocol sign-ins (1-30, default 7).

.PARAMETER TopActions
    How many Secure Score improvement actions to list (1-20, default 5).

.PARAMETER SkipExchange
    Graph checks only: no Exchange Online connection (forwarding and auditing are SKIPPED).

.PARAMETER SkipInboxRules
    Do not read every mailbox's inbox rules (slow in tenants with thousands of mailboxes).

.PARAMETER DeviceCode
    Sign in with a device code (works over SSH and on computers without a browser).

.PARAMETER KeepConnection
    Leave the Graph and Exchange Online connections open at the end.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with MfaGaps, ConditionalAccess,
    LegacySignIns, Admins, ExternalForwarding, Guests and SecureScoreActions tables.

.EXAMPLE
    pwsh -File .\Get-M365SecurityPosture.ps1 -OutputPath ~/Desktop/Contoso-M365

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-M365SecurityPosture.ps1 -DeviceCode -SkipInboxRules

.NOTES
    Purpose       : "How well is this tenant protected?" in one read-only run.
    Use Case      : Client onboarding, quarterly security reviews, after a suspected compromise.
    Scope         : The signed-in admin's Microsoft 365 tenant, read through Microsoft Graph and
                    Exchange Online. Nothing on this computer is read or changed.
    Risk Level    : Read-Only -- read-only Graph scopes, Get- cmdlets only.
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 on Windows; PowerShell 7 on macOS and
                    Linux | Modules: Microsoft.Graph (Authentication, Reports, Identity.SignIns,
                    Identity.DirectoryManagement, Users, Security) and ExchangeOnlineManagement
                    (Install-Module Microsoft.Graph, ExchangeOnlineManagement -Scope CurrentUser)
                    | Account: Global Reader (covers every check). An admin must consent to the
                    five Graph scopes once per tenant (see above).
    Version       : 1.0.0
    Limitations   : Role holders are read from active assignments; PIM-eligible assignments are
                    not listed. MFA registration counts every member account in the report,
                    including disabled ones. Sign-in logs and reports can lag by hours. Secure
                    Score is the last daily snapshot.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [int]$InactiveGuestDays = 90,
    [int]$LegacySignInDays = 7,
    [int]$TopActions = 5,
    [switch]$SkipExchange,
    [switch]$SkipInboxRules,
    [switch]$DeviceCode,
    [switch]$KeepConnection,
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core,Change
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Change | SHA256: b7ec528772c2c6727e3b8daae63d862d65b946fd3324035f7fa7c3741d3b0f52
#region MSPHelper:Core
# --- Run state ---------------------------------------------------------------------------
# One toolkit script = one "run": one log file, one findings list, one optional export.
$script:MSPRun = $null
$script:MSPSchemaVersion = '2.0'
$script:MSPStatusOrder = @('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR')
$script:MSPSeverityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

function Get-MSPPlatform {
    <# 'Windows', 'macOS' or 'Linux'. Windows PowerShell 5.1 has no $IsWindows; its edition is 'Desktop'. #>
    if ($PSVersionTable.PSEdition -ne 'Core') { return 'Windows' }
    if (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue) { return 'Windows' }
    if (Get-Variable -Name IsMacOS -ValueOnly -ErrorAction SilentlyContinue) { return 'macOS' }
    return 'Linux'
}

function Get-MSPOSVersion {
    <# Short OS description, matching what the bash helper reports ("macOS 15.1", PRETTY_NAME on Linux). #>
    param([string]$Platform = (Get-MSPPlatform))
    try {
        if ($Platform -eq 'Windows') {
            $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $build = [int]$cv.CurrentBuildNumber
            # ProductName still says "Windows 10" on Windows 11; the build number decides.
            $name = [string]$cv.ProductName
            if ($build -ge 22000) { $name = $name -replace 'Windows 10', 'Windows 11' }
            $release = [string]$cv.DisplayVersion
            if (-not $release) { $release = [string]$cv.ReleaseId }
            return (('{0} {1} (build {2}.{3})' -f $name, $release, $build, $cv.UBR) -replace '\s+', ' ')
        }
        if ($Platform -eq 'macOS') {
            return ('macOS {0}' -f ([string](& sw_vers -productVersion 2>$null)).Trim())
        }
        $line = Get-Content -LiteralPath '/etc/os-release' -ErrorAction Stop | Where-Object { $_ -like 'PRETTY_NAME=*' } | Select-Object -First 1
        if ($line) { return ($line -replace '^PRETTY_NAME=', '').Trim('"') }
    }
    catch {
        Write-Verbose ('OS version lookup failed: {0}' -f $_.Exception.Message)
    }
    return $Platform
}

function Get-MSPLogFolder {
    <# Windows: %TEMP%\MSP-Toolkit. macOS/Linux: ${TMPDIR:-/tmp}/msp-toolkit (same folder the bash scripts use). #>
    if ((Get-MSPPlatform) -eq 'Windows') { return (Join-Path -Path $env:TEMP -ChildPath 'MSP-Toolkit') }
    $base = $env:TMPDIR
    if (-not $base) { $base = '/tmp' }
    return (Join-Path -Path $base -ChildPath 'msp-toolkit')
}

function Test-MSPIsAdmin {
    <# True when elevated: "Run as administrator" on Windows, root (sudo) on macOS/Linux. #>
    try {
        if ((Get-MSPPlatform) -ne 'Windows') { return ([string](& id -u) -eq '0') }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        # If the OS cannot tell us, assume not elevated: admin-only checks are SKIPPED, nothing breaks.
        return $false
    }
}

function Get-MSPAdminTerm {
    <# The word technicians see for elevation on this platform. #>
    if ((Get-MSPPlatform) -eq 'Windows') { return 'administrator' }
    return 'root (sudo)'
}

function Write-MSPLog {
    <# Appends one line to the run log. Never throws: a full or locked disk must not stop a diagnostic. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    if (-not $script:MSPRun -or -not $script:MSPRun.LogPath -or $script:MSPRun.LogFailed) { return }
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        Add-Content -LiteralPath $script:MSPRun.LogPath -Value $line -Encoding UTF8 -ErrorAction Stop -WhatIf:$false
    }
    catch {
        # Stop retrying after the first failure; the console output is still complete.
        $script:MSPRun.LogFailed = $true
    }
}

function Format-MSPParameter {
    <# Turns a parameter dictionary into "Name=Value; Name=Value" for the log. #>
    param([System.Collections.IDictionary]$Parameters)
    if (-not $Parameters -or $Parameters.Count -eq 0) { return '(none)' }
    $parts = foreach ($key in $Parameters.Keys) { '{0}={1}' -f $key, $Parameters[$key] }
    return ($parts -join '; ')
}

function Initialize-MSPRun {
    <#
        Starts a run: creates the log (see Get-MSPLogFolder), records start time, host, user,
        version and parameters, and prints the banner. Call once at the top of every script.
        -CheckId is the catalog ID (A1, B2, ...), identical for the Windows, macOS and Linux
        versions of a script so reports can line their results up.
        -AdminSections names the parts that need elevation, so the banner says so up front.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$ScriptVersion,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9-]*$')][string]$CheckId,
        [Parameter(Mandatory)][ValidateSet('Read-Only', 'Safe', 'Elevated', 'Destructive')][string]$RiskLevel,
        [System.Collections.IDictionary]$Parameters = @{},
        [string]$Description = '',
        [string[]]$AdminSections = @()
    )
    $start = Get-Date
    $platform = Get-MSPPlatform
    # Short host name on every platform (macOS can report "name.local").
    $hostName = ([Environment]::MachineName -split '\.')[0]
    $logPath = $null
    try {
        $logDir = Get-MSPLogFolder
        if (-not (Test-Path -LiteralPath $logDir)) {
            $null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop -WhatIf:$false
        }
        $logPath = Join-Path -Path $logDir -ChildPath ('{0}_{1}_{2}.log' -f $ScriptName, $hostName, $start.ToString('yyyyMMdd-HHmmss'))
    }
    catch {
        $logPath = $null
    }

    # Copy parameters to plain strings so the log and JSON never hold live objects.
    $paramCopy = [ordered]@{}
    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) { $value = $value.IsPresent }
        elseif ($value -is [array]) { $value = ($value -join ', ') }
        $paramCopy[$key] = [string]$value
    }

    $user = [Environment]::UserName
    if ($platform -eq 'Windows') { $user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME }
    $shell = 'PowerShell {0}' -f $PSVersionTable.PSVersion
    if ($PSVersionTable.PSEdition -ne 'Core') { $shell = 'Windows PowerShell {0}' -f $PSVersionTable.PSVersion }

    $script:MSPRun = [pscustomobject]@{
        CheckId       = $CheckId
        ScriptName    = $ScriptName
        ScriptVersion = $ScriptVersion
        RiskLevel     = $RiskLevel
        Platform      = $platform
        OSVersion     = (Get-MSPOSVersion -Platform $platform)
        Shell         = $shell
        Host          = $hostName
        User          = $user
        IsAdmin       = (Test-MSPIsAdmin)
        StartTime     = $start
        EndTime       = $null
        Parameters    = $paramCopy
        LogPath       = $logPath
        LogFailed     = $false
        Findings      = New-Object System.Collections.Generic.List[object]
        Data          = [ordered]@{}
    }
    $run = $script:MSPRun

    Write-MSPLog -Message ('===== START {0} v{1} ({2}) =====' -f $ScriptName, $ScriptVersion, $CheckId)
    Write-MSPLog -Message ('Host={0}; User={1}; Elevated={2}; Platform={3}; OS={4}; Shell={5}; Risk={6}' -f `
            $run.Host, $run.User, $run.IsAdmin, $run.Platform, $run.OSVersion, $run.Shell, $RiskLevel)
    Write-MSPLog -Message ('Parameters: {0}' -f (Format-MSPParameter -Parameters $paramCopy))

    $adminTerm = Get-MSPAdminTerm
    $adminText = 'No'
    if ($run.IsAdmin) { $adminText = 'Yes' }
    $bar = '=' * 72
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host (' {0} v{1}   [{2}]   [Risk: {3}]' -f $ScriptName, $ScriptVersion, $CheckId, $RiskLevel) -ForegroundColor Cyan
    if ($Description) { Write-Host (' {0}' -f $Description) -ForegroundColor Gray }
    Write-Host (' Computer: {0} ({1})' -f $run.Host, $run.OSVersion) -ForegroundColor Gray
    Write-Host (' User    : {0}   Elevated ({1}): {2}' -f $run.User, $adminTerm, $adminText) -ForegroundColor Gray
    Write-Host (' Started : {0}' -f $start.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Gray
    if ($logPath) { Write-Host (' Log     : {0}' -f $logPath) -ForegroundColor Gray }
    Write-Host $bar -ForegroundColor Cyan
    if (-not $run.IsAdmin) {
        Write-Host (' Not running as {0}. Checks that need it will show SKIPPED;' -f $adminTerm) -ForegroundColor DarkGray
        Write-Host ' everything else still runs.' -ForegroundColor DarkGray
        if ($AdminSections.Count -gt 0) {
            Write-Host (' Needs {0}: {1}' -f $adminTerm, ($AdminSections -join ', ')) -ForegroundColor DarkGray
        }
        if ($platform -eq 'Windows') { Write-Host ' For full results, use "Run as administrator".' -ForegroundColor DarkGray }
    }
}

function Write-MSPSection {
    <# Prints a section heading so long output is easy to follow on a screen share. #>
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host ('--- {0} ' -f $Title).PadRight(72, '-') -ForegroundColor Cyan
    Write-MSPLog -Message ('--- {0}' -f $Title)
}

function Get-MSPStatusColor {
    param([string]$Status)
    switch ($Status) {
        'PASS' { return 'Green' }
        'WARN' { return 'Yellow' }
        'FAIL' { return 'Red' }
        'INFO' { return 'Cyan' }
        'SKIPPED' { return 'DarkGray' }
        'ERROR' { return 'Magenta' }
        default { return 'White' }
    }
}

function ConvertTo-MSPIdPart {
    <# "Remote-access tool: Kaseya" -> "Remote-access-tool-Kaseya". Must match msp_id_part in the bash helper. #>
    param([AllowEmptyString()][string]$Text)
    $part = ($Text -replace '[^A-Za-z0-9]+', '-').Trim('-')
    if (-not $part) { $part = 'General' }
    return $part
}

function Add-MSPFinding {
    <#
        Records one finding and prints it as a colored line.
        Status   = what the check found (PASS/WARN/FAIL/INFO) or why it has no answer (SKIPPED/ERROR).
        Severity = how much it matters if it is not a PASS. Drives remediation priority in reports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR')][string]$Status,
        [AllowEmptyString()][string]$Detail = '',
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [AllowEmptyString()][string]$Recommendation = '',
        [string]$Category = 'General',
        [string]$Id,
        [string]$Target,
        [System.Collections.IDictionary]$Evidence,
        [switch]$NoConsole
    )
    if (-not $script:MSPRun) { throw 'Initialize-MSPRun must be called before Add-MSPFinding.' }

    if (-not $Severity) {
        switch ($Status) {
            'FAIL' { $Severity = 'High' }
            'WARN' { $Severity = 'Medium' }
            default { $Severity = 'Info' }
        }
    }
    if (-not $Target) { $Target = $script:MSPRun.Host }
    if (-not $Id) {
        # Stable, platform-neutral ID (<CheckId>.<Category>.<Check>) so reports can line up the
        # same check across runs and across Windows/macOS/Linux. The bash helper builds it the same way.
        $Id = '{0}.{1}.{2}' -f $script:MSPRun.CheckId, (ConvertTo-MSPIdPart -Text $Category), (ConvertTo-MSPIdPart -Text $Check)
    }

    $finding = [pscustomobject]@{
        Id             = $Id
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Severity       = $Severity
        Target         = $Target
        Detail         = $Detail
        Recommendation = $Recommendation
        Evidence       = $Evidence
    }
    $script:MSPRun.Findings.Add($finding)
    Write-MSPLog -Message ('[{0}/{1}] {2} | {3} | {4}' -f $Status, $Severity, $Check, $Target, $Detail)

    if (-not $NoConsole) {
        $tag = ('[{0}]' -f $Status).PadRight(10)
        Write-Host ('  {0}' -f $tag) -ForegroundColor (Get-MSPStatusColor -Status $Status) -NoNewline
        if ($Detail) { Write-Host ('{0} - {1}' -f $Check, $Detail) }
        else { Write-Host $Check }
        if ($Recommendation -and $Status -in @('WARN', 'FAIL')) {
            Write-Host ('            -> {0}' -f $Recommendation) -ForegroundColor DarkGray
        }
    }
}

function ConvertTo-MSPFriendlyError {
    <# Turns an exception into one plain-English sentence a Tier 1 tech can paste into a ticket. #>
    param([Parameter(Mandatory)]$ErrorRecord)
    $exception = $ErrorRecord.Exception
    # .NET method errors wrap the useful exception one level down.
    if ($exception -is [System.Management.Automation.MethodInvocationException] -and $exception.InnerException) {
        $exception = $exception.InnerException
    }
    $message = $exception.Message
    $os = 'Windows'
    if ((Get-MSPPlatform) -ne 'Windows') { $os = 'The operating system' }
    if ($exception -is [System.UnauthorizedAccessException] -or $message -match 'Access is denied|access denied|Unauthorized|Permission denied') {
        return ('{0} denied access to this information for the current account. Running as {1} may allow it.' -f $os, (Get-MSPAdminTerm))
    }
    if ($exception -is [System.Management.Automation.CommandNotFoundException]) {
        return ('A command this check needs ({0}) is not available on this computer. This is normal on some editions or versions.' -f $ErrorRecord.CategoryInfo.TargetName)
    }
    if ($message -match 'Invalid namespace|Invalid class|Not supported|not supported') {
        return 'This component is not present on this computer (common on Windows Server or older/limited editions).'
    }
    if ($message -match 'timed out|timeout') {
        return 'The check took too long to answer and was stopped.'
    }
    if ($exception -is [System.Runtime.InteropServices.COMException]) {
        return ('A Windows component did not respond (error 0x{0:X8}). {1}' -f $exception.HResult, $message.Trim())
    }
    return ('The check could not complete: {0}' -f $message.Trim())
}

function Test-MSPParameterRange {
    <#
        Checks number parameters against their allowed ranges. Scripts do this in the body instead
        of with [ValidateRange], so a wrong value gets a plain-English Setup finding, the usual
        summary, log and export, and a clean exit (the caller exits 1), on Windows PowerShell 5.1
        and PowerShell 7 alike. Only values given on the command line are checked (defaults are
        always in range). Returns $true when every value is in range.
        Example: Test-MSPParameterRange -Bound $PSBoundParameters -Range ([ordered]@{ Days = 1, 30 })
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Bound,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Range
    )
    $ok = $true
    # Keys, not .Contains(): on $PSBoundParameters .Contains() is the key/value-pair overload.
    $given = @($Bound.Keys)
    foreach ($name in @($Range.Keys)) {
        if ($given -notcontains $name) { continue }
        $min = $Range[$name][0]
        $max = $Range[$name][1]
        $value = $Bound[$name]
        if ($value -ge $min -and $value -le $max) { continue }
        $ok = $false
        Add-MSPFinding -Check 'Parameters' -Category 'Setup' -Status ERROR `
            -Detail ('-{0} must be between {1} and {2} (you gave {3}). Nothing was checked or changed.' -f $name, $min, $max, $value) `
            -Recommendation ('Run it again with -{0} set to a number from {1} to {2}, or leave it out to use the default.' -f $name, $min, $max)
    }
    return $ok
}

function Skip-MSPCheck {
    <#
        Ends the current Invoke-MSPCheck with SKIPPED instead of ERROR, for "could not be checked
        here, and that is expected" cases (for example: only a VPN adapter has a gateway).
    #>
    param(
        [Parameter(Mandatory)][string]$Reason,
        [string]$Recommendation = ''
    )
    $exception = New-Object System.OperationCanceledException($Reason)
    $marker = @{ MSPSkip = $true; Reason = $Reason; Recommendation = $Recommendation }
    $record = New-Object System.Management.Automation.ErrorRecord($exception, 'MSPCheckSkipped', [System.Management.Automation.ErrorCategory]::NotEnabled, $marker)
    throw $record
}

function Invoke-MSPCheck {
    <#
        Runs one check safely:
          - If -RequiresAdmin and not elevated: records SKIPPED with a plain-language note instead of failing.
          - Skip-MSPCheck inside the check records SKIPPED with its reason.
          - Any other error inside the check becomes an ERROR finding; the script keeps going.
        Anything the script block outputs is passed back to the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$Category = 'General',
        [switch]$RequiresAdmin,
        [string]$AdminReason = ''
    )
    if ($RequiresAdmin -and -not $script:MSPRun.IsAdmin) {
        $detail = 'Skipped: requires {0}.' -f (Get-MSPAdminTerm)
        if ($AdminReason) { $detail = '{0} {1}' -f $detail, $AdminReason }
        $how = 'Re-run with sudo to include this check.'
        if ($script:MSPRun.Platform -eq 'Windows') { $how = 'Re-run from PowerShell opened with "Run as administrator" to include this check.' }
        Add-MSPFinding -Check $Name -Category $Category -Status SKIPPED -Severity Info -Detail $detail -Recommendation $how
        return
    }
    Write-MSPLog -Message ('Check start: {0}' -f $Name)
    # Make every error inside the check catchable, including non-terminating cmdlet errors.
    $ErrorActionPreference = 'Stop'
    try {
        & $ScriptBlock
    }
    catch {
        $marker = $_.TargetObject
        if ($marker -is [System.Collections.IDictionary] -and $marker['MSPSkip']) {
            Write-MSPLog -Message ('Check skipped "{0}": {1}' -f $Name, $marker['Reason'])
            Add-MSPFinding -Check $Name -Category $Category -Status SKIPPED -Severity Info -Detail $marker['Reason'] -Recommendation $marker['Recommendation']
            return
        }
        $friendly = ConvertTo-MSPFriendlyError -ErrorRecord $_
        Write-MSPLog -Level ERROR -Message ('Check error in "{0}": {1}: {2} | {3}' -f $Name, $_.Exception.GetType().FullName, $_.Exception.Message, $_.InvocationInfo.PositionMessage)
        Add-MSPFinding -Check $Name -Category $Category -Status ERROR -Severity Info -Detail $friendly `
            -Recommendation 'This check could not run; the other results are still valid. If it matters for this ticket, re-run as administrator or escalate with the log file.'
    }
}

function Add-MSPData {
    <# Attaches a table (for example a device or software list) to the run for JSON/CSV export. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyCollection()][object[]]$Rows = @()
    )
    $script:MSPRun.Data[$Name] = @($Rows)
}

function Get-MSPSummaryCount {
    $counts = [ordered]@{}
    foreach ($status in $script:MSPStatusOrder) {
        $counts[$status] = @($script:MSPRun.Findings | Where-Object { $_.Status -eq $status }).Count
    }
    return $counts
}

function Get-MSPSortedIssue {
    <# FAIL/WARN findings, most severe first (FAIL before WARN at equal severity). #>
    $issues = @($script:MSPRun.Findings | Where-Object { $_.Status -in @('FAIL', 'WARN') })
    return @($issues | Sort-Object -Property @{ Expression = { $script:MSPSeverityRank[$_.Severity] } }, @{ Expression = { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } })
}

function Get-MSPTicketText {
    <# Plain-text block (no colors, no special characters) for pasting into a ticket. #>
    param([int]$MaxIssueLines = 40)
    $run = $script:MSPRun
    $end = $run.EndTime
    if (-not $end) { $end = Get-Date }
    $duration = [int]($end - $run.StartTime).TotalSeconds
    $counts = Get-MSPSummaryCount
    $adminText = 'No'
    if ($run.IsAdmin) { $adminText = 'Yes' }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('[MSP Toolkit] {0} {1} v{2} | Risk: {3}' -f $run.CheckId, $run.ScriptName, $run.ScriptVersion, $run.RiskLevel))
    $lines.Add(('Computer: {0} ({1}) | User: {2} | Elevated: {3} | Run: {4} ({5}s)' -f $run.Host, $run.OSVersion, $run.User, $adminText, $run.StartTime.ToString('yyyy-MM-dd HH:mm'), $duration))
    $lines.Add(('Result: PASS {0} | WARN {1} | FAIL {2} | INFO {3} | SKIPPED {4} | ERROR {5}' -f `
                $counts['PASS'], $counts['WARN'], $counts['FAIL'], $counts['INFO'], $counts['SKIPPED'], $counts['ERROR']))

    $issues = @(Get-MSPSortedIssue)
    if ($issues.Count -gt 0) {
        $lines.Add('Issues (most severe first):')
        $shown = 0
        foreach ($f in $issues) {
            if ($shown -ge $MaxIssueLines) {
                $lines.Add(('  ... {0} more issue(s) - see the exported CSV/JSON or the log.' -f ($issues.Count - $shown)))
                break
            }
            $target = ''
            if ($f.Target -and $f.Target -ne $run.Host) { $target = ' [{0}]' -f $f.Target }
            $text = '  - [{0}/{1}] {2}{3}: {4}' -f $f.Status, $f.Severity, $f.Check, $target, $f.Detail
            if ($f.Recommendation) { $text = '{0} Action: {1}' -f $text, $f.Recommendation }
            $lines.Add($text)
            $shown++
        }
    }
    else {
        $lines.Add('Issues: none found by the checks that ran.')
    }

    $errors = @($run.Findings | Where-Object { $_.Status -eq 'ERROR' })
    if ($errors.Count -gt 0) {
        $lines.Add('Could not run (ERROR - not the same as a failed check):')
        foreach ($f in $errors) { $lines.Add(('  - {0}: {1}' -f $f.Check, $f.Detail)) }
    }
    $skipped = @($run.Findings | Where-Object { $_.Status -eq 'SKIPPED' })
    if ($skipped.Count -gt 0) {
        $lines.Add('Skipped:')
        foreach ($f in $skipped) { $lines.Add(('  - {0}: {1}' -f $f.Check, $f.Detail)) }
    }
    if ($run.LogPath -and -not $run.LogFailed) { $lines.Add(('Log: {0}' -f $run.LogPath)) }
    return ($lines -join [Environment]::NewLine)
}

function Write-MSPSummary {
    <# Prints the colored summary, the top issues, and the plain-text ticket block. #>
    $counts = Get-MSPSummaryCount
    $bar = '=' * 72
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host ' SUMMARY  ' -ForegroundColor Cyan -NoNewline
    foreach ($status in $script:MSPStatusOrder) {
        $color = 'DarkGray'
        if ($counts[$status] -gt 0) { $color = Get-MSPStatusColor -Status $status }
        Write-Host ('{0}: {1}   ' -f $status, $counts[$status]) -ForegroundColor $color -NoNewline
    }
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan

    $issues = @(Get-MSPSortedIssue)
    if ($issues.Count -gt 0) {
        Write-Host ' Most important items:' -ForegroundColor White
        foreach ($f in ($issues | Select-Object -First 10)) {
            Write-Host ('  [{0}/{1}] ' -f $f.Status, $f.Severity) -ForegroundColor (Get-MSPStatusColor -Status $f.Status) -NoNewline
            Write-Host ('{0}: {1}' -f $f.Check, $f.Detail)
        }
        if ($issues.Count -gt 10) { Write-Host ('  ... and {0} more (see ticket block below).' -f ($issues.Count - 10)) -ForegroundColor DarkGray }
    }
    else {
        Write-Host ' No WARN or FAIL items from the checks that ran.' -ForegroundColor Green
    }
    if ($counts['ERROR'] -gt 0) {
        Write-Host (' {0} check(s) could not run (ERROR). That is not a failed check - see details above.' -f $counts['ERROR']) -ForegroundColor Magenta
    }

    $ticket = Get-MSPTicketText
    Write-Host ''
    Write-Host '----- COPY FOR TICKET (plain text) ' -ForegroundColor White -NoNewline
    Write-Host ('-' * 37) -ForegroundColor White
    Write-Host $ticket
    Write-Host ('-' * 72) -ForegroundColor White
    Write-MSPLog -Message ('Ticket block:{0}{1}' -f [Environment]::NewLine, $ticket)
}

function Get-MSPResultObject {
    <# Builds the shared-schema result (see README "Output schema"). #>
    $run = $script:MSPRun
    $endTime = $run.EndTime
    if (-not $endTime) { $endTime = Get-Date }
    $findings = foreach ($f in $run.Findings) {
        [ordered]@{
            Id             = $f.Id
            Category       = $f.Category
            Check          = $f.Check
            Status         = $f.Status
            Severity       = $f.Severity
            Target         = $f.Target
            Detail         = $f.Detail
            Recommendation = $f.Recommendation
            Evidence       = $f.Evidence
        }
    }
    # Field order and names are shared with the bash helper (msp_json_result).
    return [ordered]@{
        SchemaVersion = $script:MSPSchemaVersion
        CheckId       = $run.CheckId
        ScriptName    = $run.ScriptName
        Version       = $run.ScriptVersion
        Platform      = $run.Platform
        OSVersion     = $run.OSVersion
        Shell         = $run.Shell
        Host          = $run.Host
        User          = $run.User
        IsAdmin       = $run.IsAdmin
        RiskLevel     = $run.RiskLevel
        Parameters    = $run.Parameters
        Timestamp     = (ConvertTo-MSPIsoTime -Time $run.StartTime)
        EndTime       = (ConvertTo-MSPIsoTime -Time $endTime)
        Summary       = (Get-MSPSummaryCount)
        Findings      = @($findings)
        Data          = $run.Data
    }
}

function ConvertTo-MSPIsoTime {
    <# ISO 8601 local time with offset, to the second (2026-10-16T14:05:09+02:00), as the bash helper writes it. #>
    param([Parameter(Mandatory)][datetime]$Time)
    return $Time.ToString('yyyy-MM-ddTHH:mm:sszzz')
}

function Export-MSPResult {
    <#
        Writes <Script>_<Host>_<yyyyMMdd-HHmmss>.json (full result), ..._findings.csv
        (one row per finding) and ..._<Table>.csv for each attached data table.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputPath)
    $run = $script:MSPRun
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop -WhatIf:$false
    }
    $folder = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $base = '{0}_{1}_{2}' -f $run.ScriptName, $run.Host, $run.StartTime.ToString('yyyyMMdd-HHmmss')

    $jsonPath = Join-Path -Path $folder -ChildPath ('{0}.json' -f $base)
    $json = Get-MSPResultObject | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))

    # Same columns, in the same order, as the bash helper's findings CSV.
    $csvPath = Join-Path -Path $folder -ChildPath ('{0}_findings.csv' -f $base)
    $timestamp = ConvertTo-MSPIsoTime -Time $run.StartTime
    $run.Findings | Select-Object @{ n = 'CheckId'; e = { $run.CheckId } }, @{ n = 'ScriptName'; e = { $run.ScriptName } },
    @{ n = 'Platform'; e = { $run.Platform } }, @{ n = 'Host'; e = { $run.Host } }, @{ n = 'Timestamp'; e = { $timestamp } },
    Id, Category, Check, Status, Severity, Target, Detail, Recommendation |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

    $dataPaths = @()
    foreach ($name in $run.Data.Keys) {
        $rows = @($run.Data[$name])
        if ($rows.Count -eq 0) { continue }
        $dataPath = Join-Path -Path $folder -ChildPath ('{0}_{1}.csv' -f $base, ($name -replace '[^A-Za-z0-9]+', ''))
        $rows | Export-Csv -LiteralPath $dataPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        $dataPaths += $dataPath
    }

    Write-Host ''
    Write-Host ' Results saved:' -ForegroundColor Green
    Write-Host ('   {0}' -f $jsonPath) -ForegroundColor Gray
    Write-Host ('   {0}' -f $csvPath) -ForegroundColor Gray
    foreach ($p in $dataPaths) { Write-Host ('   {0}' -f $p) -ForegroundColor Gray }
    Write-MSPLog -Message ('Exported: {0}; {1}; {2}' -f $jsonPath, $csvPath, ($dataPaths -join '; '))
    return [pscustomobject]@{ Json = $jsonPath; FindingsCsv = $csvPath; DataCsv = $dataPaths }
}

function Complete-MSPRun {
    <#
        Ends the run: prints the summary and ticket block, exports if -OutputPath was given,
        and writes the end time to the log. Findings never change the exit code; the exit
        code only says whether the script itself ran.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [switch]$PassThru
    )
    $run = $script:MSPRun
    $run.EndTime = Get-Date
    Write-MSPSummary
    if ($OutputPath) {
        try {
            $null = Export-MSPResult -OutputPath $OutputPath
        }
        catch {
            Write-Host (' Could not save results to "{0}": {1}' -f $OutputPath, $_.Exception.Message) -ForegroundColor Red
            Write-Host ' The console output and log above are still complete.' -ForegroundColor Red
            Write-MSPLog -Level ERROR -Message ('Export failed: {0}' -f $_.Exception.Message)
        }
    }
    $counts = Get-MSPSummaryCount
    $duration = [int]($run.EndTime - $run.StartTime).TotalSeconds
    Write-MSPLog -Message ('===== END {0} | duration {1}s | PASS {2} WARN {3} FAIL {4} INFO {5} SKIPPED {6} ERROR {7} =====' -f `
            $run.EndTime.ToString('yyyy-MM-dd HH:mm:ss'), $duration, $counts['PASS'], $counts['WARN'], $counts['FAIL'], $counts['INFO'], $counts['SKIPPED'], $counts['ERROR'])
    if ($run.LogPath -and -not $run.LogFailed) {
        Write-Host (' Log file: {0}' -f $run.LogPath) -ForegroundColor DarkGray
    }
    Write-Host ''
    if ($PassThru) { return (Get-MSPResultObject) }
}
#endregion MSPHelper:Core

#region MSPHelper:Change
function Test-MSPInteractive {
    <#
        True when a person can answer a prompt: a console (or ISE / VS Code) with keyboard input.
        False under RMM agents, scheduled tasks, "powershell -NonInteractive" and redirected input.
    #>
    try {
        if ([Console]::IsInputRedirected) { return $false }
    }
    catch {
        return $false
    }
    if (-not [Environment]::UserInteractive) { return $false }
    if ([Environment]::GetCommandLineArgs() -match '^-NonI') { return $false }
    return ($Host.Name -in @('ConsoleHost', 'Windows PowerShell ISE Host', 'Visual Studio Code Host'))
}

function Write-MSPChangePlan {
    <# Prints and logs the numbered list of changes before anything is changed. #>
    param(
        [Parameter(Mandatory)][string[]]$Step,
        [string]$Title = 'Planned changes'
    )
    Write-MSPSection -Title $Title
    $n = 0
    foreach ($s in $Step) {
        $n++
        Write-Host ('  {0}. {1}' -f $n, $s)
        Write-MSPLog -Message ('Plan {0}: {1}' -f $n, $s)
    }
}

function Write-MSPWhatIf {
    <#
        Prints one "What if:" line for a change a dry run would make, and logs it.
        Scripts that change state read -WhatIf into their own $dryRun flag at the very top and
        then set $WhatIfPreference = $false. Otherwise -WhatIf also reaches the helpers' log
        writes and module auto-loading, which floods the screen with "What if:" noise and
        leaves no log of the dry run.
    #>
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Action
    )
    Write-Host ('What if: {0} on "{1}".' -f $Action, $Target) -ForegroundColor DarkGray
    Write-MSPLog -Message ('What if: {0} on "{1}"' -f $Action, $Target)
}

function Confirm-MSPChange {
    <#
        Asks the technician to type YES before changes are made. Returns $true to go ahead.
          -Force                       : no question (logged and recorded as a finding).
          not interactive, no -Force   : refuses (SKIPPED finding), so an RMM job or pasted
                                         command can never make changes by accident.
        Callers skip this entirely under -WhatIf, which changes nothing.
    #>
    param(
        [Parameter(Mandatory)][string]$Question,
        [switch]$Force
    )
    if ($Force) {
        Add-MSPFinding -Check 'Confirmation' -Category 'Safety' -Status INFO -Detail 'Not asked: -Force was given.'
        return $true
    }
    if (-not (Test-MSPInteractive)) {
        Add-MSPFinding -Check 'Confirmation' -Category 'Safety' -Status SKIPPED `
            -Detail 'No changes made: this session cannot answer a confirmation prompt (non-interactive) and -Force was not given.' `
            -Recommendation 'Run it in an interactive PowerShell window, or add -Force once you are sure (use -WhatIf first to see the plan).'
        return $false
    }
    Write-Host ''
    Write-Host ('  {0}' -f $Question) -ForegroundColor Yellow
    $answer = Read-Host '  Type YES to continue (anything else cancels)'
    Write-MSPLog -Message ('Confirmation answer: "{0}"' -f $answer)
    if ($answer -ceq 'YES') { return $true }
    Add-MSPFinding -Check 'Confirmation' -Category 'Safety' -Status INFO -Detail 'Cancelled by the technician. No changes were made.'
    return $false
}
#endregion MSPHelper:Change
#endregion MSPToolkit (generated)

$ScriptVersion = '1.0.0'
Initialize-MSPRun -ScriptName 'Get-M365SecurityPosture' -ScriptVersion $ScriptVersion -CheckId 'C4' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Microsoft 365 tenant security posture: MFA, CA, legacy auth, admins, forwarding, guests, auditing, Secure Score (read-only)'
# Number ranges are checked here, not with [ValidateRange], so a wrong value gets a plain message
# and a clean exit 1 instead of a parameter-binding error.
if (-not (Test-MSPParameterRange -Bound $PSBoundParameters -Range ([ordered]@{ InactiveGuestDays = 30, 365; LegacySignInDays = 1, 30; TopActions = 1, 20 }))) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

# Windows PowerShell 5.1 or PowerShell 7 on Windows; PowerShell 7 on macOS and Linux (PowerShell 6
# is out of support and the Microsoft modules no longer test against it).
if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -lt 7) {
    Add-MSPFinding -Check 'PowerShell version' -Category 'Setup' -Status ERROR `
        -Detail ('PowerShell {0} is not supported; nothing was read.' -f $PSVersionTable.PSVersion) `
        -Recommendation 'Run it with PowerShell 7 (pwsh), or on Windows with Windows PowerShell 5.1 (powershell.exe).'
    Complete-MSPRun
    exit 1
}

$requiredScopes = @('User.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'SecurityEvents.Read.All')
# The only Exchange cmdlets the connection loads (Get-EXO* cmdlets are part of the module).
$readCmdlets = @('Get-AcceptedDomain', 'Get-HostedOutboundSpamFilterPolicy', 'Get-InboxRule', 'Get-OrganizationConfig')
$roleHint = 'Sign in with an account that has the Global Reader role.'
$p1Reason = 'This tenant has no Microsoft Entra ID P1 or P2 license, which Microsoft requires for this data (P1 is included in Microsoft 365 Business Premium, E3 and E5).'
$now = Get-Date

# Directory role template IDs (fixed across tenants). Global Administrator is checked on its own.
$globalAdminTemplate = '62e90394-69f5-4237-9190-012177145e10'
$privilegedTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
}
# clientAppUsed values of sign-ins that use legacy (basic) authentication.
$legacyClients = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'Authenticated SMTP', 'Exchange Web Services', 'MAPI Over HTTP',
    'Outlook Anywhere (RPC over HTTP)', 'Offline Address Book', 'Exchange Online PowerShell', 'Autodiscover', 'Other clients')

function Test-AccessDenied {
    <# True for "not allowed" answers (missing role, scope or consent). #>
    param($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'Authorization_RequestDenied|Insufficient privileges|Forbidden|403|Access is denied|AccessDenied|UnknownError.*permission')
}

function Test-NoPremium {
    <# True when Graph refuses because the tenant has no Entra ID P1/P2 license. #>
    param($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'NonPremium|premium license|AadPremiumLicenseRequired|does not have a SKU')
}

function Invoke-Graph {
    <# One Graph read; no P1 or a role/scope refusal becomes SKIPPED with the reason. #>
    param([scriptblock]$Call, [string]$Scope)
    if ($Scope -and $script:scopesNow -notcontains $Scope -and $script:scopesNow -notcontains 'Directory.Read.All') {
        Skip-MSPCheck -Reason ('Needs the {0} scope, which this connection does not have.' -f $Scope) `
            -Recommendation ('Disconnect-MgGraph, then run again so the script signs in with {0}.' -f ($requiredScopes -join ', '))
    }
    try { & $Call }
    catch {
        if (Test-NoPremium $_) { $script:p1Missing = $true; Skip-MSPCheck -Reason $p1Reason -Recommendation 'Check this in the Entra admin center instead, or license Entra ID P1 (Business Premium) for the tenant.' }
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason ('The signed-in account may not read this ({0}).' -f $_.Exception.Message.Split([Environment]::NewLine)[0]) -Recommendation $roleHint }
        throw
    }
}

function Invoke-Exchange {
    <# One Exchange read; a role problem becomes SKIPPED with the role to use. #>
    param([scriptblock]$Call)
    if (-not $script:exoConnected) { Skip-MSPCheck -Reason $script:exoReason -Recommendation 'Run again without -SkipExchange, with the ExchangeOnlineManagement module installed.' }
    try { & $Call }
    catch {
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason ('The signed-in account may not read this ({0}).' -f $_.Exception.Message.Split([Environment]::NewLine)[0]) -Recommendation $roleHint }
        throw
    }
}

function Get-DateValue {
    <# Newest of the given values as a DateTime, or $null. #>
    param([object[]]$Value)
    $dates = @($Value | Where-Object { $_ } | ForEach-Object { [datetime]$_ })
    if ($dates.Count -eq 0) { return $null }
    return ($dates | Sort-Object | Select-Object -Last 1)
}

# =========================================================================================
Write-MSPSection -Title 'Connections'
# =========================================================================================
$graphConnected = $false
$graphWeConnected = $false
$tenantId = ''
$scopesNow = @()
$p1Missing = $false
Invoke-MSPCheck -Name 'Graph connection' -Category 'Connection' -ScriptBlock {
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Get-MgReportAuthenticationMethodUserRegistrationDetail -ErrorAction SilentlyContinue)) {
        Skip-MSPCheck -Reason 'The Microsoft Graph PowerShell modules are not installed, so no Graph check could run.' `
            -Recommendation 'Install them once (no admin rights needed): Install-Module Microsoft.Graph -Scope CurrentUser'
    }
    $context = Get-MgContext
    if (-not $context) {
        if (-not $DeviceCode -and -not (Test-MSPInteractive)) {
            Skip-MSPCheck -Reason 'Not signed in to Microsoft Graph, and this session cannot show a sign-in window.' `
                -Recommendation ('Run from a terminal, add -DeviceCode, or run Connect-MgGraph -Scopes {0} first.' -f ($requiredScopes -join ','))
        }
        Write-Host ('  Signing in to Microsoft Graph with read-only scopes: {0}' -f ($requiredScopes -join ', ')) -ForegroundColor Cyan
        $connectArgs = @{ Scopes = $requiredScopes; NoWelcome = $true; ContextScope = 'Process'; ErrorAction = 'Stop' }
        if ($DeviceCode) { $connectArgs['UseDeviceCode'] = $true }
        Connect-MgGraph @connectArgs
        $script:graphWeConnected = $true
        $context = Get-MgContext
    }
    if (-not $context) { throw 'The sign-in did not complete.' }
    $script:graphConnected = $true
    $script:tenantId = [string]$context.TenantId
    $script:scopesNow = @($context.Scopes)
    $missing = @($requiredScopes | Where-Object { $script:scopesNow -notcontains $_ })
    $writeScopes = @($script:scopesNow | Where-Object { $_ -match 'ReadWrite|\.Write' })
    $text = 'Signed in as {0} (tenant {1}); scopes: {2}.' -f $context.Account, $context.TenantId, ($script:scopesNow -join ', ')
    if ($writeScopes.Count -gt 0) { $text += ' The connection also allows changes; this script only reads.' }
    Add-MSPFinding -Check 'Graph connection' -Category 'Connection' -Status INFO -Detail $text `
        -Evidence @{ Account = [string]$context.Account; TenantId = [string]$context.TenantId; Scopes = ($script:scopesNow -join ' '); ConnectedByScript = $script:graphWeConnected }
    if ($missing.Count -gt 0) {
        Add-MSPFinding -Check 'Graph scopes' -Category 'Connection' -Status WARN -Severity Low `
            -Detail ('The connection is missing {0}; the checks that need it are SKIPPED.' -f ($missing -join ', ')) `
            -Recommendation ('Disconnect-MgGraph, then run again so the script signs in with {0}.' -f ($requiredScopes -join ', '))
    }
}

$exoConnected = $false
$exoWeConnected = $false
$exoReason = 'Not connected to Exchange Online.'
if ($SkipExchange) {
    $exoReason = 'Not read: -SkipExchange was given.'
    Add-MSPFinding -Check 'Exchange connection' -Category 'Connection' -Status SKIPPED -Detail $exoReason
}
else {
    Invoke-MSPCheck -Name 'Exchange connection' -Category 'Connection' -ScriptBlock {
        if (-not (Get-Command -Name Get-EXOMailbox -ErrorAction SilentlyContinue)) {
            $script:exoReason = 'The ExchangeOnlineManagement module is not installed, so the Exchange checks could not run.'
            Skip-MSPCheck -Reason $script:exoReason -Recommendation 'Install it once (no admin rights needed): Install-Module ExchangeOnlineManagement -Scope CurrentUser'
        }
        $connection = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Connected' }) | Select-Object -First 1
        if (-not $connection) {
            if (-not $DeviceCode -and -not (Test-MSPInteractive)) {
                $script:exoReason = 'Not connected to Exchange Online, and this session cannot show a sign-in window.'
                Skip-MSPCheck -Reason $script:exoReason -Recommendation 'Run from a terminal, add -DeviceCode, or run Connect-ExchangeOnline first.'
            }
            Write-Host ('  Connecting to Exchange Online; loading only: Get-EXO* cmdlets, {0}' -f ($readCmdlets -join ', ')) -ForegroundColor Cyan
            $connectArgs = @{ ShowBanner = $false; CommandName = $readCmdlets; SkipLoadingFormatData = $true; ErrorAction = 'Stop' }
            if ($DeviceCode) { $connectArgs['Device'] = $true }
            Connect-ExchangeOnline @connectArgs
            $script:exoWeConnected = $true
            $connection = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Connected' }) | Select-Object -First 1
        }
        if (-not $connection) { throw 'The sign-in did not complete.' }
        $script:exoConnected = $true
        if (-not $script:tenantId) { $script:tenantId = [string]$connection.TenantID }
        Add-MSPFinding -Check 'Exchange connection' -Category 'Connection' -Status INFO `
            -Detail ('Signed in as {0} (tenant {1}).' -f $connection.UserPrincipalName, $connection.TenantID) `
            -Evidence @{ Account = [string]$connection.UserPrincipalName; TenantId = [string]$connection.TenantID; ConnectedByScript = $script:exoWeConnected }
    }
}
if (-not $graphConnected -and -not $exoConnected) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}
$graphReason = 'Not signed in to Microsoft Graph (see "Graph connection").'
function Assert-Graph { if (-not $script:graphConnected) { Skip-MSPCheck -Reason $graphReason -Recommendation 'Install the Microsoft Graph modules and run again from a terminal (or with -DeviceCode).' } }

# =========================================================================================
Write-MSPSection -Title 'Sign-in protection'
# =========================================================================================
$mfaRows = @()
$mfaByUpn = @{}
Invoke-MSPCheck -Name 'MFA registration' -Category 'Identity' -ScriptBlock {
    Assert-Graph
    $details = @(Invoke-Graph -Scope 'AuditLog.Read.All' -Call { Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop })
    foreach ($d in $details) { $script:mfaByUpn[([string]$d.UserPrincipalName).ToLowerInvariant()] = [bool]$d.IsMfaRegistered }
    $members = @($details | Where-Object { [string]$_.UserType -ne 'guest' })
    $gaps = @($members | Where-Object { -not $_.IsMfaRegistered })
    $script:mfaRows = @($gaps | ForEach-Object { [pscustomobject]@{ UserPrincipalName = [string]$_.UserPrincipalName; DisplayName = [string]$_.UserDisplayName; IsAdmin = [bool]$_.IsAdmin; MethodsRegistered = (@($_.MethodsRegistered) -join ', ') } })
    Add-MSPData -Name 'MfaGaps' -Rows $script:mfaRows
    $admins = @($gaps | Where-Object { $_.IsAdmin })
    $users = @($gaps | Where-Object { -not $_.IsAdmin })
    $evidence = @{ Members = $members.Count; WithoutMfa = $gaps.Count; AdminsWithoutMfa = $admins.Count }
    if ($admins.Count -gt 0) {
        Add-MSPFinding -Check 'Admins without MFA' -Category 'Identity' -Target $tenantId -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('{0} admin account(s) have no MFA method registered: {1}.' -f $admins.Count, ((@($admins | ForEach-Object { [string]$_.UserPrincipalName })) -join ', ')) `
            -Recommendation 'Register MFA for every admin now (Microsoft Authenticator or a passkey), or block their sign-in until they do. Admin accounts without MFA are the usual way tenants are taken over.'
    }
    else {
        Add-MSPFinding -Check 'Admins without MFA' -Category 'Identity' -Target $tenantId -Status PASS -Detail 'Every admin account has an MFA method registered.'
    }
    if ($users.Count -gt 0) {
        $names = @($users | Select-Object -First 10 | ForEach-Object { [string]$_.UserPrincipalName })
        $more = ''
        if ($users.Count -gt 10) { $more = ' and {0} more (MfaGaps table)' -f ($users.Count - 10) }
        Add-MSPFinding -Check 'Users without MFA' -Category 'Identity' -Target $tenantId -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('{0} of {1} member account(s) have no MFA method registered: {2}{3}.' -f $users.Count, $members.Count, ($names -join ', '), $more) `
            -Recommendation 'Have each user register Microsoft Authenticator (aka.ms/mfasetup). Accounts no longer used should be blocked; shared or service mailboxes should have sign-in blocked instead.'
    }
    else {
        Add-MSPFinding -Check 'Users without MFA' -Category 'Identity' -Target $tenantId -Status PASS -Detail ('All {0} member account(s) have an MFA method registered.' -f $members.Count)
    }
}

$defaultsOn = $null
$caPolicies = @()
$caRead = $false
Invoke-MSPCheck -Name 'Security defaults' -Category 'Identity' -ScriptBlock {
    Assert-Graph
    $policy = Invoke-Graph -Scope 'Policy.Read.All' -Call { Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop }
    $script:defaultsOn = [bool]$policy.IsEnabled
    Write-MSPLog -Message ('Security defaults enabled: {0}' -f $script:defaultsOn)
}
Invoke-MSPCheck -Name 'Conditional Access policies' -Category 'Identity' -ScriptBlock {
    Assert-Graph
    $script:caPolicies = @(Invoke-Graph -Scope 'Policy.Read.All' -Call { Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop })
    $script:caRead = $true
    $rows = foreach ($p in $script:caPolicies) {
        [pscustomobject]@{
            Name = [string]$p.DisplayName; State = [string]$p.State
            Users = (@($p.Conditions.Users.IncludeUsers) -join ', '); ClientApps = (@($p.Conditions.ClientAppTypes) -join ', ')
            Grant = (@($p.GrantControls.BuiltInControls) -join ', ')
        }
    }
    Add-MSPData -Name 'ConditionalAccess' -Rows @($rows)
}

function Test-AllUserScope { param($Policy) return (@($Policy.Conditions.Users.IncludeUsers) -contains 'All') }
$enabledCa = @($caPolicies | Where-Object { [string]$_.State -eq 'enabled' })
Invoke-MSPCheck -Name 'Security defaults or Conditional Access' -Category 'Identity' -ScriptBlock {
    Assert-Graph
    if ($null -eq $defaultsOn) { Skip-MSPCheck -Reason 'The security defaults setting could not be read (see "Security defaults").' -Recommendation $roleHint }
    $check = 'Security defaults or Conditional Access'
    if ($defaultsOn) {
        Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status PASS `
            -Detail 'Security defaults are on: MFA registration for everyone, MFA for admins and risky sign-ins, legacy authentication blocked.'
        return
    }
    if ($enabledCa.Count -gt 0) {
        $mfaAll = @($enabledCa | Where-Object { (Test-AllUserScope $_) -and (@($_.GrantControls.BuiltInControls) -contains 'mfa') })
        if ($mfaAll.Count -gt 0) {
            Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status PASS `
                -Detail ('Conditional Access is in use: {0} enabled policy(ies); MFA for all users by "{1}".' -f $enabledCa.Count, ((@($mfaAll | ForEach-Object { [string]$_.DisplayName })) -join '", "'))
        }
        else {
            Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status WARN -Severity High `
                -Detail ('Conditional Access is in use ({0} enabled policy(ies)) but none requires MFA for all users.' -f $enabledCa.Count) `
                -Recommendation 'Add a Conditional Access policy requiring MFA for all users (exclude one break-glass account), first in report-only mode, then on.'
        }
        return
    }
    $why = 'no enabled Conditional Access policy'
    if (-not $caRead) {
        if (-not $p1Missing) { Skip-MSPCheck -Reason 'Security defaults are off and the Conditional Access policies could not be read (see "Conditional Access policies").' -Recommendation $roleHint }
        $why = 'Conditional Access is not available (it needs Entra ID P1)'
    }
    Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status FAIL -Severity High `
        -Detail ('Neither is protecting the tenant: security defaults are off and {0}. Nothing enforces MFA or blocks legacy sign-ins.' -f $why) `
        -Recommendation 'Without Entra ID P1: turn security defaults on (Entra admin center > Overview > Properties > Manage security defaults). With P1: create Conditional Access policies for MFA and blocking legacy authentication.'
}

Invoke-MSPCheck -Name 'Legacy authentication blocked' -Category 'Identity' -ScriptBlock {
    Assert-Graph
    $check = 'Legacy authentication blocked'
    if ($defaultsOn) {
        Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status PASS -Detail 'Blocked by security defaults.'
        return
    }
    $legacyTypes = { param($p) $t = @($p.Conditions.ClientAppTypes); ($t -contains 'all') -or (($t -contains 'exchangeActiveSync') -and ($t -contains 'other')) }
    $blocking = @($caPolicies | Where-Object { (@($_.GrantControls.BuiltInControls) -contains 'block') -and (Test-AllUserScope $_) -and (& $legacyTypes $_) })
    $on = @($blocking | Where-Object { [string]$_.State -eq 'enabled' })
    $reportOnly = @($blocking | Where-Object { [string]$_.State -eq 'enabledForReportingButNotEnforced' })
    if ($on.Count -gt 0) {
        Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status PASS -Detail ('Blocked by Conditional Access: "{0}".' -f ((@($on | ForEach-Object { [string]$_.DisplayName })) -join '", "'))
    }
    elseif ($reportOnly.Count -gt 0) {
        Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status WARN -Severity Medium `
            -Detail ('A blocking policy exists but only in report-only mode: "{0}". Legacy sign-ins still work.' -f ((@($reportOnly | ForEach-Object { [string]$_.DisplayName })) -join '", "')) `
            -Recommendation 'Check the policy''s report-only results (sign-in logs), then switch it to On.'
    }
    elseif (-not $caRead) {
        if (-not $p1Missing) { Skip-MSPCheck -Reason 'Security defaults are off and the Conditional Access policies could not be read (see "Conditional Access policies").' -Recommendation $roleHint }
        Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status WARN -Severity High `
            -Detail 'Not blocked: security defaults are off and Conditional Access is not available (it needs Entra ID P1).' `
            -Recommendation 'Turn security defaults on, or with Entra ID P1 add a Conditional Access policy that blocks legacy authentication for all users.'
    }
    else {
        Add-MSPFinding -Check $check -Category 'Identity' -Target $tenantId -Status WARN -Severity High `
            -Detail 'Not blocked: security defaults are off and no enabled Conditional Access policy blocks legacy clients for all users.' `
            -Recommendation 'Add a Conditional Access policy: all users, client apps "Exchange ActiveSync clients" and "Other clients", grant Block. Report-only first to see who still uses them.'
    }
}

Invoke-MSPCheck -Name 'Legacy sign-ins' -Category 'Identity' -ScriptBlock {
    Assert-Graph
    $since = $now.ToUniversalTime().AddDays(-$LegacySignInDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($app in $legacyClients) {
        $filter = "createdDateTime ge {0} and clientAppUsed eq '{1}'" -f $since, $app
        $rows = @(Invoke-Graph -Scope 'AuditLog.Read.All' -Call { Get-MgAuditLogSignIn -Filter $filter -Top 200 -ErrorAction Stop })
        foreach ($s in $rows) {
            $found.Add([pscustomobject]@{
                    Time = ([datetime]$s.CreatedDateTime).ToString('yyyy-MM-dd HH:mm'); UserPrincipalName = [string]$s.UserPrincipalName; ClientApp = [string]$s.ClientAppUsed
                    Succeeded = ([int]$s.Status.ErrorCode -eq 0); Application = [string]$s.AppDisplayName
                })
        }
    }
    Add-MSPData -Name 'LegacySignIns' -Rows $found.ToArray()
    $ok = @($found | Where-Object { $_.Succeeded })
    if ($ok.Count -gt 0) {
        $byUser = @($ok | Group-Object UserPrincipalName | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, ((@($_.Group | ForEach-Object { $_.ClientApp } | Sort-Object -Unique)) -join ', ') })
        Add-MSPFinding -Check 'Legacy sign-ins' -Category 'Identity' -Target $tenantId -Status WARN -Severity High `
            -Evidence @{ Days = $LegacySignInDays; Successful = $ok.Count; Failed = ($found.Count - $ok.Count) } `
            -Detail ('{0} successful legacy sign-in(s) in the last {1} day(s): {2}.' -f $ok.Count, $LegacySignInDays, ($byUser -join '; ')) `
            -Recommendation 'Move these users and devices to modern authentication (current Outlook, mail apps that use OAuth), then block legacy authentication. Unknown ones: treat as an attack and reset the password.'
    }
    elseif ($found.Count -gt 0) {
        Add-MSPFinding -Check 'Legacy sign-ins' -Category 'Identity' -Target $tenantId -Status INFO `
            -Detail ('No successful legacy sign-in in {0} day(s); {1} attempt(s) failed (often password-spray attempts that the block stopped).' -f $LegacySignInDays, $found.Count)
    }
    else {
        Add-MSPFinding -Check 'Legacy sign-ins' -Category 'Identity' -Target $tenantId -Status PASS -Detail ('No legacy sign-in in the last {0} day(s).' -f $LegacySignInDays)
    }
}

# =========================================================================================
Write-MSPSection -Title 'Admin roles'
# =========================================================================================
Invoke-MSPCheck -Name 'Admin roles' -Category 'Admins' -ScriptBlock {
    Assert-Graph
    $roles = @(Invoke-Graph -Scope 'RoleManagement.Read.Directory' -Call { Get-MgDirectoryRole -All -ErrorAction Stop } | Where-Object { $privilegedTemplates.ContainsKey([string]$_.RoleTemplateId) })
    $rows = New-Object System.Collections.Generic.List[object]
    $userCache = @{}
    foreach ($role in $roles) {
        $roleName = $privilegedTemplates[[string]$role.RoleTemplateId]
        foreach ($m in @(Invoke-Graph -Scope 'RoleManagement.Read.Directory' -Call { Get-MgDirectoryRoleMember -DirectoryRoleId ([string]$role.Id) -All -ErrorAction Stop })) {
            $props = $m.AdditionalProperties
            $type = ([string]$props['@odata.type']) -replace '^#microsoft\.graph\.', ''
            $name = [string]$props['userPrincipalName']
            if (-not $name) { $name = [string]$props['displayName'] }
            $mailbox = ''
            if ($type -eq 'user') {
                if (-not $userCache.ContainsKey([string]$m.Id)) {
                    # Unknown ('') when the account's licenses cannot be read; the role list still counts.
                    $userCache[[string]$m.Id] = ''
                    try {
                        $u = Get-MgUser -UserId ([string]$m.Id) -Property 'id', 'userPrincipalName', 'accountEnabled', 'assignedPlans' -ErrorAction Stop
                        $userCache[[string]$m.Id] = @($u.AssignedPlans | Where-Object { [string]$_.Service -eq 'exchange' -and [string]$_.CapabilityStatus -eq 'Enabled' }).Count -gt 0
                    }
                    catch { Write-MSPLog -Level WARN -Message ('Licenses of {0} not readable: {1}' -f $name, $_.Exception.Message) }
                }
                $mailbox = $userCache[[string]$m.Id]
            }
            $mfa = ''
            if ($mfaByUpn.ContainsKey($name.ToLowerInvariant())) { $mfa = $mfaByUpn[$name.ToLowerInvariant()] }
            $rows.Add([pscustomobject]@{ Role = $roleName; Member = $name; Type = $type; LicensedMailbox = $mailbox; MfaRegistered = $mfa })
        }
    }
    Add-MSPData -Name 'Admins' -Rows $rows.ToArray()

    $globalAdmins = @($rows | Where-Object { $_.Role -eq $privilegedTemplates[$globalAdminTemplate] -and $_.Type -eq 'user' })
    $gaNames = (@($globalAdmins | ForEach-Object { $_.Member }) -join ', ')
    $evidence = @{ GlobalAdmins = $globalAdmins.Count; PrivilegedAssignments = $rows.Count }
    if ($globalAdmins.Count -gt 4) {
        Add-MSPFinding -Check 'Global Administrators' -Category 'Admins' -Target $tenantId -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('{0} Global Administrators (more than 4): {1}.' -f $globalAdmins.Count, $gaNames) `
            -Recommendation 'Keep 2-4 Global Administrators. Move the others to the narrower role they need (Exchange, User, Helpdesk Administrator, ...).'
    }
    elseif ($globalAdmins.Count -lt 2) {
        Add-MSPFinding -Check 'Global Administrators' -Category 'Admins' -Target $tenantId -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('{0} Global Administrator(s) (fewer than 2): {1}. If that account is locked out, nobody can manage the tenant.' -f $globalAdmins.Count, $(if ($gaNames) { $gaNames } else { 'none' })) `
            -Recommendation 'Add a second Global Administrator: a cloud-only break-glass account with a long password kept offline, excluded from Conditional Access lockouts.'
    }
    else {
        Add-MSPFinding -Check 'Global Administrators' -Category 'Admins' -Target $tenantId -Status PASS -Evidence $evidence -Detail ('{0} Global Administrators: {1}.' -f $globalAdmins.Count, $gaNames)
    }
    $others = @($rows | Where-Object { $_.Role -ne $privilegedTemplates[$globalAdminTemplate] })
    if ($others.Count -gt 0) {
        Add-MSPFinding -Check 'Other privileged roles' -Category 'Admins' -Target $tenantId -Status INFO `
            -Detail ((@($others | Group-Object Role | ForEach-Object { '{0}: {1}' -f $_.Name, ((@($_.Group | ForEach-Object { $_.Member })) -join ', ') })) -join '; ')
    }
    $daily = @($rows | Where-Object { $_.LicensedMailbox -eq $true } | ForEach-Object { $_.Member } | Sort-Object -Unique)
    if ($daily.Count -gt 0) {
        Add-MSPFinding -Check 'Admins with a mailbox' -Category 'Admins' -Target $tenantId -Status WARN -Severity Medium `
            -Detail ('{0} admin account(s) also have a licensed mailbox, so they read mail and browse with admin rights: {1}.' -f $daily.Count, ($daily -join ', ')) `
            -Recommendation 'Give each admin a separate, unlicensed admin account (admin-name@tenant.onmicrosoft.com) and remove the admin role from their everyday account.'
    }
    else {
        Add-MSPFinding -Check 'Admins with a mailbox' -Category 'Admins' -Target $tenantId -Status PASS -Detail 'No admin account has a licensed mailbox.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'External forwarding'
# =========================================================================================
$domains = @()
Invoke-MSPCheck -Name 'Accepted domains' -Category 'Forwarding' -ScriptBlock {
    $script:domains = @(Invoke-Exchange { Get-AcceptedDomain -ErrorAction Stop } | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    Write-MSPLog -Message ('Accepted domains: {0}' -f ($script:domains -join ', '))
}
function Get-ExternalAddress {
    <# The addresses in TEXT whose domain is not one of the tenant's accepted domains. #>
    param([string]$Text)
    if ($domains.Count -eq 0) { return @() }
    return @([regex]::Matches($Text, '[A-Za-z0-9._%+''-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})') | Where-Object { $domains -notcontains $_.Groups[1].Value.ToLowerInvariant() } | ForEach-Object { $_.Value } | Select-Object -Unique)
}
$forwardRows = New-Object System.Collections.Generic.List[object]

Invoke-MSPCheck -Name 'Outbound forwarding policy' -Category 'Forwarding' -ScriptBlock {
    $policies = @(Invoke-Exchange { Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop })
    $open = @($policies | Where-Object { [string]$_.AutoForwardingMode -eq 'On' })
    $text = (@($policies | ForEach-Object { '{0}: {1}' -f $_.Name, $_.AutoForwardingMode }) -join '; ')
    if ($open.Count -gt 0) {
        Add-MSPFinding -Check 'Outbound forwarding policy' -Category 'Forwarding' -Target $tenantId -Status WARN -Severity High `
            -Detail ('Automatic forwarding to outside addresses is allowed by: {0} ({1}).' -f ((@($open | ForEach-Object { [string]$_.Name })) -join ', '), $text) `
            -Recommendation 'Set automatic forwarding to Off (or Automatic) in the outbound spam policy (Defender portal > Policies > Anti-spam > Outbound), and allow it only for named senders that need it.'
    }
    else {
        Add-MSPFinding -Check 'Outbound forwarding policy' -Category 'Forwarding' -Target $tenantId -Status PASS -Detail ('Automatic external forwarding is not allowed ({0}).' -f $text)
    }
}

$mailboxes = @()
Invoke-MSPCheck -Name 'Mailbox forwarding' -Category 'Forwarding' -ScriptBlock {
    $script:mailboxes = @(Invoke-Exchange { Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward -ErrorAction Stop })
    if ($domains.Count -eq 0) { Skip-MSPCheck -Reason 'The tenant''s domains could not be read, so outside addresses cannot be told apart (see "Accepted domains").' -Recommendation $roleHint }
    $external = @()
    foreach ($m in $script:mailboxes) {
        $smtp = ([string]$m.ForwardingSmtpAddress) -replace '^smtp:', ''
        if ($smtp -and @(Get-ExternalAddress -Text $smtp).Count -gt 0) {
            $external += ('{0} -> {1}' -f $m.UserPrincipalName, $smtp)
            $forwardRows.Add([pscustomobject]@{ Mailbox = [string]$m.UserPrincipalName; Kind = 'Mailbox forwarding'; Name = ''; To = $smtp; KeepsCopy = [bool]$m.DeliverToMailboxAndForward })
        }
    }
    if ($external.Count -gt 0) {
        Add-MSPFinding -Check 'Mailbox forwarding' -Category 'Forwarding' -Target $tenantId -Status WARN -Severity High `
            -Detail ('{0} mailbox(es) forward to outside addresses: {1}.' -f $external.Count, ($external -join '; ')) `
            -Recommendation 'Confirm each one with the mailbox owner. Unknown forwarding is a sign of account takeover: reset the password, sign out all sessions and remove the forwarding (run C1 Get-UserMailboxStatus.ps1 on that mailbox).'
    }
    else {
        Add-MSPFinding -Check 'Mailbox forwarding' -Category 'Forwarding' -Target $tenantId -Status PASS -Detail ('None of {0} mailbox(es) forwards outside the organization.' -f $script:mailboxes.Count)
    }
}

if ($SkipInboxRules) {
    Add-MSPFinding -Check 'Forwarding rules' -Category 'Forwarding' -Target $tenantId -Status SKIPPED -Detail 'Not read: -SkipInboxRules was given.' `
        -Recommendation 'Run again without -SkipInboxRules, or check single mailboxes with C1 Get-UserMailboxStatus.ps1.'
}
else {
    Invoke-MSPCheck -Name 'Forwarding rules' -Category 'Forwarding' -ScriptBlock {
        if (-not $exoConnected) { Skip-MSPCheck -Reason $exoReason }
        if ($domains.Count -eq 0 -or $mailboxes.Count -eq 0) { Skip-MSPCheck -Reason 'The mailboxes or the tenant''s domains could not be read (see "Mailbox forwarding").' -Recommendation $roleHint }
        $hits = @()
        $denied = 0
        foreach ($m in $mailboxes) {
            $upn = [string]$m.UserPrincipalName
            try { $rules = @(Get-InboxRule -Mailbox $upn -ErrorAction Stop) }
            catch { if (Test-AccessDenied $_) { $denied++; continue }; Write-MSPLog -Level WARN -Message ('Inbox rules of {0} not readable: {1}' -f $upn, $_.Exception.Message); continue }
            foreach ($r in @($rules | Where-Object { $_.Enabled })) {
                $to = (@($r.ForwardTo) + @($r.ForwardAsAttachmentTo) + @($r.RedirectTo) | Where-Object { $_ }) -join '; '
                $ext = @(Get-ExternalAddress -Text $to)
                if ($ext.Count -gt 0) {
                    $hits += ('{0}: "{1}" -> {2}' -f $upn, $r.Name, ($ext -join ', '))
                    $forwardRows.Add([pscustomobject]@{ Mailbox = $upn; Kind = 'Inbox rule'; Name = [string]$r.Name; To = ($ext -join '; '); KeepsCopy = '' })
                }
            }
        }
        if ($denied -eq $mailboxes.Count) { Skip-MSPCheck -Reason 'The signed-in account may not read inbox rules.' -Recommendation $roleHint }
        $note = ''
        if ($denied -gt 0) { $note = ' {0} mailbox(es) could not be read.' -f $denied }
        if ($hits.Count -gt 0) {
            Add-MSPFinding -Check 'Forwarding rules' -Category 'Forwarding' -Target $tenantId -Status WARN -Severity High `
                -Detail ('{0} enabled inbox rule(s) forward or redirect outside the organization: {1}.{2}' -f $hits.Count, ($hits -join '; '), $note) `
                -Recommendation 'Confirm each rule with the mailbox owner; unknown ones mean the account is compromised: reset the password, sign out all sessions, remove the rule, review MFA methods.'
        }
        else {
            Add-MSPFinding -Check 'Forwarding rules' -Category 'Forwarding' -Target $tenantId -Status PASS -Detail ('No enabled inbox rule in {0} mailbox(es) forwards outside the organization.{1}' -f ($mailboxes.Count - $denied), $note)
        }
    }
}
Add-MSPData -Name 'ExternalForwarding' -Rows $forwardRows.ToArray()

# =========================================================================================
Write-MSPSection -Title 'Guests, auditing and Secure Score'
# =========================================================================================
Invoke-MSPCheck -Name 'Guest users' -Category 'Guests' -ScriptBlock {
    Assert-Graph
    $props = 'id', 'displayName', 'userPrincipalName', 'mail', 'createdDateTime', 'accountEnabled'
    $withSignIn = $true
    $guests = @()
    try { $guests = @(Invoke-Graph -Scope 'User.Read.All' -Call { Get-MgUser -All -Filter "userType eq 'Guest'" -Property ($props + 'signInActivity') -ErrorAction Stop }) }
    catch {
        # Without Entra ID P1 Graph refuses signInActivity (Invoke-Graph turns that into a skip);
        # the guests themselves can still be read.
        if (-not $script:p1Missing) { throw }
        $withSignIn = $false
    }
    if (-not $withSignIn) { $guests = @(Invoke-Graph -Scope 'User.Read.All' -Call { Get-MgUser -All -Filter "userType eq 'Guest'" -Property $props -ErrorAction Stop }) }
    $rows = foreach ($g in $guests) {
        $last = $null
        if ($withSignIn -and $g.SignInActivity) { $last = Get-DateValue @($g.SignInActivity.LastSignInDateTime, $g.SignInActivity.LastNonInteractiveSignInDateTime, $g.SignInActivity.LastSuccessfulSignInDateTime) }
        $created = $null
        if ($g.CreatedDateTime) { $created = [datetime]$g.CreatedDateTime }
        $inactive = $false
        if ($withSignIn) {
            if ($last) { $inactive = ($now - $last).TotalDays -gt $InactiveGuestDays }
            elseif ($created) { $inactive = ($now - $created).TotalDays -gt $InactiveGuestDays }
        }
        [pscustomobject]@{
            Guest = $(if ($g.Mail) { [string]$g.Mail } else { [string]$g.UserPrincipalName }); Enabled = [bool]$g.AccountEnabled
            Created = $(if ($created) { $created.ToString('yyyy-MM-dd') } else { '' }); LastSignIn = $(if ($last) { $last.ToString('yyyy-MM-dd') } else { '' }); Inactive = $inactive
        }
    }
    $rows = @($rows)
    Add-MSPData -Name 'Guests' -Rows $rows
    Add-MSPFinding -Check 'Guest users' -Category 'Guests' -Target $tenantId -Status INFO -Detail ('{0} guest account(s), {1} enabled.' -f $rows.Count, @($rows | Where-Object { $_.Enabled }).Count)
    if (-not $withSignIn) {
        Add-MSPFinding -Check 'Inactive guests' -Category 'Guests' -Target $tenantId -Status SKIPPED -Detail ('Not checked: {0}' -f $p1Reason) `
            -Recommendation 'Review guests by hand in the Entra admin center (Users > filter User type = Guest), or use an access review if the client has Entra ID P2.'
        return
    }
    $stale = @($rows | Where-Object { $_.Inactive })
    if ($stale.Count -gt 0) {
        $names = @($stale | Select-Object -First 10 | ForEach-Object { if ($_.LastSignIn) { '{0} (last {1})' -f $_.Guest, $_.LastSignIn } else { '{0} (never, invited {1})' -f $_.Guest, $_.Created } })
        Add-MSPFinding -Check 'Inactive guests' -Category 'Guests' -Target $tenantId -Status WARN -Severity Low `
            -Detail ('{0} guest(s) without a sign-in for {1}+ days: {2}{3}.' -f $stale.Count, $InactiveGuestDays, ($names -join ', '), $(if ($stale.Count -gt 10) { ' and more (Guests table)' } else { '' })) `
            -Recommendation 'Ask the client which guests still need access; block and later delete the rest (they keep access to shared files and Teams until removed).'
    }
    else {
        Add-MSPFinding -Check 'Inactive guests' -Category 'Guests' -Target $tenantId -Status PASS -Detail ('Every guest signed in within {0} days.' -f $InactiveGuestDays)
    }
}

Invoke-MSPCheck -Name 'Mailbox auditing' -Category 'Auditing' -ScriptBlock {
    $org = Invoke-Exchange { Get-OrganizationConfig -ErrorAction Stop }
    if ($org.AuditDisabled) {
        Add-MSPFinding -Check 'Mailbox auditing' -Category 'Auditing' -Target $tenantId -Status FAIL -Severity High `
            -Detail 'Mailbox auditing is turned off for the whole organization: mailbox access and changes are not recorded.' `
            -Recommendation 'Turn it back on (Exchange Online PowerShell: Set-OrganizationConfig -AuditDisabled $false). Without it, a mailbox compromise cannot be investigated.'
    }
    else {
        Add-MSPFinding -Check 'Mailbox auditing' -Category 'Auditing' -Target $tenantId -Status PASS -Detail 'Mailbox auditing is on for the organization (the default).'
    }
}

Invoke-MSPCheck -Name 'Secure Score' -Category 'Secure Score' -ScriptBlock {
    Assert-Graph
    $scores = @(Invoke-Graph -Scope 'SecurityEvents.Read.All' -Call { Get-MgSecuritySecureScore -Top 7 -ErrorAction Stop })
    if ($scores.Count -eq 0) { Skip-MSPCheck -Reason 'Microsoft has not calculated a Secure Score for this tenant yet (new tenants take a day or two).' }
    $latest = @($scores | Sort-Object { [datetime]$_.CreatedDateTime } -Descending)[0]
    $current = [double]$latest.CurrentScore
    $max = [double]$latest.MaxScore
    $pct = 0
    if ($max -gt 0) { $pct = [int][math]::Round(100 * $current / $max) }
    $profiles = @{}
    foreach ($p in @(Invoke-Graph -Scope 'SecurityEvents.Read.All' -Call { Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop })) { $profiles[[string]$p.Id] = $p }
    $actions = foreach ($c in @($latest.ControlScores)) {
        $p = $profiles[[string]$c.ControlName]
        if (-not $p -or $p.Deprecated) { continue }
        $gain = [double]$p.MaxScore - [double]$c.Score
        if ($gain -le 0) { continue }
        [pscustomobject]@{ Action = [string]$p.Title; Category = [string]$p.ControlCategory; PointsAvailable = [math]::Round($gain, 1); UserImpact = [string]$p.UserImpact; ImplementationCost = [string]$p.ImplementationCost; Control = [string]$c.ControlName }
    }
    $actions = @($actions | Sort-Object PointsAvailable -Descending)
    Add-MSPData -Name 'SecureScoreActions' -Rows $actions
    $top = @($actions | Select-Object -First $TopActions)
    $topText = ''
    if ($top.Count -gt 0) { $topText = ' Top improvements: ' + ((@($top | ForEach-Object { '{0} (+{1})' -f $_.Action, $_.PointsAvailable })) -join '; ') + '.' }
    Add-MSPFinding -Check 'Secure Score' -Category 'Secure Score' -Target $tenantId -Status INFO `
        -Evidence @{ CurrentScore = $current; MaxScore = $max; Percent = $pct; Date = ([datetime]$latest.CreatedDateTime).ToString('yyyy-MM-dd') } `
        -Detail ('{0} of {1} points ({2} %) on {3:yyyy-MM-dd}.{4}' -f [math]::Round($current, 1), [math]::Round($max, 1), $pct, [datetime]$latest.CreatedDateTime, $topText) `
        -Recommendation 'Work through the top actions with the client; full list in the SecureScoreActions table and in the Defender portal (Exposure management > Secure Score).'
}

# One line on what Entra ID P1/P2 decided.
if ($graphConnected) {
    $needP1 = 'MFA registration, Conditional Access, legacy sign-ins, inactive guests'
    if ($p1Missing) {
        Add-MSPFinding -Check 'Entra ID P1/P2' -Category 'Licensing' -Target $tenantId -Status INFO `
            -Detail ('Not in this tenant, so these were SKIPPED or limited: {0}. {1}' -f $needP1, $p1Reason)
    }
    else {
        Add-MSPFinding -Check 'Entra ID P1/P2' -Category 'Licensing' -Target $tenantId -Status INFO -Detail ('Available (or not needed by what was read): {0} could run.' -f $needP1)
    }
}

if ($graphWeConnected -and -not $KeepConnection) {
    try { $null = Disconnect-MgGraph -ErrorAction Stop; Write-MSPLog -Message 'Disconnected from Microsoft Graph.' }
    catch { Write-MSPLog -Level WARN -Message ('Disconnect-MgGraph failed: {0}' -f $_.Exception.Message) }
}
if ($exoWeConnected -and -not $KeepConnection) {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop; Write-MSPLog -Message 'Disconnected from Exchange Online.' }
    catch { Write-MSPLog -Level WARN -Message ('Disconnect-ExchangeOnline failed: {0}' -f $_.Exception.Message) }
}
Complete-MSPRun -OutputPath $OutputPath
