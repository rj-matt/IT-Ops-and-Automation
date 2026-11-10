<#
.SYNOPSIS
    Read-only first look at one Microsoft 365 user suspected of being compromised (business
    email compromise): sign-ins, risk, inbox rules, forwarding, delegates, MFA methods, app
    consents, sent-mail volume and the audit log, plus the containment steps to take by hand.

.DESCRIPTION
    Gathers evidence for the ticket and changes nothing: read-only Graph scopes, Exchange Online
    read cmdlets only. It does not reset passwords, revoke sessions or remove anything; the
    "What to do now" section at the end lists those steps for the technician to do by hand.
    Every check that the tenant's licenses or the signed-in account's role do not allow is
    SKIPPED with the reason; the others still run. Window: the last -Days days (default 14).

    Checks (Target = the user)                                            Needs
      Account              Enabled, created, last password change.
      Sign-ins             Every sign-in in the window (time, country, IP, app, result).   Entra ID P1
                           Flags: a country new in the last 3 days, failed MFA followed
                           by a success within an hour, successful legacy-protocol
                           sign-ins, successful sign-ins from two countries within 4 hours.
      Risk                 Entra ID Protection risk level and risk detections.             Entra ID P2
      Inbox rules          Every rule. Flags enabled rules that forward or redirect,
                           delete, move to RSS Feeds / Conversation History / Archive /
                           Junk, mark as read, or look for words such as invoice, payment,
                           wire, bank.
      Mailbox forwarding   Forwarding set on the mailbox (outside the tenant = WARN High).
      Delegates            Full Access, Send As, Send on Behalf (listed to confirm).
      MFA methods          Registered methods; methods added in the window = WARN High
                           (from the method's date and the directory audit log).
      App consents         OAuth apps the user granted access to; grants in the window =
                           WARN High; non-Microsoft apps with mail or file scopes = WARN.
      Sent mail            Messages sent per day (message trace); a day with at least 20
                           and 3x the usual number = WARN High.
      Audit log            The user's mailbox and sign-in events in the window, and         auditing on
                           changes others made to the mailbox (rules, forwarding,
                           permissions). Rule, forwarding or permission changes and mass
                           deletions = WARN High.
      What to do now       The containment steps to take by hand, naming what was found.

    Sign-in: uses existing Microsoft Graph and Exchange Online connections when there are any.
    Otherwise it signs in (browser, or -DeviceCode) to Graph with only these scopes:
      User.Read.All                       the account (enabled, last password change)
      AuditLog.Read.All                   sign-in logs; directory audit (MFA registrations, consents)
      UserAuthenticationMethod.Read.All   the user's registered MFA methods
      DelegatedPermissionGrant.Read.All   the OAuth permission grants the user gave
      Application.Read.All                names and publishers of the apps in those grants
      IdentityRiskyUser.Read.All          the user's Entra ID Protection risk level
      IdentityRiskEvent.Read.All          the user's risk detections
    The Graph token is kept for this PowerShell process only (-ContextScope Process). Exchange
    Online loads only the read cmdlets this script calls (Connect-ExchangeOnline -CommandName);
    Exchange has no read-only sign-in scope, so use a Global Reader account (the audit log search
    also needs the View-Only Audit Logs role). Both connections are closed at the end unless
    -KeepConnection is given.

    FIRST SIGN-IN = TENANT-WIDE ADMIN CONSENT. The first time these scopes are used in a
    tenant, Microsoft asks an administrator to consent "on behalf of your organization" for
    Microsoft's own "Microsoft Graph Command Line Tools" app. That consent covers the whole
    tenant and stays until an admin removes it: anyone in the tenant who signs in to that app
    can then use these read scopes, within the limits of their own role. In a client's tenant,
    get the client's approval before consenting and note it in the ticket (who approved,
    when, which scopes). To remove it later: Entra admin center > Enterprise applications >
    Microsoft Graph Command Line Tools > Permissions (or delete the app's service principal).

.PARAMETER UserPrincipalName
    The user to investigate (sign-in name / email address).

.PARAMETER Days
    How many days back to look (1-30, default 14). Sign-in logs keep 30 days with Entra ID P1;
    message trace is read in 10-day pieces.

.PARAMETER SkipExchange
    Graph checks only: no Exchange Online connection (rules, forwarding, delegates, sent mail and
    the audit log are SKIPPED).

.PARAMETER DeviceCode
    Sign in with a device code (works over SSH and on computers without a browser).

.PARAMETER KeepConnection
    Leave the Graph and Exchange Online connections open at the end.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with SignIns, RiskDetections,
    InboxRules, Delegates, MfaMethods, AppConsents, SentPerDay, AuditEvents and NextSteps tables.
    The results name the user, IP addresses and correspondents: keep them with the ticket.

.EXAMPLE
    pwsh -File .\Get-AccountCompromiseTriage.ps1 -UserPrincipalName alice@contoso.com -OutputPath ~/Desktop/Ticket123

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-AccountCompromiseTriage.ps1 -UserPrincipalName alice@contoso.com -Days 30 -DeviceCode

.NOTES
    Purpose       : "Is this account compromised, and what has the attacker set up?" in one run.
    Use Case      : A user or the client reports odd emails, payment-change requests or a phishing
                    click; a partner reports mail from the user that they did not send.
    Scope         : One user in the signed-in admin's Microsoft 365 tenant, read through Microsoft
                    Graph and Exchange Online. Nothing on this computer is read or changed.
    Risk Level    : Read-Only -- read-only Graph scopes, Get-/Search- cmdlets only.
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 on Windows; PowerShell 7 on macOS and
                    Linux | Modules: Microsoft.Graph (Authentication, Users, Reports,
                    Identity.SignIns, Applications) and ExchangeOnlineManagement 3.x
                    (Install-Module Microsoft.Graph, ExchangeOnlineManagement -Scope CurrentUser)
                    | Account: Global Reader, plus View-Only Audit Logs for the audit log. An admin
                    must consent to the seven Graph scopes once per tenant (see above).
    Version       : 1.1.0
    Limitations   : A clean result does not prove the account is safe. Sign-ins need Entra ID P1,
                    risk needs P2. Rules created through MAPI as hidden rules are not listed by
                    Get-InboxRule. Logs can lag by up to a few hours; the audit log by up to a day.
                    Message trace and the audit log are read up to 5000 records per query.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [int]$Days = 14,
    [switch]$SkipExchange,
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

$ScriptVersion = '1.1.0'
Initialize-MSPRun -ScriptName 'Get-AccountCompromiseTriage' -ScriptVersion $ScriptVersion -CheckId 'C5' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Microsoft 365 account compromise triage for one user (read-only; changes nothing)'
# Number ranges are checked here, not with [ValidateRange], so a wrong value gets a plain message
# and a clean exit 1 instead of a parameter-binding error.
if (-not (Test-MSPParameterRange -Bound $PSBoundParameters -Range ([ordered]@{ Days = 1, 30 }))) {
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

$target = $UserPrincipalName.Trim()
$requiredScopes = @('User.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'DelegatedPermissionGrant.Read.All',
    'Application.Read.All', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All')
# The only Exchange cmdlets the connection loads (Get-EXO* cmdlets are part of the module).
$readCmdlets = @('Get-AcceptedDomain', 'Get-InboxRule', 'Get-MessageTraceV2', 'Get-AdminAuditLogConfig', 'Search-UnifiedAuditLog')
$roleHint = 'Sign in with an account that has the Global Reader role.'
$auditRoleHint = 'Sign in with an account that also has the View-Only Audit Logs role (Microsoft Purview > Roles and scopes), or search the audit log in the Purview portal.'
$p1Reason = 'This tenant has no Microsoft Entra ID P1 or P2 license, which Microsoft requires for sign-in logs (P1 is included in Microsoft 365 Business Premium, E3 and E5).'
$p2Reason = 'This tenant has no Microsoft Entra ID P2 license, which Microsoft requires for Entra ID Protection risk data (P2 is included in Microsoft 365 E5).'
$now = Get-Date
$since = $now.AddDays(-$Days)
$sinceUtc = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
# Microsoft's own tenant: apps it publishes (Outlook, Teams, ...) are not third-party consents.
$microsoftTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
$legacyClients = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'Authenticated SMTP', 'Exchange Web Services', 'MAPI Over HTTP',
    'Outlook Anywhere (RPC over HTTP)', 'Offline Address Book', 'Exchange Online PowerShell', 'Autodiscover', 'Other clients')
# Sign-in error codes: MFA was asked for and not completed / failed.
$mfaFailCodes = @(500121, 50074, 50076, 50158)
$mailFileScopes = 'Mail\.|MailboxSettings\.|EWS\.|full_access_as_user|IMAP\.|POP\.|SMTP\.Send|Files\.|Sites\.|Notes\.'
$moneyWords = 'invoice|payment|wire|bank|transfer|remittance|iban|swift|routing|ach\b|payroll|w-2|w2'
$hideFolders = 'RSS Feeds|RSS Subscriptions|Conversation History|Archive|Junk'
$next = New-Object System.Collections.Generic.List[object]
# Reasons to block sign-in before anything else (a recent successful suspicious sign-in, a sent-mail spike today).
$urgent = New-Object System.Collections.Generic.List[string]
$urgentSince = $now.AddHours(-24)

function Add-Step {
    <# One "What to do now" step about TOPIC; a generic step is left out when a specific one covers its topic. #>
    param([string]$Topic, [string]$Text)
    $script:next.Add([pscustomobject]@{ Topic = $Topic; Text = $Text })
}

function Add-Urgent {
    <# Records a successful suspicious sign-in from the last 24 hours as a reason to block sign-in first. #>
    param($SignIn, [string]$What)
    if ($SignIn.Time -ge $script:urgentSince) { $script:urgent.Add(('{0} at {1:yyyy-MM-dd HH:mm} from {2} ({3})' -f $What, $SignIn.Time, $SignIn.Country, $SignIn.IP)) }
}

function Test-AccessDenied {
    <# True for "not allowed" answers (missing role, scope or consent). #>
    param($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'Authorization_RequestDenied|Insufficient privileges|Forbidden|403|Access is denied|AccessDenied|not allowed to|does not have permission')
}

function Test-NoPremium {
    <# True when Graph refuses because the tenant lacks the Entra ID P1/P2 license the data needs. #>
    param($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'NonPremium|premium license|AadPremiumLicenseRequired|does not have a SKU|not licensed for this feature')
}

function Invoke-Graph {
    <# One Graph read; a missing license, scope or role becomes SKIPPED with the reason. #>
    param([scriptblock]$Call, [string]$Scope, [string]$License = 'P1')
    if (-not $script:graphConnected) { Skip-MSPCheck -Reason 'Not signed in to Microsoft Graph (see "Graph connection").' -Recommendation 'Install the Microsoft Graph modules and run again from a terminal (or with -DeviceCode).' }
    if (-not $script:userId) { Skip-MSPCheck -Reason ('The user {0} was not found (see "Account").' -f $target) }
    if ($Scope -and $script:scopesNow -notcontains $Scope) {
        Skip-MSPCheck -Reason ('Needs the {0} scope, which this connection does not have.' -f $Scope) `
            -Recommendation ('Disconnect-MgGraph, then run again so the script signs in with {0}.' -f ($requiredScopes -join ', '))
    }
    try { & $Call }
    catch {
        if (Test-NoPremium $_) {
            if ($License -eq 'P2') { Skip-MSPCheck -Reason $p2Reason -Recommendation 'Check the user''s sign-ins and risky activity in the Entra admin center by hand.' }
            Skip-MSPCheck -Reason $p1Reason -Recommendation 'Check the user''s sign-ins in the Entra admin center (Users > the user > Sign-in logs), which shows 7 days without P1.'
        }
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason ('The signed-in account may not read this ({0}).' -f $_.Exception.Message.Split([Environment]::NewLine)[0]) -Recommendation $roleHint }
        throw
    }
}

function Invoke-Exchange {
    <# One Exchange read; a role problem becomes SKIPPED with the role to use. #>
    param([scriptblock]$Call, [string]$RoleHint = $roleHint)
    if (-not $script:exoConnected) { Skip-MSPCheck -Reason $script:exoReason -Recommendation 'Run again without -SkipExchange, with the ExchangeOnlineManagement module installed.' }
    try { & $Call }
    catch {
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason ('The signed-in account may not read this ({0}).' -f $_.Exception.Message.Split([Environment]::NewLine)[0]) -Recommendation $RoleHint }
        throw
    }
}

function Add-Finding {
    <# Add-MSPFinding for this user (Target = the UPN). #>
    param([string]$Check, [string]$Category, [string]$Status, [string]$Detail, [string]$Severity = '', [string]$Recommendation = '', [hashtable]$Evidence = $null)
    $a = @{ Check = $Check; Category = $Category; Status = $Status; Detail = $Detail; Target = $target }
    if ($Severity) { $a['Severity'] = $Severity }
    if ($Recommendation) { $a['Recommendation'] = $Recommendation }
    if ($Evidence) { $a['Evidence'] = $Evidence }
    Add-MSPFinding @a
}

function Invoke-UserCheck {
    <# Invoke-MSPCheck whose SKIPPED / ERROR findings name the user as Target. #>
    param([string]$Name, [string]$Category, [scriptblock]$ScriptBlock)
    $before = $script:MSPRun.Findings.Count
    Invoke-MSPCheck -Name $Name -Category $Category -ScriptBlock $ScriptBlock
    for ($i = $before; $i -lt $script:MSPRun.Findings.Count; $i++) {
        $f = $script:MSPRun.Findings[$i]
        if ($f.Status -in @('SKIPPED', 'ERROR') -and $f.Target -eq $script:MSPRun.Host) { $f.Target = $target }
    }
}

function Get-Text {
    <# Joined text of values that can be strings, arrays (one level deep) or empty. #>
    param($Value)
    return ((@($Value | ForEach-Object { $_ }) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join '; ')
}

# =========================================================================================
Write-MSPSection -Title 'Connections'
# =========================================================================================
$graphConnected = $false
$graphWeConnected = $false
$scopesNow = @()
Invoke-MSPCheck -Name 'Graph connection' -Category 'Connection' -ScriptBlock {
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Get-MgAuditLogSignIn -ErrorAction SilentlyContinue)) {
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
        Add-MSPFinding -Check 'Exchange connection' -Category 'Connection' -Status INFO `
            -Detail ('Signed in as {0} (tenant {1}).' -f $connection.UserPrincipalName, $connection.TenantID) `
            -Evidence @{ Account = [string]$connection.UserPrincipalName; TenantId = [string]$connection.TenantID; ConnectedByScript = $script:exoWeConnected }
    }
}
if (-not $graphConnected -and -not $exoConnected) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

# =========================================================================================
Write-MSPSection -Title ('Account {0} (last {1} days)' -f $target, $Days)
# =========================================================================================
$userId = ''
Invoke-UserCheck -Name 'Account' -Category 'Account' -ScriptBlock {
    if (-not $graphConnected) { Skip-MSPCheck -Reason 'Not signed in to Microsoft Graph (see "Graph connection").' }
    if ($scopesNow -notcontains 'User.Read.All') { Skip-MSPCheck -Reason 'Needs the User.Read.All scope, which this connection does not have.' }
    try { $u = Get-MgUser -UserId $target -Property 'id', 'displayName', 'userPrincipalName', 'accountEnabled', 'createdDateTime', 'lastPasswordChangeDateTime' -ErrorAction Stop }
    catch {
        if ([string]$_.Exception.Message -match 'Request_ResourceNotFound|does not exist|NotFound|404') {
            Add-Finding -Check 'Account' -Category 'Account' -Status FAIL -Severity Medium -Detail ('No user {0} in this tenant.' -f $target) `
                -Recommendation 'Check the spelling of the address, or whether the account was deleted (Entra ID > Deleted users).'
            return
        }
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason 'The signed-in account may not read users.' -Recommendation $roleHint }
        throw
    }
    $script:userId = [string]$u.Id
    $pw = 'unknown'
    if ($u.LastPasswordChangeDateTime) { $pw = ([datetime]$u.LastPasswordChangeDateTime).ToString('yyyy-MM-dd HH:mm') }
    Add-Finding -Check 'Account' -Category 'Account' -Status INFO `
        -Detail ('{0}: sign-in {1}; created {2}; password last changed {3}.' -f $u.DisplayName, $(if ($u.AccountEnabled) { 'allowed' } else { 'BLOCKED' }), ([datetime]$u.CreatedDateTime).ToString('yyyy-MM-dd'), $pw) `
        -Evidence @{ UserId = $script:userId; Enabled = [bool]$u.AccountEnabled; PasswordChanged = $pw }
}

# =========================================================================================
Write-MSPSection -Title 'Sign-ins and risk'
# =========================================================================================
Invoke-UserCheck -Name 'Sign-ins' -Category 'Sign-ins' -ScriptBlock {
    $filter = "userId eq '{0}' and createdDateTime ge {1}" -f $userId, $sinceUtc
    $raw = @(Invoke-Graph -Scope 'AuditLog.Read.All' -License 'P1' -Call { Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop })
    $rows = @($raw | ForEach-Object {
            $code = [int]$_.Status.ErrorCode
            [pscustomobject]@{
                Time = [datetime]$_.CreatedDateTime; Country = [string]$_.Location.CountryOrRegion; City = [string]$_.Location.City; IP = [string]$_.IPAddress
                App = [string]$_.AppDisplayName; Client = [string]$_.ClientAppUsed; ErrorCode = $code; Succeeded = ($code -eq 0)
                Result = $(if ($code -eq 0) { 'Success' } else { ('{0} {1}' -f $code, $_.Status.FailureReason).Trim() })
            }
        } | Sort-Object Time)
    Add-MSPData -Name 'SignIns' -Rows @($rows | Select-Object @{ n = 'Time'; e = { $_.Time.ToString('yyyy-MM-dd HH:mm') } }, Country, City, IP, App, Client, Result)
    $ok = @($rows | Where-Object { $_.Succeeded })
    $countries = @($ok | Where-Object { $_.Country } | Group-Object Country | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
    Add-Finding -Check 'Sign-ins' -Category 'Sign-ins' -Status INFO `
        -Detail ('{0} sign-in(s) in {1} day(s), {2} successful; countries: {3}.' -f $rows.Count, $Days, $ok.Count, $(if ($countries) { $countries -join ', ' } else { 'none recorded' }))

    # A country with successful sign-ins in the last 3 days and none before that.
    $recentCut = $now.AddDays(-3)
    $before = @($ok | Where-Object { $_.Time -lt $recentCut -and $_.Country } | ForEach-Object { $_.Country } | Sort-Object -Unique)
    $newOnes = @($ok | Where-Object { $_.Time -ge $recentCut -and $_.Country -and $before -notcontains $_.Country } | Group-Object Country)
    if ($before.Count -gt 0 -and $newOnes.Count -gt 0) {
        $text = @($newOnes | ForEach-Object { '{0} (first {1:yyyy-MM-dd HH:mm} from {2}, {3})' -f $_.Name, ($_.Group[0].Time), $_.Group[0].IP, $_.Group[0].App })
        Add-Finding -Check 'New sign-in countries' -Category 'Sign-ins' -Status WARN -Severity High `
            -Detail ('Successful sign-ins from a country not seen earlier in the window: {0}. Usual: {1}.' -f ($text -join '; '), ($before -join ', ')) `
            -Recommendation 'Ask the user whether they travelled or use a VPN there. If not, treat the account as compromised.'
        Add-Step -Topic 'country' -Text ('Ask the user about sign-ins from {0}; if not theirs, treat as compromised.' -f ((@($newOnes | ForEach-Object { $_.Name })) -join ', '))
        foreach ($g in $newOnes) { foreach ($x in $g.Group) { Add-Urgent $x 'a sign-in from a new country' } }
    }
    elseif ($before.Count -eq 0) {
        Add-Finding -Check 'New sign-in countries' -Category 'Sign-ins' -Status INFO -Detail 'Not enough sign-ins before the last 3 days to tell which countries are usual.'
    }
    else {
        Add-Finding -Check 'New sign-in countries' -Category 'Sign-ins' -Status PASS -Detail ('No new country in the last 3 days (usual: {0}).' -f ($before -join ', '))
    }

    # Failed or interrupted MFA, then a success within an hour (MFA fatigue, a stolen session).
    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($rows | Where-Object { $mfaFailCodes -contains $_.ErrorCode })) {
        $after = @($ok | Where-Object { $_.Time -gt $f.Time -and $_.Time -le $f.Time.AddHours(1) }) | Select-Object -First 1
        if ($after) {
            $pairs.Add(('{0:yyyy-MM-dd HH:mm} MFA failed ({1}, {2}) -> {3:HH:mm} success ({4}, {5})' -f $f.Time, $f.Country, $f.IP, $after.Time, $after.Country, $after.IP))
            Add-Urgent $after 'a sign-in right after a failed MFA'
        }
    }
    if ($pairs.Count -gt 0) {
        Add-Finding -Check 'Failed MFA then success' -Category 'Sign-ins' -Status WARN -Severity High `
            -Detail ('{0} time(s): {1}.' -f $pairs.Count, ((@($pairs | Select-Object -Unique)) -join '; ')) `
            -Recommendation 'Ask the user whether they approved an MFA prompt they did not start. Repeated prompts followed by an approval is the usual pattern of MFA fatigue.'
        Add-Step -Topic 'mfaprompt' -Text 'Ask the user about MFA prompts they approved without signing in themselves.'
    }
    else { Add-Finding -Check 'Failed MFA then success' -Category 'Sign-ins' -Status PASS -Detail 'No failed MFA followed by a successful sign-in within an hour.' }

    $legacy = @($ok | Where-Object { $legacyClients -contains $_.Client })
    if ($legacy.Count -gt 0) {
        Add-Finding -Check 'Legacy-protocol sign-ins' -Category 'Sign-ins' -Status WARN -Severity High `
            -Detail ('{0} successful sign-in(s) over legacy protocols, which skip MFA: {1}.' -f $legacy.Count, ((@($legacy | Group-Object Client | ForEach-Object { '{0} x{1} (last from {2}, {3})' -f $_.Name, $_.Count, $_.Group[-1].IP, $_.Group[-1].Country })) -join '; ')) `
            -Recommendation 'Unless the user has an old mail app on purpose, this is a password being used without MFA: block legacy authentication for the tenant (run C4) and reset the password.'
        Add-Step -Topic 'legacy' -Text 'Block legacy authentication (security defaults or a Conditional Access policy); legacy sign-ins succeeded.'
        foreach ($x in $legacy) { Add-Urgent $x ('a sign-in over {0}' -f $x.Client) }
    }
    else { Add-Finding -Check 'Legacy-protocol sign-ins' -Category 'Sign-ins' -Status PASS -Detail 'No successful legacy-protocol sign-in.' }

    # Two countries within 4 hours (impossible travel, or a VPN).
    $travel = New-Object System.Collections.Generic.List[string]
    $located = @($ok | Where-Object { $_.Country })
    for ($i = 1; $i -lt $located.Count; $i++) {
        $a = $located[$i - 1]
        $b = $located[$i]
        if ($a.Country -ne $b.Country -and ($b.Time - $a.Time).TotalHours -le 4) {
            $travel.Add(('{0} {1:yyyy-MM-dd HH:mm} -> {2} {3:HH:mm} ({4:N1} h)' -f $a.Country, $a.Time, $b.Country, $b.Time, ($b.Time - $a.Time).TotalHours))
            Add-Urgent $b ('a sign-in {0:N1} h after one from {1}' -f ($b.Time - $a.Time).TotalHours, $a.Country)
        }
    }
    if ($travel.Count -gt 0) {
        Add-Finding -Check 'Two countries within hours' -Category 'Sign-ins' -Status WARN -Severity High `
            -Detail ('Successful sign-ins from different countries within 4 hours: {0}.' -f ((@($travel | Select-Object -First 5)) -join '; ')) `
            -Recommendation 'Rule out a VPN or a mobile network that exits abroad; otherwise someone else signed in with the account.'
    }
    else { Add-Finding -Check 'Two countries within hours' -Category 'Sign-ins' -Status PASS -Detail 'No successful sign-ins from two countries within 4 hours.' }
}

Invoke-UserCheck -Name 'Risk' -Category 'Risk' -ScriptBlock {
    $risky = $null
    try { $risky = Invoke-Graph -Scope 'IdentityRiskyUser.Read.All' -License 'P2' -Call { Get-MgRiskyUser -RiskyUserId $userId -ErrorAction Stop } }
    catch {
        # A user Entra ID Protection never flagged has no riskyUser entry.
        if ([string]$_.Exception.Message -notmatch 'ResourceNotFound|NotFound|404|does not exist') { throw }
    }
    $filter = "userId eq '{0}' and detectedDateTime ge {1}" -f $userId, $sinceUtc
    $detections = @(Invoke-Graph -Scope 'IdentityRiskEvent.Read.All' -License 'P2' -Call { Get-MgRiskDetection -Filter $filter -All -ErrorAction Stop })
    $rows = @($detections | Sort-Object { [datetime]$_.DetectedDateTime } | ForEach-Object {
            [pscustomobject]@{ Time = ([datetime]$_.DetectedDateTime).ToString('yyyy-MM-dd HH:mm'); Type = [string]$_.RiskEventType; Level = [string]$_.RiskLevel; State = [string]$_.RiskState; IP = [string]$_.IPAddress; Country = [string]$_.Location.CountryOrRegion }
        })
    Add-MSPData -Name 'RiskDetections' -Rows $rows
    $level = 'none'
    $state = ''
    if ($risky) { $level = [string]$risky.RiskLevel; $state = [string]$risky.RiskState }
    $text = 'Risk level {0}{1}; {2} risk detection(s) in the window{3}' -f $level, $(if ($state) { ' (' + $state + ')' } else { '' }), $rows.Count, $(if ($rows) { ': ' + ((@($rows | ForEach-Object { '{0} {1} ({2}, {3})' -f $_.Time, $_.Type, $_.Level, $_.Country })) -join '; ') } else { '' })
    if ($level -in @('high', 'medium') -or @($rows | Where-Object { $_.Level -in @('high', 'medium') }).Count -gt 0) {
        Add-Finding -Check 'Risk' -Category 'Risk' -Status WARN -Severity High -Detail ($text + '.') `
            -Recommendation 'Entra ID Protection considers this account at risk. Contain it (see What to do now), then confirm or dismiss the risk in Entra admin center > Protection > Risky users.'
    }
    elseif ($rows.Count -gt 0 -or $level -eq 'low') {
        Add-Finding -Check 'Risk' -Category 'Risk' -Status INFO -Detail ($text + '.')
    }
    else { Add-Finding -Check 'Risk' -Category 'Risk' -Status PASS -Detail 'No risk level and no risk detections for this user.' }
}

# =========================================================================================
Write-MSPSection -Title 'Mailbox: rules, forwarding, delegates'
# =========================================================================================
$domains = @()
$mailbox = $null
Invoke-UserCheck -Name 'Mailbox' -Category 'Mailbox' -ScriptBlock {
    $script:domains = @(Invoke-Exchange { Get-AcceptedDomain -ErrorAction Stop } | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    try { $script:mailbox = Invoke-Exchange { Get-EXOMailbox -Identity $target -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward, GrantSendOnBehalfTo, RecipientTypeDetails -ErrorAction Stop } }
    catch {
        if ([string]$_.Exception.Message -match "couldn't be found|could not be found|not found") {
            Add-Finding -Check 'Mailbox' -Category 'Mailbox' -Status FAIL -Severity Medium -Detail ('No mailbox {0}.' -f $target) -Recommendation 'Check the address; an unlicensed user has no mailbox.'
            return
        }
        throw
    }
    Write-MSPLog -Message ('Mailbox found ({0}); accepted domains: {1}' -f $script:mailbox.RecipientTypeDetails, ($script:domains -join ', '))
}
function Get-ExternalAddress {
    <# The addresses in TEXT whose domain is not one of the tenant's accepted domains. #>
    param([string]$Text)
    if ($domains.Count -eq 0) { return @() }
    return @([regex]::Matches($Text, '[A-Za-z0-9._%+''-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})') | Where-Object { $domains -notcontains $_.Groups[1].Value.ToLowerInvariant() } | ForEach-Object { $_.Value } | Select-Object -Unique)
}
function Assert-Mailbox { if (-not $script:mailbox) { Skip-MSPCheck -Reason 'The mailbox could not be read (see "Mailbox").' } }

Invoke-UserCheck -Name 'Inbox rules' -Category 'Mailbox' -ScriptBlock {
    Assert-Mailbox
    $rules = @(Invoke-Exchange { Get-InboxRule -Mailbox $target -ErrorAction Stop })
    $rows = New-Object System.Collections.Generic.List[object]
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rules) {
        $to = Get-Text @($r.ForwardTo, $r.ForwardAsAttachmentTo, $r.RedirectTo)
        $words = Get-Text @($r.SubjectContainsWords, $r.BodyContainsWords, $r.SubjectOrBodyContainsWords, $r.FromAddressContainsWords)
        $folder = [string]$r.MoveToFolder
        $why = New-Object System.Collections.Generic.List[string]
        $external = @(Get-ExternalAddress -Text $to)
        if ($to) { $why.Add($(if ($external.Count -gt 0) { 'forwards outside to ' + ($external -join ', ') } else { 'forwards to ' + $to })) }
        if ($r.DeleteMessage) { $why.Add('deletes mail') }
        if ($folder -match $hideFolders) { $why.Add('moves to ' + (($folder -split '\\')[-1])) }
        if ($r.MarkAsRead) { $why.Add('marks as read') }
        if ($words -match $moneyWords) { $why.Add('matches "' + $words + '"') }
        $rows.Add([pscustomobject]@{ Name = [string]$r.Name; Enabled = [bool]$r.Enabled; ForwardTo = $to; DeleteMessage = [bool]$r.DeleteMessage; MoveToFolder = $folder; MarkAsRead = [bool]$r.MarkAsRead; Words = $words; Flags = ($why -join ', ') })
        if ($r.Enabled -and $why.Count -gt 0) {
            $bad.Add(('"{0}" ({1})' -f $r.Name, ($why -join ', ')))
            Add-Step -Topic 'rule' -Text ('Remove the inbox rule "{0}" ({1}) after taking a screenshot for the ticket.' -f $r.Name, ($why -join ', '))
        }
    }
    Add-MSPData -Name 'InboxRules' -Rows $rows.ToArray()
    if ($bad.Count -gt 0) {
        Add-Finding -Check 'Inbox rules' -Category 'Mailbox' -Status WARN -Severity High `
            -Detail ('{0} of {1} rule(s) look like an attacker''s: {2}.' -f $bad.Count, $rules.Count, ($bad -join '; ')) `
            -Recommendation 'Rules that forward, delete, hide or watch for payment words are the usual sign of business email compromise. Record them, then remove them (see What to do now).'
    }
    else {
        Add-Finding -Check 'Inbox rules' -Category 'Mailbox' -Status PASS -Detail ('{0} rule(s); none forwards, deletes, hides mail or watches for payment words.' -f $rules.Count)
    }
}

Invoke-UserCheck -Name 'Mailbox forwarding' -Category 'Mailbox' -ScriptBlock {
    Assert-Mailbox
    $smtp = ([string]$mailbox.ForwardingSmtpAddress) -replace '^smtp:', ''
    $internal = [string]$mailbox.ForwardingAddress
    if (-not $smtp -and -not $internal) { Add-Finding -Check 'Mailbox forwarding' -Category 'Mailbox' -Status PASS -Detail 'No forwarding set on the mailbox.'; return }
    $to = (@($smtp, $internal) | Where-Object { $_ }) -join ', '
    $keep = 'a copy stays in the mailbox'
    if (-not $mailbox.DeliverToMailboxAndForward) { $keep = 'NO copy stays in the mailbox' }
    $external = @(Get-ExternalAddress -Text $smtp)
    if ($external.Count -gt 0) {
        Add-Finding -Check 'Mailbox forwarding' -Category 'Mailbox' -Status WARN -Severity High -Detail ('All mail is forwarded outside the organization to {0} ({1}).' -f $to, $keep) `
            -Recommendation 'Unless the user set this up, it is the attacker''s copy of the mailbox. Record it, then remove it (see What to do now).'
        Add-Step -Topic 'forwarding' -Text ('Remove the mailbox forwarding to {0}.' -f $to)
    }
    else { Add-Finding -Check 'Mailbox forwarding' -Category 'Mailbox' -Status INFO -Detail ('Mail is forwarded inside the organization to {0} ({1}).' -f $to, $keep) }
}

Invoke-UserCheck -Name 'Delegates' -Category 'Mailbox' -ScriptBlock {
    Assert-Mailbox
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Invoke-Exchange { Get-EXOMailboxPermission -Identity $target -ErrorAction Stop })) {
        if ($p.IsInherited -or $p.Deny -or [string]$p.User -match '^(NT AUTHORITY|S-1-5-)') { continue }
        if (@($p.AccessRights) -match 'FullAccess') { $rows.Add([pscustomobject]@{ Delegate = [string]$p.User; Access = 'Full Access' }) }
    }
    foreach ($p in @(Invoke-Exchange { Get-EXORecipientPermission -Identity $target -ErrorAction Stop })) {
        if ($p.IsInherited -or [string]$p.Trustee -match '^(NT AUTHORITY|S-1-5-)') { continue }
        if (@($p.AccessRights) -match 'SendAs') { $rows.Add([pscustomobject]@{ Delegate = [string]$p.Trustee; Access = 'Send As' }) }
    }
    foreach ($d in @($mailbox.GrantSendOnBehalfTo | Where-Object { $_ })) { $rows.Add([pscustomobject]@{ Delegate = [string]$d; Access = 'Send on Behalf' }) }
    Add-MSPData -Name 'Delegates' -Rows $rows.ToArray()
    if ($rows.Count -eq 0) { Add-Finding -Check 'Delegates' -Category 'Mailbox' -Status PASS -Detail 'Nobody else has access to this mailbox.'; return }
    Add-Finding -Check 'Delegates' -Category 'Mailbox' -Status INFO `
        -Detail ('{0}. Confirm each with the client; an unknown delegate means someone else can read or send as this user. Recent changes are under "Mailbox changes".' -f ((@($rows | ForEach-Object { '{0} ({1})' -f $_.Delegate, $_.Access })) -join '; '))
    Add-Step -Topic 'delegates' -Text ('Confirm the mailbox delegates with the client: {0}.' -f ((@($rows | ForEach-Object { '{0} ({1})' -f $_.Delegate, $_.Access })) -join '; '))
}

# =========================================================================================
Write-MSPSection -Title 'MFA methods and app consents'
# =========================================================================================
$directoryAudits = $null
function Get-DirectoryAudit {
    <# Directory audit events in the window that target or were started by the user (read once). #>
    if ($null -eq $script:directoryAudits) {
        $byTarget = "activityDateTime ge {0} and targetResources/any(t:t/id eq '{1}')" -f $sinceUtc, $userId
        $byActor = "activityDateTime ge {0} and initiatedBy/user/id eq '{1}'" -f $sinceUtc, $userId
        $a = @(Invoke-Graph -Scope 'AuditLog.Read.All' -Call { Get-MgAuditLogDirectoryAudit -Filter $byTarget -All -ErrorAction Stop })
        $b = @(Invoke-Graph -Scope 'AuditLog.Read.All' -Call { Get-MgAuditLogDirectoryAudit -Filter $byActor -All -ErrorAction Stop })
        $seen = @{}
        $script:directoryAudits = @(@($a) + @($b) | Where-Object { $k = [string]$_.Id; if ($seen.ContainsKey($k)) { $false } else { $seen[$k] = $true; $true } })
    }
    return $script:directoryAudits
}

Invoke-UserCheck -Name 'MFA methods' -Category 'MFA' -ScriptBlock {
    $methods = @(Invoke-Graph -Scope 'UserAuthenticationMethod.Read.All' -Call { Get-MgUserAuthenticationMethod -UserId $userId -All -ErrorAction Stop })
    $rows = foreach ($m in $methods) {
        $p = $m.AdditionalProperties
        $type = ([string]$p['@odata.type']) -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
        $detail = @($p['displayName'], $p['phoneNumber'], $p['emailAddress'], $p['model']) | Where-Object { $_ } | Select-Object -First 1
        $created = $null
        if ($p['createdDateTime']) { $created = [datetime]$p['createdDateTime'] }
        [pscustomobject]@{ Type = $type; Detail = [string]$detail; Added = $(if ($created) { $created.ToString('yyyy-MM-dd HH:mm') } else { '' }); InWindow = [bool]($created -and $created -ge $since) }
    }
    $rows = @($rows | Where-Object { $_.Type -ne 'password' })
    Add-MSPData -Name 'MfaMethods' -Rows $rows
    $audit = @()
    try { $audit = @(Get-DirectoryAudit | Where-Object { [string]$_.ActivityDisplayName -match 'security info' }) }
    catch { Write-MSPLog -Level WARN -Message ('Directory audit not read for MFA changes: {0}' -f $_.Exception.Message) }
    $added = @($rows | Where-Object { $_.InWindow } | ForEach-Object { '{0} {1} (added {2})' -f $_.Type, $_.Detail, $_.Added })
    $added += @($audit | Where-Object { [string]$_.ActivityDisplayName -match 'registered|changed default' } | ForEach-Object { '{0} at {1:yyyy-MM-dd HH:mm}' -f $_.ActivityDisplayName, ([datetime]$_.ActivityDateTime) })
    $list = (@($rows | ForEach-Object { ('{0} {1}' -f $_.Type, $_.Detail).Trim() })) -join '; '
    if ($rows.Count -eq 0) {
        Add-Finding -Check 'MFA methods' -Category 'MFA' -Status WARN -Severity High -Detail 'No MFA method registered: the password alone signs in.' `
            -Recommendation 'Have the user register Microsoft Authenticator after the password reset, in person or on a call you started.'
        Add-Step -Topic 'mfa' -Text 'Register MFA for the user after the password reset (none is registered).'
    }
    elseif ($added.Count -gt 0) {
        Add-Finding -Check 'MFA methods' -Category 'MFA' -Status WARN -Severity High `
            -Detail ('Changed in the last {0} days: {1}. Registered now: {2}.' -f $Days, ((@($added | Select-Object -Unique)) -join '; '), $list) `
            -Recommendation 'Ask the user whether they added these. Attackers register their own authenticator to keep access after a password reset.'
        Add-Step -Topic 'mfa' -Text ('Review the MFA methods with the user and delete any they did not add ({0}).' -f ((@($added | Select-Object -Unique)) -join '; '))
    }
    else {
        Add-Finding -Check 'MFA methods' -Category 'MFA' -Status PASS -Detail ('No method added in the last {0} days. Registered: {1}.' -f $Days, $list)
    }
}

Invoke-UserCheck -Name 'App consents' -Category 'Apps' -ScriptBlock {
    $grants = @(Invoke-Graph -Scope 'DelegatedPermissionGrant.Read.All' -Call { Get-MgUserOauth2PermissionGrant -UserId $userId -All -ErrorAction Stop })
    $recent = @()
    try { $recent = @(Get-DirectoryAudit | Where-Object { [string]$_.ActivityDisplayName -match '^Consent to application' }) }
    catch { Write-MSPLog -Level WARN -Message ('Directory audit not read for consents: {0}' -f $_.Exception.Message) }
    $recentNames = @($recent | ForEach-Object { @($_.TargetResources | ForEach-Object { [string]$_.DisplayName }) } | Where-Object { $_ })
    $rows = New-Object System.Collections.Generic.List[object]
    $flag = New-Object System.Collections.Generic.List[string]
    $high = $false
    foreach ($g in $grants) {
        $name = [string]$g.ClientId
        $publisher = ''
        $verified = ''
        $microsoft = $false
        $sp = $null
        try {
            $sp = Invoke-Graph -Scope 'Application.Read.All' -Call { Get-MgServicePrincipal -ServicePrincipalId ([string]$g.ClientId) -Property 'id', 'displayName', 'appOwnerOrganizationId', 'verifiedPublisher', 'publisherName' -ErrorAction Stop }
            $name = [string]$sp.DisplayName
            $verified = [string]$sp.VerifiedPublisher.DisplayName
            $publisher = $verified
            if (-not $publisher) { $publisher = [string]$sp.PublisherName }
            $microsoft = ([string]$sp.AppOwnerOrganizationId -eq $microsoftTenant)
        }
        catch { Write-MSPLog -Level WARN -Message ('App {0} not readable: {1}' -f $g.ClientId, $_.Exception.Message) }
        $scopeText = ([string]$g.Scope).Trim()
        $isRecent = $recentNames -contains $name
        $mailFile = $scopeText -match $mailFileScopes
        $rows.Add([pscustomobject]@{ App = $name; Publisher = $publisher; Microsoft = $microsoft; ConsentType = [string]$g.ConsentType; Scopes = $scopeText; GrantedInWindow = $isRecent })
        if ($microsoft -and -not $isRecent) { continue }
        if ($isRecent -or $mailFile) {
            $why = @()
            if ($isRecent) { $why += ('consented in the last {0} days' -f $Days); $high = $true }
            if ($mailFile) { $why += 'mail/file access' }
            if (-not $verified) { $why += 'publisher not verified' }
            $flag.Add(('"{0}" ({1}; scopes: {2})' -f $name, ($why -join ', '), $scopeText))
            Add-Step -Topic 'consent' -Text ('Review the app consent "{0}" and remove it if the user did not mean to grant it (Entra admin center > Enterprise applications > the app > Permissions / Users).' -f $name)
        }
    }
    Add-MSPData -Name 'AppConsents' -Rows $rows.ToArray()
    if ($flag.Count -gt 0) {
        $sev = 'Medium'
        if ($high) { $sev = 'High' }
        Add-Finding -Check 'App consents' -Category 'Apps' -Status WARN -Severity $sev `
            -Detail ('{0} of {1} app grant(s) need a look: {2}.' -f $flag.Count, $grants.Count, ($flag -join '; ')) `
            -Recommendation 'An app the user consented to keeps reading mail or files after a password reset (its token is not tied to the password). Confirm each with the user.'
    }
    else {
        Add-Finding -Check 'App consents' -Category 'Apps' -Status PASS -Detail ('{0} app grant(s); none recent and none from a third party with mail or file access.' -f $grants.Count)
    }
}

# =========================================================================================
Write-MSPSection -Title 'Sent mail and the audit log'
# =========================================================================================
Invoke-UserCheck -Name 'Sent mail' -Category 'Mail flow' -ScriptBlock {
    Assert-Mailbox
    $all = New-Object System.Collections.Generic.List[object]
    $capped = $false
    # Message trace answers at most 10 days per query.
    $start = $since
    while ($start -lt $now) {
        $end = $start.AddDays(10)
        if ($end -gt $now) { $end = $now }
        $part = @(Invoke-Exchange { Get-MessageTraceV2 -SenderAddress $target -StartDate $start -EndDate $end -ResultSize 5000 -ErrorAction Stop })
        if ($part.Count -ge 5000) { $capped = $true }
        foreach ($m in $part) { $all.Add($m) }
        $start = $end
    }
    $byDay = @{}
    for ($d = $since.Date; $d -le $now.Date; $d = $d.AddDays(1)) { $byDay[$d.ToString('yyyy-MM-dd')] = 0 }
    foreach ($m in $all) { $k = ([datetime]$m.Received).ToString('yyyy-MM-dd'); if ($byDay.ContainsKey($k)) { $byDay[$k]++ } }
    $rows = @($byDay.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Day = $_; Sent = $byDay[$_] } })
    Add-MSPData -Name 'SentPerDay' -Rows $rows
    $counts = @($rows | ForEach-Object { $_.Sent } | Sort-Object)
    $median = 0
    if ($counts.Count -gt 0) { $median = $counts[[int][math]::Floor(($counts.Count - 1) / 2)] }
    $spikes = @($rows | Where-Object { $_.Sent -ge 20 -and $_.Sent -ge (3 * [math]::Max($median, 1)) })
    $note = ''
    if ($capped) { $note = ' At least one 10-day piece hit 5000 messages, so the counts are a minimum.' }
    $evidence = @{ Total = $all.Count; MedianPerDay = $median }
    if ($spikes.Count -gt 0) {
        Add-Finding -Check 'Sent mail' -Category 'Mail flow' -Status WARN -Severity High -Evidence $evidence `
            -Detail ('{0} message(s) sent in {1} days (usually {2} a day); unusual days: {3}.{4}' -f $all.Count, $Days, $median, ((@($spikes | ForEach-Object { '{0}: {1}' -f $_.Day, $_.Sent })) -join ', '), $note) `
            -Recommendation 'A burst of sent mail is typical of a compromised account sending phishing to contacts. Check the Sent Items and the message trace for those days; warn the recipients.'
        Add-Step -Topic 'sent' -Text ('Check Sent Items, Deleted Items and the message trace for {0}; warn the people who received phishing.' -f ((@($spikes | ForEach-Object { $_.Day })) -join ', '))
        $today = @($spikes | Where-Object { $_.Day -eq $now.ToString('yyyy-MM-dd') })
        if ($today.Count -gt 0) { $script:urgent.Add(('{0} messages sent today' -f $today[0].Sent)) }
    }
    else {
        Add-Finding -Check 'Sent mail' -Category 'Mail flow' -Status PASS -Evidence $evidence -Detail ('{0} message(s) sent in {1} days (usually {2} a day); no unusual day.{3}' -f $all.Count, $Days, $median, $note)
    }
}

Invoke-UserCheck -Name 'Audit log' -Category 'Audit' -ScriptBlock {
    $config = Invoke-Exchange { Get-AdminAuditLogConfig -ErrorAction Stop }
    if (-not $config.UnifiedAuditLogIngestionEnabled) {
        Skip-MSPCheck -Reason 'Auditing (the unified audit log) is turned off in this tenant, so there is no record to search.' `
            -Recommendation 'Turn auditing on (Purview portal > Audit, or Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true) so the next incident can be investigated; it does not cover the past.'
    }
    $mine = @(Invoke-Exchange -RoleHint $auditRoleHint { Search-UnifiedAuditLog -StartDate $since -EndDate $now -UserIds $target -ResultSize 5000 -ErrorAction Stop })
    $changeOps = @('New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Set-Mailbox', 'Add-MailboxPermission', 'Add-RecipientPermission', 'Set-MailboxJunkEmailConfiguration')
    $others = @(Invoke-Exchange -RoleHint $auditRoleHint { Search-UnifiedAuditLog -StartDate $since -EndDate $now -ObjectIds $target -Operations $changeOps -ResultSize 5000 -ErrorAction Stop })
    $seen = @{}
    $records = @(@($mine) + @($others) | Where-Object { $k = '{0}|{1}|{2}' -f $_.CreationDate, $_.Operations, $_.UserIds; if ($seen.ContainsKey($k)) { $false } else { $seen[$k] = $true; $true } } | Sort-Object { [datetime]$_.CreationDate })
    $rows = foreach ($r in $records) {
        $ip = ''
        try { $ip = [string](([string]$r.AuditData | ConvertFrom-Json).ClientIP) } catch { $ip = '' }
        [pscustomobject]@{ Time = ([datetime]$r.CreationDate).ToString('yyyy-MM-dd HH:mm'); Operation = [string]$r.Operations; By = [string]$r.UserIds; ClientIP = $ip; RecordType = [string]$r.RecordType }
    }
    $rows = @($rows)
    Add-MSPData -Name 'AuditEvents' -Rows $rows
    $summary = (@($rows | Group-Object Operation | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })) -join ', '
    Add-Finding -Check 'Audit log' -Category 'Audit' -Status INFO -Detail ('{0} event(s) in {1} days{2}.' -f $rows.Count, $Days, $(if ($summary) { ': ' + $summary } else { '' }))
    $changes = @($rows | Where-Object { $changeOps -contains $_.Operation })
    if ($changes.Count -gt 0) {
        Add-Finding -Check 'Mailbox changes' -Category 'Audit' -Status WARN -Severity High `
            -Detail ('Rules, forwarding or permissions changed in the window: {0}.' -f ((@($changes | ForEach-Object { '{0} {1} by {2}{3}' -f $_.Time, $_.Operation, $_.By, $(if ($_.ClientIP) { ' from ' + $_.ClientIP } else { '' }) })) -join '; ')) `
            -Recommendation 'Match each change with the rules, forwarding and delegates above; the IP shows where the change came from (compare with the sign-ins).'
    }
    else { Add-Finding -Check 'Mailbox changes' -Category 'Audit' -Status PASS -Detail 'No rule, forwarding or permission change recorded in the window.' }
    $deletes = @($rows | Where-Object { $_.Operation -in @('HardDelete', 'SoftDelete', 'MoveToDeletedItems') })
    if ($deletes.Count -ge 100) {
        Add-Finding -Check 'Mass deletion' -Category 'Audit' -Status WARN -Severity High -Detail ('{0} messages deleted in the window (attackers delete replies and bounce messages to stay hidden).' -f $deletes.Count) `
            -Recommendation 'Check Recoverable Items for what was deleted, and when (compare with the sign-ins).'
    }
}

# =========================================================================================
Write-MSPSection -Title 'What to do now (by hand; this script changed nothing)'
# =========================================================================================
$indicators = @($script:MSPRun.Findings | Where-Object { $_.Status -in @('WARN', 'FAIL') -and $_.Severity -eq 'High' -and $_.Target -eq $target })
if ($indicators.Count -gt 0) {
    Add-Finding -Check 'Compromise indicators' -Category 'Summary' -Status WARN -Severity High `
        -Detail ('{0} sign(s) of compromise: {1}.' -f $indicators.Count, ((@($indicators | ForEach-Object { $_.Check } | Select-Object -Unique)) -join ', ')) `
        -Recommendation 'Contain the account now (steps below), then look for what the attacker did with it.'
}
else {
    Add-Finding -Check 'Compromise indicators' -Category 'Summary' -Status INFO `
        -Detail 'No strong sign of compromise in what could be read. That does not prove the account is safe: check the SKIPPED items by hand.'
}
$steps = New-Object System.Collections.Generic.List[string]
$reset = 'Reset the password of {0} (admin center > Users > Active users > Reset password); give the new one to the user by phone, not email.' -f $target
$revoke = 'Revoke all sessions so stolen tokens stop working: Entra admin center > Users > the user > Revoke sessions (or Revoke-MgUserSignInSession -UserId {0}).' -f $target
if ($urgent.Count -gt 0) {
    # The attacker may be active right now: lock them out first, then end their sessions, then
    # change the password while sign-in is still blocked.
    $steps.Add(('Block sign-in for {0} now (admin center > Users > Active users > Block sign-in), because of {1}. Order matters: blocking stops the attacker signing in again while you work; revoking then ends the sessions they already hold (a password reset alone does not); resetting the password last keeps them out once sign-in is allowed again.' -f $target, ((@($urgent | Select-Object -Unique)) -join '; ')))
    $steps.Add($revoke)
    $steps.Add($reset)
}
else {
    $steps.Add($reset)
    $steps.Add($revoke)
}
foreach ($n in $next) { $steps.Add($n.Text) }
# Generic steps only where no specific step already covers the topic.
$topics = @($next | ForEach-Object { $_.Topic })
if ($topics -notcontains 'mfa') { $steps.Add('Review the MFA methods with the user; delete any they did not add.') }
if ($topics -notcontains 'consent') { $steps.Add('Review the app consents with the user; remove any they did not mean to grant.') }
if ($topics -notcontains 'sent') { $steps.Add('Check Sent Items and Deleted Items for mail the user did not write; warn the recipients of any phishing.') }
if ($urgent.Count -gt 0) { $steps.Add('Allow sign-in again only after the password is reset, the sessions are revoked and the items above are dealt with.') }
$steps.Add('Tell the client what happened and what was changed, and record it in the ticket (keep this report with it).')
$steps = @($steps | Select-Object -Unique)
$i = 0
$stepRows = foreach ($s in $steps) { $i++; Write-Host ('  {0,2}. {1}' -f $i, $s); [pscustomobject]@{ Step = $i; Action = $s } }
Add-MSPData -Name 'NextSteps' -Rows @($stepRows)
Add-Finding -Check 'What to do now' -Category 'Summary' -Status INFO -Detail ((@($stepRows | ForEach-Object { '{0}. {1}' -f $_.Step, $_.Action })) -join ' ')

if ($graphWeConnected -and -not $KeepConnection) {
    try { $null = Disconnect-MgGraph -ErrorAction Stop; Write-MSPLog -Message 'Disconnected from Microsoft Graph.' }
    catch { Write-MSPLog -Level WARN -Message ('Disconnect-MgGraph failed: {0}' -f $_.Exception.Message) }
}
if ($exoWeConnected -and -not $KeepConnection) {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop; Write-MSPLog -Message 'Disconnected from Exchange Online.' }
    catch { Write-MSPLog -Level WARN -Message ('Disconnect-ExchangeOnline failed: {0}' -f $_.Exception.Message) }
}
Complete-MSPRun -OutputPath $OutputPath
