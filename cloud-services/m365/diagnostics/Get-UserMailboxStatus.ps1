<#
.SYNOPSIS
    Read-only Exchange Online mailbox check for one user: size and quota, archive, holds,
    recoverable items, forwarding (mailbox and inbox rules), rules that hide mail, auto-reply,
    mail protocols, mobile devices and delegates.

.DESCRIPTION
    Uses the ExchangeOnlineManagement module with Get- cmdlets only. Nothing in the mailbox or
    the tenant is changed.

    Checks (Target = the mailbox)
      Mailbox              Found, type (user / shared ...), sign-in blocked, last logon.
      Mailbox size         Used against the "prohibit send" quota: 100 % = FAIL (cannot send),
                           90 % or the warning quota = WARN.
      Archive              Archive mailbox on/off and its size; a mailbox over 75 % full without
                           one = WARN.
      Holds                Litigation hold, eDiscovery / retention holds, delay hold, retention
                           hold. Holds are why deleted mail does not free space.
      Recoverable items    Deleted-items storage against its quota (90 % = WARN): when full, the
                           user cannot delete mail.
      Mailbox forwarding   Forwarding set on the mailbox. To an address outside the tenant's
                           domains = WARN High (common after an account takeover).
      Forwarding rules     Enabled inbox rules that forward or redirect = WARN High.
      Rules that hide mail Enabled rules that delete mail or move it to RSS Feeds, Conversation
                           History, Archive or Junk and mark it read = WARN High (the usual
                           pattern after a business email compromise).
      Auto-reply           On / scheduled, and whether outsiders get it.
      Mail apps            Outlook (MAPI), Outlook on the web, mobile (ActiveSync), EWS, POP, IMAP.
                           Outlook or web access switched off = WARN.
      Mobile devices       Each phone/tablet syncing the mailbox; blocked or quarantined = WARN.
      Delegates            Full Access, Send As and Send on Behalf; listed for the client to confirm.

    Sign-in: uses an existing Exchange Online connection when there is one. Otherwise it
    connects (browser, or -DeviceCode) and loads only the read cmdlets this script calls
    (Connect-ExchangeOnline -CommandName). Exchange Online has no read-only sign-in scope:
    what an account may read is set by its admin role, so sign in with Global Reader or
    View-Only Organization Management. The connection is closed at the end unless
    -KeepConnection is given.

.PARAMETER UserPrincipalName
    The mailbox to check (email address or UPN).

.PARAMETER InactiveDeviceDays
    Mobile devices that have not synced for this many days are counted as inactive (7-365,
    default 30).

.PARAMETER DeviceCode
    Sign in with a device code (works over SSH and on computers without a browser).

.PARAMETER KeepConnection
    Leave the Exchange Online connection open at the end.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with InboxRules, MobileDevices
    and Delegates tables.

.EXAMPLE
    pwsh -File .\Get-UserMailboxStatus.ps1 -UserPrincipalName alice@contoso.com

.EXAMPLE
    pwsh -File .\Get-UserMailboxStatus.ps1 -UserPrincipalName alice@contoso.com -DeviceCode -OutputPath ~/Desktop/Ticket123

.NOTES
    Purpose       : Answer "what is wrong with this mailbox, and has anyone tampered with it?"
    Use Case      : "Email not working", mailbox full, phone not syncing, suspected compromise
                    (forwarding and hiding rules), departing-user checks.
    Scope         : One mailbox in the signed-in admin's Exchange Online tenant. Nothing on this
                    computer is read or changed.
    Risk Level    : Read-Only -- Get- cmdlets only; the connection loads no other cmdlets.
    Prerequisites : PowerShell 7 (Windows, macOS, Linux) | Module: ExchangeOnlineManagement 3.x
                    (Install-Module ExchangeOnlineManagement -Scope CurrentUser) | Account:
                    Global Reader or View-Only Organization Management (Exchange)
    Version       : 2.0.0
    Limitations   : Rules created in other mail clients or hidden by an attacker through MAPI
                    may not be listed by Get-InboxRule; check the message trace and the
                    unified audit log in a suspected compromise. Transport (organization) rules
                    and outbound spam policy are not checked.
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][Alias('EmailAddress', 'Identity')][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
    [ValidateRange(7, 365)][int]$InactiveDeviceDays = 30,
    [switch]$DeviceCode,
    [switch]$KeepConnection,
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core,Change
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Change | SHA256: ab51e62fe464996b1ba69106b38fcdc5cc974c2d2f441c6448772439d56c35e0
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

$ScriptVersion = '2.0.0'
Initialize-MSPRun -ScriptName 'Get-UserMailboxStatus' -ScriptVersion $ScriptVersion -CheckId 'C1' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Exchange Online mailbox: size, archive, holds, forwarding, rules, devices (read-only)'

# The only Exchange cmdlets the connection loads (Get-EXO* cmdlets are part of the module).
$readCmdlets = @('Get-InboxRule', 'Get-MailboxAutoReplyConfiguration', 'Get-AcceptedDomain')
$roleHint = 'Sign in with an account that has the Global Reader or View-Only Organization Management role.'
$now = Get-Date
$target = $UserPrincipalName

function Invoke-TargetCheck {
    <#
        Invoke-MSPCheck for a check about one user or mailbox: a SKIPPED or ERROR finding it
        records gets that user as its Target (instead of this computer), like the others.
    #>
    param([string]$CheckTarget, [string]$Name, [string]$Category, [scriptblock]$ScriptBlock)
    $before = $script:MSPRun.Findings.Count
    Invoke-MSPCheck -Name $Name -Category $Category -ScriptBlock $ScriptBlock
    for ($i = $before; $i -lt $script:MSPRun.Findings.Count; $i++) {
        $f = $script:MSPRun.Findings[$i]
        if ($f.Status -in @('SKIPPED', 'ERROR') -and $f.Target -eq $script:MSPRun.Host) { $f.Target = $CheckTarget }
    }
}

function ConvertTo-ByteCount {
    <#
        Exchange sizes arrive as ByteQuantifiedSize objects or as text such as
        "1.5 GB (1,610,612,736 bytes)". Returns the byte count, or $null for "Unlimited"/empty.
    #>
    param($Size)
    if ($null -eq $Size) { return $null }
    if ($Size.PSObject.Properties['Value'] -and $Size.Value -and $Size.Value.PSObject.Methods['ToBytes']) { return [double]$Size.Value.ToBytes() }
    $m = [regex]::Match([string]$Size, '\(([\d,.]+) bytes\)')
    if ($m.Success) { return [double]($m.Groups[1].Value -replace '[,.]', '') }
    return $null
}
function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    return ('{0:N0} MB' -f ($Bytes / 1MB))
}
function Test-AccessDenied {
    <# True for Exchange's "not allowed" answers (role missing). #>
    param($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'is not recognized as a name of a cmdlet|not within the scope|Access is denied|AccessDenied|UnAuthorized|Unauthorized|Forbidden|403|insufficient')
}
function Invoke-Exchange {
    <# Runs one read call; a role problem becomes SKIPPED with the role to use. #>
    param([scriptblock]$Call)
    try { & $Call }
    catch {
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason ('The signed-in account may not read this ({0}).' -f $_.Exception.Message.Split([Environment]::NewLine)[0]) -Recommendation $roleHint }
        throw
    }
}

# =========================================================================================
Write-MSPSection -Title 'Exchange Online connection'
# =========================================================================================
$connected = $false
$weConnected = $false
Invoke-MSPCheck -Name 'Exchange connection' -Category 'Connection' -ScriptBlock {
    if (-not (Get-Command -Name Get-EXOMailbox -ErrorAction SilentlyContinue)) {
        Skip-MSPCheck -Reason 'The ExchangeOnlineManagement module is not installed, so nothing could be read.' `
            -Recommendation 'Install it once (no admin rights needed): Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    $connection = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Connected' }) | Select-Object -First 1
    if (-not $connection) {
        if (-not $DeviceCode -and -not (Test-MSPInteractive)) {
            Skip-MSPCheck -Reason 'Not connected to Exchange Online, and this session cannot show a sign-in window.' `
                -Recommendation 'Run from a terminal, add -DeviceCode, or run Connect-ExchangeOnline first.'
        }
        Write-Host ('  Connecting to Exchange Online; loading only: Get-EXO* cmdlets, {0}' -f ($readCmdlets -join ', ')) -ForegroundColor Cyan
        $connectArgs = @{ ShowBanner = $false; CommandName = $readCmdlets; SkipLoadingFormatData = $true; ErrorAction = 'Stop' }
        if ($DeviceCode) { $connectArgs['Device'] = $true }
        Connect-ExchangeOnline @connectArgs
        $script:weConnected = $true
        $connection = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Connected' }) | Select-Object -First 1
    }
    if (-not $connection) { throw 'The sign-in did not complete.' }
    $script:connected = $true
    Add-MSPFinding -Check 'Exchange connection' -Category 'Connection' -Status INFO `
        -Detail ('Signed in as {0} (tenant {1}).' -f $connection.UserPrincipalName, $connection.TenantID) `
        -Evidence @{ Account = [string]$connection.UserPrincipalName; TenantId = [string]$connection.TenantID; ConnectedByScript = $script:weConnected }
}
if (-not $connected) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

# =========================================================================================
Write-MSPSection -Title ('Mailbox {0}' -f $target)
# =========================================================================================
$mailbox = $null
$stats = $null
Invoke-TargetCheck -CheckTarget $target -Name 'Mailbox' -Category 'Mailbox' -ScriptBlock {
    $props = 'RecipientTypeDetails', 'AccountDisabled', 'ProhibitSendQuota', 'ProhibitSendReceiveQuota', 'IssueWarningQuota', 'RecoverableItemsQuota',
    'ArchiveStatus', 'ArchiveGuid', 'AutoExpandingArchiveEnabled', 'LitigationHoldEnabled', 'LitigationHoldDate', 'InPlaceHolds', 'ComplianceTagHoldApplied',
    'DelayHoldApplied', 'RetentionHoldEnabled', 'ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward', 'GrantSendOnBehalfTo'
    try { $script:mailbox = Invoke-Exchange { Get-EXOMailbox -Identity $target -Properties $props -ErrorAction Stop } }
    catch {
        if ([string]$_.Exception.Message -match "couldn't be found|could not be found|ManagementObjectNotFound|not found") {
            Add-MSPFinding -Check 'Mailbox' -Category 'Mailbox' -Target $target -Status FAIL -Severity High `
                -Detail ('No mailbox {0} in this tenant.' -f $target) `
                -Recommendation 'Check the address. If the user exists, confirm they have a license that includes Exchange Online (C2 Get-UserLicenseReport.ps1).'
            return
        }
        throw
    }
    $script:stats = Invoke-Exchange { Get-EXOMailboxStatistics -Identity $target -Properties LastLogonTime -ErrorAction Stop }
    $last = 'never'
    if ($stats.LastLogonTime) { $last = ([datetime]$stats.LastLogonTime).ToString('yyyy-MM-dd HH:mm') }
    $type = [string]$mailbox.RecipientTypeDetails
    $evidence = @{ Type = $type; AccountDisabled = [bool]$mailbox.AccountDisabled; LastLogon = $last; Items = [int]$stats.ItemCount }
    $text = '{0}, {1} item(s), last logon {2}.' -f $type, $stats.ItemCount, $last
    if ($mailbox.AccountDisabled -and $type -eq 'UserMailbox') {
        Add-MSPFinding -Check 'Mailbox' -Category 'Mailbox' -Target $target -Status WARN -Severity Low -Evidence $evidence `
            -Detail ('{0} Sign-in to the account is blocked.' -f $text) `
            -Recommendation 'If the person has left, convert it to a shared mailbox (no license needed under 50 GB); if not, unblock sign-in in the admin center.'
    }
    else {
        Add-MSPFinding -Check 'Mailbox' -Category 'Mailbox' -Target $target -Status INFO -Evidence $evidence -Detail $text
    }
}
if (-not $mailbox) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}
$usedBytes = ConvertTo-ByteCount $stats.TotalItemSize
$sendQuota = ConvertTo-ByteCount $mailbox.ProhibitSendQuota
$percent = $null
if ($usedBytes -and $sendQuota) { $percent = [math]::Round(100 * $usedBytes / $sendQuota, 1) }

Invoke-TargetCheck -CheckTarget $target -Name 'Mailbox size' -Category 'Storage' -ScriptBlock {
    if ($null -eq $usedBytes) { throw ('Exchange did not report the mailbox size ({0}).' -f $stats.TotalItemSize) }
    $warnQuota = ConvertTo-ByteCount $mailbox.IssueWarningQuota
    $evidence = @{ UsedBytes = $usedBytes; ProhibitSendBytes = $sendQuota; Percent = $percent }
    if (-not $sendQuota) {
        Add-MSPFinding -Check 'Mailbox size' -Category 'Storage' -Target $target -Status PASS -Evidence $evidence -Detail ('{0} used; no send limit.' -f (Format-Size $usedBytes))
        return
    }
    $text = '{0} of {1} used ({2} %).' -f (Format-Size $usedBytes), (Format-Size $sendQuota), $percent
    if ($percent -ge 100) {
        Add-MSPFinding -Check 'Mailbox size' -Category 'Storage' -Target $target -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('{0} The mailbox is full: the user cannot send mail.' -f $text) `
            -Recommendation 'Free space now: empty Deleted Items, delete or archive large old mail, or turn on the archive mailbox (needs an archive-capable license).'
    }
    elseif ($percent -ge 90 -or ($warnQuota -and $usedBytes -ge $warnQuota)) {
        Add-MSPFinding -Check 'Mailbox size' -Category 'Storage' -Target $target -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('{0} Outlook is already warning the user, and sending stops at 100 %.' -f $text) `
            -Recommendation 'Clean up large items or turn on the archive mailbox (and an archive policy) before the mailbox fills.'
    }
    else {
        Add-MSPFinding -Check 'Mailbox size' -Category 'Storage' -Target $target -Status PASS -Evidence $evidence -Detail $text
    }
}

Invoke-TargetCheck -CheckTarget $target -Name 'Archive' -Category 'Storage' -ScriptBlock {
    $active = ([string]$mailbox.ArchiveStatus -eq 'Active') -or ($mailbox.ArchiveGuid -and [string]$mailbox.ArchiveGuid -ne '00000000-0000-0000-0000-000000000000')
    if ($active) {
        $archive = Invoke-Exchange { Get-EXOMailboxStatistics -Identity $target -Archive -ErrorAction Stop }
        $size = ConvertTo-ByteCount $archive.TotalItemSize
        $auto = ''
        if ($mailbox.AutoExpandingArchiveEnabled) { $auto = ', auto-expanding' }
        Add-MSPFinding -Check 'Archive' -Category 'Storage' -Target $target -Status INFO -Evidence @{ ArchiveBytes = $size; AutoExpanding = [bool]$mailbox.AutoExpandingArchiveEnabled } `
            -Detail ('Archive mailbox on{0}: {1} in {2} item(s).' -f $auto, $(if ($null -ne $size) { Format-Size $size } else { 'size unknown' }), $archive.ItemCount)
    }
    elseif ($null -ne $percent -and $percent -ge 75) {
        Add-MSPFinding -Check 'Archive' -Category 'Storage' -Target $target -Status WARN -Severity Low `
            -Detail ('No archive mailbox, and the mailbox is {0} % full.' -f $percent) `
            -Recommendation 'Turn on the archive (Exchange admin center > Mailboxes > the user > Others > Mailbox archive) if the license includes it.'
    }
    else {
        Add-MSPFinding -Check 'Archive' -Category 'Storage' -Target $target -Status INFO -Detail 'No archive mailbox.'
    }
}

$holds = New-Object System.Collections.Generic.List[string]
Invoke-TargetCheck -CheckTarget $target -Name 'Holds' -Category 'Storage' -ScriptBlock {
    if ($mailbox.LitigationHoldEnabled) {
        $since = ''
        if ($mailbox.LitigationHoldDate) { $since = ' since {0:yyyy-MM-dd}' -f [datetime]$mailbox.LitigationHoldDate }
        $holds.Add(('litigation hold{0}' -f $since))
    }
    $inPlace = @($mailbox.InPlaceHolds | Where-Object { $_ })
    if ($inPlace.Count -gt 0) { $holds.Add(('{0} eDiscovery / retention hold(s)' -f $inPlace.Count)) }
    if ($mailbox.ComplianceTagHoldApplied) { $holds.Add('retention label hold') }
    if ($mailbox.DelayHoldApplied) { $holds.Add('delay hold (a hold was removed in the last 30 days)') }
    if ($mailbox.RetentionHoldEnabled) { $holds.Add('retention hold (retention policies paused)') }
    if ($holds.Count -gt 0) {
        Add-MSPFinding -Check 'Holds' -Category 'Storage' -Target $target -Status INFO -Evidence @{ Holds = ($holds -join '; ') } `
            -Detail ('{0}. Deleted mail is kept, so deleting does not free space.' -f ($holds -join '; '))
    }
    else {
        Add-MSPFinding -Check 'Holds' -Category 'Storage' -Target $target -Status PASS -Detail 'No holds.'
    }
}

Invoke-TargetCheck -CheckTarget $target -Name 'Recoverable items' -Category 'Storage' -ScriptBlock {
    $used = ConvertTo-ByteCount $stats.TotalDeletedItemSize
    $quota = ConvertTo-ByteCount $mailbox.RecoverableItemsQuota
    if ($null -eq $used -or -not $quota) { throw 'Exchange did not report the recoverable items size or quota.' }
    $pct = [math]::Round(100 * $used / $quota, 1)
    $text = '{0} of {1} ({2} %).' -f (Format-Size $used), (Format-Size $quota), $pct
    if ($pct -ge 90) {
        $rec = 'Empty "Recoverable Items" in Outlook (Deleted Items > Recover items deleted from this folder).'
        if ($holds.Count -gt 0) { $rec = 'A hold keeps these items: turn on the archive with auto-expanding archiving, or ask whoever placed the hold whether it can be lifted. Do not remove a legal hold without the client''s approval.' }
        Add-MSPFinding -Check 'Recoverable items' -Category 'Storage' -Target $target -Status WARN -Severity Medium -Detail ('{0} When it is full the user cannot delete mail.' -f $text) -Recommendation $rec
    }
    else {
        Add-MSPFinding -Check 'Recoverable items' -Category 'Storage' -Target $target -Status PASS -Detail $text
    }
}

# =========================================================================================
Write-MSPSection -Title 'Forwarding and rules'
# =========================================================================================
$domains = @()
Invoke-TargetCheck -CheckTarget $target -Name 'Accepted domains' -Category 'Forwarding' -ScriptBlock {
    $script:domains = @(Invoke-Exchange { Get-AcceptedDomain -ErrorAction Stop } | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
    Write-MSPLog -Message ('Accepted domains: {0}' -f ($script:domains -join ', '))
}
function Get-ExternalAddress {
    <# The addresses in TEXT whose domain is not one of the tenant's accepted domains. #>
    param([string]$Text)
    if ($domains.Count -eq 0) { return @() }
    return @([regex]::Matches($Text, '[A-Za-z0-9._%+''-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})') | Where-Object { $domains -notcontains $_.Groups[1].Value.ToLowerInvariant() } | ForEach-Object { $_.Value } | Select-Object -Unique)
}

Invoke-TargetCheck -CheckTarget $target -Name 'Mailbox forwarding' -Category 'Forwarding' -ScriptBlock {
    $smtp = ([string]$mailbox.ForwardingSmtpAddress) -replace '^smtp:', ''
    $internal = [string]$mailbox.ForwardingAddress
    $keep = 'a copy stays in the mailbox'
    if (-not $mailbox.DeliverToMailboxAndForward) { $keep = 'NO copy stays in the mailbox' }
    if (-not $smtp -and -not $internal) {
        Add-MSPFinding -Check 'Mailbox forwarding' -Category 'Forwarding' -Target $target -Status PASS -Detail 'No forwarding set on the mailbox.'
        return
    }
    $to = @($smtp, $internal) | Where-Object { $_ }
    $external = @(Get-ExternalAddress -Text $smtp)
    $evidence = @{ ForwardingSmtpAddress = $smtp; ForwardingAddress = $internal; KeepCopy = [bool]$mailbox.DeliverToMailboxAndForward }
    if ($external.Count -gt 0 -or ($smtp -and $domains.Count -eq 0)) {
        Add-MSPFinding -Check 'Mailbox forwarding' -Category 'Forwarding' -Target $target -Status WARN -Severity High -Evidence $evidence `
            -Detail ('All mail is forwarded to {0} ({1}){2}.' -f ($to -join ', '), $keep, $(if ($external.Count -gt 0) { ', outside the organization' } else { '' })) `
            -Recommendation 'Confirm with the user that they set this up. If not, treat the account as compromised: reset the password, sign out all sessions, review MFA methods, and remove the forwarding.'
    }
    else {
        Add-MSPFinding -Check 'Mailbox forwarding' -Category 'Forwarding' -Target $target -Status INFO -Evidence $evidence `
            -Detail ('Mail is forwarded inside the organization to {0} ({1}).' -f ($to -join ', '), $keep)
    }
}

$rules = @()
$rulesRead = $false
Invoke-TargetCheck -CheckTarget $target -Name 'Inbox rules' -Category 'Forwarding' -ScriptBlock {
    $script:rules = @(Invoke-Exchange { Get-InboxRule -Mailbox $target -ErrorAction Stop })
    $script:rulesRead = $true
    $rows = foreach ($r in $script:rules) {
        [pscustomobject]@{
            Name = [string]$r.Name; Enabled = [bool]$r.Enabled; ForwardTo = (@($r.ForwardTo) -join '; '); ForwardAsAttachmentTo = (@($r.ForwardAsAttachmentTo) -join '; ')
            RedirectTo = (@($r.RedirectTo) -join '; '); DeleteMessage = [bool]$r.DeleteMessage; MoveToFolder = [string]$r.MoveToFolder; MarkAsRead = [bool]$r.MarkAsRead
            Description = (([string]$r.Description) -replace '\s+', ' ').Trim()
        }
    }
    Add-MSPData -Name 'InboxRules' -Rows @($rows)
    Add-MSPFinding -Check 'Inbox rules' -Category 'Forwarding' -Target $target -Status INFO -Detail ('{0} rule(s), {1} enabled.' -f $script:rules.Count, @($script:rules | Where-Object { $_.Enabled }).Count)
}

Invoke-TargetCheck -CheckTarget $target -Name 'Forwarding rules' -Category 'Forwarding' -ScriptBlock {
    if (-not $rulesRead) { Skip-MSPCheck -Reason 'The inbox rules could not be read (see Inbox rules).' -Recommendation $roleHint }
    $forwarding = @($rules | Where-Object { $_.Enabled -and ($_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo) })
    if ($forwarding.Count -eq 0) {
        Add-MSPFinding -Check 'Forwarding rules' -Category 'Forwarding' -Target $target -Status PASS -Detail 'No enabled rule forwards or redirects mail.'
        return
    }
    $items = foreach ($r in $forwarding) {
        $to = (@($r.ForwardTo) + @($r.ForwardAsAttachmentTo) + @($r.RedirectTo) | Where-Object { $_ }) -join ', '
        $ext = @(Get-ExternalAddress -Text $to)
        '"{0}" -> {1}{2}' -f $r.Name, $to, $(if ($ext.Count -gt 0) { ' (outside the organization)' } else { '' })
    }
    Add-MSPFinding -Check 'Forwarding rules' -Category 'Forwarding' -Target $target -Status WARN -Severity High `
        -Detail ('{0} rule(s) forward mail: {1}.' -f $forwarding.Count, ($items -join '; ')) `
        -Recommendation 'Confirm each rule with the user. A rule they did not create means the account was taken over: reset the password, sign out all sessions, check MFA methods, then delete the rule.'
}

Invoke-TargetCheck -CheckTarget $target -Name 'Rules that hide mail' -Category 'Forwarding' -ScriptBlock {
    if (-not $rulesRead) { Skip-MSPCheck -Reason 'The inbox rules could not be read (see Inbox rules).' -Recommendation $roleHint }
    $hidingFolders = 'RSS Feeds', 'RSS Subscriptions', 'Conversation History', 'Archive', 'Junk Email', 'Junk E-mail'
    $hiding = @($rules | Where-Object {
            $folder = ([string]$_.MoveToFolder) -replace '^.*\\', ''
            $_.Enabled -and ($_.DeleteMessage -or ($hidingFolders -contains $folder -and ($_.MarkAsRead -or ([string]$_.Name).Trim().Length -le 2)))
        })
    if ($hiding.Count -eq 0) {
        Add-MSPFinding -Check 'Rules that hide mail' -Category 'Forwarding' -Target $target -Status PASS -Detail 'No enabled rule deletes mail or hides it in a rarely opened folder.'
        return
    }
    $items = foreach ($r in $hiding) {
        $action = 'deletes'
        if (-not $r.DeleteMessage) { $action = 'moves to {0} and marks read' -f $r.MoveToFolder }
        '"{0}" {1}' -f $r.Name, $action
    }
    Add-MSPFinding -Check 'Rules that hide mail' -Category 'Forwarding' -Target $target -Status WARN -Severity High `
        -Detail ('{0} rule(s): {1}.' -f $hiding.Count, ($items -join '; ')) `
        -Recommendation 'Ask the user whether they made these rules. Attackers use rules like this to hide replies to fraudulent emails; if unknown, handle as a compromised account and check what was sent from the mailbox.'
}

Invoke-TargetCheck -CheckTarget $target -Name 'Auto-reply' -Category 'Mailbox' -ScriptBlock {
    $auto = Invoke-Exchange { Get-MailboxAutoReplyConfiguration -Identity $target -ErrorAction Stop }
    $state = [string]$auto.AutoReplyState
    if ($state -eq 'Disabled' -or -not $state) {
        Add-MSPFinding -Check 'Auto-reply' -Category 'Mailbox' -Target $target -Status INFO -Detail 'Off.'
        return
    }
    $when = ''
    if ($state -eq 'Scheduled') { $when = ' from {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}' -f [datetime]$auto.StartTime, [datetime]$auto.EndTime }
    Add-MSPFinding -Check 'Auto-reply' -Category 'Mailbox' -Target $target -Status INFO -Evidence @{ State = $state; ExternalAudience = [string]$auto.ExternalAudience } `
        -Detail ('{0}{1}; outside senders: {2}.' -f $state, $when, $auto.ExternalAudience)
}

# =========================================================================================
Write-MSPSection -Title 'Access'
# =========================================================================================
Invoke-TargetCheck -CheckTarget $target -Name 'Mail apps' -Category 'Access' -ScriptBlock {
    $cas = Invoke-Exchange { Get-EXOCasMailbox -Identity $target -Properties MAPIEnabled, OWAEnabled, ActiveSyncEnabled, EwsEnabled, PopEnabled, ImapEnabled -ErrorAction Stop }
    $state = [ordered]@{ Outlook = $cas.MAPIEnabled; 'Outlook on the web' = $cas.OWAEnabled; Mobile = $cas.ActiveSyncEnabled; EWS = $cas.EwsEnabled; POP = $cas.PopEnabled; IMAP = $cas.ImapEnabled }
    $on = @($state.Keys | Where-Object { $state[$_] })
    $off = @($state.Keys | Where-Object { -not $state[$_] })
    $evidence = @{}
    foreach ($k in $state.Keys) { $evidence[$k] = [bool]$state[$k] }
    $blocked = @($off | Where-Object { $_ -in @('Outlook', 'Outlook on the web', 'Mobile') })
    if ($blocked.Count -gt 0) {
        Add-MSPFinding -Check 'Mail apps' -Category 'Access' -Target $target -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('Switched off: {0}. On: {1}.' -f ($off -join ', '), ($on -join ', ')) `
            -Recommendation 'If the user cannot get mail in one of these apps, turn it back on (Exchange admin center > Mailboxes > the user > Email apps), unless it was switched off on purpose.'
    }
    else {
        Add-MSPFinding -Check 'Mail apps' -Category 'Access' -Target $target -Status PASS -Evidence $evidence -Detail ('On: {0}. Off: {1}.' -f ($on -join ', '), $(if ($off) { $off -join ', ' } else { 'none' }))
    }
}

Invoke-TargetCheck -CheckTarget $target -Name 'Mobile devices' -Category 'Access' -ScriptBlock {
    $devices = @(Invoke-Exchange { Get-EXOMobileDeviceStatistics -Mailbox $target -ErrorAction Stop })
    $rows = foreach ($d in $devices) {
        $last = $null
        if ($d.LastSuccessSync) { $last = [datetime]$d.LastSuccessSync }
        [pscustomobject]@{
            Device = ('{0} {1}' -f $d.DeviceManufacturer, $d.DeviceModel).Trim(); OS = [string]$d.DeviceOS; ClientType = [string]$d.ClientType
            AccessState = [string]$d.DeviceAccessState; LastSync = $(if ($last) { $last.ToString('yyyy-MM-dd HH:mm') } else { '' })
            Inactive = ($null -eq $last -or ($now - $last).TotalDays -gt $InactiveDeviceDays)
        }
    }
    $rows = @($rows)
    Add-MSPData -Name 'MobileDevices' -Rows $rows
    $blocked = @($rows | Where-Object { $_.AccessState -in @('Blocked', 'Quarantined') })
    $inactive = @($rows | Where-Object { $_.Inactive }).Count
    if ($blocked.Count -gt 0) {
        Add-MSPFinding -Check 'Mobile devices' -Category 'Access' -Target $target -Status WARN -Severity Medium `
            -Detail ('{0} device(s) blocked or quarantined: {1}.' -f $blocked.Count, (($blocked | ForEach-Object { '{0} ({1})' -f $_.Device, $_.AccessState }) -join '; ')) `
            -Recommendation 'This is why the phone does not sync. Allow it (Exchange admin center > Mobile > quarantined devices) if it is the user''s phone.'
    }
    elseif ($rows.Count -eq 0) {
        Add-MSPFinding -Check 'Mobile devices' -Category 'Access' -Target $target -Status INFO -Detail 'No mobile devices sync this mailbox.'
    }
    else {
        Add-MSPFinding -Check 'Mobile devices' -Category 'Access' -Target $target -Status INFO `
            -Detail ('{0} device(s), {1} not synced in {2} days: {3}.' -f $rows.Count, $inactive, $InactiveDeviceDays, (($rows | ForEach-Object { '{0} (last sync {1})' -f $_.Device, $(if ($_.LastSync) { $_.LastSync } else { 'never' }) }) -join '; '))
    }
}

Invoke-TargetCheck -CheckTarget $target -Name 'Delegates' -Category 'Access' -ScriptBlock {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Invoke-Exchange { Get-EXOMailboxPermission -Identity $target -ErrorAction Stop })) {
        $who = [string]$p.User
        if ($p.IsInherited -or $p.Deny -or $who -match '^NT AUTHORITY\\|^S-1-5-|^NAMPR|Discovery Management|Organization Management') { continue }
        if (@($p.AccessRights) -match 'FullAccess') { $rows.Add([pscustomobject]@{ Delegate = $who; Access = 'Full Access' }) }
    }
    foreach ($p in @(Invoke-Exchange { Get-EXORecipientPermission -Identity $target -ErrorAction Stop })) {
        $who = [string]$p.Trustee
        if ($who -match '^NT AUTHORITY\\' -or $p.IsInherited) { continue }
        if (@($p.AccessRights) -match 'SendAs') { $rows.Add([pscustomobject]@{ Delegate = $who; Access = 'Send As' }) }
    }
    foreach ($who in @($mailbox.GrantSendOnBehalfTo | Where-Object { $_ })) { $rows.Add([pscustomobject]@{ Delegate = [string]$who; Access = 'Send on Behalf' }) }
    Add-MSPData -Name 'Delegates' -Rows $rows.ToArray()
    if ($rows.Count -eq 0) {
        Add-MSPFinding -Check 'Delegates' -Category 'Access' -Target $target -Status PASS -Detail 'Nobody else has access to this mailbox.'
    }
    else {
        Add-MSPFinding -Check 'Delegates' -Category 'Access' -Target $target -Status INFO `
            -Detail ('{0}. Confirm each one with the client; unexpected access is a sign of a takeover.' -f (($rows | ForEach-Object { '{0} ({1})' -f $_.Delegate, $_.Access }) -join '; '))
    }
}

if ($weConnected -and -not $KeepConnection) {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop; Write-MSPLog -Message 'Disconnected from Exchange Online.' }
    catch { Write-MSPLog -Level WARN -Message ('Disconnect-ExchangeOnline failed: {0}' -f $_.Exception.Message) }
}
Complete-MSPRun -OutputPath $OutputPath
