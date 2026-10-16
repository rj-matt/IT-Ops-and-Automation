<#
.SYNOPSIS
    Gives classic Outlook a fresh profile for the signed-in user: backs up the profile settings,
    creates a NEW empty default profile and keeps the old one. The mail account must then be
    added to the new profile by hand.

.DESCRIPTION
    For classic Outlook (Microsoft 365 Apps / Office 2016-2021) problems that a new profile fixes:
    Outlook will not open or hangs on "Loading profile", repeated password prompts, a corrupt
    profile or OST, mailbox not updating.

    What it does, in order:
      1. Pre-flight (read-only): checks it is running as the affected user, finds the Outlook
         profiles and the default profile, lists OST/PST data files and free disk space, and
         checks whether Outlook is open.
      2. Prints the plan and asks you to type YES (-Force skips the question; -WhatIf shows the
         plan only).
      3. If Outlook is open, asks the USER to close it and waits. It never closes Outlook itself
         (that could lose an unsent message). A non-interactive run with Outlook open stops.
      4. Exports the Outlook settings key (including all profiles) to a .reg file under
         %LOCALAPPDATA%\MSP-Toolkit\Backups\OutlookProfile_<time>\ and writes the previous
         default-profile name next to it.
      5. Creates a new, EMPTY profile (default name Outlook-<yyyyMMdd>) and makes it the default.
         Existing profiles, OST and PST files are not touched or deleted.
      6. Prints the steps to finish (add the account) and to roll back.

    THE NEW PROFILE HAS NO ACCOUNT. On the next start Outlook asks to add one: enter the user's
    email address and sign in (Autodiscover fills in the server). If Outlook shows a profile list
    instead, choose the new profile. PST files that were open in the old profile must be
    re-opened (File > Open & Export > Open Outlook Data File). Shared mailboxes added by hand,
    signatures stored in the profile, and other per-profile settings must be set up again.

    Rollback: set the default profile back (the exact command is printed), or import the saved
    .reg file with Outlook closed. The new profile can then be removed in Control Panel > Mail.

.PARAMETER Force
    Do not ask for confirmation. Required for non-interactive runs. Even with -Force the script
    stops if Outlook is open.

.PARAMETER NewProfileName
    Name for the new profile. Default: Outlook-<yyyyMMdd> (a number is added if it exists).

.PARAMETER CloseWaitMinutes
    How long to wait for the user to close Outlook (1-30). Default 10.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0).

.EXAMPLE
    .\Reset-OutlookProfile.ps1 -WhatIf
    Pre-flight and plan only. Changes nothing.

.EXAMPLE
    .\Reset-OutlookProfile.ps1
    Run in a normal PowerShell window as the affected user (not "Run as administrator" with a
    different account). Asks the user to close Outlook if needed, then asks for YES.

.NOTES
    Purpose       : Replace a broken Outlook profile without deleting the old one.
    Use Case      : Outlook will not open, hangs, keeps asking for a password, or stops syncing.
    Scope         : The signed-in user's Outlook profile settings in HKCU. No mailbox, Microsoft
                    365 tenant, OST or PST file is changed.
    Risk Level    : Elevated -- changes which profile Outlook uses; the account must be added
                    again by hand; reversible with the printed steps.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (run as the affected user) | Classic Outlook
                    installed | Modules: built-in only
    Exit codes    : 0 new profile created and set as default (or -WhatIf / nothing to do); 1 nothing
                    changed (wrong user, not confirmed, Outlook still open, non-interactive without
                    -Force); 2 a step failed (see findings)
    Version       : 2.0.0
    Limitations   : Classic Outlook only; the new Outlook for Windows does not use these profiles.
                    Current user only: resetting another user's profile from an admin account is
                    deliberately not supported (it would change the admin's own profile).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [ValidatePattern('^[^\\/:*?"<>|]{1,64}$')][string]$NewProfileName,
    [ValidateRange(1, 30)][int]$CloseWaitMinutes = 10,
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
# Read -WhatIf into our own flag, then switch it off so it cannot reach the log writes and
# module loading. The dry run prints its own "What if:" lines with Write-MSPWhatIf.
$dryRun = [bool]$WhatIfPreference
$WhatIfPreference = $false
Initialize-MSPRun -ScriptName 'Reset-OutlookProfile' -ScriptVersion $ScriptVersion -CheckId 'D3' -RiskLevel 'Elevated' `
    -Parameters $PSBoundParameters -Description 'New default Outlook profile; the old profile is kept (account must be added by hand)'

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$exitCode = 0
$outlookKey = $null
$profilesKey = $null
$profiles = @()
$oldDefault = ''

function Test-OutlookRunning {
    return [bool](Get-Process -Name 'OUTLOOK' -ErrorAction SilentlyContinue)
}

# =========================================================================================
Write-MSPSection -Title 'Pre-flight (read-only)'
# =========================================================================================
$wrongUser = $false
Invoke-MSPCheck -Name 'Running as the affected user' -Category 'Preflight' -ScriptBlock {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $console = [string](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
    if ($console -and $console -ne $me) {
        $script:wrongUser = $true
        Add-MSPFinding -Check 'Running as the affected user' -Category 'Preflight' -Status FAIL -Severity High `
            -Detail ('PowerShell runs as {0}, but {1} is signed in. Changes would go to {0}''s Outlook, not the user''s.' -f $me, $console) `
            -Recommendation 'Open a normal PowerShell window in the user''s own session (not "Run as administrator" with another account) and run again.'
    }
    elseif (-not $console) {
        Add-MSPFinding -Check 'Running as the affected user' -Category 'Preflight' -Status INFO -Detail ('Running as {0} (no console user reported, e.g. a Remote Desktop session). Make sure this is the affected user.' -f $me)
    }
    else {
        Add-MSPFinding -Check 'Running as the affected user' -Category 'Preflight' -Status PASS -Detail ('Running as the signed-in user {0}.' -f $me)
    }
}

Invoke-MSPCheck -Name 'Outlook profiles' -Category 'Preflight' -ScriptBlock {
    foreach ($version in @('16.0', '15.0')) {
        $candidate = 'HKCU:\Software\Microsoft\Office\{0}\Outlook' -f $version
        if (Test-Path -LiteralPath (Join-Path $candidate 'Profiles')) {
            $script:outlookKey = $candidate
            $script:profilesKey = Join-Path $candidate 'Profiles'
            break
        }
    }
    if (-not $script:profilesKey) {
        Add-MSPFinding -Check 'Outlook profiles' -Category 'Preflight' -Status INFO -Detail 'No Outlook profile exists for this user yet. Outlook creates one on first start; nothing to reset.'
        return
    }
    $script:profiles = @(Get-ChildItem -LiteralPath $script:profilesKey -ErrorAction Stop | ForEach-Object { $_.PSChildName })
    $script:oldDefault = [string](Get-ItemProperty -LiteralPath $script:outlookKey -Name DefaultProfile -ErrorAction SilentlyContinue).DefaultProfile
    $pick = [string](Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Exchange\Client\Options' -Name PickLogonProfile -ErrorAction SilentlyContinue).PickLogonProfile
    $detail = 'Profiles: {0}. Default: {1}.' -f ($script:profiles -join ', '), $(if ($script:oldDefault) { $script:oldDefault } else { '(not set)' })
    if ($pick -eq '1') { $detail = '{0} Outlook is set to ask which profile to use at start.' -f $detail }
    Add-MSPFinding -Check 'Outlook profiles' -Category 'Preflight' -Status INFO -Detail $detail -Evidence @{ Key = $script:profilesKey; Profiles = ($script:profiles -join ', '); Default = $script:oldDefault }
}

Invoke-MSPCheck -Name 'Outlook version' -Category 'Preflight' -ScriptBlock {
    $classic = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE' -ErrorAction SilentlyContinue
    $newOutlook = [bool](Get-Process -Name 'olk' -ErrorAction SilentlyContinue) -or [bool](Get-AppxPackage -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue)
    if ($classic) {
        Add-MSPFinding -Check 'Outlook version' -Category 'Preflight' -Status INFO -Detail ('Classic Outlook: {0}' -f $classic.'(default)')
    }
    else {
        Add-MSPFinding -Check 'Outlook version' -Category 'Preflight' -Status WARN -Detail 'Classic Outlook (OUTLOOK.EXE) was not found.' `
            -Recommendation 'This script only helps classic Outlook. For the new Outlook, remove and re-add the account in Outlook settings.'
    }
    if ($newOutlook) {
        Add-MSPFinding -Check 'New Outlook' -Category 'Preflight' -Status INFO -Detail 'The new Outlook for Windows is also present; it does not use these profiles and is not affected.'
    }
}

Invoke-MSPCheck -Name 'Data files' -Category 'Preflight' -ScriptBlock {
    $ostFolder = Join-Path $env:LOCALAPPDATA 'Microsoft\Outlook'
    $osts = @(Get-ChildItem -LiteralPath $ostFolder -Filter '*.ost' -File -ErrorAction SilentlyContinue)
    $psts = @(Get-ChildItem -LiteralPath ([Environment]::GetFolderPath('MyDocuments')) -Filter '*.pst' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue)
    $ostGB = [math]::Round((($osts | Measure-Object -Property Length -Sum).Sum) / 1GB, 2)
    $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop
    $freeGB = [math]::Round($drive.FreeSpace / 1GB, 1)
    Add-MSPFinding -Check 'Data files' -Category 'Preflight' -Status INFO `
        -Detail ('{0} OST file(s), {1} GB total (kept; the new profile downloads a fresh copy). {2} PST file(s) in Documents (kept; re-open them in the new profile if they were in use). {3} GB free.' -f $osts.Count, $ostGB, $psts.Count, $freeGB)
    if ($ostGB -gt 0 -and $freeGB -lt ($ostGB + 5)) {
        Add-MSPFinding -Check 'Disk space for new OST' -Category 'Preflight' -Status WARN -Detail ('The new profile needs about {0} GB for its mailbox copy; only {1} GB is free.' -f $ostGB, $freeGB) `
            -Recommendation 'Free disk space first, or reduce the "Mail to keep offline" setting after adding the account.'
    }
}

$outlookOpen = Test-OutlookRunning
Add-MSPFinding -Check 'Outlook open' -Category 'Preflight' -Status INFO -Detail $(if ($outlookOpen) { 'Outlook is open. It must be closed by the user before any change (this script never closes it).' } else { 'Outlook is closed.' })

if ($wrongUser) {
    Add-MSPFinding -Check 'Result' -Category 'Safety' -Status SKIPPED -Detail 'No changes made: wrong user account (see above).'
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}
if (-not $profilesKey -or $profiles.Count -eq 0) {
    Add-MSPFinding -Check 'Result' -Category 'Safety' -Status INFO -Detail 'Nothing to reset: this user has no Outlook profile.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}

# =========================================================================================
# Plan
# =========================================================================================
if (-not $NewProfileName) { $NewProfileName = 'Outlook-{0}' -f (Get-Date).ToString('yyyyMMdd') }
$baseName = $NewProfileName
$n = 2
while ($profiles -contains $NewProfileName) { $NewProfileName = '{0}-{1}' -f $baseName, $n; $n++ }
$backupDir = Join-Path $env:LOCALAPPDATA ('MSP-Toolkit\Backups\OutlookProfile_{0}' -f $stamp)
$regKey = ($outlookKey -replace '^HKCU:\\', 'HKCU\')
$regFile = Join-Path $backupDir 'Outlook-settings.reg'

Write-MSPChangePlan -Title 'Planned changes (nothing is deleted)' -Step @(
    ('Back up {0} (all profiles) to {1}' -f $regKey, $regFile),
    ('Create a new, EMPTY profile "{0}". Existing profile(s) kept unchanged: {1}' -f $NewProfileName, ($profiles -join ', ')),
    ('Make "{0}" the default profile (was: {1})' -f $NewProfileName, $(if ($oldDefault) { $oldDefault } else { 'not set' })),
    'Afterwards the account must be ADDED BY HAND: start Outlook, enter the user''s email address, sign in',
    'Not touched: OST and PST files, the mailbox, Microsoft 365 settings'
)

if ($dryRun) {
    Write-MSPWhatIf -Target ($regFile) -Action ('Export Outlook settings')
    Write-MSPWhatIf -Target ((Join-Path $profilesKey $NewProfileName)) -Action ('Create empty profile')
    Write-MSPWhatIf -Target (('{0} DefaultProfile' -f $outlookKey)) -Action (('Set to {0}' -f $NewProfileName))
    Add-MSPFinding -Check 'Dry run' -Category 'Safety' -Status INFO -Detail '-WhatIf: the plan was shown; nothing was changed.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}

# Outlook must be closed by the user; never by this script.
if (Test-OutlookRunning) {
    if (-not (Test-MSPInteractive)) {
        Add-MSPFinding -Check 'Outlook open' -Category 'Safety' -Status SKIPPED -Detail 'No changes made: Outlook is open and this session cannot ask the user to close it. This script never closes Outlook itself.' `
            -Recommendation 'Ask the user to close Outlook, then run again.'
        Complete-MSPRun -OutputPath $OutputPath
        exit 1
    }
    $deadline = (Get-Date).AddMinutes($CloseWaitMinutes)
    while ((Test-OutlookRunning) -and (Get-Date) -lt $deadline) {
        Write-Host ''
        Write-Host '  Outlook is open. Ask the user to save any drafts and close Outlook.' -ForegroundColor Yellow
        $answer = Read-Host '  Press Enter when Outlook is closed, or type Q to cancel'
        if ($answer -match '^[Qq]') { break }
        Start-Sleep -Seconds 2
    }
    if (Test-OutlookRunning) {
        Add-MSPFinding -Check 'Outlook open' -Category 'Safety' -Status SKIPPED -Detail 'No changes made: Outlook is still open (cancelled or not closed in time). This script never closes Outlook itself.' `
            -Recommendation 'Close Outlook (check the taskbar and system tray), then run again.'
        Complete-MSPRun -OutputPath $OutputPath
        exit 1
    }
    Add-MSPFinding -Check 'Outlook closed' -Category 'Safety' -Status PASS -Detail 'The user closed Outlook.'
}

if (-not (Confirm-MSPChange -Question ('Create the new default Outlook profile "{0}" for {1}? The account will need to be added by hand.' -f $NewProfileName, $script:MSPRun.User) -Force:$Force)) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}
if (Test-OutlookRunning) {
    Add-MSPFinding -Check 'Outlook open' -Category 'Safety' -Status SKIPPED -Detail 'No changes made: Outlook was opened again before the change.' -Recommendation 'Close Outlook and run again.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

# =========================================================================================
Write-MSPSection -Title 'Backup'
# =========================================================================================
$backupOk = $false
if ($PSCmdlet.ShouldProcess($regFile, 'Export Outlook settings')) {
    try {
        $null = New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop
        $out = @(& reg.exe export $regKey $regFile /y 2>&1 | ForEach-Object { "$_" })
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $regFile)) { throw ('reg export failed (exit {0}): {1}' -f $LASTEXITCODE, ($out -join ' ')) }
        $note = @(
            ('Previous default profile: {0}' -f $(if ($oldDefault) { $oldDefault } else { '(not set)' })),
            ('Profiles before the change: {0}' -f ($profiles -join ', ')),
            ('New profile: {0}' -f $NewProfileName),
            '',
            'Roll back (close Outlook first):',
            $(if ($oldDefault) { ('  reg add "{0}" /v DefaultProfile /t REG_SZ /d "{1}" /f' -f $regKey, $oldDefault) } else { ('  reg delete "{0}" /v DefaultProfile /f' -f $regKey) }),
            ('  or restore everything: reg import "{0}"' -f $regFile),
            '  then remove the new profile: Control Panel > Mail (Microsoft Outlook) > Show Profiles > select it > Remove'
        )
        [System.IO.File]::WriteAllText((Join-Path $backupDir 'previous-default-profile.txt'), ($note -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        $backupOk = $true
        Add-MSPFinding -Check 'Backup' -Category 'Backup' -Status PASS -Detail ('Saved {0}' -f $regFile) -Evidence @{ Folder = $backupDir }
    }
    catch {
        $exitCode = 2
        Add-MSPFinding -Check 'Backup' -Category 'Backup' -Status FAIL -Detail ('Could not back up the Outlook settings: {0}. Nothing was changed.' -f $_.Exception.Message) `
            -Recommendation 'Check free space in the user profile and run again. No change is made without a backup.'
    }
}
if (-not $backupOk) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 2
}

# =========================================================================================
Write-MSPSection -Title 'New profile'
# =========================================================================================
$newKey = Join-Path $profilesKey $NewProfileName
$created = $false
if ($PSCmdlet.ShouldProcess($newKey, 'Create empty profile')) {
    try {
        $null = New-Item -Path $newKey -ErrorAction Stop
        $created = $true
        Add-MSPFinding -Check 'Create profile' -Category 'Change' -Status PASS -Detail ('Created empty profile "{0}".' -f $NewProfileName)
    }
    catch {
        $exitCode = 2
        Add-MSPFinding -Check 'Create profile' -Category 'Change' -Status FAIL -Detail ('Could not create the profile key: {0}. The default profile was not changed.' -f $_.Exception.Message)
    }
}
if ($created -and $PSCmdlet.ShouldProcess(('{0} DefaultProfile' -f $outlookKey), ('Set to {0}' -f $NewProfileName))) {
    try {
        Set-ItemProperty -LiteralPath $outlookKey -Name DefaultProfile -Value $NewProfileName -Type String -ErrorAction Stop
        Add-MSPFinding -Check 'Default profile' -Category 'Change' -Status PASS -Detail ('Default profile: "{0}" -> "{1}".' -f $(if ($oldDefault) { $oldDefault } else { 'not set' }), $NewProfileName)
    }
    catch {
        $exitCode = 2
        Add-MSPFinding -Check 'Default profile' -Category 'Change' -Status FAIL -Detail ('Could not set the default profile: {0}' -f $_.Exception.Message) `
            -Recommendation 'Set it by hand: Control Panel > Mail (Microsoft Outlook) > Show Profiles > "Always use this profile".'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Check and next steps'
# =========================================================================================
$nowDefault = [string](Get-ItemProperty -LiteralPath $outlookKey -Name DefaultProfile -ErrorAction SilentlyContinue).DefaultProfile
$stillThere = @($profiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $profilesKey $_)) })
if ($nowDefault -eq $NewProfileName -and (Test-Path -LiteralPath $newKey)) {
    Add-MSPFinding -Check 'New profile is default' -Category 'After' -Status PASS -Detail ('"{0}" exists and is the default.' -f $NewProfileName)
}
else {
    $exitCode = 2
    Add-MSPFinding -Check 'New profile is default' -Category 'After' -Status FAIL -Detail ('Default profile is "{0}".' -f $nowDefault)
}
if ($stillThere.Count -eq 0) {
    Add-MSPFinding -Check 'Old profiles kept' -Category 'After' -Status PASS -Detail ('Still present: {0}' -f ($profiles -join ', '))
}
else {
    Add-MSPFinding -Check 'Old profiles kept' -Category 'After' -Status WARN -Detail ('Not found any more: {0}' -f ($stillThere -join ', ')) -Recommendation ('Restore from {0}.' -f $regFile)
}
Add-MSPFinding -Check 'Add the account (by hand)' -Category 'After' -Status WARN -Severity Medium `
    -Detail ('The new profile "{0}" has no account yet. Start Outlook; when it asks, enter {1}''s email address and sign in. If Outlook shows a profile list, choose "{0}".' -f $NewProfileName, $env:USERNAME) `
    -Recommendation 'Then re-open any PST files and re-add shared mailboxes or signatures that were set up by hand.'
$rollback = 'reg add "{0}" /v DefaultProfile /t REG_SZ /d "{1}" /f' -f $regKey, $oldDefault
if (-not $oldDefault) { $rollback = 'reg delete "{0}" /v DefaultProfile /f' -f $regKey }
Add-MSPFinding -Check 'Rollback' -Category 'After' -Status INFO `
    -Detail ('With Outlook closed: {0}   (or: reg import "{1}"). Details: {2}' -f $rollback, $regFile, (Join-Path $backupDir 'previous-default-profile.txt'))

Complete-MSPRun -OutputPath $OutputPath
exit $exitCode
