<#
.SYNOPSIS
    Read-only report of who has administrator rights on this PC: every member of the local
    Administrators group, with unused, built-in, password and orphaned-entry checks.

.DESCRIPTION
    Checks
      Administrators                 Every member of Administrators (found by its well-known
                                     SID, so it works on any Windows language): local users,
                                     domain and Entra ID users and groups (Admins table).
      Number of administrators       More enabled administrator accounts than -MaxAdmins
                                     (default 2) = WARN Low.
      Built-in Administrator account Enabled = WARN Medium.
      Unused administrator accounts  Enabled local administrators not signed in for
                                     -StaleDays days (default 90), or never = WARN Medium.
      Administrator password age     Local administrator passwords older than a year = WARN Low
                                     (a sign the same password may be reused on every PC).
      Administrators without a password   Local administrators allowed to have an empty
                                          password = WARN Medium.
      Orphaned administrator entries      Entries for accounts that no longer exist (SID only)
                                          = WARN Low.
      Domain and cloud administrators     Domain / Entra ID users and groups, listed for review.
      Local admin password management     Windows LAPS or legacy LAPS policy present (INFO).

.PARAMETER MaxAdmins
    How many enabled administrator accounts are expected (1-10, default 2).

.PARAMETER StaleDays
    Administrators unused for this many days are flagged (14-3650, default 90).

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with an Admins table.

.EXAMPLE
    .\Get-LocalAdminReport.ps1

.EXAMPLE
    .\Get-LocalAdminReport.ps1 -MaxAdmins 1 -OutputPath C:\Temp\Audit

.NOTES
    Purpose       : Answer "who can install software and change settings on this PC?"
    Use Case      : Onboarding and periodic audits, cyber-insurance questionnaires, offboarding.
    Scope         : This PC only. No network traffic (domain accounts are listed by name; their
                    details are not looked up in the domain).
    Risk Level    : Read-Only -- reads local accounts, group membership and policy; changes nothing.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: built-in only
    Version       : 1.0.0
    Limitations   : Members of nested domain groups are not expanded. Last sign-in and password
                    dates are known for local accounts only. macOS/Linux version:
                    get-local-admin-report.sh (same check names).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 10)][int]$MaxAdmins = 2,
    [ValidateRange(14, 3650)][int]$StaleDays = 90,
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core,LocalAdmin
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,LocalAdmin | SHA256: 0bfaeba99e6bfb059c0ef5a06f4a902f43416379827da1489a4bf927e6da59a5
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

#region MSPHelper:LocalAdmin
function Get-MSPLocalAdminMember {
    <#
        Members of the local Administrators group (found by its well-known SID S-1-5-32-544, so it
        works on non-English Windows). Get-LocalGroupMember fails on some PCs with Entra ID or
        orphaned members; the ADSI fallback still lists them.
    #>
    [CmdletBinding()]
    param()
    $members = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($m in (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
            $members.Add([pscustomobject]@{
                    Name        = $m.Name
                    ObjectClass = [string]$m.ObjectClass
                    Source      = [string]$m.PrincipalSource
                    SID         = [string]$m.SID
                    Method      = 'Get-LocalGroupMember'
                })
        }
    }
    catch {
        Write-MSPLog -Level WARN -Message ('Get-LocalGroupMember failed ({0}); using ADSI fallback.' -f $_.Exception.Message)
        $groupName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]('WinNT://{0}/{1},group' -f $env:COMPUTERNAME, $groupName)
        foreach ($member in @($group.Invoke('Members'))) {
            $path = $member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
            $class = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
            $sidText = ''
            try {
                $sidBytes = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
                $sidText = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            }
            catch {
                $sidText = ''
            }
            $name = ($path -replace '^WinNT://', '') -replace '/', '\'
            $source = 'Unknown'
            if ($sidText -like 'S-1-12-1-*') { $source = 'AzureAD' }
            elseif ($name -like ('{0}\*' -f $env:COMPUTERNAME)) { $source = 'Local' }
            elseif ($name -match '^S-1-') { $source = 'Unknown (orphaned SID)' }
            else { $source = 'ActiveDirectory' }
            $members.Add([pscustomobject]@{ Name = $name; ObjectClass = $class; Source = $source; SID = $sidText; Method = 'ADSI' })
        }
    }
    # Enabled state is only knowable for local accounts; others are left blank, not guessed.
    foreach ($member in $members) {
        $enabled = ''
        if ($member.Source -eq 'Local' -and $member.ObjectClass -eq 'User' -and $member.SID) {
            $localUser = Get-LocalUser -SID $member.SID -ErrorAction SilentlyContinue
            if ($localUser) { $enabled = [string]$localUser.Enabled }
        }
        $member | Add-Member -NotePropertyName Enabled -NotePropertyValue $enabled -Force
        $member | Add-Member -NotePropertyName IsBuiltinAdministrator -NotePropertyValue ($member.SID -like 'S-1-5-21-*-500') -Force
    }
    return $members.ToArray()
}
#endregion MSPHelper:LocalAdmin
#endregion MSPToolkit (generated)

$ScriptVersion = '1.0.0'
Initialize-MSPRun -ScriptName 'Get-LocalAdminReport' -ScriptVersion $ScriptVersion -CheckId 'E1' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Local administrators and their accounts (read-only)'

$now = Get-Date

# =========================================================================================
Write-MSPSection -Title 'Administrators'
# =========================================================================================
$admins = @()
Invoke-MSPCheck -Name 'Administrators' -Category 'Admins' -ScriptBlock {
    $rows = foreach ($m in @(Get-MSPLocalAdminMember)) {
        $user = $null
        if ($m.Source -eq 'Local' -and $m.ObjectClass -eq 'User' -and $m.SID) { $user = Get-LocalUser -SID $m.SID -ErrorAction SilentlyContinue }
        $type = 'Local user'
        if ($m.ObjectClass -eq 'Group') { $type = '{0} group' -f $m.Source }
        elseif ($m.Source -ne 'Local') { $type = '{0} user' -f $m.Source }
        if ($m.Source -like 'Unknown*' -or $m.Name -match '^S-1-') { $type = 'Orphaned (account no longer exists)' }
        [pscustomobject]@{
            Name             = [string]$m.Name
            Type             = $type
            SID              = [string]$m.SID
            Enabled          = $(if ($user) { [bool]$user.Enabled } else { $null })
            BuiltIn          = [bool]$m.IsBuiltinAdministrator
            LastLogon        = $(if ($user -and $user.LastLogon) { ([datetime]$user.LastLogon).ToString('yyyy-MM-dd') } else { '' })
            PasswordLastSet  = $(if ($user -and $user.PasswordLastSet) { ([datetime]$user.PasswordLastSet).ToString('yyyy-MM-dd') } else { '' })
            PasswordRequired = $(if ($user) { [bool]$user.PasswordRequired } else { $null })
            Local            = [bool]$user
        }
    }
    $script:admins = @($rows)
    Add-MSPData -Name 'Admins' -Rows $script:admins
    Add-MSPFinding -Check 'Administrators' -Category 'Admins' -Status INFO `
        -Detail ((@($script:admins | ForEach-Object { '{0} ({1}{2})' -f $_.Name, $_.Type, $(if ($_.Enabled -eq $false) { ', disabled' } else { '' }) })) -join '; ')
}
$localUsers = @($admins | Where-Object { $_.Local })
$enabledLocal = @($localUsers | Where-Object { $_.Enabled })

Invoke-MSPCheck -Name 'Number of administrators' -Category 'Admins' -ScriptBlock {
    $accounts = @($admins | Where-Object { $_.Enabled -or (-not $_.Local -and $_.Type -like '* user') })
    if ($accounts.Count -gt $MaxAdmins) {
        Add-MSPFinding -Check 'Number of administrators' -Category 'Admins' -Status WARN -Severity Low `
            -Detail ('{0} enabled administrator account(s), more than the {1} expected: {2}.' -f $accounts.Count, $MaxAdmins, (($accounts | ForEach-Object { $_.Name }) -join ', ')) `
            -Recommendation 'Every administrator account is one more way in. Make day-to-day accounts Standard users and keep one or two admin accounts.'
    }
    else {
        Add-MSPFinding -Check 'Number of administrators' -Category 'Admins' -Status PASS -Detail ('{0} enabled administrator account(s).' -f $accounts.Count)
    }
}

Invoke-MSPCheck -Name 'Built-in Administrator account' -Category 'Admins' -ScriptBlock {
    $builtin = @($admins | Where-Object { $_.BuiltIn }) | Select-Object -First 1
    if (-not $builtin) {
        $u = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -like 'S-1-5-21-*-500' }) | Select-Object -First 1
        if ($u) { $builtin = [pscustomobject]@{ Name = $u.Name; Enabled = [bool]$u.Enabled } }
    }
    if (-not $builtin) { Add-MSPFinding -Check 'Built-in Administrator account' -Category 'Admins' -Status INFO -Detail 'Not found (renamed or removed by policy).'; return }
    if ($builtin.Enabled) {
        Add-MSPFinding -Check 'Built-in Administrator account' -Category 'Admins' -Status WARN -Severity Medium -Detail ('"{0}" is enabled. Its name is known to attackers and it is never locked out.' -f $builtin.Name) `
            -Recommendation 'Disable it unless it is managed by LAPS (Computer Management > Local Users and Groups > Users), after confirming another administrator account works.'
    }
    else {
        Add-MSPFinding -Check 'Built-in Administrator account' -Category 'Admins' -Status PASS -Detail ('"{0}" is disabled (Windows default).' -f $builtin.Name)
    }
}

Invoke-MSPCheck -Name 'Unused administrator accounts' -Category 'Admins' -ScriptBlock {
    $stale = @($enabledLocal | Where-Object { -not $_.LastLogon -or ($now - [datetime]$_.LastLogon).TotalDays -gt $StaleDays })
    if ($stale.Count -eq 0) { Add-MSPFinding -Check 'Unused administrator accounts' -Category 'Admins' -Status PASS -Detail ('Every enabled local administrator signed in within {0} days.' -f $StaleDays); return }
    Add-MSPFinding -Check 'Unused administrator accounts' -Category 'Admins' -Status WARN -Severity Medium `
        -Detail ((@($stale | ForEach-Object { '{0} (last sign-in {1})' -f $_.Name, $(if ($_.LastLogon) { $_.LastLogon } else { 'never' }) })) -join '; ') `
        -Recommendation 'Unused admin accounts are a favourite target. Confirm with the client, then disable or remove them (or make them Standard users).'
}

Invoke-MSPCheck -Name 'Administrator password age' -Category 'Admins' -ScriptBlock {
    $old = @($enabledLocal | Where-Object { $_.PasswordLastSet -and ($now - [datetime]$_.PasswordLastSet).TotalDays -gt 365 })
    if ($old.Count -eq 0) { Add-MSPFinding -Check 'Administrator password age' -Category 'Admins' -Status PASS -Detail 'No enabled local administrator password is older than a year.'; return }
    Add-MSPFinding -Check 'Administrator password age' -Category 'Admins' -Status WARN -Severity Low `
        -Detail ((@($old | ForEach-Object { '{0} (set {1})' -f $_.Name, $_.PasswordLastSet })) -join '; ') `
        -Recommendation 'Old local admin passwords are often the same on every PC. Give each PC a unique one, ideally managed by Windows LAPS.'
}

Invoke-MSPCheck -Name 'Administrators without a password' -Category 'Admins' -ScriptBlock {
    $none = @($enabledLocal | Where-Object { $_.PasswordRequired -eq $false })
    if ($none.Count -eq 0) { Add-MSPFinding -Check 'Administrators without a password' -Category 'Admins' -Status PASS -Detail 'Every enabled local administrator must have a password.'; return }
    Add-MSPFinding -Check 'Administrators without a password' -Category 'Admins' -Status WARN -Severity Medium `
        -Detail ('Allowed to have an empty password: {0}.' -f (($none | ForEach-Object { $_.Name }) -join ', ')) `
        -Recommendation 'Set a password on these accounts (or remove them). An empty admin password lets anyone at the keyboard take over the PC.'
}

Invoke-MSPCheck -Name 'Orphaned administrator entries' -Category 'Admins' -ScriptBlock {
    $orphans = @($admins | Where-Object { $_.Type -like 'Orphaned*' })
    if ($orphans.Count -eq 0) { Add-MSPFinding -Check 'Orphaned administrator entries' -Category 'Admins' -Status PASS -Detail 'Every member is an existing account or group.'; return }
    Add-MSPFinding -Check 'Orphaned administrator entries' -Category 'Admins' -Status WARN -Severity Low `
        -Detail ('Accounts that no longer exist: {0}.' -f (($orphans | ForEach-Object { if ($_.SID) { $_.SID } else { $_.Name } }) -join ', ')) `
        -Recommendation 'Usually a deleted domain or Entra ID account. Remove the entry from Administrators once you are sure it is not a domain that is just out of reach.'
}

Invoke-MSPCheck -Name 'Domain and cloud administrators' -Category 'Admins' -ScriptBlock {
    $remote = @($admins | Where-Object { -not $_.Local -and $_.Type -notlike 'Orphaned*' -and $_.Type -ne 'Local group' })
    if ($remote.Count -eq 0) { Add-MSPFinding -Check 'Domain and cloud administrators' -Category 'Admins' -Status INFO -Detail 'None: only local accounts are administrators.'; return }
    Add-MSPFinding -Check 'Domain and cloud administrators' -Category 'Admins' -Status INFO `
        -Detail ('{0}. Their members are managed in the domain or Entra ID; review them there.' -f (($remote | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Type }) -join '; '))
}

Invoke-MSPCheck -Name 'Local admin password management' -Category 'Admins' -ScriptBlock {
    $found = @()
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') {
        $p = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        if ($key -like '*\LAPS' -and $null -ne $p.BackupDirectory -and [int]$p.BackupDirectory -ne 0) { $found += ('Windows LAPS (backup to {0})' -f $(if ([int]$p.BackupDirectory -eq 1) { 'Entra ID' } else { 'Active Directory' })) }
        if ($key -like '*AdmPwd' -and [int]$p.AdmPwdEnabled -eq 1) { $found += 'legacy Microsoft LAPS' }
    }
    if ($found.Count -gt 0) { Add-MSPFinding -Check 'Local admin password management' -Category 'Admins' -Status PASS -Detail ('Managed by {0}.' -f ($found -join ', ')); return }
    Add-MSPFinding -Check 'Local admin password management' -Category 'Admins' -Status INFO `
        -Detail 'No LAPS policy found: local administrator passwords are managed by hand (normal for home and small-office PCs).'
}

Complete-MSPRun -OutputPath $OutputPath
