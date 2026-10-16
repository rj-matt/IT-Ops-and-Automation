<#
.SYNOPSIS
    Read-only Windows Update compliance check: Windows version and end-of-support date, last
    update installed, pending updates (via the Windows Update API), pending restart, and any
    policy, pause or disabled service that stops updates.

.DESCRIPTION
    Checks
      Windows version   Edition, version (for example 24H2) and build, compared with a built-in
                        Microsoft lifecycle table. Flags versions that are out of support or
                        will be within 90 days.
      Last update       Newest of: Windows Update's "last successful install" and the newest
                        installed update (Get-HotFix). Flags PCs more than 45 / 75 days behind.
      Pending updates   Windows Update COM API. By default reads the result of Windows' last own
                        scan (fast). -Online asks Microsoft's servers now (accurate; can take a
                        few minutes; needs internet). Neither mode downloads or installs anything.
      Restart           Pending-restart flags and uptime.
      Update settings   Group Policy / registry settings that disable or delay updates, a company
                        WSUS server, paused updates, and disabled update services.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 1.0), with PendingUpdates and
    RecentHotfixes tables.

.PARAMETER Online
    Search Microsoft Update now instead of using the last scan result.

.EXAMPLE
    .\Get-WindowsUpdateCompliance.ps1

.EXAMPLE
    .\Get-WindowsUpdateCompliance.ps1 -Online -OutputPath C:\Temp\Audit

.NOTES
    Purpose       : Answer "is this PC getting security updates, and is its Windows version still supported?"
    Use Case      : Home network security audits; patch tickets; onboarding.
    Scope         : Local computer only.
    Risk Level    : Read-Only -- queries Windows Update and reads settings; never downloads, installs,
                    un-pauses or changes anything.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: none (Windows Update COM API) |
                    -Online needs internet access
    Version       : 1.1.0
    Limitations   : The lifecycle table is built in (dates as published by Microsoft, last
                    reviewed 2026-10); update the table when new versions ship. Windows 10
                    Extended Security Updates (ESU) enrolment cannot be detected reliably, so it
                    is reported as a question for the technician. Windows Server lifecycle is
                    not evaluated. Get-HotFix does not list every update type.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Online
)

#region MSPToolkit (generated) Sections=Core,Updates
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Updates | SHA256: 23898c18133df17c9f88e76bb7fbcb52dab91f4429852ef977d75b49d5bee853
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

#region MSPHelper:Updates
function Get-MSPWindowsUpdateInfo {
    <#
        Windows Update status from the built-in Windows Update COM API (works without admin).
        -Online asks Microsoft's servers (accurate, can take minutes, needs internet).
        Without -Online it reads the result of Windows' last own scan (fast; may be stale).
    #>
    [CmdletBinding()]
    param([switch]$Online)
    $info = [ordered]@{
        SearchMode            = 'Cached (last Windows Update scan)'
        LastSearchSuccess     = $null
        LastInstallSuccess    = $null
        PendingCount          = 0
        SecurityPendingCount  = 0
        DriverPendingCount    = 0
        FeatureUpdatePending  = $false
        Pending               = @()
    }
    if ($Online) { $info.SearchMode = 'Online (Microsoft Update servers)' }

    $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
    # These dates are reported in UTC; DateTime.MinValue (year 1) means "never".
    $lastSearch = $autoUpdate.Results.LastSearchSuccessDate
    $lastInstall = $autoUpdate.Results.LastInstallationSuccessDate
    if ($lastSearch -and $lastSearch.Year -gt 2000) { $info.LastSearchSuccess = $lastSearch.ToLocalTime() }
    if ($lastInstall -and $lastInstall.Year -gt 2000) { $info.LastInstallSuccess = $lastInstall.ToLocalTime() }

    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'MSP Toolkit (read-only)'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = [bool]$Online
    $result = $searcher.Search('IsInstalled=0 and IsHidden=0')

    $pending = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $result.Updates.Count; $i++) {
        $update = $result.Updates.Item($i)
        $categories = @()
        foreach ($c in $update.Categories) { $categories += $c.Name }
        $kbs = @()
        foreach ($kb in $update.KBArticleIDs) { $kbs += ('KB{0}' -f $kb) }
        $isDriver = ($update.Type -eq 2)
        $isSecurity = ($update.MsrcSeverity -in @('Critical', 'Important')) -or ($categories -contains 'Security Updates') -or ($categories -contains 'Critical Updates')
        $isFeature = ($categories -contains 'Upgrades')
        $pending.Add([pscustomobject]@{
                Title        = $update.Title
                KB           = ($kbs -join ', ')
                Severity     = [string]$update.MsrcSeverity
                Categories   = ($categories -join ', ')
                IsSecurity   = $isSecurity
                IsDriver     = $isDriver
                IsFeature    = $isFeature
                IsDownloaded = [bool]$update.IsDownloaded
            })
    }
    $info.Pending = $pending.ToArray()
    $info.PendingCount = $pending.Count
    $info.SecurityPendingCount = @($pending | Where-Object { $_.IsSecurity }).Count
    $info.DriverPendingCount = @($pending | Where-Object { $_.IsDriver }).Count
    $info.FeatureUpdatePending = (@($pending | Where-Object { $_.IsFeature }).Count -gt 0)
    return [pscustomobject]$info
}

function Get-MSPPendingReboot {
    <# Reasons Windows is waiting for a restart (empty list = no restart pending). Registry reads only. #>
    $reasons = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('Windows component servicing (CBS)')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('Windows Update')
    }
    $sessionManager = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($sessionManager -and $sessionManager.PendingFileRenameOperations) {
        # Common and often harmless (installers queue file replacements), so reported last.
        $reasons.Add('Pending file rename operations')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData') {
        $reasons.Add('Configuration Manager client')
    }
    return $reasons.ToArray()
}
#endregion MSPHelper:Updates
#endregion MSPToolkit (generated)

$ScriptVersion = '1.1.0'
Initialize-MSPRun -ScriptName 'Get-WindowsUpdateCompliance' -ScriptVersion $ScriptVersion -CheckId 'A6' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Windows Update compliance and end-of-support check (read-only)'

# --- Microsoft lifecycle table -------------------------------------------------------------
# Build -> version and end-of-servicing dates. Consumer = Home/Pro; Business = Enterprise/Education.
# Source: Microsoft Lifecycle / Windows release health pages. Reviewed 2026-10.
$lifecycle = @{
    17763 = @{ Version = '1809'; Product = 'Windows 10'; Consumer = '2020-11-10'; Business = '2021-05-11'; Ltsc = '2029-01-09' }
    18363 = @{ Version = '1909'; Product = 'Windows 10'; Consumer = '2021-05-11'; Business = '2022-05-10' }
    19041 = @{ Version = '2004'; Product = 'Windows 10'; Consumer = '2021-12-14'; Business = '2021-12-14' }
    19042 = @{ Version = '20H2'; Product = 'Windows 10'; Consumer = '2022-05-10'; Business = '2023-05-09' }
    19043 = @{ Version = '21H1'; Product = 'Windows 10'; Consumer = '2022-12-13'; Business = '2022-12-13' }
    19044 = @{ Version = '21H2'; Product = 'Windows 10'; Consumer = '2023-06-13'; Business = '2024-06-11'; Ltsc = '2027-01-12' }
    19045 = @{ Version = '22H2'; Product = 'Windows 10'; Consumer = '2025-10-14'; Business = '2025-10-14' }
    22000 = @{ Version = '21H2'; Product = 'Windows 11'; Consumer = '2023-10-10'; Business = '2024-10-08' }
    22621 = @{ Version = '22H2'; Product = 'Windows 11'; Consumer = '2024-10-08'; Business = '2025-10-14' }
    22631 = @{ Version = '23H2'; Product = 'Windows 11'; Consumer = '2025-11-11'; Business = '2026-11-10' }
    26100 = @{ Version = '24H2'; Product = 'Windows 11'; Consumer = '2026-10-13'; Business = '2027-10-12'; Ltsc = '2029-10-09' }
    26200 = @{ Version = '25H2'; Product = 'Windows 11'; Consumer = '2027-10-12'; Business = '2028-10-10' }
}
# Windows 10 22H2 paid Extended Security Updates: consumer ESU ended 2026-10-13;
# business ESU runs in yearly terms to 2028-10-10.
$win10ConsumerEsuEnd = [datetime]'2026-10-13'
$win10BusinessEsuEnd = [datetime]'2028-10-10'

$now = Get-Date

# =========================================================================================
Write-MSPSection -Title 'Windows version and support'
# =========================================================================================
Invoke-MSPCheck -Name 'Windows version support' -Category 'Lifecycle' -ScriptBlock {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build = [int]$cv.CurrentBuildNumber
    $ubr = [int]$cv.UBR
    $editionId = [string]$cv.EditionID
    $displayVersion = [string]$cv.DisplayVersion
    if (-not $displayVersion) { $displayVersion = [string]$cv.ReleaseId }
    # ProductName still says "Windows 10" on Windows 11; the build number is authoritative.
    $caption = [string]$os.Caption
    $evidence = @{ Caption = $caption; EditionID = $editionId; DisplayVersion = $displayVersion; Build = ('{0}.{1}' -f $build, $ubr) }
    Add-MSPFinding -Check 'Windows version' -Category 'Lifecycle' -Status INFO -Evidence $evidence `
        -Detail ('{0} version {1} (build {2}.{3})' -f $caption, $displayVersion, $build, $ubr)

    if ([int]$os.ProductType -ne 1) {
        Add-MSPFinding -Check 'Windows version support' -Category 'Lifecycle' -Status INFO -Evidence $evidence `
            -Detail 'This is Windows Server; this script does not evaluate Server lifecycle dates.'
        return
    }
    $entry = $lifecycle[$build]
    if (-not $entry) {
        if ($build -lt 17763) {
            Add-MSPFinding -Check 'Windows version support' -Category 'Lifecycle' -Status FAIL -Severity Critical -Evidence $evidence `
                -Detail ('Build {0} is a Windows version that has been out of support for years. It no longer receives security updates.' -f $build) `
                -Recommendation 'Upgrade to a supported Windows 11 version, or replace the PC if it cannot run Windows 11.'
        }
        else {
            Add-MSPFinding -Check 'Windows version support' -Category 'Lifecycle' -Status WARN -Severity Low -Evidence $evidence `
                -Detail ('Build {0} is newer than (or not in) this script''s lifecycle table, so its end-of-support date is unknown here.' -f $build) `
                -Recommendation 'Check the version on Microsoft''s Windows release health page; update this script''s lifecycle table.'
        }
        return
    }

    $channel = 'Consumer'
    $channelLabel = 'Home/Pro'
    if ($editionId -match 'EnterpriseS|IoTEnterpriseS|LTSC') { $channel = 'Ltsc'; $channelLabel = 'LTSC' }
    elseif ($editionId -match 'Enterprise|Education') { $channel = 'Business'; $channelLabel = 'Enterprise/Education' }
    $endText = $entry[$channel]
    if (-not $endText) { $endText = $entry.Consumer; $channelLabel = 'Home/Pro' }
    $end = [datetime]$endText
    $daysLeft = [int]($end - $now.Date).TotalDays
    $evidence.EndOfSupport = $end.ToString('yyyy-MM-dd')
    $evidence.Channel = $channelLabel
    $name = '{0} {1} ({2})' -f $entry.Product, $entry.Version, $channelLabel

    if ($daysLeft -lt 0) {
        $detail = '{0} reached end of support on {1:yyyy-MM-dd} and no longer receives security updates.' -f $name, $end
        $advice = 'Install the latest Windows 11 feature update (Settings > Windows Update), or upgrade/replace the PC if it is not eligible.'
        if ($build -eq 19045) {
            if ($channel -eq 'Consumer') {
                if ($now -gt $win10ConsumerEsuEnd) {
                    $detail += (' Consumer Extended Security Updates (ESU) also ended {0:yyyy-MM-dd}.' -f $win10ConsumerEsuEnd)
                }
                else {
                    $detail += (' Consumer Extended Security Updates (ESU) run until {0:yyyy-MM-dd} if enrolled; confirm in Settings > Windows Update (enrolment cannot be detected by this script).' -f $win10ConsumerEsuEnd)
                }
            }
            else {
                $detail += (' Business ESU (if purchased) can extend security updates until {0:yyyy-MM-dd}; ESU enrolment cannot be detected by this script.' -f $win10BusinessEsuEnd)
            }
            $advice = 'Upgrade to Windows 11 if the PC is eligible (PC Health Check), otherwise plan a replacement. Until then, make sure antivirus is current and the PC is not used for sensitive work.'
        }
        Add-MSPFinding -Check 'Windows version support' -Category 'Lifecycle' -Status FAIL -Severity Critical -Evidence $evidence -Detail $detail -Recommendation $advice
    }
    elseif ($daysLeft -le 90) {
        Add-MSPFinding -Check 'Windows version support' -Category 'Lifecycle' -Status WARN -Severity High -Evidence $evidence `
            -Detail ('{0} reaches end of support on {1:yyyy-MM-dd} ({2} days).' -f $name, $end, $daysLeft) `
            -Recommendation 'Install the latest Windows 11 feature update (Settings > Windows Update > "Download and install") before that date.'
    }
    else {
        Add-MSPFinding -Check 'Windows version support' -Category 'Lifecycle' -Status PASS -Evidence $evidence `
            -Detail ('{0} is supported until {1:yyyy-MM-dd}.' -f $name, $end)
    }
}

# =========================================================================================
Write-MSPSection -Title 'Updates installed and pending'
# =========================================================================================
$wu = $null
Invoke-MSPCheck -Name 'Windows Update status' -Category 'Updates' -ScriptBlock {
    if ($Online) { Write-Host '  Asking Microsoft Update for available updates (can take a few minutes)...' -ForegroundColor DarkGray }
    $script:wu = Get-MSPWindowsUpdateInfo -Online:$Online
}

Invoke-MSPCheck -Name 'Last update installed' -Category 'Updates' -ScriptBlock {
    $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object -Property InstalledOn -Descending)
    Add-MSPData -Name 'RecentHotfixes' -Rows @($hotfixes | Select-Object -First 20 | ForEach-Object {
            [pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $_.InstalledOn.ToString('yyyy-MM-dd') }
        })
    $dates = @()
    if ($hotfixes.Count -gt 0) { $dates += $hotfixes[0].InstalledOn }
    if ($wu -and $wu.LastInstallSuccess) { $dates += $wu.LastInstallSuccess }
    if ($dates.Count -eq 0) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status WARN -Severity Medium `
            -Detail 'Windows reports no successful update installation date.' -Recommendation 'Open Settings > Windows Update > Update history and confirm updates are installing.'
        return
    }
    $last = ($dates | Sort-Object -Descending)[0]
    $age = [int]($now - $last).TotalDays
    $evidence = @{ LastInstall = $last.ToString('yyyy-MM-dd'); DaysAgo = $age }
    if ($hotfixes.Count -gt 0) { $evidence.NewestHotfix = $hotfixes[0].HotFixID }
    # Microsoft releases security updates monthly ("Patch Tuesday"), so >45 days = at least one missed.
    if ($age -gt 75) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('The last update was installed {0:yyyy-MM-dd} ({1} days ago). At least two monthly security releases are missing.' -f $last, $age) `
            -Recommendation 'Run Settings > Windows Update > Check for updates and install everything, then restart. If updates fail, escalate (see Clear-WindowsUpdateCache.ps1).'
    }
    elseif ($age -gt 45) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('The last update was installed {0:yyyy-MM-dd} ({1} days ago); last month''s security release appears to be missing.' -f $last, $age) `
            -Recommendation 'Run Settings > Windows Update > Check for updates and install everything, then restart.'
    }
    else {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status PASS -Evidence $evidence -Detail ('{0:yyyy-MM-dd} ({1} days ago).' -f $last, $age)
    }
}

if ($wu) {
    Invoke-MSPCheck -Name 'Last update scan' -Category 'Updates' -ScriptBlock {
        if (-not $wu.LastSearchSuccess) {
            Add-MSPFinding -Check 'Last update scan' -Category 'Updates' -Status WARN -Severity Medium `
                -Detail 'Windows Update has no record of a successful scan for updates.' -Recommendation 'Run Settings > Windows Update > Check for updates.'
            return
        }
        $age = [int]($now - $wu.LastSearchSuccess).TotalDays
        if ($age -gt 14) {
            Add-MSPFinding -Check 'Last update scan' -Category 'Updates' -Status WARN -Severity Medium `
                -Detail ('Windows last checked for updates successfully on {0:yyyy-MM-dd} ({1} days ago). It normally checks daily.' -f $wu.LastSearchSuccess, $age) `
                -Recommendation 'Run Check for updates; if it fails, check the update settings below and the internet connection.'
        }
        else {
            Add-MSPFinding -Check 'Last update scan' -Category 'Updates' -Status PASS -Detail ('{0:yyyy-MM-dd HH:mm} ({1} day(s) ago).' -f $wu.LastSearchSuccess, $age)
        }
    }

    Invoke-MSPCheck -Name 'Pending updates' -Category 'Updates' -ScriptBlock {
        $rows = @($wu.Pending)
        Add-MSPData -Name 'PendingUpdates' -Rows $rows
        $source = $wu.SearchMode
        if ($rows.Count -eq 0) {
            Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status PASS -Detail ('None. Source: {0}.' -f $source)
            return
        }
        foreach ($r in ($rows | Select-Object -First 15)) { Write-Host ('    - {0}' -f $r.Title) -ForegroundColor Gray }
        if ($wu.SecurityPendingCount -gt 0) {
            $titles = ($rows | Where-Object { $_.IsSecurity } | Select-Object -First 5 | ForEach-Object { $_.Title }) -join '; '
            Add-MSPFinding -Check 'Pending security updates' -Category 'Updates' -Status WARN -Severity High `
                -Detail ('{0} security/critical update(s) waiting: {1}. Source: {2}.' -f $wu.SecurityPendingCount, $titles, $source) `
                -Recommendation 'Install them now: Settings > Windows Update > Download and install, then restart.' `
                -Evidence @{ SecurityPending = $wu.SecurityPendingCount; TotalPending = $wu.PendingCount }
        }
        $other = $wu.PendingCount - $wu.SecurityPendingCount
        if ($other -gt 0) {
            $detail = '{0} other update(s) available ({1} driver).' -f $other, $wu.DriverPendingCount
            if ($wu.FeatureUpdatePending) { $detail += ' Includes a Windows feature update (new version).' }
            Add-MSPFinding -Check 'Other pending updates' -Category 'Updates' -Status INFO -Detail ('{0} Source: {1}.' -f $detail, $source)
        }
        if (-not $Online) {
            Add-MSPFinding -Check 'Pending updates source' -Category 'Updates' -Status INFO `
                -Detail ('Based on Windows'' own last scan ({0:yyyy-MM-dd HH:mm}). Re-run with -Online for a live check.' -f $wu.LastSearchSuccess)
        }
    }
}

Invoke-MSPCheck -Name 'Restart pending' -Category 'Updates' -ScriptBlock {
    $reasons = @(Get-MSPPendingReboot)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $uptimeDays = [int]($now - $os.LastBootUpTime).TotalDays
    if ($reasons.Count -gt 0) {
        Add-MSPFinding -Check 'Restart pending' -Category 'Updates' -Status WARN -Severity Medium `
            -Detail ('Windows is waiting for a restart ({0}). Updates are not fully installed until then. Up {1} day(s).' -f ($reasons -join ', '), $uptimeDays) `
            -Recommendation 'Restart the PC at a convenient time (with the client''s agreement).' -Evidence @{ Reasons = ($reasons -join ', '); UptimeDays = $uptimeDays }
    }
    else {
        Add-MSPFinding -Check 'Restart pending' -Category 'Updates' -Status PASS -Detail ('No restart pending. Up {0} day(s).' -f $uptimeDays)
    }
    if ($uptimeDays -gt 30) {
        Add-MSPFinding -Check 'Uptime' -Category 'Updates' -Status WARN -Severity Low `
            -Detail ('The PC has not restarted for {0} days. Some updates only finish after a restart.' -f $uptimeDays) `
            -Recommendation 'Restart the PC (Start > Power > Restart, not Shut down; Fast Startup makes "Shut down" skip this).'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Update settings'
# =========================================================================================
Invoke-MSPCheck -Name 'Update services' -Category 'Policy' -ScriptBlock {
    $problems = 0
    foreach ($svc in @(@{ Name = 'wuauserv'; Label = 'Windows Update' }, @{ Name = 'UsoSvc'; Label = 'Update Orchestrator' }, @{ Name = 'BITS'; Label = 'Background Intelligent Transfer' })) {
        $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        if ([string]$s.StartType -eq 'Disabled') {
            $problems++
            Add-MSPFinding -Check ('{0} service' -f $svc.Label) -Category 'Policy' -Status FAIL -Severity High `
                -Detail ('The {0} service ({1}) is Disabled, which stops updates.' -f $svc.Label, $svc.Name) `
                -Recommendation 'Set it back to Manual (Services console, as administrator). Ask the client first: some "update blocker" tools do this deliberately.'
        }
    }
    if ($problems -eq 0) { Add-MSPFinding -Check 'Update services' -Category 'Policy' -Status PASS -Detail 'Windows Update services are not disabled.' }
}

Invoke-MSPCheck -Name 'Update policies' -Category 'Policy' -ScriptBlock {
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auKey = Join-Path $wuKey 'AU'
    $wuPol = Get-ItemProperty -LiteralPath $wuKey -ErrorAction SilentlyContinue
    $auPol = Get-ItemProperty -LiteralPath $auKey -ErrorAction SilentlyContinue
    $found = 0
    if ($auPol -and $auPol.NoAutoUpdate -eq 1) {
        $found++
        Add-MSPFinding -Check 'Automatic updates' -Category 'Policy' -Status FAIL -Severity High `
            -Detail ('Automatic updates are turned off by policy ({0}\NoAutoUpdate = 1).' -f $auKey) `
            -Recommendation 'Unless an IT department manages this PC, remove the policy so Windows updates automatically.'
    }
    elseif ($auPol -and $auPol.AUOptions) {
        $found++
        $modes = @{ 2 = 'notify before download'; 3 = 'download automatically, notify to install'; 4 = 'install automatically'; 5 = 'local administrator chooses'; 7 = 'download automatically, notify to restart' }
        $mode = $modes[[int]$auPol.AUOptions]
        if (-not $mode) { $mode = 'option {0}' -f $auPol.AUOptions }
        $status = 'INFO'
        if ([int]$auPol.AUOptions -eq 2) { $status = 'WARN' }
        Add-MSPFinding -Check 'Automatic update mode' -Category 'Policy' -Status $status -Severity Low -Detail ('Set by policy: {0}.' -f $mode) `
            -Recommendation 'On a home PC, "install automatically" is safest.'
    }
    if ($wuPol -and $wuPol.WUServer -and $auPol -and $auPol.UseWUServer -eq 1) {
        $found++
        Add-MSPFinding -Check 'Update server' -Category 'Policy' -Status WARN -Severity Medium `
            -Detail ('Updates come from a company update server (WSUS): {0}. Away from that network, this PC may receive no updates.' -f $wuPol.WUServer) `
            -Recommendation 'If this is a personal PC or the company no longer manages it, remove the WSUS policy (escalate first: it may be a work device).'
    }
    if ($wuPol -and $wuPol.DisableWindowsUpdateAccess -eq 1) {
        $found++
        Add-MSPFinding -Check 'Windows Update access' -Category 'Policy' -Status WARN -Severity Medium `
            -Detail 'The user is blocked from using Windows Update (DisableWindowsUpdateAccess = 1).' -Recommendation 'Remove the policy unless IT manages this PC.'
    }
    if ($wuPol -and $wuPol.DeferQualityUpdates -eq 1 -and $wuPol.DeferQualityUpdatesPeriodInDays) {
        $found++
        $days = [int]$wuPol.DeferQualityUpdatesPeriodInDays
        $status = 'INFO'
        if ($days -gt 14) { $status = 'WARN' }
        Add-MSPFinding -Check 'Security update delay' -Category 'Policy' -Status $status -Severity Low `
            -Detail ('Security/quality updates are deferred {0} day(s) after release.' -f $days) -Recommendation 'On a home PC, set the deferral to 0-7 days.'
    }
    if ($wuPol -and $wuPol.TargetReleaseVersion -eq 1 -and $wuPol.TargetReleaseVersionInfo) {
        $found++
        Add-MSPFinding -Check 'Pinned Windows version' -Category 'Policy' -Status INFO `
            -Detail ('Feature updates are held at {0} {1} by policy. When that version leaves support, this PC will stop getting security updates.' -f $wuPol.ProductVersion, $wuPol.TargetReleaseVersionInfo)
    }
    if ($found -eq 0) {
        Add-MSPFinding -Check 'Update policies' -Category 'Policy' -Status PASS -Detail 'No policies disable or delay Windows Update (normal for a home PC).'
    }
}

Invoke-MSPCheck -Name 'Updates paused' -Category 'Policy' -ScriptBlock {
    $ux = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue
    $until = $null
    foreach ($name in @('PauseUpdatesExpiryTime', 'PauseQualityUpdatesEndTime')) {
        if ($ux -and $ux.PSObject.Properties[$name] -and $ux.$name) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse([string]$ux.$name, [ref]$parsed) -and $parsed -gt $now -and (-not $until -or $parsed -gt $until)) { $until = $parsed }
        }
    }
    if ($until) {
        Add-MSPFinding -Check 'Updates paused' -Category 'Policy' -Status WARN -Severity Medium `
            -Detail ('Windows Update is paused until {0:yyyy-MM-dd}.' -f $until) `
            -Recommendation 'With the client''s agreement: Settings > Windows Update > Resume updates.'
    }
    else {
        Add-MSPFinding -Check 'Updates paused' -Category 'Policy' -Status PASS -Detail 'Updates are not paused.'
    }
}

Complete-MSPRun -OutputPath $OutputPath
