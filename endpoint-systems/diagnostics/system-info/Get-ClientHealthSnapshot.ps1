<#
.SYNOPSIS
    Read-only health snapshot of this PC for a ticket: computer and Windows version, uptime and
    pending restart, memory, CPU load, free disk space, last update installed and updates waiting.

.DESCRIPTION
    Checks
      Computer          Maker, model, serial number, domain or workgroup, signed-in user.
      OS version        Windows edition, version and build, architecture, install date.
      Uptime            Days since the last restart (more than 30 = WARN).
      Restart pending   Windows Update, component servicing, file renames, ConfigMgr.
      Memory            Memory in use (90 % or more = WARN).
      CPU               Average load over 3 seconds (90 % or more = WARN).
      Disk space        Every fixed drive. The system drive is "System drive space", other
                        drives "Disk space <drive>". Less than 10 % (or 5 GB) free = FAIL,
                        less than 20 % (or 15 GB) = WARN; 100 GB or more free is always fine.
      Updates           Last update installed (same thresholds as A6) and updates waiting,
                        from Windows Update's last own scan (no online search).

    For full update compliance (end of support, policies, online search) run
    Get-WindowsUpdateCompliance.ps1 (A6).

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with a Disks table.

.EXAMPLE
    .\Get-ClientHealthSnapshot.ps1

.EXAMPLE
    .\Get-ClientHealthSnapshot.ps1 -OutputPath C:\Temp\Ticket123

.NOTES
    Purpose       : One-screen "how healthy is this PC right now" for the start of a ticket.
    Use Case      : Slow PC, crashes, "it's acting up" tickets; onboarding.
    Scope         : Local computer only. No network traffic.
    Risk Level    : Read-Only -- reads WMI/CIM, the registry and Windows Update's cached results;
                    changes nothing.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: built-in only
    Version       : 2.0.0
    Limitations   : CPU and memory are a snapshot of this moment, not a trend. Pending updates
                    come from Windows' last scan and can be out of date. macOS/Linux version:
                    get-client-health-snapshot.sh (same check names and IDs).
#>
[CmdletBinding()]
param(
    [string]$OutputPath
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

$ScriptVersion = '2.0.0'
Initialize-MSPRun -ScriptName 'Get-ClientHealthSnapshot' -ScriptVersion $ScriptVersion -CheckId 'B1' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Health snapshot: system, uptime, memory, CPU, disk space, updates (read-only)'

$now = Get-Date

function Get-DiskStatus {
    <# PASS/WARN/FAIL for free space, same rule on every platform (see the help text). #>
    param([double]$FreeGB, [double]$PercentFree)
    if ($FreeGB -ge 100) { return 'PASS' }
    if ($PercentFree -lt 10 -or $FreeGB -lt 5) { return 'FAIL' }
    if ($PercentFree -lt 20 -or $FreeGB -lt 15) { return 'WARN' }
    return 'PASS'
}

# =========================================================================================
Write-MSPSection -Title 'System'
# =========================================================================================
Invoke-MSPCheck -Name 'Computer' -Category 'System' -ScriptBlock {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $joined = '{0} (workgroup)' -f $cs.Workgroup
    if ($cs.PartOfDomain) { $joined = '{0} (domain)' -f $cs.Domain }
    $serial = ''
    if ($bios) { $serial = [string]$bios.SerialNumber }
    $evidence = @{ Manufacturer = [string]$cs.Manufacturer; Model = [string]$cs.Model; Serial = $serial; Joined = $joined }
    Add-MSPFinding -Check 'Computer' -Category 'System' -Status INFO -Evidence $evidence `
        -Detail ('{0} {1} (S/N {2}), {3}, user {4}' -f $cs.Manufacturer, $cs.Model, $serial, $joined, $script:MSPRun.User)
}

$os = $null
Invoke-MSPCheck -Name 'OS version' -Category 'System' -ScriptBlock {
    $script:os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $display = ''
    if ($cv) { $display = [string]$cv.DisplayVersion }
    $evidence = @{ Caption = [string]$os.Caption; Version = [string]$os.Version; DisplayVersion = $display; Architecture = [string]$os.OSArchitecture; InstallDate = $os.InstallDate.ToString('yyyy-MM-dd') }
    Add-MSPFinding -Check 'OS version' -Category 'System' -Status INFO -Evidence $evidence `
        -Detail ('{0} {1} (build {2}, {3}), installed {4:yyyy-MM-dd}' -f $os.Caption, $display, $os.BuildNumber, $os.OSArchitecture, $os.InstallDate)
}

Invoke-MSPCheck -Name 'Uptime' -Category 'System' -ScriptBlock {
    if (-not $os) { $script:os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    $up = $now - $os.LastBootUpTime
    $days = [int][math]::Floor($up.TotalDays)
    $evidence = @{ LastBoot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'); Days = $days }
    $text = 'Up {0} day(s) {1} hour(s), since {2:yyyy-MM-dd HH:mm}.' -f $days, $up.Hours, $os.LastBootUpTime
    if ($days -gt 30) {
        Add-MSPFinding -Check 'Uptime' -Category 'System' -Status WARN -Severity Low -Evidence $evidence -Detail $text `
            -Recommendation 'Restart the PC: updates and many fixes only take effect after a restart. (Shut down with Fast Startup does not count as a restart.)'
    }
    else {
        Add-MSPFinding -Check 'Uptime' -Category 'System' -Status PASS -Evidence $evidence -Detail $text
    }
}

Invoke-MSPCheck -Name 'Restart pending' -Category 'System' -ScriptBlock {
    $reasons = @(Get-MSPPendingReboot)
    if ($reasons.Count -gt 0) {
        Add-MSPFinding -Check 'Restart pending' -Category 'System' -Status WARN -Severity Medium -Evidence @{ Reasons = ($reasons -join '; ') } `
            -Detail ('Windows is waiting for a restart: {0}.' -f ($reasons -join ', ')) `
            -Recommendation 'Restart the PC at a convenient time (with the client''s agreement).'
    }
    else {
        Add-MSPFinding -Check 'Restart pending' -Category 'System' -Status PASS -Detail 'No restart pending.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Resources'
# =========================================================================================
Invoke-MSPCheck -Name 'Memory' -Category 'Resources' -ScriptBlock {
    if (-not $os) { $script:os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    $usedPct = [int][math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100)
    $evidence = @{ TotalGB = $totalGB; AvailableGB = $freeGB; UsedPercent = $usedPct }
    $text = '{0} % of {1} GB in use ({2} GB available).' -f $usedPct, $totalGB, $freeGB
    if ($usedPct -ge 90) {
        Add-MSPFinding -Check 'Memory' -Category 'Resources' -Status WARN -Severity Medium -Evidence $evidence -Detail $text `
            -Recommendation 'Close programs and browser tabs that are not needed (Task Manager > Processes, sort by Memory). If it is always this high, the PC needs more memory.'
    }
    else {
        Add-MSPFinding -Check 'Memory' -Category 'Resources' -Status PASS -Evidence $evidence -Detail $text
    }
}

Invoke-MSPCheck -Name 'CPU' -Category 'Resources' -ScriptBlock {
    $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    $samples = @()
    for ($i = 0; $i -lt 3; $i++) {
        if ($i -gt 0) { Start-Sleep -Seconds 1 }
        $samples += (@(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop) | Measure-Object -Property LoadPercentage -Average).Average
    }
    $load = [int][math]::Round(($samples | Measure-Object -Average).Average)
    $cores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
    $logical = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $name = ([string]$cpus[0].Name).Trim()
    $evidence = @{ Name = $name; Cores = $cores; LogicalProcessors = $logical; LoadPercent = $load }
    $text = '{0} ({1} cores / {2} threads): {3} % load over 3 seconds.' -f $name, $cores, $logical, $load
    if ($load -ge 90) {
        Add-MSPFinding -Check 'CPU' -Category 'Resources' -Status WARN -Severity Low -Evidence $evidence -Detail $text `
            -Recommendation 'Find the busy program in Task Manager > Processes (sort by CPU). A short spike is normal; constant high load is not.'
    }
    else {
        Add-MSPFinding -Check 'CPU' -Category 'Resources' -Status PASS -Evidence $evidence -Detail $text
    }
}

Invoke-MSPCheck -Name 'Disk space' -Category 'Resources' -ScriptBlock {
    $systemDrive = $env:SystemDrive
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | Where-Object { $_.Size -gt 0 })
    $rows = foreach ($d in $disks) {
        $sizeGB = [math]::Round($d.Size / 1GB, 1)
        $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
        $pct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
        $status = Get-DiskStatus -FreeGB $freeGB -PercentFree $pct
        $check = 'Disk space {0}' -f $d.DeviceID
        if ($d.DeviceID -eq $systemDrive) { $check = 'System drive space' }
        $label = ''
        if ($d.VolumeName) { $label = ' ({0})' -f $d.VolumeName }
        $text = '{0}{1}: {2} GB free of {3} GB ({4} % free).' -f $d.DeviceID, $label, $freeGB, $sizeGB, $pct
        $evidence = @{ Drive = $d.DeviceID; SizeGB = $sizeGB; FreeGB = $freeGB; PercentFree = $pct }
        switch ($status) {
            'FAIL' {
                Add-MSPFinding -Check $check -Category 'Resources' -Status FAIL -Severity High -Evidence $evidence -Detail $text `
                    -Recommendation 'Free up space now (Settings > System > Storage > Cleanup recommendations; empty Downloads and the Recycle Bin). Windows and updates fail when the drive is nearly full.'
            }
            'WARN' {
                Add-MSPFinding -Check $check -Category 'Resources' -Status WARN -Severity Medium -Evidence $evidence -Detail $text `
                    -Recommendation 'Free up space (Settings > System > Storage) before it runs out; large feature updates need 20 GB or more.'
            }
            default { Add-MSPFinding -Check $check -Category 'Resources' -Status PASS -Evidence $evidence -Detail $text }
        }
        [pscustomobject]@{ Drive = $d.DeviceID; Label = [string]$d.VolumeName; FileSystem = [string]$d.FileSystem; SizeGB = $sizeGB; FreeGB = $freeGB; PercentFree = $pct; Status = $status }
    }
    Add-MSPData -Name 'Disks' -Rows @($rows)
    if ($disks.Count -eq 0) {
        Add-MSPFinding -Check 'System drive space' -Category 'Resources' -Status WARN -Severity Low -Detail 'No fixed drives were reported by Windows.' `
            -Recommendation 'Check Disk Management; escalate if the system drive is not listed.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Updates'
# =========================================================================================
$wu = $null
Invoke-MSPCheck -Name 'Pending updates' -Category 'Updates' -ScriptBlock {
    $script:wu = Get-MSPWindowsUpdateInfo
    $evidence = @{ Pending = $wu.PendingCount; Security = $wu.SecurityPendingCount; LastScan = '' }
    if ($wu.LastSearchSuccess) { $evidence.LastScan = $wu.LastSearchSuccess.ToString('yyyy-MM-dd') }
    $scanText = 'never'
    if ($wu.LastSearchSuccess) { $scanText = $wu.LastSearchSuccess.ToString('yyyy-MM-dd') }
    if ($wu.SecurityPendingCount -gt 0) {
        Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status WARN -Severity High -Evidence $evidence `
            -Detail ('{0} update(s) waiting, {1} of them security updates (Windows'' last scan: {2}).' -f $wu.PendingCount, $wu.SecurityPendingCount, $scanText) `
            -Recommendation 'Install them: Settings > Windows Update > Download and install, then restart.'
    }
    elseif ($wu.PendingCount -gt 0) {
        Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status INFO -Evidence $evidence `
            -Detail ('{0} non-security update(s) waiting (Windows'' last scan: {1}).' -f $wu.PendingCount, $scanText)
    }
    else {
        Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status PASS -Evidence $evidence `
            -Detail ('None waiting at Windows'' last scan ({0}). For a live check run Get-WindowsUpdateCompliance.ps1 -Online.' -f $scanText)
    }
}

Invoke-MSPCheck -Name 'Last update installed' -Category 'Updates' -ScriptBlock {
    $dates = @()
    $newest = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1)
    if ($newest.Count -gt 0) { $dates += $newest[0].InstalledOn }
    if ($wu -and $wu.LastInstallSuccess) { $dates += $wu.LastInstallSuccess }
    if ($dates.Count -eq 0) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status WARN -Severity Medium `
            -Detail 'Windows reports no successful update installation date.' -Recommendation 'Open Settings > Windows Update > Update history and confirm updates are installing.'
        return
    }
    $last = ($dates | Sort-Object -Descending)[0]
    $age = [int]($now - $last).TotalDays
    $evidence = @{ LastInstall = $last.ToString('yyyy-MM-dd'); DaysAgo = $age }
    if ($age -gt 75) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('The last update was installed {0:yyyy-MM-dd} ({1} days ago). At least two monthly security releases are missing.' -f $last, $age) `
            -Recommendation 'Install all updates (Settings > Windows Update) and restart; run Get-WindowsUpdateCompliance.ps1 for the reason updates stopped.'
    }
    elseif ($age -gt 45) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('The last update was installed {0:yyyy-MM-dd} ({1} days ago); last month''s security release appears to be missing.' -f $last, $age) `
            -Recommendation 'Install all updates (Settings > Windows Update) and restart.'
    }
    else {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status PASS -Evidence $evidence -Detail ('{0:yyyy-MM-dd} ({1} days ago).' -f $last, $age)
    }
}

Complete-MSPRun -OutputPath $OutputPath
