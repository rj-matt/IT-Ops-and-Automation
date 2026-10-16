<#
.SYNOPSIS
    Builds one self-contained HTML security audit report from the JSON results of the home
    network audit scripts: executive summary, prioritized remediation, per-device findings.

.DESCRIPTION
    Reads every toolkit JSON file (schema 1.0) in -InputPath, for example the folder written by
    Invoke-HomeAuditBundle.ps1, and writes a single HTML file with no external links, scripts or
    images, so it can be emailed, printed or saved as PDF from the browser.

    Report sections
      Executive summary     Overall rating, issue counts by priority, the most important items.
      Coverage              Which scripts ran on which device, as administrator or not, and any
                            script that failed to run (from the bundle's own results).
      Remediation plan      Every FAIL/WARN item grouped Critical / High / Medium / Low, with the
                            recommended action and every device/target it affects.
      Router checklist      Answers from Get-RouterSecurityCheck.ps1's guided checklist.
      Per-device findings   Issues first, then all results per script (collapsed).
      Could not check       ERROR (the check itself failed to run) and SKIPPED (for example
                            needs administrator) are listed separately from FAIL: they are gaps
                            in coverage, not problems found.

    When the same script ran more than once on the same computer, only the newest result is used.

.PARAMETER InputPath
    Folder containing the JSON result files.

.PARAMETER TechnicianName
    Name shown on the report as the technician who performed the audit.

.PARAMETER ClientName
    Optional client/household name for the report title.

.PARAMETER ReportPath
    Optional full path of the HTML file. Default: SecurityAuditReport_<yyyyMMdd-HHmm>.html in -InputPath.

.PARAMETER Recurse
    Also read JSON files in sub-folders of -InputPath (for example one folder per PC).

.EXAMPLE
    .\Export-SecurityAuditReport.ps1 -InputPath C:\Temp\HomeAudit_PC1_20261016-1900 -TechnicianName "J. Smith"

.EXAMPLE
    .\Export-SecurityAuditReport.ps1 -InputPath D:\Audits\Smith -Recurse -ClientName "Smith household" -TechnicianName "J. Smith"
    Combines several PCs' result folders into one report.

.NOTES
    Purpose       : Turn raw audit results into a client-ready report with a prioritized fix list.
    Use Case      : Final step of a home network security audit.
    Scope         : Reads JSON files in -InputPath; writes one HTML file. No system or network access.
    Risk Level    : Read-Only -- reads result files and writes the report file only.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: none
    Version       : 1.1.0
    Limitations   : Reports only what the scripts found at the time they ran; it is not a
                    penetration test. Files that are not toolkit schema 1.0 are skipped (listed
                    in the console and log). Router settings marked "Not verified" were not seen.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TechnicianName,
    [string]$ClientName = '',
    [string]$ReportPath,
    [switch]$Recurse
)

#region MSPToolkit (generated) Sections=Core
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core | SHA256: 75e41e4c97747c4b54696e39056282bac01ba630bee10d9b0bed446fb2728602
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
#endregion MSPToolkit (generated)

$ScriptVersion = '1.1.0'
Initialize-MSPRun -ScriptName 'Export-SecurityAuditReport' -ScriptVersion $ScriptVersion -CheckId 'A9' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'HTML security audit report from toolkit JSON results'

# The audit scripts in run order, with a plain-English name for the report.
$auditScripts = [ordered]@{
    'Get-EndpointSecurityStatus'  = 'PC security settings'
    'Get-HomeNetworkMap'          = 'Devices on the network'
    'Get-WiFiSecurityAudit'       = 'Wi-Fi security'
    'Get-OpenPortScan'            = 'Open ports'
    'Get-BrowserSecurityCheck'    = 'Web browsers'
    'Get-WindowsUpdateCompliance' = 'Windows updates'
    'Get-RouterSecurityCheck'     = 'Router'
    'Get-HomeDeviceInventory'     = 'Device and software inventory'
}
$severityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

function ConvertTo-Html5Text {
    <# HTML-encodes any value. Every piece of data from the JSON files goes through this. #>
    param($Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-IssuePriority {
    <# FAIL/WARN items marked "Info" severity still need doing; list them as Low. #>
    param($Finding)
    if ($Finding.Severity -and $Finding.Severity -ne 'Info') { return [string]$Finding.Severity }
    return 'Low'
}

# =========================================================================================
Write-MSPSection -Title 'Reading results'
# =========================================================================================
$results = New-Object System.Collections.Generic.List[object]
$bundleRuns = New-Object System.Collections.Generic.List[object]
Invoke-MSPCheck -Name 'Read result files' -Category 'Input' -ScriptBlock {
    if (-not (Test-Path -LiteralPath $InputPath -PathType Container)) {
        throw ('The folder "{0}" does not exist.' -f $InputPath)
    }
    $files = @(Get-ChildItem -LiteralPath $InputPath -Filter '*.json' -File -Recurse:$Recurse -ErrorAction Stop)
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($file in $files) {
        $data = $null
        try {
            $data = [System.IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
        }
        catch {
            $skipped.Add(('{0} (not valid JSON)' -f $file.Name))
            continue
        }
        if (-not $data.SchemaVersion -or -not $data.ScriptName -or $null -eq $data.Findings) {
            $skipped.Add(('{0} (not a toolkit result file)' -f $file.Name))
            continue
        }
        if ($data.ScriptName -eq 'Export-SecurityAuditReport') { continue }
        $data | Add-Member -NotePropertyName SourceFile -NotePropertyValue $file.FullName -Force
        # Schema 2.0 renamed Computer/StartTime/ScriptVersion to Host/Timestamp/Version. Map 2.0
        # files onto the names used below; 1.0 files only ever came from Windows.
        if ([string]$data.SchemaVersion -like '2.*') {
            $data | Add-Member -NotePropertyName Computer -NotePropertyValue $data.Host -Force
            $data | Add-Member -NotePropertyName StartTime -NotePropertyValue $data.Timestamp -Force
            $data | Add-Member -NotePropertyName ScriptVersion -NotePropertyValue $data.Version -Force
        }
        else {
            $data | Add-Member -NotePropertyName Platform -NotePropertyValue 'Windows' -Force
        }
        if ($data.ScriptName -eq 'Invoke-HomeAuditBundle') { $script:bundleRuns.Add($data) }
        else { $script:results.Add($data) }
    }
    if ($skipped.Count -gt 0) {
        Add-MSPFinding -Check 'Files skipped' -Category 'Input' -Status WARN -Severity Low `
            -Detail ('{0} file(s) ignored: {1}' -f $skipped.Count, ($skipped -join '; ')) -Recommendation 'Only toolkit result files (schema 1.0 or 2.0) are included in the report.'
    }
}

# Keep only the newest run of each script per computer.
$latest = @{}
foreach ($r in $results) {
    $key = '{0}|{1}' -f $r.Computer, $r.ScriptName
    if (-not $latest.ContainsKey($key) -or [datetime]$r.StartTime -gt [datetime]$latest[$key].StartTime) { $latest[$key] = $r }
}
$superseded = $results.Count - $latest.Count
$runs = @($latest.Values | Sort-Object -Property Computer, @{ Expression = { $i = [array]::IndexOf(@($auditScripts.Keys), $_.ScriptName); if ($i -lt 0) { 99 } else { $i } } })

if ($runs.Count -eq 0) {
    Add-MSPFinding -Check 'Audit results' -Category 'Input' -Status FAIL -Severity High `
        -Detail ('No toolkit result files were found in "{0}".' -f $InputPath) `
        -Recommendation 'Run Invoke-HomeAuditBundle.ps1 (or the individual scripts with -OutputPath) first, then point -InputPath at that folder.'
    Complete-MSPRun
    exit 1
}
Add-MSPFinding -Check 'Audit results' -Category 'Input' -Status INFO `
    -Detail ('{0} result file(s) from {1} computer(s) will be reported.' -f $runs.Count, @($runs | ForEach-Object { $_.Computer } | Select-Object -Unique).Count)
if ($superseded -gt 0) {
    Add-MSPFinding -Check 'Older results' -Category 'Input' -Status INFO -Detail ('{0} older duplicate result(s) were ignored; the newest run of each script per computer is used.' -f $superseded)
}

# --- Flatten findings ----------------------------------------------------------------------
$allFindings = New-Object System.Collections.Generic.List[object]
foreach ($run in $runs) {
    foreach ($f in @($run.Findings)) {
        $allFindings.Add([pscustomobject]@{
                Computer       = [string]$run.Computer
                ScriptName     = [string]$run.ScriptName
                Id             = [string]$f.Id
                Category       = [string]$f.Category
                Check          = [string]$f.Check
                Status         = [string]$f.Status
                Severity       = [string]$f.Severity
                Target         = [string]$f.Target
                Detail         = [string]$f.Detail
                Recommendation = [string]$f.Recommendation
            })
    }
}
$computers = @($runs | ForEach-Object { $_.Computer } | Select-Object -Unique | Sort-Object)
$issues = @($allFindings | Where-Object { $_.Status -in @('FAIL', 'WARN') })

# Remediation items: the same check (Id) on several devices/targets becomes one item.
$remediation = foreach ($group in ($issues | Group-Object -Property Id)) {
    $items = @($group.Group)
    $priority = ($items | ForEach-Object { Get-IssuePriority -Finding $_ } | Sort-Object -Property { $severityRank[$_] } | Select-Object -First 1)
    $affected = @($items | ForEach-Object {
            if ($_.Target -and $_.Target -ne $_.Computer) { '{0} ({1})' -f $_.Target, $_.Computer } else { $_.Computer }
        } | Select-Object -Unique)
    $hasFail = @($items | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0
    [pscustomobject]@{
        Priority       = $priority
        Rank           = $severityRank[$priority]
        Status         = $(if ($hasFail) { 'FAIL' } else { 'WARN' })
        Check          = $items[0].Check
        Area           = $(if ($auditScripts.Contains($items[0].ScriptName)) { $auditScripts[$items[0].ScriptName] } else { $items[0].ScriptName })
        Detail         = $items[0].Detail
        Recommendation = ($items | ForEach-Object { $_.Recommendation } | Where-Object { $_ } | Select-Object -First 1)
        Affected       = $affected
    }
}
$remediation = @($remediation | Sort-Object -Property Rank, @{ Expression = { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } }, @{ Expression = { -$_.Affected.Count } })
$priorityCounts = [ordered]@{}
foreach ($p in @('Critical', 'High', 'Medium', 'Low')) { $priorityCounts[$p] = @($remediation | Where-Object { $_.Priority -eq $p }).Count }
$statusCounts = [ordered]@{}
foreach ($s in @('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR')) { $statusCounts[$s] = @($allFindings | Where-Object { $_.Status -eq $s }).Count }

$rating = @{ Label = 'Good'; Css = 'good'; Text = 'No significant security problems were found by the checks that ran.' }
if ($priorityCounts['Critical'] -gt 0) { $rating = @{ Label = 'Action needed now'; Css = 'critical'; Text = 'At least one critical problem leaves this network or a device open to attack. Fix the Critical items first.' } }
elseif ($priorityCounts['High'] -gt 0) { $rating = @{ Label = 'Needs attention'; Css = 'high'; Text = 'There are important gaps that should be fixed soon. Start with the High items.' } }
elseif ($priorityCounts['Medium'] -gt 0 -or $priorityCounts['Low'] -gt 0) { $rating = @{ Label = 'Fair'; Css = 'medium'; Text = 'No urgent problems, but some improvements are recommended.' } }

# Audit scripts the bundle could not run (crash, timeout, file missing). Reported next to ERROR:
# a gap in coverage, never a failed check.
$scriptFailures = @(foreach ($b in $bundleRuns) {
        foreach ($f in @($b.Findings | Where-Object { $_.Category -eq 'Run' -and $_.Status -eq 'ERROR' })) {
            [pscustomobject]@{ Computer = [string]$b.Computer; ScriptName = [string]$f.Check; Detail = [string]$f.Detail }
        }
    })
if ($scriptFailures.Count -gt 0 -and $rating.Css -eq 'good') {
    $rating = @{ Label = 'Incomplete'; Css = 'medium'; Text = 'No problems were found in the areas that were checked, but some audit scripts did not run, so parts of the network were not reviewed.' }
}

# =========================================================================================
Write-MSPSection -Title 'Building report'
# =========================================================================================
$auditStart = ($runs | ForEach-Object { [datetime]$_.StartTime } | Sort-Object | Select-Object -First 1)
$auditEnd = ($runs | ForEach-Object { [datetime]$_.EndTime } | Sort-Object | Select-Object -Last 1)
$title = 'Home Network Security Audit'
if ($ClientName) { $title = '{0} - {1}' -f $title, $ClientName }

$html = New-Object System.Text.StringBuilder
function Add-Html { param([string]$Text) $null = $html.AppendLine($Text) }
function Get-StatusBadge { param([string]$Status) return ('<span class="badge s-{0}">{1}</span>' -f $Status.ToLower(), (ConvertTo-Html5Text $Status)) }
function Get-PriorityBadge { param([string]$Priority) return ('<span class="badge p-{0}">{1}</span>' -f $Priority.ToLower(), (ConvertTo-Html5Text $Priority)) }

Add-Html '<!DOCTYPE html>'
Add-Html '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
Add-Html ('<title>{0}</title>' -f (ConvertTo-Html5Text $title))
Add-Html @'
<style>
:root { --ink:#1f2933; --muted:#5f6b7a; --line:#d9dee5; --bg:#ffffff; --panel:#f5f7fa;
  --pass:#1e7b34; --warn:#9a6700; --fail:#b42318; --info:#1d5fa8; --skip:#5f6b7a; --error:#7a2e9e;
  --critical:#b42318; --high:#c4520f; --medium:#9a6700; --low:#1d5fa8; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 "Segoe UI", Arial, sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:26px; margin:0 0 4px; } h2 { font-size:20px; margin:36px 0 10px; padding-bottom:4px; border-bottom:2px solid var(--line); }
h3 { font-size:16px; margin:22px 0 8px; } .muted { color:var(--muted); } .small { font-size:13px; }
.meta { display:flex; flex-wrap:wrap; gap:6px 24px; color:var(--muted); font-size:14px; margin-bottom:8px; }
.rating { border-radius:8px; padding:16px 18px; margin:16px 0; border-left:8px solid; background:var(--panel); }
.rating.good { border-color:var(--pass); } .rating.medium { border-color:var(--medium); } .rating.high { border-color:var(--high); } .rating.critical { border-color:var(--critical); }
.rating strong { font-size:20px; display:block; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:10px; margin:12px 0; }
.tile { background:var(--panel); border-radius:8px; padding:10px 12px; border-top:4px solid var(--line); }
.tile b { display:block; font-size:24px; } .tile span { font-size:13px; color:var(--muted); }
.tile.critical { border-top-color:var(--critical); } .tile.high { border-top-color:var(--high); } .tile.medium { border-top-color:var(--medium); } .tile.low { border-top-color:var(--low); } .tile.error { border-top-color:var(--error); } .tile.skipped { border-top-color:var(--skip); }
table { width:100%; border-collapse:collapse; margin:8px 0 16px; font-size:14px; }
th, td { text-align:left; vertical-align:top; padding:6px 8px; border-bottom:1px solid var(--line); }
th { background:var(--panel); font-weight:600; } td.num { text-align:right; white-space:nowrap; }
.badge { display:inline-block; min-width:62px; text-align:center; padding:1px 6px; border-radius:4px; font-size:12px; font-weight:600; color:#fff; white-space:nowrap; }
.s-pass { background:var(--pass); } .s-warn { background:var(--warn); } .s-fail { background:var(--fail); } .s-info { background:var(--info); } .s-skipped { background:var(--skip); } .s-error { background:var(--error); }
.p-critical { background:var(--critical); } .p-high { background:var(--high); } .p-medium { background:var(--medium); } .p-low { background:var(--low); }
.item { border:1px solid var(--line); border-left:6px solid var(--line); border-radius:6px; padding:10px 12px; margin:8px 0; break-inside:avoid; }
.item.critical { border-left-color:var(--critical); } .item.high { border-left-color:var(--high); } .item.medium { border-left-color:var(--medium); } .item.low { border-left-color:var(--low); }
.item .fix { margin-top:6px; } .item .fix b { color:var(--ink); }
details { margin:6px 0 14px; } summary { cursor:pointer; color:var(--info); }
.note { background:var(--panel); border-radius:6px; padding:10px 12px; font-size:14px; }
.toc a { margin-right:14px; color:var(--info); }
@media (max-width:640px) { th:nth-child(n+4), td:nth-child(n+4) { display:none; } }
@media print { details { display:block; } details > summary { display:none; } details:not([open]) > * { display:block; } h2 { break-after:avoid; } .item, tr { break-inside:avoid; } .toc { display:none; } }
</style></head><body><main>
'@
Add-Html ('<h1>{0}</h1>' -f (ConvertTo-Html5Text $title))
Add-Html ('<div class="meta"><span>Technician: <b>{0}</b></span><span>Audit performed: {1}</span><span>Report created: {2}</span><span>Devices: {3}</span></div>' -f `
        (ConvertTo-Html5Text $TechnicianName), (ConvertTo-Html5Text ($auditStart.ToString('yyyy-MM-dd HH:mm') + ' to ' + $auditEnd.ToString('yyyy-MM-dd HH:mm'))), (Get-Date).ToString('yyyy-MM-dd HH:mm'), (ConvertTo-Html5Text ($computers -join ', ')))
Add-Html '<div class="toc small"><a href="#summary">Summary</a><a href="#plan">Remediation plan</a><a href="#coverage">Coverage</a><a href="#router">Router checklist</a><a href="#devices">Per-device results</a><a href="#gaps">Could not check</a></div>'

# --- Executive summary -------------------------------------------------------------------
Add-Html '<h2 id="summary">Executive summary</h2>'
Add-Html ('<div class="rating {0}"><strong>{1}</strong>{2}</div>' -f $rating.Css, (ConvertTo-Html5Text $rating.Label), (ConvertTo-Html5Text $rating.Text))
Add-Html '<div class="tiles">'
foreach ($p in $priorityCounts.Keys) { Add-Html ('<div class="tile {0}"><b>{1}</b><span>{2} priority item(s)</span></div>' -f $p.ToLower(), $priorityCounts[$p], $p) }
Add-Html ('<div class="tile error"><b>{0}</b><span>checks could not run (ERROR)</span></div>' -f $statusCounts['ERROR'])
Add-Html ('<div class="tile skipped"><b>{0}</b><span>checks skipped</span></div>' -f $statusCounts['SKIPPED'])
Add-Html '</div>'
if ($scriptFailures.Count -gt 0) {
    Add-Html ('<p class="note"><b>{0} audit script(s) did not run</b> ({1}), so those areas were not checked. See Coverage and Could not check below.</p>' -f `
            $scriptFailures.Count, (ConvertTo-Html5Text (($scriptFailures | ForEach-Object { '{0} on {1}' -f $(if ($auditScripts.Contains($_.ScriptName)) { $auditScripts[$_.ScriptName] } else { $_.ScriptName }), $_.Computer }) -join '; ')))
}
Add-Html ('<p class="small muted">All results: {0} passed, {1} warnings, {2} failed, {3} informational, {4} skipped, {5} could not run. ERROR means the check itself could not run (not that something failed); SKIPPED usually means it needs administrator rights.</p>' -f `
        $statusCounts['PASS'], $statusCounts['WARN'], $statusCounts['FAIL'], $statusCounts['INFO'], $statusCounts['SKIPPED'], $statusCounts['ERROR'])
if ($remediation.Count -gt 0) {
    Add-Html '<h3>Most important items</h3><ol>'
    foreach ($r in ($remediation | Select-Object -First 5)) {
        Add-Html ('<li>{0} <b>{1}</b> - {2}</li>' -f (Get-PriorityBadge $r.Priority), (ConvertTo-Html5Text $r.Check), (ConvertTo-Html5Text $r.Recommendation))
    }
    Add-Html '</ol>'
}

# --- Remediation plan ----------------------------------------------------------------------
Add-Html '<h2 id="plan">Remediation plan</h2>'
if ($remediation.Count -eq 0) {
    Add-Html '<p>No items need fixing based on the checks that ran.</p>'
}
foreach ($p in @('Critical', 'High', 'Medium', 'Low')) {
    $items = @($remediation | Where-Object { $_.Priority -eq $p })
    if ($items.Count -eq 0) { continue }
    $when = @{ Critical = 'Fix now.'; High = 'Fix within a week.'; Medium = 'Fix within a month.'; Low = 'Fix when convenient.' }[$p]
    Add-Html ('<h3>{0} {1} item(s) <span class="muted small">{2}</span></h3>' -f (Get-PriorityBadge $p), $items.Count, $when)
    foreach ($r in $items) {
        Add-Html ('<div class="item {0}">' -f $p.ToLower())
        Add-Html ('<div>{0} <b>{1}</b> <span class="muted small">({2})</span></div>' -f (Get-StatusBadge $r.Status), (ConvertTo-Html5Text $r.Check), (ConvertTo-Html5Text $r.Area))
        Add-Html ('<div class="small">{0}</div>' -f (ConvertTo-Html5Text $r.Detail))
        if ($r.Recommendation) { Add-Html ('<div class="fix"><b>What to do:</b> {0}</div>' -f (ConvertTo-Html5Text $r.Recommendation)) }
        Add-Html ('<div class="small muted">Affects: {0}</div>' -f (ConvertTo-Html5Text ($r.Affected -join ', ')))
        Add-Html '</div>'
    }
}

# --- Coverage ----------------------------------------------------------------------------
Add-Html '<h2 id="coverage">Coverage</h2>'
Add-Html '<table><tr><th>Device</th><th>Check</th><th>Ran</th><th>Admin</th><th class="num">Pass</th><th class="num">Warn</th><th class="num">Fail</th><th class="num">Could not run</th><th class="num">Skipped</th></tr>'
$bundleStatus = @{}
foreach ($b in $bundleRuns) {
    foreach ($f in @($b.Findings | Where-Object { $_.Category -eq 'Run' })) { $bundleStatus[('{0}|{1}' -f $b.Computer, $f.Check)] = $f }
}
foreach ($computer in $computers) {
    foreach ($name in $auditScripts.Keys) {
        $run = $runs | Where-Object { $_.Computer -eq $computer -and $_.ScriptName -eq $name } | Select-Object -First 1
        if ($run) {
            $admin = 'No'
            if ($run.IsAdmin) { $admin = 'Yes' }
            Add-Html ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class="num">{4}</td><td class="num">{5}</td><td class="num">{6}</td><td class="num">{7}</td><td class="num">{8}</td></tr>' -f `
                    (ConvertTo-Html5Text $computer), (ConvertTo-Html5Text $auditScripts[$name]), ([datetime]$run.StartTime).ToString('yyyy-MM-dd HH:mm'), $admin,
                $run.Summary.PASS, $run.Summary.WARN, $run.Summary.FAIL, $run.Summary.ERROR, $run.Summary.SKIPPED)
        }
        else {
            $reason = 'Not run'
            $b = $bundleStatus[('{0}|{1}' -f $computer, $name)]
            if ($b -and $b.Status -eq 'ERROR') { $reason = 'Failed to run: {0}' -f $b.Detail }
            elseif ($b -and $b.Status -eq 'SKIPPED') { $reason = 'Skipped by the technician' }
            Add-Html ('<tr><td>{0}</td><td>{1}</td><td colspan="7" class="muted">{2}</td></tr>' -f (ConvertTo-Html5Text $computer), (ConvertTo-Html5Text $auditScripts[$name]), (ConvertTo-Html5Text $reason))
        }
    }
}
Add-Html '</table>'

# --- Router checklist ----------------------------------------------------------------------
Add-Html '<h2 id="router">Router checklist</h2>'
$checklist = @($allFindings | Where-Object { $_.ScriptName -eq 'Get-RouterSecurityCheck' -and $_.Category -eq 'Checklist' })
if ($checklist.Count -eq 0) {
    Add-Html '<p class="muted">Get-RouterSecurityCheck.ps1 was not run, so router settings were not reviewed.</p>'
}
else {
    Add-Html '<table><tr><th>Result</th><th>Setting</th><th>Notes</th></tr>'
    foreach ($c in $checklist) {
        $label = $c.Status
        if ($c.Status -eq 'INFO') { $label = 'INFO' }
        $text = $c.Detail
        if ($c.Status -eq 'INFO') { $text = 'Not verified. ' + ($c.Detail -replace '^(Not verified\.|Could not be checked\.)\s*', '') }
        Add-Html ('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Get-StatusBadge $label), (ConvertTo-Html5Text ($c.Check -replace '^Checklist:\s*', '')), (ConvertTo-Html5Text $text))
    }
    Add-Html '</table>'
}

# --- Per-device results ----------------------------------------------------------------------
Add-Html '<h2 id="devices">Per-device results</h2>'
foreach ($computer in $computers) {
    Add-Html ('<h3>{0}</h3>' -f (ConvertTo-Html5Text $computer))
    foreach ($run in @($runs | Where-Object { $_.Computer -eq $computer })) {
        $label = $run.ScriptName
        if ($auditScripts.Contains($run.ScriptName)) { $label = '{0} ({1})' -f $auditScripts[$run.ScriptName], $run.ScriptName }
        $findings = @($allFindings | Where-Object { $_.Computer -eq $computer -and $_.ScriptName -eq $run.ScriptName })
        $runIssues = @($findings | Where-Object { $_.Status -in @('FAIL', 'WARN') } | Sort-Object -Property @{ Expression = { $severityRank[(Get-IssuePriority -Finding $_)] } })
        Add-Html ('<p><b>{0}</b> <span class="muted small">v{1}, {2}, administrator: {3}</span></p>' -f (ConvertTo-Html5Text $label), (ConvertTo-Html5Text $run.ScriptVersion), ([datetime]$run.StartTime).ToString('yyyy-MM-dd HH:mm'), $(if ($run.IsAdmin) { 'yes' } else { 'no' }))
        if ($runIssues.Count -gt 0) {
            Add-Html '<table><tr><th>Status</th><th>Priority</th><th>Check</th><th>Detail</th></tr>'
            foreach ($f in $runIssues) {
                $target = ''
                if ($f.Target -and $f.Target -ne $computer) { $target = ' [{0}]' -f $f.Target }
                Add-Html ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Get-StatusBadge $f.Status), (Get-PriorityBadge (Get-IssuePriority -Finding $f)), (ConvertTo-Html5Text ($f.Check + $target)), (ConvertTo-Html5Text $f.Detail))
            }
            Add-Html '</table>'
        }
        else {
            Add-Html '<p class="small">No issues found.</p>'
        }
        Add-Html ('<details><summary>All {0} result(s)</summary><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>' -f $findings.Count)
        foreach ($f in $findings) {
            $target = ''
            if ($f.Target -and $f.Target -ne $computer) { $target = ' [{0}]' -f $f.Target }
            Add-Html ('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Get-StatusBadge $f.Status), (ConvertTo-Html5Text ($f.Check + $target)), (ConvertTo-Html5Text $f.Detail))
        }
        Add-Html '</table></details>'
    }
}

# --- Could not check ----------------------------------------------------------------------
Add-Html '<h2 id="gaps">Could not check</h2>'
$errors = @($allFindings | Where-Object { $_.Status -eq 'ERROR' })
$skippedItems = @($allFindings | Where-Object { $_.Status -eq 'SKIPPED' })
Add-Html '<p class="note">These are gaps in what was checked, not problems found. <b>ERROR</b> means the check itself could not run on that device. <b>SKIPPED</b> usually means it needs to be run as administrator.</p>'
if ($errors.Count -eq 0 -and $skippedItems.Count -eq 0 -and $scriptFailures.Count -eq 0) { Add-Html '<p>Every check ran.</p>' }
else {
    Add-Html '<table><tr><th>Status</th><th>Device</th><th>Check</th><th>Reason</th></tr>'
    foreach ($s in $scriptFailures) {
        Add-Html ('<tr><td>{0}</td><td>{1}</td><td>{2} (whole script)</td><td>{3}</td></tr>' -f (Get-StatusBadge 'ERROR'), (ConvertTo-Html5Text $s.Computer), (ConvertTo-Html5Text $s.ScriptName), (ConvertTo-Html5Text $s.Detail))
    }
    foreach ($f in @($errors) + @($skippedItems)) {
        Add-Html ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Get-StatusBadge $f.Status), (ConvertTo-Html5Text $f.Computer), (ConvertTo-Html5Text $f.Check), (ConvertTo-Html5Text $f.Detail))
    }
    Add-Html '</table>'
}

Add-Html ('<p class="small muted">This report reflects what the MSP Toolkit scripts found when they ran. It is a point-in-time review, not a penetration test, and cannot see settings the scripts could not access. Generated by Export-SecurityAuditReport.ps1 v{0} from {1} result file(s).</p>' -f $ScriptVersion, $runs.Count)
Add-Html '</main></body></html>'

Invoke-MSPCheck -Name 'Write report' -Category 'Output' -ScriptBlock {
    $path = $ReportPath
    if (-not $path) { $path = Join-Path -Path $InputPath -ChildPath ('SecurityAuditReport_{0}.html' -f (Get-Date).ToString('yyyyMMdd-HHmm')) }
    $folder = Split-Path -Path $path -Parent
    if ($folder -and -not (Test-Path -LiteralPath $folder)) { $null = New-Item -ItemType Directory -Path $folder -Force }
    [System.IO.File]::WriteAllText($path, $html.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    $resolved = (Resolve-Path -LiteralPath $path).ProviderPath
    Add-MSPFinding -Check 'Report written' -Category 'Output' -Status PASS -Detail $resolved
    Add-MSPFinding -Check 'Report contents' -Category 'Output' -Status INFO `
        -Detail ('{0}: {1} Critical, {2} High, {3} Medium, {4} Low item(s); {5} check(s) and {6} whole script(s) could not run.' -f $rating.Label, $priorityCounts['Critical'], $priorityCounts['High'], $priorityCounts['Medium'], $priorityCounts['Low'], $statusCounts['ERROR'], $scriptFailures.Count)
}

Complete-MSPRun
