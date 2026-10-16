<#
.SYNOPSIS
    Read-only browser check: Chrome, Edge, Firefox and Brave versions (flagging ones that look
    out of date), installed extensions by name and ID, and policies that block updates or
    force-install extensions. Browser passwords, cookies and history are never opened.

.DESCRIPTION
    Versions
      Read from each browser's program file. Without internet access the script cannot know
      today's exact latest version, so it ESTIMATES the current major version from each
      browser's fixed release schedule (Chrome/Edge/Brave about every 4-5 weeks, Firefox every
      4 weeks) and flags browsers that are several releases behind. The estimate can be off by
      one or two releases; confirm in the browser's "About" page, which also installs updates.
      Supply -ChromiumLatestMajor / -FirefoxLatestMajor to use exact numbers instead.

    Extensions
      Read from each profile's Extensions folder (manifest.json: name, version, update source,
      permissions) and Firefox's extensions.json. Flags extensions that did not come from the
      official store (a common sign of adware) and lists ones with access to every website.

    Policies
      Browser policies under HKLM/HKCU\SOFTWARE\Policies. On a home PC these are unusual and
      are a known adware/hijacker trick: force-installed extensions, disabled updates.

    Files that are NEVER opened: Login Data, Cookies, History, Web Data, logins.json, key4.db,
    cookies.sqlite, places.sqlite, or any other credential/history store.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 1.0), with Browsers and Extensions tables.

.PARAMETER AllUsers
    Also check the browser profiles of every other user on this PC. Requires administrator.

.PARAMETER ChromiumLatestMajor
    Current Chrome/Edge major version (for example 141), if you looked it up. Overrides the estimate.

.PARAMETER FirefoxLatestMajor
    Current Firefox major version, if you looked it up. Overrides the estimate.

.EXAMPLE
    .\Get-BrowserSecurityCheck.ps1

.EXAMPLE
    .\Get-BrowserSecurityCheck.ps1 -AllUsers -OutputPath C:\Temp\Audit
    As administrator: every user's browsers, saved for the HTML report.

.NOTES
    Purpose       : Find out-of-date browsers and unwanted extensions without touching private data.
    Use Case      : Home network security audits; pop-ups, redirects or "my browser is acting strange".
    Scope         : This PC. Current user's browser profiles (all users with -AllUsers as admin).
    Risk Level    : Read-Only -- reads program versions, extension manifests and policy keys only.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (Yes for -AllUsers) | Modules: none
    Version       : 1.1.0
    Limitations   : "Out of date" is an estimate from the release schedule unless exact versions
                    are supplied. Extension names come from the extension's own manifest; a
                    malicious extension can pick a harmless-sounding name. Store-delivered
                    extensions can still be malicious; not from the store is a stronger signal.
                    Opera/Vivaldi and Microsoft Store browser installs are not checked.
                    Replaces _archive\...\Check-BrowserSecurity.ps1.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$AllUsers,
    [ValidateRange(100, 400)][int]$ChromiumLatestMajor,
    [ValidateRange(100, 400)][int]$FirefoxLatestMajor
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
Initialize-MSPRun -ScriptName 'Get-BrowserSecurityCheck' -ScriptVersion $ScriptVersion -CheckId 'A5' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Browser versions, extensions and policies (read-only; no passwords, cookies or history)'

# --- Release-schedule estimate ---------------------------------------------------------------
# Anchors are real release dates; both browsers ship a new major version every 4 weeks.
# Chromium (Chrome, Edge, Brave share major numbers): Chrome 140 stable = 2025-09-02.
# Firefox: Firefox 144 = 2025-10-14. The newest stable install found on the PC raises the
# estimate if it is higher (see below), so a slipped schedule cannot cause false FAILs.
function Get-EstimatedLatestMajor {
    param([ValidateSet('Chromium', 'Firefox')][string]$Family)
    $today = (Get-Date).Date
    if ($Family -eq 'Chromium') {
        if ($ChromiumLatestMajor) { return [pscustomobject]@{ Major = $ChromiumLatestMajor; Estimated = $false } }
        $major = 140 + [math]::Floor(($today - [datetime]'2025-09-02').TotalDays / 28)
    }
    else {
        if ($FirefoxLatestMajor) { return [pscustomobject]@{ Major = $FirefoxLatestMajor; Estimated = $false } }
        $major = 144 + [math]::Floor(($today - [datetime]'2025-10-14').TotalDays / 28)
    }
    return [pscustomobject]@{ Major = [int]$major; Estimated = $true }
}

# Firefox ESR (Extended Support Release) majors and the approximate month support ends.
# An ESR install is judged against its own branch, not the monthly releases. Dates are
# approximate (Mozilla sometimes extends a branch), so a passed date is a WARN, not a FAIL.
$firefoxEsr = @{ 115 = [datetime]'2026-03-01'; 128 = [datetime]'2025-09-01'; 140 = [datetime]'2026-09-01'; 153 = [datetime]'2027-09-01' }

# Official store update sources. Anything else (or none) was sideloaded or installed by a program.
$storeUpdatePattern = '^https://(clients2\.google\.com|edge\.microsoft\.com|extensionupdater\.brave\.com|go-updater\.brave\.com)/'

$browserDefinitions = @(
    @{ Name = 'Google Chrome'; Family = 'Chromium'; Exe = @('Google\Chrome\Application\chrome.exe'); UserData = 'Google\Chrome\User Data'; PolicyKey = 'Google\Chrome' }
    @{ Name = 'Microsoft Edge'; Family = 'Chromium'; Exe = @('Microsoft\Edge\Application\msedge.exe'); UserData = 'Microsoft\Edge\User Data'; PolicyKey = 'Microsoft\Edge' }
    @{ Name = 'Brave'; Family = 'Chromium'; Exe = @('BraveSoftware\Brave-Browser\Application\brave.exe'); UserData = 'BraveSoftware\Brave-Browser\User Data'; PolicyKey = 'BraveSoftware\Brave' }
    @{ Name = 'Mozilla Firefox'; Family = 'Firefox'; Exe = @('Mozilla Firefox\firefox.exe'); UserData = $null; PolicyKey = 'Mozilla\Firefox' }
    # Pre-release channel: rated like the others, but never used to raise the expected version.
    @{ Name = 'Firefox Developer Edition'; Family = 'Firefox'; Prerelease = $true; Exe = @('Firefox Developer Edition\firefox.exe'); UserData = $null; PolicyKey = 'Mozilla\Firefox' }
)

# --- Which user profiles to look at ----------------------------------------------------------
$userProfiles = New-Object System.Collections.Generic.List[object]
$userProfiles.Add([pscustomobject]@{ User = $env:USERNAME; LocalAppData = $env:LOCALAPPDATA; RoamingAppData = $env:APPDATA })
if ($AllUsers) {
    Invoke-MSPCheck -Name 'Other users'' browser profiles' -Category 'Scope' -RequiresAdmin -AdminReason 'Other users'' profile folders are protected.' -ScriptBlock {
        foreach ($p in (Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special = FALSE' -ErrorAction Stop)) {
            if (-not $p.LocalPath -or $p.LocalPath -eq $env:USERPROFILE) { continue }
            $name = Split-Path -Path $p.LocalPath -Leaf
            $script:userProfiles.Add([pscustomobject]@{ User = $name; LocalAppData = (Join-Path $p.LocalPath 'AppData\Local'); RoamingAppData = (Join-Path $p.LocalPath 'AppData\Roaming') })
        }
        Add-MSPFinding -Check 'Other users'' browser profiles' -Category 'Scope' -Status INFO -Detail ('Checking {0} user profile(s).' -f $script:userProfiles.Count)
    }
}

function Get-ChromiumExtensionName {
    <# Extension display name, resolving "__MSG_key__" placeholders from the _locales folder. #>
    param($Manifest, [string]$VersionFolder)
    $name = [string]$Manifest.name
    if ($name -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        $locales = @()
        if ($Manifest.default_locale) { $locales += [string]$Manifest.default_locale }
        $locales += @('en', 'en_US')
        foreach ($loc in $locales) {
            $messagesPath = Join-Path -Path $VersionFolder -ChildPath ('_locales\{0}\messages.json' -f $loc)
            if (-not (Test-Path -LiteralPath $messagesPath)) { continue }
            try {
                $messages = [System.IO.File]::ReadAllText($messagesPath) | ConvertFrom-Json
                foreach ($prop in $messages.PSObject.Properties) {
                    if ($prop.Name -ieq $key -and $prop.Value.message) { return [string]$prop.Value.message }
                }
            }
            catch {
                Write-MSPLog -Level WARN -Message ('Could not read {0}: {1}' -f $messagesPath, $_.Exception.Message)
            }
        }
    }
    return $name
}

$browserRows = New-Object System.Collections.Generic.List[object]
$extensionRows = New-Object System.Collections.Generic.List[object]

# =========================================================================================
Write-MSPSection -Title 'Browser versions'
# =========================================================================================
# Pass 1 finds every install; pass 2 rates them. A stable browser can never be newer than the
# latest release, so the newest stable install of a family corrects a low schedule estimate.
$installs = New-Object System.Collections.Generic.List[object]
Invoke-MSPCheck -Name 'Find installed browsers' -Category 'Version' -ScriptBlock {
    foreach ($def in $browserDefinitions) {
        # Machine-wide installs, then per-user installs (Chrome can install to AppData without admin).
        $candidates = New-Object System.Collections.Generic.List[string]
        foreach ($rel in $def.Exe) {
            foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($base) { $candidates.Add((Join-Path $base $rel)) } }
            foreach ($u in $userProfiles) { if ($u.LocalAppData) { $candidates.Add((Join-Path $u.LocalAppData $rel)) } }
        }
        foreach ($exe in ($candidates | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $exe)) { continue }
            $item = Get-Item -LiteralPath $exe
            $versionText = [string]$item.VersionInfo.ProductVersion
            $major = 0
            if ($versionText -match '^(\d+)') { $major = [int]$Matches[1] }
            $script:installs.Add([pscustomobject]@{ Def = $def; Exe = $exe; Version = $versionText; Major = $major; AgeDays = [int]((Get-Date) - $item.LastWriteTime).TotalDays })
        }
    }
}
$newestStable = @{}
foreach ($i in $installs) {
    if ($i.Def.Prerelease) { continue }
    if (-not $newestStable.ContainsKey($i.Def.Family) -or $i.Major -gt $newestStable[$i.Def.Family]) { $newestStable[$i.Def.Family] = $i.Major }
}

foreach ($inst in $installs) {
    $def = $inst.Def
    Invoke-MSPCheck -Name ('{0} version' -f $def.Name) -Category 'Version' -ScriptBlock {
        $exe = $inst.Exe
        $versionText = $inst.Version
        $major = $inst.Major
        $ageDays = $inst.AgeDays
        $latest = Get-EstimatedLatestMajor -Family $def.Family
        if ($latest.Estimated -and $newestStable[$def.Family] -gt $latest.Major) {
            $latest = [pscustomobject]@{ Major = [int]$newestStable[$def.Family]; Estimated = $true }
        }
        # Firefox records its release channel ("release", "esr", ...) next to the program.
        $isEsr = $false
        if ($def.Family -eq 'Firefox') {
            $channelFile = Join-Path (Split-Path $exe) 'defaults\pref\channel-prefs.js'
            if ((Test-Path -LiteralPath $channelFile) -and ([System.IO.File]::ReadAllText($channelFile) -match '"esr"')) { $isEsr = $true }
        }
        $behind = $latest.Major - $major
        $browserRows.Add([pscustomobject]@{
                Browser          = $def.Name
                Version          = $versionText
                Path             = $exe
                FileAgeDays      = $ageDays
                ExpectedMajor    = $latest.Major
                ExpectedEstimate = $latest.Estimated
                ReleasesBehind   = [math]::Max(0, $behind)
            })
        $basis = 'current'
        if ($latest.Estimated) { $basis = 'estimated current' }
        $evidence = @{ Version = $versionText; ExpectedMajor = $latest.Major; Estimated = $latest.Estimated; FileAgeDays = $ageDays; Path = $exe }
        $check = '{0} version' -f $def.Name
        if ($isEsr) {
            $end = $firefoxEsr[$major]
            if (-not $end) {
                Add-MSPFinding -Check $check -Category 'Version' -Status WARN -Severity Low -Evidence $evidence `
                    -Detail ('{0} is Extended Support Release {1}, which this script has no support date for.' -f $versionText, $major) `
                    -Recommendation 'Check the ESR support date at mozilla.org, or switch to the regular Firefox release.'
            }
            elseif ((Get-Date) -gt $end) {
                Add-MSPFinding -Check $check -Category 'Version' -Status WARN -Severity Medium -Evidence $evidence `
                    -Detail ('{0} is Extended Support Release {1}, whose support was due to end around {2:yyyy-MM}.' -f $versionText, $major, $end) `
                    -Recommendation 'Confirm at mozilla.org whether this ESR branch still gets security fixes; if not, update to the current release (Menu > Help > About Firefox).'
            }
            else {
                Add-MSPFinding -Check $check -Category 'Version' -Status PASS -Evidence $evidence `
                    -Detail ('{0} (Extended Support Release {1}, supported until about {2:yyyy-MM}).' -f $versionText, $major, $end)
            }
            return
        }
        if ($behind -ge 4) {
            Add-MSPFinding -Check $check -Category 'Version' -Status FAIL -Severity High -Evidence $evidence `
                -Detail ('{0} is about {1} releases behind the {2} version {3}. It is missing security fixes; the program file was last updated {4} days ago.' -f $versionText, $behind, $basis, $latest.Major, $ageDays) `
                -Recommendation ('Open {0} > Settings > About to update it. If it will not update, check the "Update policies" results below.' -f $def.Name)
        }
        elseif ($behind -ge 2) {
            Add-MSPFinding -Check $check -Category 'Version' -Status WARN -Severity Medium -Evidence $evidence `
                -Detail ('{0} may be {1} releases behind the {2} version {3}.' -f $versionText, $behind, $basis, $latest.Major) `
                -Recommendation ('Open {0} > Settings > About to check for and install updates, then restart the browser.' -f $def.Name)
        }
        else {
            Add-MSPFinding -Check $check -Category 'Version' -Status PASS -Evidence $evidence `
                -Detail ('{0} (up to date with the {1} version {2}).' -f $versionText, $basis, $latest.Major)
        }
    }
}
if ($browserRows.Count -eq 0) {
    Add-MSPFinding -Check 'Browsers found' -Category 'Version' -Status INFO -Detail 'Chrome, Edge, Brave and Firefox were not found in their standard install folders.'
}

# =========================================================================================
Write-MSPSection -Title 'Extensions'
# =========================================================================================
foreach ($def in $browserDefinitions) {
    # Firefox Developer Edition shares Firefox's profile folder and policy key; check those once.
    if ($def.Prerelease) { continue }
    foreach ($u in $userProfiles) {
        $label = '{0} extensions ({1})' -f $def.Name, $u.User
        Invoke-MSPCheck -Name $label -Category 'Extensions' -ScriptBlock {
            $rows = New-Object System.Collections.Generic.List[object]
            if ($def.Family -eq 'Chromium') {
                $userData = Join-Path $u.LocalAppData $def.UserData
                if (-not (Test-Path -LiteralPath $userData)) { return }
                # Browser profiles are "Default", "Profile 1", "Profile 2", ...
                $profileDirs = @(Get-ChildItem -LiteralPath $userData -Directory -ErrorAction Stop | Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })
                foreach ($profileDir in $profileDirs) {
                    $extRoot = Join-Path $profileDir.FullName 'Extensions'
                    if (-not (Test-Path -LiteralPath $extRoot)) { continue }
                    foreach ($extDir in (Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) {
                        if ($extDir.Name -notmatch '^[a-p]{32}$') { continue }
                        $versionDir = Get-ChildItem -LiteralPath $extDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
                        if (-not $versionDir) { continue }
                        $manifestPath = Join-Path $versionDir.FullName 'manifest.json'
                        if (-not (Test-Path -LiteralPath $manifestPath)) { continue }
                        try {
                            $manifest = [System.IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
                        }
                        catch {
                            Write-MSPLog -Level WARN -Message ('Unreadable manifest {0}' -f $manifestPath)
                            continue
                        }
                        $permissions = @($manifest.permissions) + @($manifest.host_permissions) + @($manifest.optional_permissions | Where-Object { $_ -is [string] }) | Where-Object { $_ -is [string] }
                        $allSites = [bool]($permissions | Where-Object { $_ -eq '<all_urls>' -or $_ -match '^(\*|https?)://\*/' })
                        $updateUrl = [string]$manifest.update_url
                        $rows.Add([pscustomobject]@{
                                Browser       = $def.Name
                                User          = $u.User
                                Profile       = $profileDir.Name
                                Name          = (Get-ChromiumExtensionName -Manifest $manifest -VersionFolder $versionDir.FullName)
                                Id            = $extDir.Name
                                Version       = [string]$manifest.version
                                Enabled       = 'Unknown'
                                FromStore     = ($updateUrl -match $storeUpdatePattern)
                                UpdateSource  = $updateUrl
                                AllSiteAccess = $allSites
                            })
                    }
                }
            }
            else {
                $ffProfiles = Join-Path $u.RoamingAppData 'Mozilla\Firefox\Profiles'
                if (-not (Test-Path -LiteralPath $ffProfiles)) { return }
                foreach ($profileDir in (Get-ChildItem -LiteralPath $ffProfiles -Directory -ErrorAction Stop)) {
                    # extensions.json is Firefox's add-on list. It holds no passwords or browsing data.
                    $listPath = Join-Path $profileDir.FullName 'extensions.json'
                    if (-not (Test-Path -LiteralPath $listPath)) { continue }
                    $list = [System.IO.File]::ReadAllText($listPath) | ConvertFrom-Json
                    foreach ($addon in @($list.addons)) {
                        if ($addon.type -ne 'extension') { continue }
                        # Built-in Mozilla components are not user-installed extensions.
                        if ([string]$addon.location -like 'app-builtin*' -or [string]$addon.location -like 'app-system*' -or $addon.location -eq 'app-profile-builtin') { continue }
                        $name = [string]$addon.defaultLocale.name
                        if (-not $name) { $name = [string]$addon.id }
                        $origins = @($addon.userPermissions.origins)
                        $rows.Add([pscustomobject]@{
                                Browser       = $def.Name
                                User          = $u.User
                                Profile       = $profileDir.Name
                                Name          = $name
                                Id            = [string]$addon.id
                                Version       = [string]$addon.version
                                Enabled       = [string]$addon.active
                                FromStore     = ([bool]$addon.signedState -and [int]$addon.signedState -ge 2 -and $addon.location -eq 'app-profile')
                                UpdateSource  = [string]$addon.location
                                AllSiteAccess = [bool]($origins | Where-Object { $_ -eq '<all_urls>' -or $_ -match '^\*://\*/' })
                            })
                    }
                }
            }
            if ($rows.Count -eq 0) {
                if ($def.Family -eq 'Chromium' -or (Test-Path -LiteralPath (Join-Path $u.RoamingAppData 'Mozilla\Firefox\Profiles'))) {
                    Add-MSPFinding -Check $label -Category 'Extensions' -Status PASS -Detail 'No extensions installed.'
                }
                return
            }
            foreach ($r in $rows) { $script:extensionRows.Add($r) }

            $names = ($rows | ForEach-Object { $_.Name } | Select-Object -Unique) -join '; '
            $uniqueCount = @($rows | ForEach-Object { $_.Id } | Select-Object -Unique).Count
            Add-MSPFinding -Check $label -Category 'Extensions' -Status INFO -Detail ('{0} extension(s) across {1} browser profile(s): {2}' -f $uniqueCount, @($rows | ForEach-Object { $_.Profile } | Select-Object -Unique).Count, $names)

            foreach ($r in @($rows | Where-Object { -not $_.FromStore })) {
                $source = $r.UpdateSource
                if (-not $source) { $source = 'none' }
                Add-MSPFinding -Check ('Extension not from the official store: {0}' -f $r.Name) -Category 'Extensions' -Status WARN -Severity Medium `
                    -Detail ('{0} / {1}: "{2}" (ID {3}) was not installed from the browser''s store (update source: {4}). Adware commonly installs extensions this way.' -f $def.Name, $r.Profile, $r.Name, $r.Id, $source) `
                    -Recommendation 'Ask the client whether they installed it. If not, remove it from the browser''s Extensions page (and check Apps & Features for the program that added it).' `
                    -Evidence @{ Id = $r.Id; Version = $r.Version; UpdateSource = $r.UpdateSource }
            }
            $broad = @($rows | Where-Object { $_.AllSiteAccess -and $_.FromStore })
            if ($broad.Count -gt 0) {
                Add-MSPFinding -Check ('{0}: extensions that can read every website' -f $label) -Category 'Extensions' -Status INFO `
                    -Detail (('{0}. Normal for ad blockers and password managers; anything else the client does not recognise should be removed.' -f (($broad | ForEach-Object { $_.Name } | Select-Object -Unique) -join '; ')))
            }
            if ($uniqueCount -gt 15) {
                Add-MSPFinding -Check ('{0}: number of extensions' -f $label) -Category 'Extensions' -Status WARN -Severity Low `
                    -Detail ('{0} different extensions installed. Each one is code with access to browsing.' -f $uniqueCount) `
                    -Recommendation 'Review the list with the client and remove extensions they no longer use.'
            }
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'Update and extension policies'
# =========================================================================================
Invoke-MSPCheck -Name 'Browser policies' -Category 'Policy' -ScriptBlock {
    $anyPolicy = $false
    foreach ($def in $browserDefinitions) {
        if ($def.Prerelease) { continue }
        foreach ($hive in @('HKLM:', 'HKCU:')) {
            $key = '{0}\SOFTWARE\Policies\{1}' -f $hive, $def.PolicyKey
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $anyPolicy = $true
            $forceKey = Join-Path $key 'ExtensionInstallForcelist'
            if ($def.Family -eq 'Firefox') { $forceKey = Join-Path $key 'Extensions\Install' }
            if (Test-Path -LiteralPath $forceKey) {
                $values = @((Get-ItemProperty -LiteralPath $forceKey).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { [string]$_.Value })
                Add-MSPFinding -Check ('{0}: force-installed extensions' -f $def.Name) -Category 'Policy' -Status WARN -Severity High `
                    -Detail ('A policy in {0} forces {1} extension(s) into the browser and stops the user removing them: {2}' -f $key, $values.Count, ($values -join '; ')) `
                    -Recommendation 'On a home PC this is a common adware/hijacker technique. Identify the program that set it, remove that program, then remove the policy key (escalate if unsure).'
            }
            $settings = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
            $names = @($settings.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name })
            if ($names.Count -gt 0) {
                Add-MSPFinding -Check ('{0}: browser policies set' -f $def.Name) -Category 'Policy' -Status INFO `
                    -Detail ('{0} has policy settings: {1}. The browser will show "Managed by your organization".' -f $key, (($names | Select-Object -First 12) -join ', '))
            }
            if ($def.Family -eq 'Firefox' -and $settings.DisableAppUpdate -eq 1) {
                Add-MSPFinding -Check 'Firefox: updates disabled by policy' -Category 'Policy' -Status FAIL -Severity High `
                    -Detail ('{0}\DisableAppUpdate = 1. Firefox cannot update itself.' -f $key) -Recommendation 'Remove the DisableAppUpdate policy unless an IT department deliberately set it.'
            }
        }
    }
    # Chrome and Edge are updated by separate updater services with their own policies.
    $updaters = @(
        @{ Name = 'Google Update (Chrome)'; Key = 'HKLM:\SOFTWARE\Policies\Google\Update' }
        @{ Name = 'Microsoft Edge Update'; Key = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' }
    )
    foreach ($up in $updaters) {
        if (-not (Test-Path -LiteralPath $up.Key)) { continue }
        $anyPolicy = $true
        $p = Get-ItemProperty -LiteralPath $up.Key
        $blocked = @()
        if ($p.PSObject.Properties['UpdateDefault'] -and $p.UpdateDefault -eq 0) { $blocked += 'UpdateDefault=0 (updates disabled)' }
        if ($p.PSObject.Properties['AutoUpdateCheckPeriodMinutes'] -and $p.AutoUpdateCheckPeriodMinutes -eq 0) { $blocked += 'AutoUpdateCheckPeriodMinutes=0 (never checks)' }
        foreach ($prop in $p.PSObject.Properties) { if ($prop.Name -like 'Update{*}' -and $prop.Value -eq 0) { $blocked += ('{0}=0' -f $prop.Name) } }
        if ($blocked.Count -gt 0) {
            Add-MSPFinding -Check ('{0}: updates blocked by policy' -f $up.Name) -Category 'Policy' -Status FAIL -Severity High `
                -Detail ('{0}: {1}' -f $up.Key, ($blocked -join '; ')) -Recommendation 'Remove these values so the browser can update itself, unless IT deliberately manages updates another way.'
        }
    }
    if (-not $anyPolicy) {
        Add-MSPFinding -Check 'Browser policies' -Category 'Policy' -Status PASS -Detail 'No browser or browser-updater policies are set (normal for a home PC).'
    }
}

Add-MSPData -Name 'Browsers' -Rows $browserRows.ToArray()
Add-MSPData -Name 'Extensions' -Rows $extensionRows.ToArray()
Complete-MSPRun -OutputPath $OutputPath
