<#
.SYNOPSIS
    Restarts a short allow-list of Windows services that commonly fix everyday problems
    (Print Spooler, Windows Update, BITS) and clears the DNS Client cache, with before/after
    state, a printed plan, confirmation and -WhatIf.

.DESCRIPTION
    Allow-list (nothing else can be restarted with this script):
      Spooler   Print Spooler                       stuck printing, printers missing
      wuauserv  Windows Update                      update checks stuck
      BITS      Background Intelligent Transfer     update / Store downloads stuck at 0 %
      Dnscache  DNS Client                          Windows does not allow this service to be
                                                    restarted, so its cache is CLEARED instead,
                                                    which is what a restart would achieve

    For each service:
      Running              -> restart it; dependent services that were running are started again
      Stopped, Automatic   -> start it (it should be running)
      Stopped, Manual      -> left alone (Windows starts it when needed); -StartIfStopped starts it
      Disabled / missing   -> never changed; reported

    Order: record the current state, print the plan, ask you to type YES (-Force skips the
    question; -WhatIf shows the plan only), make the changes, record the state again.

.PARAMETER Services
    Which services: Spooler, wuauserv, BITS, Dnscache or All (default).

.PARAMETER StartIfStopped
    Also start allow-listed services whose start type is Manual and that are stopped.

.PARAMETER Force
    Do not ask for confirmation. Required for non-interactive runs; without it a non-interactive
    run changes nothing.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with before/after tables.

.PARAMETER ServiceTimeoutSeconds
    How long to wait for each service to stop or start (10-300). Default 60.

.EXAMPLE
    .\Restart-CommonServices.ps1 -WhatIf
    Current state and what would be restarted. Changes nothing; no admin needed.

.EXAMPLE
    .\Restart-CommonServices.ps1 -Services Spooler
    Run as administrator: restarts only the Print Spooler after you type YES.

.EXAMPLE
    .\Restart-CommonServices.ps1 -Force -OutputPath C:\Temp\Ticket123
    No prompt (RMM); all allow-listed services; saves before/after results.

.NOTES
    Purpose       : The "turn it off and on again" fix for a few services, done safely and documented.
    Use Case      : Printing, Windows Update and DNS-resolution tickets.
    Scope         : Local computer; only the four allow-listed services (and dependents that were
                    running, which are started again).
    Risk Level    : Safe -- services restart in seconds; print jobs in progress may need resending.
    Prerequisites : Windows PowerShell 5.1 | Admin: Yes for changes (No for -WhatIf) | Modules: built-in only
    Exit codes    : 0 done (or -WhatIf); 1 nothing changed (not admin, not confirmed,
                    non-interactive without -Force); 2 a service did not end up running
    Version       : 2.0.0
    Limitations   : Does not clear stuck print jobs from the queue folder or repair printer drivers.
                    A service that stops again right away has a deeper problem (check
                    Get-RecentCriticalErrors.ps1).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Spooler', 'wuauserv', 'BITS', 'Dnscache', 'All')]
    [string[]]$Services = @('All'),
    [switch]$StartIfStopped,
    [switch]$Force,
    [string]$OutputPath,
    [ValidateRange(10, 300)][int]$ServiceTimeoutSeconds = 60
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
Initialize-MSPRun -ScriptName 'Restart-CommonServices' -ScriptVersion $ScriptVersion -CheckId 'B4' -RiskLevel 'Safe' `
    -Parameters $PSBoundParameters -Description 'Restart allow-listed services (Spooler, Windows Update, BITS) and clear the DNS cache' `
    -AdminSections 'restarting services and clearing the DNS cache (not needed for -WhatIf)'

$exitCode = 0
# "powershell.exe -File" passes a list as one "a,b" string; split so both forms work.
$Services = @($Services | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$allowList = [ordered]@{
    'Spooler'  = 'Print Spooler'
    'wuauserv' = 'Windows Update'
    'BITS'     = 'Background Intelligent Transfer Service'
    'Dnscache' = 'DNS Client'
}
$selected = @($allowList.Keys)
if ($Services -notcontains 'All') { $selected = @($allowList.Keys | Where-Object { $Services -contains $_ }) }

function Get-ServiceRow {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return [pscustomobject]@{ Name = $Name; DisplayName = $allowList[$Name]; Status = 'NotFound'; StartType = ''; RunningDependents = '' } }
    $deps = @($svc.DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
    return [pscustomobject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; Status = [string]$svc.Status; StartType = [string]$svc.StartType; RunningDependents = ($deps -join ', ') }
}

function Wait-ServiceRunning {
    param([string]$Name)
    try {
        (Get-Service -Name $Name -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds($ServiceTimeoutSeconds))
        return $true
    }
    catch {
        return $false
    }
}

# =========================================================================================
Write-MSPSection -Title 'Current state (before)'
# =========================================================================================
$before = @($selected | ForEach-Object { Get-ServiceRow -Name $_ })
Add-MSPData -Name 'ServicesBefore' -Rows $before
$actions = New-Object System.Collections.Generic.List[object]
foreach ($row in $before) {
    $action = 'None'
    $why = ''
    if ($row.Status -eq 'NotFound') { $why = 'Service not found on this computer.' }
    elseif ($row.Name -eq 'Dnscache') { $action = 'FlushCache'; $why = 'Windows does not allow the DNS Client service to be restarted; its cache will be cleared instead.' }
    elseif ($row.StartType -eq 'Disabled') { $why = 'Disabled. This script never changes a disabled service.' }
    elseif ($row.Status -eq 'Running') { $action = 'Restart'; $why = 'Running; will be restarted.' }
    elseif ($row.Status -eq 'Stopped' -and $row.StartType -eq 'Automatic') { $action = 'Start'; $why = 'Stopped although it should start automatically; will be started.' }
    elseif ($row.Status -eq 'Stopped' -and $StartIfStopped) { $action = 'Start'; $why = 'Stopped (demand-start); will be started because -StartIfStopped was given.' }
    elseif ($row.Status -eq 'Stopped') { $why = 'Stopped; normal for a demand-start service (Windows starts it when needed). Left alone; use -StartIfStopped to start it.' }
    else { $action = 'Restart'; $why = ('In state {0}; will be stopped and started.' -f $row.Status) }

    $status = 'INFO'
    if ($row.Status -eq 'NotFound' -or $row.StartType -eq 'Disabled') { $status = 'WARN' }
    elseif ($row.Status -eq 'Stopped' -and $row.StartType -eq 'Automatic') { $status = 'WARN' }
    $detail = '{0}: {1}, start type {2}. {3}' -f $row.DisplayName, $row.Status, $row.StartType, $why
    if ($row.RunningDependents) { $detail = '{0} Running dependent services (started again afterwards): {1}.' -f $detail, $row.RunningDependents }
    Add-MSPFinding -Check ('Service {0}' -f $row.Name) -Category 'Before' -Status $status -Detail $detail `
        -Recommendation $(if ($row.StartType -eq 'Disabled') { 'A disabled Windows service is usually set by policy or security software; find out why before enabling it.' } else { '' })
    $actions.Add([pscustomobject]@{ Row = $row; Action = $action })
}

$plan = foreach ($a in $actions) {
    switch ($a.Action) {
        'Restart' { 'Restart {0} ({1}){2}' -f $a.Row.Name, $a.Row.DisplayName, $(if ($a.Row.RunningDependents) { ' and start again its dependents: ' + $a.Row.RunningDependents } else { '' }) }
        'Start' { 'Start {0} ({1})' -f $a.Row.Name, $a.Row.DisplayName }
        'FlushCache' { 'Clear the DNS Client cache (instead of a restart, which Windows does not allow)' }
        default { 'No change to {0} ({1})' -f $a.Row.Name, $a.Row.DisplayName }
    }
}
Write-MSPChangePlan -Step @($plan)
$changes = @($actions | Where-Object { $_.Action -ne 'None' })

if ($dryRun) {
    foreach ($a in $changes) { Write-MSPWhatIf -Target ($a.Row.Name) -Action ($a.Action) }
    Add-MSPFinding -Check 'Dry run' -Category 'Safety' -Status INFO -Detail '-WhatIf: the plan was shown; nothing was changed.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}
if ($changes.Count -eq 0) {
    Add-MSPFinding -Check 'Result' -Category 'Safety' -Status INFO -Detail 'Nothing to change.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}
if (-not $script:MSPRun.IsAdmin) {
    Add-MSPFinding -Check 'Administrator' -Category 'Safety' -Status SKIPPED -Detail 'No changes made: restarting services requires administrator.' `
        -Recommendation 'Open PowerShell with "Run as administrator" and run again (or use -WhatIf to preview without admin).'
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}
if (-not (Confirm-MSPChange -Question ('Make the {0} change(s) listed above on {1}?' -f $changes.Count, $script:MSPRun.Host) -Force:$Force)) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

# =========================================================================================
Write-MSPSection -Title 'Changes'
# =========================================================================================
foreach ($a in $changes) {
    $name = $a.Row.Name
    if (-not $PSCmdlet.ShouldProcess($name, $a.Action)) { continue }
    try {
        switch ($a.Action) {
            'FlushCache' {
                Clear-DnsClientCache -ErrorAction Stop
                Add-MSPFinding -Check ('{0}: clear cache' -f $name) -Category 'Change' -Status PASS -Detail 'DNS Client cache cleared.'
            }
            'Start' {
                Start-Service -Name $name -ErrorAction Stop
                if (-not (Wait-ServiceRunning -Name $name)) { throw ('did not reach Running within {0} seconds' -f $ServiceTimeoutSeconds) }
                Add-MSPFinding -Check ('{0}: start' -f $name) -Category 'Change' -Status PASS -Detail 'Started.'
            }
            'Restart' {
                # -Force also stops dependent services; they are started again below.
                Restart-Service -Name $name -Force -ErrorAction Stop
                if (-not (Wait-ServiceRunning -Name $name)) { throw ('did not reach Running within {0} seconds' -f $ServiceTimeoutSeconds) }
                Add-MSPFinding -Check ('{0}: restart' -f $name) -Category 'Change' -Status PASS -Detail 'Restarted.'
                foreach ($dep in @($a.Row.RunningDependents -split ',\s*' | Where-Object { $_ })) {
                    $d = Get-Service -Name $dep -ErrorAction SilentlyContinue
                    if ($d -and $d.Status -ne 'Running') {
                        try {
                            Start-Service -Name $dep -ErrorAction Stop
                            Add-MSPFinding -Check ('{0}: dependent {1}' -f $name, $dep) -Category 'Change' -Status PASS -Detail 'Dependent service started again.'
                        }
                        catch {
                            $exitCode = 2
                            Add-MSPFinding -Check ('{0}: dependent {1}' -f $name, $dep) -Category 'Change' -Status FAIL -Detail ('Dependent service did not start again: {0}' -f $_.Exception.Message) `
                                -Recommendation 'Restart the PC; Windows starts it again.'
                        }
                    }
                }
            }
        }
    }
    catch {
        $exitCode = 2
        Add-MSPFinding -Check ('{0}: {1}' -f $name, $a.Action.ToLower()) -Category 'Change' -Status FAIL -Detail ('Failed: {0}' -f $_.Exception.Message) `
            -Recommendation 'Restart the PC. If the service still will not run, check Get-RecentCriticalErrors.ps1 for the reason.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'State after'
# =========================================================================================
$after = @($selected | ForEach-Object { Get-ServiceRow -Name $_ })
Add-MSPData -Name 'ServicesAfter' -Rows $after
foreach ($a in $changes | Where-Object { $_.Action -in @('Restart', 'Start') }) {
    $now = ($after | Where-Object Name -eq $a.Row.Name).Status
    if ($now -eq 'Running') {
        Add-MSPFinding -Check ('{0} running' -f $a.Row.Name) -Category 'After' -Status PASS -Detail ('{0} -> Running' -f $a.Row.Status)
    }
    else {
        $exitCode = 2
        Add-MSPFinding -Check ('{0} running' -f $a.Row.Name) -Category 'After' -Status FAIL -Detail ('{0} -> {1}' -f $a.Row.Status, $now) `
            -Recommendation 'The service stopped again; check Get-RecentCriticalErrors.ps1 and escalate with the log.'
    }
}

Complete-MSPRun -OutputPath $OutputPath
exit $exitCode
