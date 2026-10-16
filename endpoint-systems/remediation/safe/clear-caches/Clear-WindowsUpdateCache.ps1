<#
.SYNOPSIS
    Resets the Windows Update cache by RENAMING (never deleting) the SoftwareDistribution and
    catroot2 folders, then restarts the update services and checks that Windows rebuilt them.

.DESCRIPTION
    Fixes the common "updates won't install" causes that come from a corrupt or stale update
    cache (updates stuck at 0 %, errors such as 0x80070002, 0x80070003, 0x80073712, updates that
    fail and reappear).

    What it does, in order:
      1. Records the current state: the three services, both folders (size, file count), older
         .old folders from previous runs, pending restart, free disk space.
      2. Prints the plan and asks you to type YES (skip with -Force; -WhatIf shows the plan only).
      3. Stops Windows Update (wuauserv), Cryptographic Services (cryptSvc) and BITS - only those
         that are running. If any will not stop, nothing is renamed and the stopped services are
         started again. Windows Installer (msiserver) is deliberately left alone: neither folder
         needs it, and stopping it could break a program installation in progress.
      4. Renames  C:\Windows\SoftwareDistribution  ->  SoftwareDistribution.old-<yyyyMMdd-HHmmss>
                  C:\Windows\System32\catroot2     ->  catroot2.old-<yyyyMMdd-HHmmss>
      5. Starts the services that were running before, plus Windows Update and Cryptographic
         Services so Windows creates fresh folders.
      6. Checks: services running, both folders recreated, Windows Update COM API available.

    Undo: the old folders are kept, so the change can be reversed by hand (steps are printed at
    the end and written to the log). Update history shown in Settings is stored in
    SoftwareDistribution, so it looks empty until the old folder is renamed back. The .old
    folders keep their disk space until you delete them yourself, after updates install again.

.PARAMETER Force
    Do not ask for confirmation. Required for non-interactive runs (RMM, scheduled task); without
    it a non-interactive run changes nothing.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0), including before/after service tables.

.PARAMETER ServiceTimeoutSeconds
    How long to wait for each service to stop or start (10-300). Default 60.

.EXAMPLE
    .\Clear-WindowsUpdateCache.ps1 -WhatIf
    Shows the current state and exactly what would change. Changes nothing; no admin needed.

.EXAMPLE
    .\Clear-WindowsUpdateCache.ps1
    Run as administrator. Shows the plan, asks for YES, then makes the changes.

.EXAMPLE
    .\Clear-WindowsUpdateCache.ps1 -Force -OutputPath C:\Temp\Ticket123
    No prompt (for RMM). Saves before/after results.

.NOTES
    Purpose       : Clear a corrupt Windows Update cache without deleting anything.
    Use Case      : "Updates won't install" tickets, after a restart has not helped.
    Scope         : Local computer. Three Windows services and two folders under C:\Windows.
    Risk Level    : Safe -- reversible rename; services are restarted; no reboot; no update is
                    installed or removed. Updates may download again (bandwidth, time).
    Prerequisites : Windows PowerShell 5.1 | Admin: Yes for changes (No for -WhatIf) | Modules: built-in only
    Exit codes    : 0 changes made and checked (or -WhatIf); 1 nothing changed (not admin, not
                    confirmed, non-interactive without -Force); 2 a step failed (see findings)
    Version       : 2.0.0
    Limitations   : Does not repair Windows component store corruption (use DISM /RestoreHealth
                    and sfc /scannow for that). Group Policy or security software that blocks the
                    update services is reported, not changed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [string]$OutputPath,
    [ValidateRange(10, 300)][int]$ServiceTimeoutSeconds = 60
)

#region MSPToolkit (generated) Sections=Core,Updates,Change
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Updates,Change | SHA256: 662e53a1634fb486097195c083499065d5848c93613fa670bb1831a760628082
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
Initialize-MSPRun -ScriptName 'Clear-WindowsUpdateCache' -ScriptVersion $ScriptVersion -CheckId 'D1' -RiskLevel 'Safe' `
    -Parameters $PSBoundParameters -Description 'Windows Update cache reset by renaming (never deleting) the cache folders' `
    -AdminSections 'stopping/starting services and renaming the cache folders (not needed for -WhatIf)'

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$exitCode = 0
# Order matters for starting: cryptSvc first (it owns catroot2), then BITS and Windows Update.
$serviceNames = @('cryptSvc', 'bits', 'wuauserv')
$folders = @(
    [pscustomobject]@{ Name = 'SoftwareDistribution'; Path = (Join-Path $env:SystemRoot 'SoftwareDistribution') },
    [pscustomobject]@{ Name = 'catroot2'; Path = (Join-Path $env:SystemRoot 'System32\catroot2') }
)

function Get-ServiceState {
    <# Status and start type of the three services, for before/after tables. #>
    foreach ($name in $serviceNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            [pscustomobject]@{ Name = $name; DisplayName = ''; Status = 'NotFound'; StartType = '' }
            continue
        }
        [pscustomobject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; Status = [string]$svc.Status; StartType = [string]$svc.StartType }
    }
}

function Get-FolderSummary {
    <# Size and file count; partial when some files cannot be read (normal without admin for catroot2). #>
    param([string]$Path)
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue -ErrorVariable readErrors)
    $bytes = ($files | Measure-Object -Property Length -Sum).Sum
    if (-not $bytes) { $bytes = 0 }
    return [pscustomobject]@{ Files = $files.Count; MB = [math]::Round($bytes / 1MB, 1); Partial = (@($readErrors).Count -gt 0) }
}

function Wait-ServiceStatus {
    <# Waits for a service to reach a status; returns $true if it did within the timeout. #>
    param([string]$Name, [string]$Status)
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        $svc.WaitForStatus($Status, [TimeSpan]::FromSeconds($ServiceTimeoutSeconds))
        return $true
    }
    catch {
        return $false
    }
}

# =========================================================================================
Write-MSPSection -Title 'Current state (before)'
# =========================================================================================
$before = @(Get-ServiceState)
Add-MSPData -Name 'ServicesBefore' -Rows $before
foreach ($s in $before) {
    $status = 'INFO'
    $detail = '{0}: {1} (start type {2})' -f $s.DisplayName, $s.Status, $s.StartType
    if ($s.Status -eq 'NotFound') { $status = 'WARN'; $detail = 'Service not found on this computer.' }
    elseif ($s.StartType -eq 'Disabled') { $status = 'WARN'; $detail = '{0} is DISABLED. This script will not change that; updates cannot work while it is disabled.' -f $s.DisplayName }
    Add-MSPFinding -Check ('Service {0}' -f $s.Name) -Category 'Before' -Status $status -Detail $detail `
        -Recommendation $(if ($status -eq 'WARN') { 'Check Group Policy or security software that disables Windows Update services.' } else { '' })
}

foreach ($f in $folders) {
    Invoke-MSPCheck -Name ('Folder {0}' -f $f.Name) -Category 'Before' -ScriptBlock {
        if (-not (Test-Path -LiteralPath $f.Path)) {
            Add-MSPFinding -Check ('Folder {0}' -f $f.Name) -Category 'Before' -Status INFO -Detail ('{0} does not exist (Windows creates it when needed).' -f $f.Path)
            return
        }
        $sum = Get-FolderSummary -Path $f.Path
        $note = ''
        if ($sum.Partial) { $note = ' (some files could not be read without administrator; size is a minimum)' }
        Add-MSPFinding -Check ('Folder {0}' -f $f.Name) -Category 'Before' -Status INFO -Detail ('{0}: {1} MB in {2} files{3}.' -f $f.Path, $sum.MB, $sum.Files, $note) `
            -Evidence @{ Path = $f.Path; MB = $sum.MB; Files = $sum.Files }
    }
}

Invoke-MSPCheck -Name 'Earlier .old folders' -Category 'Before' -ScriptBlock {
    $old = @(Get-ChildItem -LiteralPath $env:SystemRoot -Directory -Filter 'SoftwareDistribution.old*' -ErrorAction SilentlyContinue) +
    @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'System32') -Directory -Filter 'catroot2.old*' -ErrorAction SilentlyContinue)
    if ($old.Count -eq 0) {
        Add-MSPFinding -Check 'Earlier .old folders' -Category 'Before' -Status INFO -Detail 'None from earlier runs.'
        return
    }
    Add-MSPFinding -Check 'Earlier .old folders' -Category 'Before' -Status WARN -Severity Low `
        -Detail ('{0} folder(s) from earlier cache resets: {1}' -f $old.Count, (($old | ForEach-Object { $_.FullName }) -join '; ')) `
        -Recommendation 'If updates have installed since those resets, delete these folders by hand to free disk space. This script never deletes them.'
}

Invoke-MSPCheck -Name 'Pending restart' -Category 'Before' -ScriptBlock {
    $reasons = @(Get-MSPPendingReboot)
    if ($reasons.Count -gt 0) {
        Add-MSPFinding -Check 'Pending restart' -Category 'Before' -Status WARN -Severity Medium -Detail ('Windows is waiting for a restart: {0}.' -f ($reasons -join ', ')) `
            -Recommendation 'Restart and try Windows Update again first; many update errors clear after the pending restart. Run this script only if that does not help.'
    }
    else {
        Add-MSPFinding -Check 'Pending restart' -Category 'Before' -Status PASS -Detail 'No restart pending.'
    }
}

Invoke-MSPCheck -Name 'Free disk space' -Category 'Before' -ScriptBlock {
    $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop
    $freeGB = [math]::Round($drive.FreeSpace / 1GB, 1)
    $status = 'INFO'
    if ($freeGB -lt 10) { $status = 'WARN' }
    Add-MSPFinding -Check 'Free disk space' -Category 'Before' -Status $status -Detail ('{0} GB free on {1}. Renaming keeps the old cache''s space in use until you delete the .old folder.' -f $freeGB, $env:SystemDrive) `
        -Recommendation $(if ($status -eq 'WARN') { 'Low space can itself cause update failures; free space first (Disk Cleanup, Storage Sense).' } else { '' })
}

# =========================================================================================
# Plan
# =========================================================================================
$runningBefore = @($before | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
$toStop = @($before | Where-Object { $_.Status -notin @('Stopped', 'NotFound') } | ForEach-Object { $_.Name })
$toStart = @($serviceNames | Where-Object { ($runningBefore -contains $_) -or ($_ -in @('cryptSvc', 'wuauserv')) } |
        Where-Object { ($before | Where-Object Name -eq $_).StartType -notin @('Disabled', '') })
$renames = foreach ($f in $folders) {
    if (Test-Path -LiteralPath $f.Path) {
        [pscustomobject]@{ Folder = $f; NewName = ('{0}.old-{1}' -f $f.Name, $stamp) }
    }
}
$renames = @($renames)

$plan = @()
if ($toStop.Count -gt 0) { $plan += ('Stop services: {0}' -f ($toStop -join ', ')) } else { $plan += 'Stop services: none are running' }
foreach ($r in $renames) { $plan += ('Rename {0} -> {1}   (nothing is deleted)' -f $r.Folder.Path, $r.NewName) }
if ($renames.Count -eq 0) { $plan += 'Rename: neither folder exists, so there is nothing to rename' }
$plan += ('Start services: {0}' -f ($toStart -join ', '))
$plan += 'Check: services running, folders recreated by Windows, Windows Update API available'
Write-MSPChangePlan -Step $plan

if ($dryRun) {
    # Standard "What if:" lines for each change, then stop: nothing below this point runs.
    foreach ($name in $toStop) { Write-MSPWhatIf -Target ($name) -Action ('Stop service') }
    foreach ($r in $renames) { Write-MSPWhatIf -Target ($r.Folder.Path) -Action (('Rename to {0}' -f $r.NewName)) }
    foreach ($name in $toStart) { Write-MSPWhatIf -Target ($name) -Action ('Start service') }
    Add-MSPFinding -Check 'Dry run' -Category 'Safety' -Status INFO -Detail '-WhatIf: the plan above was shown and nothing was changed.'
    if (-not $script:MSPRun.IsAdmin) {
        Add-MSPFinding -Check 'Administrator' -Category 'Safety' -Status INFO -Detail 'A real run needs "Run as administrator".'
    }
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}

if (-not $script:MSPRun.IsAdmin) {
    Add-MSPFinding -Check 'Administrator' -Category 'Safety' -Status SKIPPED `
        -Detail 'No changes made: stopping services and renaming folders under C:\Windows requires administrator.' `
        -Recommendation 'Open PowerShell with "Run as administrator" and run the script again (or run with -WhatIf to preview without admin).'
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

if (-not (Confirm-MSPChange -Question ('Stop the update services and rename the cache folders on {0}?' -f $script:MSPRun.Host) -Force:$Force)) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

# =========================================================================================
Write-MSPSection -Title 'Stopping services'
# =========================================================================================
$stopped = New-Object System.Collections.Generic.List[string]
$stopFailed = $false
foreach ($name in $toStop) {
    if (-not $PSCmdlet.ShouldProcess($name, 'Stop service')) { continue }
    try {
        Stop-Service -Name $name -Force -ErrorAction Stop
        if (-not (Wait-ServiceStatus -Name $name -Status 'Stopped')) { throw ('did not stop within {0} seconds' -f $ServiceTimeoutSeconds) }
        $stopped.Add($name)
        Add-MSPFinding -Check ('Stop {0}' -f $name) -Category 'Change' -Status PASS -Detail 'Stopped.'
    }
    catch {
        $stopFailed = $true
        Add-MSPFinding -Check ('Stop {0}' -f $name) -Category 'Change' -Status FAIL -Detail ('Could not stop: {0}' -f $_.Exception.Message) `
            -Recommendation 'Something is holding the service (an update installing, or security software). Restart the PC and try again.'
        break
    }
}

if ($stopFailed) {
    # Leave everything as it was: start what we stopped, rename nothing.
    foreach ($name in $stopped) {
        try { Start-Service -Name $name -ErrorAction Stop } catch { Write-MSPLog -Level WARN -Message ('Restart after failed stop: {0}: {1}' -f $name, $_.Exception.Message) }
    }
    Add-MSPFinding -Check 'Rollback' -Category 'Change' -Status INFO -Detail ('Nothing was renamed. Services stopped so far were started again: {0}.' -f $(if ($stopped.Count) { $stopped -join ', ' } else { 'none' }))
    Add-MSPData -Name 'ServicesAfter' -Rows @(Get-ServiceState)
    Complete-MSPRun -OutputPath $OutputPath
    exit 2
}

# =========================================================================================
Write-MSPSection -Title 'Renaming cache folders'
# =========================================================================================
$renamed = New-Object System.Collections.Generic.List[object]
foreach ($r in $renames) {
    if (-not $PSCmdlet.ShouldProcess($r.Folder.Path, ('Rename to {0}' -f $r.NewName))) { continue }
    try {
        Rename-Item -LiteralPath $r.Folder.Path -NewName $r.NewName -ErrorAction Stop
        $renamed.Add($r)
        Add-MSPFinding -Check ('Rename {0}' -f $r.Folder.Name) -Category 'Change' -Status PASS -Detail ('{0} -> {1}' -f $r.Folder.Path, $r.NewName) `
            -Evidence @{ From = $r.Folder.Path; To = $r.NewName }
    }
    catch {
        $exitCode = 2
        Add-MSPFinding -Check ('Rename {0}' -f $r.Folder.Name) -Category 'Change' -Status FAIL -Detail ('Could not rename {0}: {1}' -f $r.Folder.Path, $_.Exception.Message) `
            -Recommendation 'A file in the folder is in use. Restart the PC and run the script again before Windows Update starts working.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Starting services'
# =========================================================================================
foreach ($name in $toStart) {
    if (-not $PSCmdlet.ShouldProcess($name, 'Start service')) { continue }
    try {
        Start-Service -Name $name -ErrorAction Stop
        if (-not (Wait-ServiceStatus -Name $name -Status 'Running')) { throw ('did not start within {0} seconds' -f $ServiceTimeoutSeconds) }
        Add-MSPFinding -Check ('Start {0}' -f $name) -Category 'Change' -Status PASS -Detail 'Running.'
    }
    catch {
        $exitCode = 2
        Add-MSPFinding -Check ('Start {0}' -f $name) -Category 'Change' -Status FAIL -Detail ('Could not start: {0}' -f $_.Exception.Message) `
            -Recommendation 'Restart the PC. If it still will not start, check Group Policy or security software that blocks it.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Checks (after)'
# =========================================================================================
$after = @(Get-ServiceState)
Add-MSPData -Name 'ServicesAfter' -Rows $after
foreach ($name in $runningBefore) {
    $state = ($after | Where-Object Name -eq $name).Status
    if ($state -eq 'Running') { Add-MSPFinding -Check ('{0} running again' -f $name) -Category 'After' -Status PASS -Detail 'Running, as before.' }
    else { Add-MSPFinding -Check ('{0} running again' -f $name) -Category 'After' -Status WARN -Detail ('Was running before, now {0}.' -f $state) -Recommendation 'Restart the PC; Windows starts it when needed.' }
}

foreach ($r in $renamed) {
    # Windows recreates the folders itself (wuauserv / cryptSvc); give it up to 30 seconds.
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $r.Folder.Path) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    if (Test-Path -LiteralPath $r.Folder.Path) {
        Add-MSPFinding -Check ('{0} recreated' -f $r.Folder.Name) -Category 'After' -Status PASS -Detail ('Windows created a fresh {0}.' -f $r.Folder.Path)
    }
    else {
        Add-MSPFinding -Check ('{0} recreated' -f $r.Folder.Name) -Category 'After' -Status WARN -Detail ('{0} is not back yet.' -f $r.Folder.Path) `
            -Recommendation 'Normal if Windows has not checked for updates yet; it is created at the next check (Settings > Windows Update > Check for updates).'
    }
}

Invoke-MSPCheck -Name 'Windows Update API' -Category 'After' -ScriptBlock {
    $null = New-Object -ComObject Microsoft.Update.Session
    Add-MSPFinding -Check 'Windows Update API' -Category 'After' -Status PASS -Detail 'The Windows Update COM API responds.'
}

if ($renamed.Count -gt 0) {
    $undo = @('To undo (as administrator): Stop-Service wuauserv, cryptSvc, bits -Force')
    foreach ($r in $renamed) {
        $undo += ('Remove-Item -LiteralPath "{0}" -Recurse -Force   (the NEW, rebuilt folder)' -f $r.Folder.Path)
        $undo += ('Rename-Item -LiteralPath "{0}" -NewName "{1}"' -f (Join-Path (Split-Path $r.Folder.Path -Parent) $r.NewName), $r.Folder.Name)
    }
    $undo += 'Start-Service cryptSvc, bits, wuauserv'
    foreach ($line in $undo) { Write-MSPLog -Message ('Undo: {0}' -f $line) }
    Add-MSPFinding -Check 'Undo steps' -Category 'After' -Status INFO -Detail ($undo -join ' | ')
    Add-MSPFinding -Check 'Next step' -Category 'After' -Status INFO `
        -Detail ('Open Settings > Windows Update > Check for updates. After updates install, delete {0} by hand to free disk space.' -f (($renamed | ForEach-Object { $_.NewName }) -join ' and '))
}

Complete-MSPRun -OutputPath $OutputPath
exit $exitCode
