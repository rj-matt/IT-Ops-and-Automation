<#
.SYNOPSIS
    Read-only "why is this PC slow?" snapshot: CPU, memory and disk sampled over a short window,
    the busiest processes, memory pressure, startup load, uptime and pending restart, throttling
    and power settings, known slow-down causes, and the specific next step for what it found.

.DESCRIPTION
    Samples every 2 seconds for -SampleSeconds (default 30) instead of taking one reading, so a
    short spike does not decide the result. Changes nothing.

    Checks
      CPU                 Average and peak use over the window; average 85 % or more = WARN.
      Memory              Average in use; 90 % or more, or less than 500 MB available = WARN.
      Memory pressure     Paging (Memory\Pages/sec, average 1000 or more = WARN) and commit
                          (90 % or more of the commit limit = WARN).
      Disk activity       Busy time of the physical disks; 95 % or more on average = WARN
                          ("disk at 100 %").
      Top processes       The busiest processes by CPU (over the window) and by memory.
      Startup programs    How many start with Windows (more than 15 = WARN) and the heaviest of
                          those running now (by memory).
      Uptime              More than 30 days = WARN. Restart pending: Windows Update, servicing,
                          file renames (same rules as B1).
      Throttling / power  CPU speed against its maximum during the window, the power plan and
                          Windows 11 power mode, on battery or plugged in.
      Known causes        Defender scanning, Windows Update installing, Search indexing (by the
                          CPU those processes used), the disk at 100 %, a nearly full system drive
                          (B5's rule: under 5 % or 5 GB free = FAIL, under 15 % or 20 GB = WARN).
      What to do          The next step for each problem found.

.PARAMETER SampleSeconds
    How long to sample (5-120, default 30).

.PARAMETER TopProcesses
    How many processes to list by CPU and by memory (3-20, default 5).

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with Samples, TopCpu, TopMemory,
    Startup and NextSteps tables.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Get-PerformanceSnapshot.ps1

.EXAMPLE
    .\Get-PerformanceSnapshot.ps1 -SampleSeconds 60 -OutputPath C:\Temp\Ticket123

.NOTES
    Purpose       : Find the reason a PC is slow, while it is slow.
    Use Case      : "My computer is slow" tickets; before deciding on more memory or a new PC.
    Scope         : This PC only. No network traffic.
    Risk Level    : Read-Only -- reads performance counters, processes and settings; changes nothing.
    Prerequisites : Windows 10/11 or Server 2016+ | Windows PowerShell 5.1 or PowerShell 7 |
                    Admin: No (administrator sees the CPU time of every process)
    Version       : 1.0.0
    Limitations   : A snapshot of the window it ran in: run it while the PC is slow. Without
                    administrator rights some system processes' CPU time cannot be read. Thermal
                    readings are not exposed on most PCs; throttling is judged from the CPU speed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [int]$SampleSeconds = 30,
    [int]$TopProcesses = 5,
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core,Updates
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Updates | SHA256: 38adea19a3db2c4e14f18bdb2079051bb6b10c24d2f117309e0a16e29e912dd2
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

$ScriptVersion = '1.0.0'
Initialize-MSPRun -ScriptName 'Get-PerformanceSnapshot' -ScriptVersion $ScriptVersion -CheckId 'B6' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Performance snapshot: CPU, memory, disk over a window; processes, startup, throttling, causes (read-only)'
# Number ranges are checked here, not with [ValidateRange], so a wrong value gets a plain message
# and a clean exit 1 instead of a parameter-binding error.
if (-not (Test-MSPParameterRange -Bound $PSBoundParameters -Range ([ordered]@{ SampleSeconds = 5, 120; TopProcesses = 3, 20 }))) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

$now = Get-Date
$steps = New-Object System.Collections.Generic.List[string]
$cores = [Environment]::ProcessorCount
$GB = [double]1GB

function Get-VolumeStatus {
    <# B5's rule: under 5 % or 5 GB free = FAIL, under 15 % or 20 GB = WARN; under 50 GB in size: percentage only. #>
    param([double]$SizeGB, [double]$FreeGB, [double]$PercentFree)
    $small = $SizeGB -lt 50
    if ($PercentFree -lt 5 -or (-not $small -and $FreeGB -lt 5)) { return 'FAIL' }
    if ($PercentFree -lt 15 -or (-not $small -and $FreeGB -lt 20)) { return 'WARN' }
    return 'PASS'
}

function Get-Average { param([double[]]$Value) if (@($Value).Count -eq 0) { return 0 } return [math]::Round((($Value | Measure-Object -Average).Average), 1) }
function Get-Peak { param([double[]]$Value) if (@($Value).Count -eq 0) { return 0 } return [math]::Round((($Value | Measure-Object -Maximum).Maximum), 1) }

# =========================================================================================
Write-MSPSection -Title ('Sampling for {0} seconds' -f $SampleSeconds)
# =========================================================================================
$samples = New-Object System.Collections.Generic.List[object]
$procStart = @{}
$procEnd = @{}
$totalMemKB = [double]0
$clock = @{ Current = New-Object System.Collections.Generic.List[double]; Max = 0 }
Invoke-MSPCheck -Name 'Sampling' -Category 'Sampling' -ScriptBlock {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $script:totalMemKB = [double]$os.TotalVisibleMemorySize
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        try { $procStart[[int]$p.Id] = [double]$p.TotalProcessorTime.TotalSeconds } catch { $procStart[[int]$p.Id] = $null }
    }
    $started = Get-Date
    $end = $started.AddSeconds($SampleSeconds)
    do {
        $cpu = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop)[0]
        $mem = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
        $disk = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue)[0]
        $cpuInfo = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)[0]
        if ($cpuInfo) { $clock.Current.Add([double]$cpuInfo.CurrentClockSpeed); $clock.Max = [double]$cpuInfo.MaxClockSpeed }
        $busy = $null
        if ($disk) { $busy = [math]::Max(0, 100 - [double]$disk.PercentIdleTime) }
        $samples.Add([pscustomobject]@{
                Time = (Get-Date).ToString('HH:mm:ss'); CpuPercent = [double]$cpu.PercentProcessorTime; AvailableMB = [double]$mem.AvailableMBytes
                PagesPerSec = [double]$mem.PagesPersec; CommitPercent = [double]$mem.PercentCommittedBytesInUse; DiskBusyPercent = $busy
            })
        if ((Get-Date) -lt $end) { Start-Sleep -Seconds 2 }
    } while ((Get-Date) -lt $end)
    $elapsed = [math]::Max(1, ((Get-Date) - $started).TotalSeconds)
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $cpuSec = $null
        try { $cpuSec = [double]$p.TotalProcessorTime.TotalSeconds } catch { $cpuSec = $null }
        $pct = $null
        if ($null -ne $cpuSec -and $procStart.ContainsKey([int]$p.Id) -and $null -ne $procStart[[int]$p.Id]) {
            $pct = [math]::Round(100 * ($cpuSec - $procStart[[int]$p.Id]) / $elapsed / $cores, 1)
        }
        $procEnd[[int]$p.Id] = [pscustomobject]@{ Name = [string]$p.ProcessName; Id = [int]$p.Id; CpuPercent = $pct; MemoryMB = [math]::Round([double]$p.WorkingSet64 / 1MB, 0); Path = [string]$p.Path }
    }
    Add-MSPData -Name 'Samples' -Rows $samples.ToArray()
    Add-MSPFinding -Check 'Sampling' -Category 'Sampling' -Status INFO -Detail ('{0} sample(s) over {1:N0} seconds, {2} logical processor(s).' -f $samples.Count, $elapsed, $cores)
}
$procs = @($procEnd.Values)
function Get-ProcCpu { param([string[]]$Name) return [double](($procs | Where-Object { $Name -contains $_.Name -and $null -ne $_.CpuPercent } | Measure-Object CpuPercent -Sum).Sum) }

# =========================================================================================
Write-MSPSection -Title 'CPU, memory and disk'
# =========================================================================================
Invoke-MSPCheck -Name 'CPU' -Category 'Load' -ScriptBlock {
    if ($samples.Count -eq 0) { Skip-MSPCheck -Reason 'No samples were taken (see "Sampling").' }
    $avg = Get-Average @($samples | ForEach-Object { $_.CpuPercent })
    $peak = Get-Peak @($samples | ForEach-Object { $_.CpuPercent })
    $text = 'Average {0} %, peak {1} % over {2} seconds.' -f $avg, $peak, $SampleSeconds
    if ($avg -ge 85) {
        $topName = @($procs | Where-Object { $null -ne $_.CpuPercent } | Sort-Object CpuPercent -Descending | Select-Object -First 1)
        Add-MSPFinding -Check 'CPU' -Category 'Load' -Status WARN -Severity High -Detail $text -Evidence @{ AveragePercent = $avg; PeakPercent = $peak } `
            -Recommendation 'The processor is the bottleneck: see the top processes below for what is using it.'
        if ($topName) { $script:steps.Add(('CPU is busy ({0} % on average): look at {1} first (it used {2} % of the CPU); close it, update it, or ask the vendor if it stays high.' -f $avg, $topName[0].Name, $topName[0].CpuPercent)) }
    }
    else { Add-MSPFinding -Check 'CPU' -Category 'Load' -Status PASS -Detail $text -Evidence @{ AveragePercent = $avg; PeakPercent = $peak } }
}

Invoke-MSPCheck -Name 'Memory' -Category 'Load' -ScriptBlock {
    if ($samples.Count -eq 0 -or $totalMemKB -le 0) { Skip-MSPCheck -Reason 'No memory samples were taken (see "Sampling").' }
    $totalMB = $totalMemKB / 1024
    $availMin = [math]::Round((($samples | Measure-Object AvailableMB -Minimum).Minimum), 0)
    $usedPct = [math]::Round(100 * (1 - (Get-Average @($samples | ForEach-Object { $_.AvailableMB })) / $totalMB), 1)
    $text = '{0} % of {1:N1} GB in use on average; lowest available {2:N0} MB.' -f $usedPct, ($totalMB / 1024), $availMin
    if ($usedPct -ge 90 -or $availMin -lt 500) {
        Add-MSPFinding -Check 'Memory' -Category 'Load' -Status WARN -Severity High -Detail $text -Recommendation 'Close what is not needed (see the top processes by memory); if it is always this full, the PC needs more memory.'
        $script:steps.Add(('Memory is nearly full ({0} % in use): close the biggest programs listed below, or plan a memory upgrade if this is normal use ({1:N0} GB installed).' -f $usedPct, ($totalMB / 1024)))
    }
    else { Add-MSPFinding -Check 'Memory' -Category 'Load' -Status PASS -Detail $text }
}

Invoke-MSPCheck -Name 'Memory pressure' -Category 'Load' -ScriptBlock {
    if ($samples.Count -eq 0) { Skip-MSPCheck -Reason 'No samples were taken (see "Sampling").' }
    $pages = Get-Average @($samples | ForEach-Object { $_.PagesPerSec })
    $commit = Get-Peak @($samples | ForEach-Object { $_.CommitPercent })
    $text = 'Paging {0} pages/s on average; commit up to {1} % of the limit.' -f $pages, $commit
    $why = @()
    if ($pages -ge 1000) { $why += 'heavy paging to disk' }
    if ($commit -ge 90) { $why += 'commit near the limit (programs may fail to start)' }
    if ($why.Count -gt 0) {
        Add-MSPFinding -Check 'Memory pressure' -Category 'Load' -Status WARN -Severity High -Detail ('{0} ({1}).' -f $text.TrimEnd('.'), ($why -join ', ')) `
            -Recommendation 'Windows is short of memory and using the page file: close programs, check for a memory leak (one process growing), or add memory.'
        $script:steps.Add(('Memory pressure ({0}): restart the program that grew the most, and check the page file is on an SSD and system-managed.' -f ($why -join ', ')))
    }
    else { Add-MSPFinding -Check 'Memory pressure' -Category 'Load' -Status PASS -Detail $text }
}

$diskBusy = $null
Invoke-MSPCheck -Name 'Disk activity' -Category 'Load' -ScriptBlock {
    $busy = @($samples | Where-Object { $null -ne $_.DiskBusyPercent } | ForEach-Object { $_.DiskBusyPercent })
    if ($busy.Count -eq 0) { Skip-MSPCheck -Reason 'The disk performance counters are not available (diskperf may be off).' }
    $avg = Get-Average $busy
    $script:diskBusy = $avg
    $text = 'Disks busy {0} % of the time on average, peak {1} %.' -f $avg, (Get-Peak $busy)
    if ($avg -ge 95) {
        Add-MSPFinding -Check 'Disk activity' -Category 'Load' -Status WARN -Severity High -Detail $text -Recommendation 'The disk is the bottleneck ("disk at 100 %"): see Known causes; an old hard disk (HDD) is the usual reason, and an SSD is the fix.'
    }
    else { Add-MSPFinding -Check 'Disk activity' -Category 'Load' -Status PASS -Detail $text }
}

Invoke-MSPCheck -Name 'Top processes' -Category 'Processes' -ScriptBlock {
    if ($procs.Count -eq 0) { Skip-MSPCheck -Reason 'No processes could be read.' }
    $byCpu = @($procs | Where-Object { $null -ne $_.CpuPercent -and $_.Name -ne 'Idle' } | Sort-Object CpuPercent -Descending | Select-Object -First $TopProcesses)
    $byMem = @($procs | Sort-Object MemoryMB -Descending | Select-Object -First $TopProcesses)
    Add-MSPData -Name 'TopCpu' -Rows @($byCpu | Select-Object Name, Id, CpuPercent, MemoryMB)
    Add-MSPData -Name 'TopMemory' -Rows @($byMem | Select-Object Name, Id, MemoryMB, CpuPercent)
    Add-MSPFinding -Check 'Top processes by CPU' -Category 'Processes' -Status INFO -Detail ((@($byCpu | ForEach-Object { '{0} {1} %' -f $_.Name, $_.CpuPercent })) -join '; ')
    Add-MSPFinding -Check 'Top processes by memory' -Category 'Processes' -Status INFO -Detail ((@($byMem | ForEach-Object { '{0} {1:N0} MB' -f $_.Name, $_.MemoryMB })) -join '; ')
}

# =========================================================================================
Write-MSPSection -Title 'Startup, uptime and restarts'
# =========================================================================================
Invoke-MSPCheck -Name 'Startup programs' -Category 'Startup' -ScriptBlock {
    $items = @(Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop)
    $rows = foreach ($i in $items) {
        $exe = ''
        # The file name without folder and .exe (split by hand: the tests run this on macOS/Linux too).
        if ([string]$i.Command -match '^\s*"?([^"]+?\.exe)') { $exe = (($Matches[1] -split '[\\/]')[-1]) -replace '\.exe$', '' }
        $running = @($procs | Where-Object { $exe -and $_.Name -eq $exe })
        [pscustomobject]@{ Name = [string]$i.Name; Command = [string]$i.Command; Location = [string]$i.Location; RunningMB = [double](($running | Measure-Object MemoryMB -Sum).Sum) }
    }
    $rows = @($rows | Sort-Object RunningMB -Descending)
    Add-MSPData -Name 'Startup' -Rows $rows
    $heavy = @($rows | Where-Object { $_.RunningMB -gt 0 } | Select-Object -First 5)
    $heavyText = ''
    if ($heavy.Count -gt 0) { $heavyText = ' Heaviest running now: ' + ((@($heavy | ForEach-Object { '{0} {1:N0} MB' -f $_.Name, $_.RunningMB })) -join ', ') + '.' }
    if ($rows.Count -gt 15) {
        Add-MSPFinding -Check 'Startup programs' -Category 'Startup' -Status WARN -Severity Low -Detail ('{0} programs start with Windows.{1}' -f $rows.Count, $heavyText) `
            -Recommendation 'Turn off what the user does not need at startup: Task Manager > Startup apps (or Settings > Apps > Startup).'
        $script:steps.Add(('Too many startup programs ({0}): in Task Manager > Startup apps, disable what the user does not need{1}.' -f $rows.Count, $(if ($heavy) { ', starting with ' + ((@($heavy | Select-Object -First 3 | ForEach-Object { $_.Name })) -join ', ') } else { '' })))
    }
    else { Add-MSPFinding -Check 'Startup programs' -Category 'Startup' -Status PASS -Detail ('{0} programs start with Windows.{1}' -f $rows.Count, $heavyText) }
}

Invoke-MSPCheck -Name 'Uptime' -Category 'Startup' -ScriptBlock {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $days = [int]($now - [datetime]$os.LastBootUpTime).TotalDays
    if ($days -gt 30) {
        Add-MSPFinding -Check 'Uptime' -Category 'Startup' -Status WARN -Severity Medium -Detail ('Up {0} days (since {1:yyyy-MM-dd}).' -f $days, [datetime]$os.LastBootUpTime) -Recommendation 'Restart the PC; Fast Startup means "Shut down" does not count.'
        $script:steps.Add(('Restart the PC (up {0} days; "Shut down" does not count with Fast Startup on). Check again after the restart.' -f $days))
    }
    else { Add-MSPFinding -Check 'Uptime' -Category 'Startup' -Status PASS -Detail ('Up {0} day(s).' -f $days) }
}

Invoke-MSPCheck -Name 'Restart pending' -Category 'Startup' -ScriptBlock {
    $reasons = @(Get-MSPPendingReboot)
    if ($reasons.Count -gt 0) {
        Add-MSPFinding -Check 'Restart pending' -Category 'Startup' -Status WARN -Severity Medium -Detail ('Waiting for a restart: {0}.' -f ($reasons -join '; ')) -Recommendation 'Restart to finish installing updates; pending updates keep using CPU and disk.'
        $script:steps.Add('Restart to finish the pending updates (they keep working in the background until then).')
    }
    else { Add-MSPFinding -Check 'Restart pending' -Category 'Startup' -Status PASS -Detail 'No restart pending.' }
}

# =========================================================================================
Write-MSPSection -Title 'Throttling and power'
# =========================================================================================
Invoke-MSPCheck -Name 'CPU speed' -Category 'Power' -ScriptBlock {
    if ($clock.Current.Count -eq 0 -or $clock.Max -le 0) { Skip-MSPCheck -Reason 'The CPU speed is not reported on this PC.' }
    $avg = Get-Average @($clock.Current.ToArray())
    $pct = [math]::Round(100 * $avg / $clock.Max, 0)
    $text = 'Average {0:N0} MHz of {1:N0} MHz rated ({2} %)' -f $avg, $clock.Max, $pct
    $busy = Get-Average @($samples | ForEach-Object { $_.CpuPercent })
    if ($pct -lt 60 -and $busy -ge 50) {
        Add-MSPFinding -Check 'CPU speed' -Category 'Power' -Status WARN -Severity Medium -Detail ('{0} while the CPU was {1} % busy: it is being held back (power saving, heat or a weak charger).' -f $text, $busy) `
            -Recommendation 'Plug in the original charger, set the power mode to Balanced or Best performance, and check the vents and fan are not blocked.'
        $script:steps.Add('The CPU is running slow while busy: use the original charger, set Power mode to Balanced or Best performance, and clean the vents.')
    }
    else { Add-MSPFinding -Check 'CPU speed' -Category 'Power' -Status INFO -Detail ($text + '.') }
}

Invoke-MSPCheck -Name 'Power plan' -Category 'Power' -ScriptBlock {
    $out = @(& powercfg.exe /getactivescheme 2>$null)
    $plan = ''
    if (($out -join ' ') -match '\(([^)]+)\)') { $plan = $Matches[1] }
    $mode = ''
    $overlay = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -ErrorAction SilentlyContinue
    $battery = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
    $onBattery = $battery.Count -gt 0 -and [int]$battery[0].BatteryStatus -eq 1
    if ($overlay) {
        $guid = [string]$overlay.ActiveOverlayAcPowerScheme
        if ($onBattery) { $guid = [string]$overlay.ActiveOverlayDcPowerScheme }
        switch ($guid) {
            '961cc777-2547-4f9d-8174-7d86181b8a7a' { $mode = 'Best power efficiency' }
            'ded574b5-45a0-4f42-8737-46345c09c238' { $mode = 'Best performance' }
            default { if ($guid) { $mode = 'Balanced' } }
        }
    }
    $power = 'no battery'
    if ($battery.Count -gt 0) { $power = '{0}, battery {1} %' -f $(if ($onBattery) { 'on battery' } else { 'plugged in' }), $battery[0].EstimatedChargeRemaining }
    $text = 'Power plan: {0}{1}; {2}.' -f $(if ($plan) { $plan } else { 'unknown' }), $(if ($mode) { '; power mode: ' + $mode } else { '' }), $power
    if ($plan -match 'saver' -or $mode -eq 'Best power efficiency') {
        Add-MSPFinding -Check 'Power plan' -Category 'Power' -Status WARN -Severity Low -Detail $text -Recommendation 'Power saving slows the CPU on purpose: set Settings > System > Power > Power mode to Balanced (or Best performance when plugged in).'
        $script:steps.Add('Power saving is on: set Settings > System > Power > Power mode to Balanced (or Best performance when plugged in).')
    }
    else { Add-MSPFinding -Check 'Power plan' -Category 'Power' -Status INFO -Detail $text }
}

# =========================================================================================
Write-MSPSection -Title 'Known slow-down causes'
# =========================================================================================
Invoke-MSPCheck -Name 'Known causes' -Category 'Causes' -ScriptBlock {
    $found = @()
    $known = @(
        @{ Name = 'Antivirus scan'; Proc = @('MsMpEng', 'MpDefenderCoreService', 'NisSrv'); Step = 'Microsoft Defender is scanning: let it finish, or schedule full scans outside working hours (Defender / the security product''s policy).' }
        @{ Name = 'Windows Update installing'; Proc = @('TiWorker', 'TrustedInstaller', 'MoUsoCoreWorker', 'wuauclt', 'UsoClient'); Step = 'Windows Update is installing: let it finish and restart; afterwards the PC should be fast again.' }
        @{ Name = 'Search indexing'; Proc = @('SearchIndexer', 'SearchProtocolHost', 'SearchFilterHost'); Step = 'Windows Search is indexing: let it finish (it slows down while the user works); if it never ends, rebuild the index (Settings > Privacy & security > Searching Windows > Advanced indexing options).' }
    )
    foreach ($k in $known) {
        $cpu = Get-ProcCpu $k.Proc
        if ($cpu -ge 10) { $found += ('{0} ({1} % CPU)' -f $k.Name, [math]::Round($cpu, 1)); $script:steps.Add($k.Step) }
    }
    if ($null -ne $diskBusy -and $diskBusy -ge 95) {
        $found += ('disk at 100 % ({0} % busy)' -f $diskBusy)
        $script:steps.Add('The disk is at 100 %: if it is a hard disk (HDD), replacing it with an SSD is the fix; otherwise find the process using it (Resource Monitor > Disk).')
    }
    $c = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f ([string]$env:SystemDrive)) -ErrorAction SilentlyContinue)
    if ($c.Count -gt 0 -and [double]$c[0].Size -gt 0) {
        $free = [double]$c[0].FreeSpace / $GB
        $size = [double]$c[0].Size / $GB
        $pct = [math]::Round(100 * $free / $size, 1)
        $status = Get-VolumeStatus -SizeGB $size -FreeGB $free -PercentFree $pct
        if ($status -ne 'PASS') {
            $found += ('system drive nearly full ({0:N1} GB free, {1} %)' -f $free, $pct)
            $script:steps.Add(('The system drive is nearly full ({0:N1} GB free): run B5 Get-DiskSpaceReport.ps1 for where the space went and what can be cleaned.' -f $free))
        }
    }
    if ($found.Count -gt 0) {
        Add-MSPFinding -Check 'Known causes' -Category 'Causes' -Status WARN -Severity Medium -Detail ('Found: {0}.' -f ($found -join '; ')) -Recommendation 'See What to do for the step for each.'
    }
    else { Add-MSPFinding -Check 'Known causes' -Category 'Causes' -Status PASS -Detail 'No antivirus scan, update install or indexing busy, disk not at 100 %, system drive not nearly full.' }
}

# =========================================================================================
Write-MSPSection -Title 'What to do (by hand; this script changed nothing)'
# =========================================================================================
$final = @($steps | Select-Object -Unique)
if ($final.Count -eq 0) { $final = @('Nothing stood out while sampling. If the user says it is slow at other times, run this again while it is slow (with -SampleSeconds 60), and check B3 Get-RecentCriticalErrors.ps1 for crashes.') }
$i = 0
$stepRows = foreach ($s in $final) { $i++; Write-Host ('  {0,2}. {1}' -f $i, $s); [pscustomobject]@{ Step = $i; Action = $s } }
Add-MSPData -Name 'NextSteps' -Rows @($stepRows)
Add-MSPFinding -Check 'What to do' -Category 'Summary' -Status INFO -Detail ((@($stepRows | ForEach-Object { '{0}. {1}' -f $_.Step, $_.Action })) -join ' ')

Complete-MSPRun -OutputPath $OutputPath
