<#
.SYNOPSIS
    First-look triage for signs of compromise on this PC: startup items, programs and network
    connections from unusual folders, Defender detections and exclusions, new accounts, failed
    sign-ins, hosts file and proxy. Read-only. NOT an antivirus or EDR.

.DESCRIPTION
    A quick look at the places malware, scam remote-access tools and adware most often leave
    traces, so a technician can decide within minutes whether to escalate. It does not scan
    files for malware, look inside memory, or follow what programs do. A clean result does
    not prove the PC is clean.

    "Unusual folders" are folders ordinary programs are not installed in: Temp folders,
    C:\Users\Public, Downloads, the Recycle Bin, C:\PerfLogs, and files placed directly in
    C:\ProgramData or AppData\Roaming. Programs in the user profile (AppData) are common and
    only flagged when they are not validly signed.

    Checks
      Startup items                Run/RunOnce keys (machine and user), Startup folders,
                                   scheduled tasks outside \Microsoft\, automatic services
                                   outside Windows and Program Files (StartupItems table).
      Startup items in unusual folders     WARN High.
      Startup items that run scripts       Encoded PowerShell, mshta, wscript/cscript,
                                           regsvr32 /i:http, rundll32 javascript, download
                                           commands. WARN High.
      Unsigned startup programs            In the user profile, not validly signed. WARN Medium.
      New startup items                    Scheduled tasks and Startup-folder files created in
                                           the last -Days days. WARN Low (confirm with the user).
      Programs running from unusual folders    WARN High; unsigned ones from the profile WARN
                                               Medium. Other users' programs need administrator.
      Connections from flagged programs        Established TCP connections of those programs.
      Defender detections           Threats found in the last -Days days; not removed = WARN High.
      Defender exclusions           Folders, processes or file types Defender skips
                                    (administrator). Exclusions of Temp, user folders, whole
                                    drives or .exe/.ps1/.dll = WARN High.
      New local accounts / Added to Administrators   Security log, last -Days days
                                                     (administrator).
      Failed sign-ins               Security log, last 24 hours; more than 20 = WARN
                                    (administrator).
      Hosts file                    Entries that redirect update, security or major sites = WARN High.
      Proxy settings                A proxy or automatic proxy script for this user = WARN Medium.

.PARAMETER Days
    How far back "new" reaches for startup items, detections and accounts (1-90, default 14).

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with StartupItems,
    FlaggedProcesses and FlaggedConnections tables.

.EXAMPLE
    .\Get-SuspiciousActivityReport.ps1

.EXAMPLE
    .\Get-SuspiciousActivityReport.ps1 -Days 30 -OutputPath C:\Temp\Ticket123

.NOTES
    Purpose       : First-look triage: "does anything on this PC look like it was tampered with?"
    Use Case      : Scam calls ("someone was on my computer"), pop-ups, a slow PC with unknown
                    programs, before or after removing a remote-access tool.
    Scope         : This PC only. No network traffic; no files are opened except the hosts file.
    Risk Level    : Read-Only -- reads the registry, task scheduler, services, processes,
                    connections, Defender status and the Security log; changes nothing.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (recommended: Yes, for the Security log,
                    Defender exclusions and other users' programs) | Modules: built-in only
    Version       : 1.0.0
    Limitations   : NOT an antivirus or EDR: no file scanning, no memory analysis, no behaviour
                    history. Signed malware and programs in Program Files are not flagged by
                    folder. Defender checks need Microsoft Defender (third-party antivirus:
                    SKIPPED). macOS/Linux versions: get-suspicious-activity-report-macos.sh and
                    -linux.sh (same check names). MSP_TEST_ROOT (development tests only)
                    prefixes the hosts file path.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)][int]$Days = 14,
    [string]$OutputPath
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

$ScriptVersion = '1.0.0'
Initialize-MSPRun -ScriptName 'Get-SuspiciousActivityReport' -ScriptVersion $ScriptVersion -CheckId 'C3' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'First-look triage for signs of compromise (read-only; not an antivirus or EDR)' `
    -AdminSections @('Security log', 'Defender exclusions', 'other users'' programs')

$now = Get-Date
$since = $now.AddDays(-$Days)
$signatureCache = @{}

function Get-CommandPath {
    <# The program a command line starts: quoted path, or everything up to ".exe", or the first word. #>
    param([string]$Command)
    $c = [Environment]::ExpandEnvironmentVariables(([string]$Command).Trim())
    if ($c.StartsWith('"')) { return ($c.Substring(1) -split '"')[0] }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|scr|vbs|js|ps1|dll))(\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-FolderRisk {
    <# 'High' for unusual folders, 'Profile' for elsewhere in a user profile, '' otherwise. #>
    param([string]$Path)
    $p = [string]$Path
    if (-not $p) { return '' }
    if ($p -match '(?i)\\(Temp|Tmp)\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle\.Bin\\|^[A-Z]:\\PerfLogs\\|^[A-Z]:\\ProgramData\\[^\\]+$|\\AppData\\Roaming\\[^\\]+$') { return 'High' }
    if ($p -match '(?i)^[A-Z]:\\Users\\[^\\]+\\') { return 'Profile' }
    return ''
}

function Test-ScriptLaunch {
    <# True for command lines that hide a script or download behind a Windows program. #>
    param([string]$Command)
    return ([string]$Command -match '(?i)powershell(\.exe)?\b.*\s-(e|ec|en|enc|encodedcommand)\s|powershell.*(downloadstring|downloadfile|invoke-webrequest|\biwr\b|frombase64string|-w(indowstyle)?\s+h)|\b(mshta|wscript|cscript)(\.exe)?\b|regsvr32(\.exe)?\b.*/i:\s*https?|rundll32(\.exe)?\b.*javascript:|\b(certutil|bitsadmin)(\.exe)?\b.*(urlcache|transfer|https?:)|cmd(\.exe)?\s+/c\s+.*(curl|powershell)')
}

function Test-Signed {
    <# $true valid signature, $false unsigned or invalid, $null if the file is missing or unreadable. #>
    param([string]$Path)
    if (-not $Path) { return $null }
    if ($signatureCache.ContainsKey($Path)) { return $signatureCache[$Path] }
    $result = $null
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ([string]$sig.Status -eq 'Valid') { $result = $true }
        elseif ([string]$sig.Status -in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError', 'Incompatible')) { $result = $false }
    }
    catch { $result = $null }
    $signatureCache[$Path] = $result
    return $result
}

Add-MSPFinding -Check 'Scope' -Category 'Scope' -Status INFO `
    -Detail ('First-look triage of common hiding places for the last {0} day(s); not an antivirus or EDR scan. A clean result does not prove the PC is clean: if compromise is suspected, run a full malware scan and escalate.' -f $Days)

# =========================================================================================
Write-MSPSection -Title 'Startup items'
# =========================================================================================
$startup = New-Object System.Collections.Generic.List[object]
function Add-StartupItem {
    param([string]$Source, [string]$Name, [string]$Command, $Created = $null)
    $path = Get-CommandPath -Command $Command
    $startup.Add([pscustomobject]@{ Source = $Source; Name = $Name; Command = $Command; Path = $path; Risk = (Get-FolderRisk -Path $path); ScriptLaunch = (Test-ScriptLaunch -Command $Command); Created = $Created; Signed = $null })
}

Invoke-MSPCheck -Name 'Run keys' -Category 'Startup' -ScriptBlock {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach ($key in $keys) {
        $values = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $values) { continue }
        foreach ($p in $values.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            Add-StartupItem -Source ($key -replace '^(HK..):\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\', '$1 ') -Name $p.Name -Command ([string]$p.Value)
        }
    }
}

Invoke-MSPCheck -Name 'Startup folders' -Category 'Startup' -ScriptBlock {
    $shell = $null
    foreach ($kind in 'Startup', 'CommonStartup') {
        $folder = [Environment]::GetFolderPath($kind)
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $command = $file.FullName
            if ($file.Extension -eq '.lnk') {
                if (-not $shell) { $shell = New-Object -ComObject WScript.Shell }
                $link = $shell.CreateShortcut($file.FullName)
                $command = ('"{0}" {1}' -f $link.TargetPath, $link.Arguments).Trim()
            }
            Add-StartupItem -Source ('{0} folder' -f $kind) -Name $file.Name -Command $command -Created $file.CreationTime
        }
    }
}

Invoke-MSPCheck -Name 'Scheduled tasks' -Category 'Startup' -ScriptBlock {
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and [string]$_.State -ne 'Disabled' })) {
        $created = $null
        if ($task.Date) { try { $created = [datetime]$task.Date } catch { $created = $null } }
        foreach ($action in @($task.Actions | Where-Object { $_.Execute })) {
            $command = ('"{0}" {1}' -f $action.Execute, $action.Arguments).Trim()
            Add-StartupItem -Source 'Scheduled task' -Name ('{0}{1}' -f $task.TaskPath, $task.TaskName) -Command $command -Created $created
        }
    }
}

Invoke-MSPCheck -Name 'Services' -Category 'Startup' -ScriptBlock {
    foreach ($svc in @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" -ErrorAction Stop)) {
        $path = Get-CommandPath -Command ([string]$svc.PathName)
        if (-not $path -or $path -match '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\))\\') { continue }
        Add-StartupItem -Source 'Service' -Name ([string]$svc.Name) -Command ([string]$svc.PathName)
    }
}

foreach ($item in $startup) {
    if ($item.Risk -eq 'Profile') { $item.Signed = Test-Signed -Path $item.Path }
}
Add-MSPData -Name 'StartupItems' -Rows @($startup | ForEach-Object {
        [pscustomobject]@{ Source = $_.Source; Name = $_.Name; Command = $_.Command; Path = $_.Path; Folder = $(if ($_.Risk -eq 'High') { 'unusual' } elseif ($_.Risk) { 'user profile' } else { '' })
            RunsScript = [bool]$_.ScriptLaunch; Signed = $_.Signed; Created = $(if ($_.Created) { ([datetime]$_.Created).ToString('yyyy-MM-dd') } else { '' })
        }
    })
Add-MSPFinding -Check 'Startup items' -Category 'Startup' -Status INFO -Detail ('{0} startup item(s) outside Windows'' own (see the StartupItems table).' -f $startup.Count)

function Format-ItemList {
    param([object[]]$Items, [int]$Max = 8)
    $text = (@($Items | Select-Object -First $Max | ForEach-Object { '{0} "{1}": {2}' -f $_.Source, $_.Name, $_.Command }) -join '; ')
    if (@($Items).Count -gt $Max) { $text += ('; and {0} more' -f (@($Items).Count - $Max)) }
    return $text
}

Invoke-MSPCheck -Name 'Startup items in unusual folders' -Category 'Startup' -ScriptBlock {
    $hits = @($startup | Where-Object { $_.Risk -eq 'High' })
    if ($hits.Count -eq 0) { Add-MSPFinding -Check 'Startup items in unusual folders' -Category 'Startup' -Status PASS -Detail 'None start from Temp, Public, Downloads or similar folders.'; return }
    Add-MSPFinding -Check 'Startup items in unusual folders' -Category 'Startup' -Status WARN -Severity High -Detail (Format-ItemList $hits) `
        -Recommendation 'Ordinary software does not start from these folders. Look up each file (name, publisher, VirusTotal hash from another computer); if it is not recognized, disconnect the PC from the network and escalate for malware removal.'
}

Invoke-MSPCheck -Name 'Startup items that run scripts' -Category 'Startup' -ScriptBlock {
    $hits = @($startup | Where-Object { $_.ScriptLaunch })
    if ($hits.Count -eq 0) { Add-MSPFinding -Check 'Startup items that run scripts' -Category 'Startup' -Status PASS -Detail 'No startup item hides a script or download command.'; return }
    Add-MSPFinding -Check 'Startup items that run scripts' -Category 'Startup' -Status WARN -Severity High -Detail (Format-ItemList $hits) `
        -Recommendation 'Encoded PowerShell, mshta, wscript and download commands at startup are typical of malware. Do not run the command; record it, disconnect the PC from the network and escalate.'
}

Invoke-MSPCheck -Name 'Unsigned startup programs' -Category 'Startup' -ScriptBlock {
    $hits = @($startup | Where-Object { $_.Risk -eq 'Profile' -and $_.Signed -eq $false })
    if ($hits.Count -eq 0) { Add-MSPFinding -Check 'Unsigned startup programs' -Category 'Startup' -Status PASS -Detail 'Every startup program in a user profile is validly signed.'; return }
    Add-MSPFinding -Check 'Unsigned startup programs' -Category 'Startup' -Status WARN -Severity Medium -Detail (Format-ItemList $hits) `
        -Recommendation 'Unsigned programs that start from a user profile are worth a look: confirm with the user what each one is. Unknown ones should be checked on VirusTotal and removed.'
}

Invoke-MSPCheck -Name 'New startup items' -Category 'Startup' -ScriptBlock {
    $hits = @($startup | Where-Object { $_.Created -and [datetime]$_.Created -ge $since })
    if ($hits.Count -eq 0) { Add-MSPFinding -Check 'New startup items' -Category 'Startup' -Status PASS -Detail ('No scheduled task or Startup-folder item was added in the last {0} day(s).' -f $Days); return }
    Add-MSPFinding -Check 'New startup items' -Category 'Startup' -Status WARN -Severity Low -Detail (Format-ItemList $hits) `
        -Recommendation 'Ask the user whether they installed something around these dates. New items around the time of a scam call or pop-up deserve a closer look.'
}

# =========================================================================================
Write-MSPSection -Title 'Running programs and connections'
# =========================================================================================
$flagged = @{}
Invoke-MSPCheck -Name 'Programs running from unusual folders' -Category 'Processes' -ScriptBlock {
    $procs = @(Get-Process -ErrorAction Stop | Where-Object { $_.Path })
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $procs) {
        $risk = Get-FolderRisk -Path $p.Path
        if (-not $risk) { continue }
        $unsigned = $false
        if ($risk -eq 'Profile') { $unsigned = ((Test-Signed -Path $p.Path) -eq $false); if (-not $unsigned) { continue } }
        $script:flagged[[int]$p.Id] = $p.Path
        $rows.Add([pscustomobject]@{ ProcessId = [int]$p.Id; Name = [string]$p.ProcessName; Path = [string]$p.Path; Reason = $(if ($risk -eq 'High') { 'unusual folder' } else { 'unsigned, in user profile' }) })
    }
    Add-MSPData -Name 'FlaggedProcesses' -Rows $rows.ToArray()
    $note = ''
    if (-not $script:MSPRun.IsAdmin) { $note = ' Other users'' programs are only visible as administrator.' }
    $high = @($rows | Where-Object { $_.Reason -eq 'unusual folder' })
    $fromProfile = @($rows | Where-Object { $_.Reason -ne 'unusual folder' })
    if ($high.Count -gt 0) {
        Add-MSPFinding -Check 'Programs running from unusual folders' -Category 'Processes' -Status WARN -Severity High `
            -Detail ('{0}.{1}' -f ((@($high | ForEach-Object { '{0} (PID {1})' -f $_.Path, $_.ProcessId })) -join '; '), $note) `
            -Recommendation 'Note the paths, then disconnect the PC from the network and escalate. Do not end the processes before a malware scan has recorded them, unless the user is in active danger (for example a remote session in progress).'
    }
    else {
        Add-MSPFinding -Check 'Programs running from unusual folders' -Category 'Processes' -Status PASS -Detail ('None.{0}' -f $note)
    }
    if ($fromProfile.Count -gt 0) {
        Add-MSPFinding -Check 'Unsigned programs running from the user profile' -Category 'Processes' -Status WARN -Severity Medium `
            -Detail ((@($fromProfile | ForEach-Object { '{0} (PID {1})' -f $_.Path, $_.ProcessId })) -join '; ') `
            -Recommendation 'Confirm with the user what each program is; check unknown ones on VirusTotal.'
    }
}

Invoke-MSPCheck -Name 'Connections from flagged programs' -Category 'Processes' -ScriptBlock {
    $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$)' })
    $rows = @(foreach ($c in $connections) {
            if ($flagged.ContainsKey([int]$c.OwningProcess)) {
                [pscustomobject]@{ ProcessId = [int]$c.OwningProcess; Path = $flagged[[int]$c.OwningProcess]; Remote = ('{0}:{1}' -f $c.RemoteAddress, $c.RemotePort) }
            }
        })
    Add-MSPData -Name 'FlaggedConnections' -Rows $rows
    if ($rows.Count -eq 0) {
        Add-MSPFinding -Check 'Connections from flagged programs' -Category 'Processes' -Status PASS -Detail ('No flagged program has a network connection ({0} connection(s) in total).' -f $connections.Count)
        return
    }
    Add-MSPFinding -Check 'Connections from flagged programs' -Category 'Processes' -Status WARN -Severity High `
        -Detail ((@($rows | ForEach-Object { '{0} -> {1}' -f $_.Path, $_.Remote })) -join '; ') `
        -Recommendation 'A flagged program talking to the internet may be sending data out or taking remote control. Disconnect the PC from the network now and escalate.'
}

# =========================================================================================
Write-MSPSection -Title 'Microsoft Defender'
# =========================================================================================
Invoke-MSPCheck -Name 'Defender detections' -Category 'Defender' -ScriptBlock {
    if (-not (Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
        Skip-MSPCheck -Reason 'Microsoft Defender commands are not available (another antivirus may be in use).' -Recommendation 'Check the detection history in the installed antivirus product.'
    }
    $detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -and [datetime]$_.InitialDetectionTime -ge $since })
    if ($detections.Count -eq 0) { Add-MSPFinding -Check 'Defender detections' -Category 'Defender' -Status PASS -Detail ('No threats detected in the last {0} day(s).' -f $Days); return }
    $names = @{}
    foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $names[[string]$t.ThreatID] = [string]$t.ThreatName }
    $items = @($detections | ForEach-Object {
            $n = $names[[string]$_.ThreatID]
            if (-not $n) { $n = 'threat {0}' -f $_.ThreatID }
            '{0} on {1:yyyy-MM-dd} ({2})' -f $n, [datetime]$_.InitialDetectionTime, $(if ($_.ActionSuccess) { 'removed' } else { 'NOT removed' })
        })
    $failed = @($detections | Where-Object { -not $_.ActionSuccess })
    if ($failed.Count -gt 0) {
        Add-MSPFinding -Check 'Defender detections' -Category 'Defender' -Status WARN -Severity High -Detail ($items -join '; ') `
            -Recommendation 'Defender could not remove at least one threat. Run a Microsoft Defender Offline scan (Windows Security > Virus & threat protection > Scan options) and escalate.'
    }
    else {
        Add-MSPFinding -Check 'Defender detections' -Category 'Defender' -Status WARN -Severity Medium -Detail ($items -join '; ') `
            -Recommendation 'Defender removed these, but something brought them onto the PC. Ask the user what they downloaded or opened around these dates, and run a full scan.'
    }
}

Invoke-MSPCheck -Name 'Defender exclusions' -Category 'Defender' -RequiresAdmin -AdminReason 'Windows only shows Defender exclusions to administrators.' -ScriptBlock {
    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        Skip-MSPCheck -Reason 'Microsoft Defender commands are not available (another antivirus may be in use).'
    }
    $pref = Get-MpPreference -ErrorAction Stop
    $all = @(@($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ -and $_ -notmatch '^N/A' })
    if ($all.Count -eq 0) { Add-MSPFinding -Check 'Defender exclusions' -Category 'Defender' -Status PASS -Detail 'No exclusions.'; return }
    $risky = @($all | Where-Object { $_ -match '(?i)^[A-Z]:\\?$|\\(Temp|Tmp)\b|\\Users\\[^\\]+\\?$|\\Users\\?$|\\AppData|\\Downloads|\\Users\\Public|^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr)$' })
    if ($risky.Count -gt 0) {
        Add-MSPFinding -Check 'Defender exclusions' -Category 'Defender' -Status WARN -Severity High -Detail ('Defender skips: {0}.' -f ($all -join '; ')) `
            -Recommendation 'Malware adds exclusions like these to hide from Defender. Unless the client''s IT set them on purpose, remove them (Windows Security > Virus & threat protection > Manage settings > Exclusions) and run a full scan.'
    }
    else {
        Add-MSPFinding -Check 'Defender exclusions' -Category 'Defender' -Status INFO -Detail ('Defender skips: {0}. Confirm each one is intended.' -f ($all -join '; '))
    }
}

# =========================================================================================
Write-MSPSection -Title 'Accounts and sign-ins'
# =========================================================================================
function Get-SecurityEvent {
    <# Security log events, or an empty list when there are none (that is not an error). #>
    param([int[]]$Id, [datetime]$Start)
    try { return @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Id; StartTime = $Start } -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $_.Exception.Message -match 'No events were found') { return @() }
        throw
    }
}

Invoke-MSPCheck -Name 'New local accounts' -Category 'Accounts' -RequiresAdmin -AdminReason 'The Security log can only be read as administrator.' -ScriptBlock {
    $created = @(Get-SecurityEvent -Id 4720 -Start $since)
    $added = @(Get-SecurityEvent -Id 4732 -Start $since | Where-Object { [string]$_.Properties[4].Value -eq 'S-1-5-32-544' })
    if ($created.Count -eq 0) {
        Add-MSPFinding -Check 'New local accounts' -Category 'Accounts' -Status PASS -Detail ('No local account was created in the last {0} day(s).' -f $Days)
    }
    else {
        Add-MSPFinding -Check 'New local accounts' -Category 'Accounts' -Status WARN -Severity Medium `
            -Detail ((@($created | ForEach-Object { '{0} by {1} on {2:yyyy-MM-dd HH:mm}' -f $_.Properties[0].Value, $_.Properties[4].Value, $_.TimeCreated })) -join '; ') `
            -Recommendation 'Confirm with the user that they created these accounts. Unknown accounts are a common way attackers keep access: disable them and escalate.'
    }
    if ($added.Count -eq 0) {
        Add-MSPFinding -Check 'Added to Administrators' -Category 'Accounts' -Status PASS -Detail ('Nobody was added to Administrators in the last {0} day(s).' -f $Days)
    }
    else {
        $items = foreach ($e in $added) {
            $member = [string]$e.Properties[1].Value
            try { $member = (New-Object System.Security.Principal.SecurityIdentifier($member)).Translate([System.Security.Principal.NTAccount]).Value } catch { Write-Verbose 'SID not resolved' }
            '{0} by {1} on {2:yyyy-MM-dd HH:mm}' -f $member, $e.Properties[6].Value, $e.TimeCreated
        }
        Add-MSPFinding -Check 'Added to Administrators' -Category 'Accounts' -Status WARN -Severity High -Detail ($items -join '; ') `
            -Recommendation 'Confirm each change with the user. An account made administrator without their knowledge means someone had control of the PC: escalate.'
    }
}

Invoke-MSPCheck -Name 'Failed sign-ins' -Category 'Accounts' -RequiresAdmin -AdminReason 'The Security log can only be read as administrator.' -ScriptBlock {
    $failed = @(Get-SecurityEvent -Id 4625 -Start $now.AddHours(-24))
    $byAccount = @($failed | Group-Object -Property { [string]$_.Properties[5].Value } | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
    $text = '{0} failed sign-in(s) in the last 24 hours{1}.' -f $failed.Count, $(if ($byAccount) { ': ' + ($byAccount -join ', ') } else { '' })
    if ($failed.Count -gt 20) {
        Add-MSPFinding -Check 'Failed sign-ins' -Category 'Accounts' -Status WARN -Severity Medium -Detail $text `
            -Recommendation 'Many failed sign-ins mean someone is guessing passwords (often through Remote Desktop open to the internet). Check A4 open ports and the router''s port forwards.'
    }
    else {
        Add-MSPFinding -Check 'Failed sign-ins' -Category 'Accounts' -Status PASS -Detail $text
    }
}

# =========================================================================================
Write-MSPSection -Title 'Network settings'
# =========================================================================================
$hostsWatch = '(?i)microsoft|windowsupdate|windows\.com|live\.com|office|defender|bing|google|apple|icloud|amazon|paypal|bank|avast|avg|norton|symantec|mcafee|kaspersky|eset|malwarebytes|sophos|bitdefender|trendmicro|webroot|crowdstrike|sentinelone|virustotal'
Invoke-MSPCheck -Name 'Hosts file' -Category 'Network' -ScriptBlock {
    $root = $env:SystemRoot
    if (-not $root) { $root = 'C:\Windows' }
    $path = '{0}\System32\drivers\etc\hosts' -f $root
    if ($env:MSP_TEST_ROOT) { $path = Join-Path -Path $env:MSP_TEST_ROOT -ChildPath 'hosts' }
    $entries = @(Get-Content -LiteralPath $path -ErrorAction Stop | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ -and $_ -notmatch '^(127\.0\.0\.1|::1)\s+localhost$' })
    if ($entries.Count -eq 0) { Add-MSPFinding -Check 'Hosts file' -Category 'Network' -Status PASS -Detail 'No entries (Windows default).'; return }
    $watched = @($entries | Where-Object { $_ -match $hostsWatch })
    if ($watched.Count -gt 0) {
        Add-MSPFinding -Check 'Hosts file' -Category 'Network' -Status WARN -Severity High -Detail ('{0} entr(ies), including: {1}' -f $entries.Count, (($watched | Select-Object -First 8) -join '; ')) `
            -Recommendation 'Entries for update, security or banking sites can block updates or send the user to fake sites. Unless the client''s IT added them, remove them (edit the hosts file as administrator) and run a malware scan.'
    }
    else {
        Add-MSPFinding -Check 'Hosts file' -Category 'Network' -Status INFO -Detail ('{0} entr(ies): {1}' -f $entries.Count, (($entries | Select-Object -First 8) -join '; '))
    }
}

Invoke-MSPCheck -Name 'Proxy settings' -Category 'Network' -ScriptBlock {
    $ie = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $items = @()
    if ($ie -and [int]$ie.ProxyEnable -eq 1 -and $ie.ProxyServer) { $items += ('proxy {0}' -f $ie.ProxyServer) }
    if ($ie -and $ie.AutoConfigURL) { $items += ('automatic proxy script {0}' -f $ie.AutoConfigURL) }
    if ($items.Count -eq 0) { Add-MSPFinding -Check 'Proxy settings' -Category 'Network' -Status PASS -Detail 'No proxy set for this user.'; return }
    Add-MSPFinding -Check 'Proxy settings' -Category 'Network' -Status WARN -Severity Medium -Detail ('This user''s web traffic goes through: {0}.' -f ($items -join '; ')) `
        -Recommendation 'Home PCs rarely need a proxy; adware sets one to watch or change web pages. Unless the client''s work requires it, turn it off (Settings > Network & internet > Proxy).'
}

Complete-MSPRun -OutputPath $OutputPath
