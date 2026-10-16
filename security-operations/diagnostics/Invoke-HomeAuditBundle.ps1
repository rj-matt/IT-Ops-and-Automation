<#
.SYNOPSIS
    Runs the eight home network audit scripts (A1-A8) in order on this PC, saves all their
    JSON/CSV results in one timestamped folder, and keeps going if any single script fails.
    Optionally builds the HTML report (A9) at the end.

.DESCRIPTION
    Run order:
      1 Get-EndpointSecurityStatus    PC security settings
      2 Get-HomeNetworkMap            Devices on the network (ping + ARP of the local subnet)
      3 Get-WiFiSecurityAudit         Wi-Fi security
      4 Get-OpenPortScan              Open ports on this PC (+ other devices with -ScanLan)
      5 Get-BrowserSecurityCheck      Browsers and extensions
      6 Get-WindowsUpdateCompliance   Windows Update and end-of-support
      7 Get-RouterSecurityCheck       Router (checklist questions only with -IncludeRouterChecklist)
      8 Get-HomeDeviceInventory       Device, users and software

    Each script runs in its own Windows PowerShell process (powershell.exe -ExecutionPolicy
    Bypass -File ...). That way a crash, hang or "exit" in one script cannot stop the others,
    and the machine's execution policy is never changed. A script still running after
    -TimeoutMinutes is stopped and reported as failed.

    Scripts are found next to this file first (a flat folder on a USB stick), then in their
    normal repository folders. Anything under an _archive folder is refused.

.PARAMETER OutputPath
    Parent folder for results. A sub-folder HomeAudit_<COMPUTER>_<yyyyMMdd-HHmmss> is created
    in it. Default: %TEMP%\MSP-Toolkit.

.PARAMETER ScanLan
    Let Get-OpenPortScan also check other devices on the local subnet for risky open ports.

.PARAMETER HomeSsid
    Name of the client's home Wi-Fi, passed to Get-WiFiSecurityAudit (use when the PC is wired).

.PARAMETER OnlineUpdateSearch
    Let Get-WindowsUpdateCompliance ask Microsoft Update now (slower) instead of using the last scan.

.PARAMETER IncludeRouterChecklist
    Ask the router checklist questions during the run (someone must be at the keyboard).
    Without it the checklist items are recorded as "Not verified".

.PARAMETER ApprovedRemoteTool
    Remote-access tools the MSP/client uses on purpose (for example 'Kaseya','ScreenConnect'),
    passed to Get-HomeDeviceInventory so they are not flagged. When given, this REPLACES the
    approved-remote-tools.txt list next to Get-HomeDeviceInventory.ps1 (Kaseya by default) for
    this run; when omitted, that file is used.

.PARAMETER AllUsers
    As administrator: include other users' browser profiles and per-user software.

.PARAMETER Skip
    Names of scripts to leave out, for example 'Get-HomeNetworkMap'.

.PARAMETER TimeoutMinutes
    Per-script time limit (2-60). Default 15.

.PARAMETER TechnicianName
    When given, Export-SecurityAuditReport.ps1 runs at the end and writes the HTML report into
    the results folder.

.PARAMETER ClientName
    Client/household name for the HTML report title.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeAuditBundle.ps1
    Runs A1-A8 with default options; prints where the results are.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-HomeAuditBundle.ps1 -ScanLan -IncludeRouterChecklist -TechnicianName "J. Smith" -ClientName "Smith household"
    Full audit with LAN port check, router questions, and the HTML report.

.NOTES
    Purpose       : One command for the whole home network audit on a PC.
    Use Case      : Home network security audits (run on each PC the client wants checked).
    Scope         : This PC, its local subnet (A2; A4 with -ScanLan) and its default gateway (A7).
    Risk Level    : Read-Only -- runs read-only scripts and writes result files only.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (recommended: Yes, for complete results) |
                    Modules: built-in only | The eight audit scripts must be present (see .DESCRIPTION)
    Version       : 1.1.0
    Limitations   : Runs on the local PC only; repeat on each PC to audit. Per-script output
                    appears on screen as each one runs; each script's own log is in
                    %TEMP%\MSP-Toolkit.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path $env:TEMP -ChildPath 'MSP-Toolkit'),
    [switch]$ScanLan,
    [string]$HomeSsid,
    [switch]$OnlineUpdateSearch,
    [switch]$IncludeRouterChecklist,
    [string[]]$ApprovedRemoteTool = @(),
    [switch]$AllUsers,
    [string[]]$Skip = @(),
    [ValidateRange(2, 60)][int]$TimeoutMinutes = 15,
    [string]$TechnicianName,
    [string]$ClientName
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
Initialize-MSPRun -ScriptName 'Invoke-HomeAuditBundle' -ScriptVersion $ScriptVersion -CheckId 'Bundle' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Home network audit: runs A1-A8 and collects the results'

# "powershell.exe -File" passes a list as one "a,b" string; split so both forms work.
$Skip = @($Skip | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() -replace '\.ps1$', '' } | Where-Object { $_ })
$ApprovedRemoteTool = @($ApprovedRemoteTool | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# $PSScriptRoot can be empty in some hosts; fall back to the invocation path.
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repoRoot = Split-Path -Path (Split-Path -Path $here -Parent) -Parent

$plan = @(
    @{ Name = 'Get-EndpointSecurityStatus'; Path = 'security-operations\diagnostics\endpoint-posture' }
    @{ Name = 'Get-HomeNetworkMap'; Path = 'core-infrastructure\networking\diagnostics' }
    @{ Name = 'Get-WiFiSecurityAudit'; Path = 'core-infrastructure\networking\diagnostics' }
    @{ Name = 'Get-OpenPortScan'; Path = 'security-operations\diagnostics\endpoint-posture' }
    @{ Name = 'Get-BrowserSecurityCheck'; Path = 'endpoint-systems\diagnostics\system-info' }
    @{ Name = 'Get-WindowsUpdateCompliance'; Path = 'endpoint-systems\diagnostics\system-info' }
    @{ Name = 'Get-RouterSecurityCheck'; Path = 'core-infrastructure\networking\diagnostics' }
    @{ Name = 'Get-HomeDeviceInventory'; Path = 'endpoint-systems\audit\software-inventory' }
)

function Find-ToolkitScript {
    <# Same folder as this script first (flat USB copy), then the repository layout. Never _archive. #>
    param([string]$Name, [string]$RelativeFolder)
    $candidates = @(
        (Join-Path -Path $here -ChildPath ('{0}.ps1' -f $Name)),
        (Join-Path -Path (Join-Path -Path $repoRoot -ChildPath $RelativeFolder) -ChildPath ('{0}.ps1' -f $Name))
    )
    foreach ($c in $candidates) {
        if ($c -match '\\_archive\\') { continue }
        if (Test-Path -LiteralPath $c -PathType Leaf) { return (Resolve-Path -LiteralPath $c).ProviderPath }
    }
    return $null
}

function ConvertTo-ArgumentText {
    <# Quotes one value for the powershell.exe command line. Double quotes are removed (not valid in these values). #>
    param([string]$Value)
    return ('"{0}"' -f ($Value -replace '"', ''))
}

# =========================================================================================
Write-MSPSection -Title 'Setup'
# =========================================================================================
$runFolder = $null
Invoke-MSPCheck -Name 'Results folder' -Category 'Setup' -ScriptBlock {
    $folder = Join-Path -Path $OutputPath -ChildPath ('HomeAudit_{0}_{1}' -f $env:COMPUTERNAME, (Get-Date).ToString('yyyyMMdd-HHmmss'))
    $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    $script:runFolder = (Resolve-Path -LiteralPath $folder).ProviderPath
    Add-MSPFinding -Check 'Results folder' -Category 'Setup' -Status INFO -Detail $script:runFolder
}
if (-not $runFolder) {
    Complete-MSPRun
    exit 1
}
if (-not $script:MSPRun.IsAdmin) {
    Add-MSPFinding -Check 'Administrator' -Category 'Setup' -Status INFO `
        -Detail 'Not running as administrator: BitLocker, TPM, SMBv1 and other-user checks will show SKIPPED. For complete results, re-run from PowerShell opened with "Run as administrator".'
}
$powershellExe = Join-Path -Path $PSHOME -ChildPath 'powershell.exe'
if (-not (Test-Path -LiteralPath $powershellExe)) { $powershellExe = 'powershell.exe' }

# =========================================================================================
$results = New-Object System.Collections.Generic.List[object]
$step = 0
foreach ($item in $plan) {
    $step++
    $name = $item.Name
    Write-MSPSection -Title ('[{0}/{1}] {2}' -f $step, $plan.Count, $name)
    if ($Skip -contains $name) {
        Add-MSPFinding -Check $name -Category 'Run' -Status SKIPPED -Detail 'Skipped with -Skip.'
        $results.Add([pscustomobject]@{ Step = $step; Script = $name; Result = 'Skipped'; Seconds = 0; PASS = ''; WARN = ''; FAIL = ''; ERROR = '' })
        continue
    }
    $path = Find-ToolkitScript -Name $name -RelativeFolder $item.Path
    if (-not $path) {
        Add-MSPFinding -Check $name -Category 'Run' -Status ERROR -Detail ('Script file {0}.ps1 was not found next to this script or in {1}.' -f $name, $item.Path) `
            -Recommendation 'Copy the complete toolkit folder (without _archive) and run again.'
        $results.Add([pscustomobject]@{ Step = $step; Script = $name; Result = 'Not found'; Seconds = 0; PASS = ''; WARN = ''; FAIL = ''; ERROR = '' })
        continue
    }

    # Script-specific options. -File passes every value as text, so lists are joined with commas
    # (the receiving scripts split them again).
    $arguments = New-Object System.Collections.Generic.List[string]
    foreach ($a in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (ConvertTo-ArgumentText $path), '-OutputPath', (ConvertTo-ArgumentText $runFolder))) { $arguments.Add($a) }
    switch ($name) {
        'Get-WiFiSecurityAudit' { if ($HomeSsid) { $arguments.Add('-HomeSsid'); $arguments.Add((ConvertTo-ArgumentText $HomeSsid)) } }
        'Get-OpenPortScan' { if ($ScanLan) { $arguments.Add('-ScanLan') } }
        'Get-BrowserSecurityCheck' { if ($AllUsers -and $script:MSPRun.IsAdmin) { $arguments.Add('-AllUsers') } }
        'Get-WindowsUpdateCompliance' { if ($OnlineUpdateSearch) { $arguments.Add('-Online') } }
        'Get-RouterSecurityCheck' { if (-not $IncludeRouterChecklist) { $arguments.Add('-SkipChecklistPrompt') } }
        'Get-HomeDeviceInventory' {
            if ($ApprovedRemoteTool.Count -gt 0) { $arguments.Add('-ApprovedRemoteTool'); $arguments.Add((ConvertTo-ArgumentText ($ApprovedRemoteTool -join ','))) }
            if ($AllUsers -and $script:MSPRun.IsAdmin) { $arguments.Add('-IncludeOtherUsers') }
        }
    }
    $argumentText = $arguments -join ' '
    Write-MSPLog -Message ('Starting {0}: {1} {2}' -f $name, $powershellExe, $argumentText)

    $started = Get-Date
    $outcome = 'Failed'
    $reason = ''
    try {
        # Same console window, so the technician sees each script's output (and can answer prompts).
        $process = Start-Process -FilePath $powershellExe -ArgumentList $argumentText -NoNewWindow -PassThru -ErrorAction Stop
        $null = $process.Handle   # keeps ExitCode available after the process ends (Windows PowerShell quirk)
        if (-not $process.WaitForExit($TimeoutMinutes * 60 * 1000)) {
            try { $process.Kill() } catch { Write-MSPLog -Level WARN -Message ('Could not stop {0}: {1}' -f $name, $_.Exception.Message) }
            $reason = 'stopped after the {0}-minute time limit' -f $TimeoutMinutes
        }
        else {
            $process.WaitForExit()
            if ($process.ExitCode -eq 0) { $outcome = 'Completed' }
            else { $reason = 'exited with code {0}' -f $process.ExitCode }
        }
    }
    catch {
        $reason = ConvertTo-MSPFriendlyError -ErrorRecord $_
    }
    $seconds = [int]((Get-Date) - $started).TotalSeconds

    $json = Get-ChildItem -LiteralPath $runFolder -Filter ('{0}_*.json' -f $name) -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $started.AddSeconds(-2) } | Sort-Object -Property LastWriteTime | Select-Object -Last 1
    $summary = $null
    if ($json) {
        try { $summary = ([System.IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json).Summary } catch { $summary = $null }
    }
    if ($outcome -eq 'Completed' -and -not $json) { $outcome = 'Failed'; $reason = 'finished but saved no results file' }

    if ($outcome -eq 'Completed') {
        Add-MSPFinding -Check $name -Category 'Run' -Status INFO -NoConsole `
            -Detail ('Completed in {0}s: PASS {1}, WARN {2}, FAIL {3}, ERROR {4}.' -f $seconds, $summary.PASS, $summary.WARN, $summary.FAIL, $summary.ERROR)
    }
    else {
        Add-MSPFinding -Check $name -Category 'Run' -Status ERROR -Detail ('Did not complete ({0}). The other scripts still ran.' -f $reason) `
            -Recommendation ('Run {0}.ps1 on its own to see the problem; its log is in %TEMP%\MSP-Toolkit.' -f $name)
    }
    $results.Add([pscustomobject]@{
            Step = $step; Script = $name; Result = $(if ($outcome -eq 'Completed') { 'Completed' } else { 'FAILED: ' + $reason }); Seconds = $seconds
            PASS = $summary.PASS; WARN = $summary.WARN; FAIL = $summary.FAIL; ERROR = $summary.ERROR
        })
}

# =========================================================================================
Write-MSPSection -Title 'Bundle results'
# =========================================================================================
Write-Host (($results | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
Add-MSPData -Name 'Runs' -Rows $results.ToArray()
Write-Host ''
Write-Host (' All results are in: {0}' -f $runFolder) -ForegroundColor Green
Complete-MSPRun -OutputPath $runFolder

if ($TechnicianName) {
    $reportScript = Find-ToolkitScript -Name 'Export-SecurityAuditReport' -RelativeFolder 'security-operations\diagnostics'
    if ($reportScript) {
        $reportArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (ConvertTo-ArgumentText $reportScript), '-InputPath', (ConvertTo-ArgumentText $runFolder), '-TechnicianName', (ConvertTo-ArgumentText $TechnicianName))
        if ($ClientName) { $reportArgs += @('-ClientName', (ConvertTo-ArgumentText $ClientName)) }
        $process = Start-Process -FilePath $powershellExe -ArgumentList ($reportArgs -join ' ') -NoNewWindow -PassThru -Wait
        if ($process.ExitCode -ne 0) { Write-Host ' The HTML report could not be created; see the messages above.' -ForegroundColor Red }
    }
    else {
        Write-Host ' Export-SecurityAuditReport.ps1 was not found, so no HTML report was created.' -ForegroundColor Yellow
    }
}
else {
    Write-Host (' To build the HTML report: .\Export-SecurityAuditReport.ps1 -InputPath "{0}" -TechnicianName "<your name>"' -f $runFolder) -ForegroundColor Gray
}

# Exit 1 only if no audit script completed; individual failures are in the summary above.
if (@($results | Where-Object { $_.Result -eq 'Completed' }).Count -eq 0) { exit 1 }
exit 0
