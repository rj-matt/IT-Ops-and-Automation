<#
.SYNOPSIS
    Read-only health report for a Windows Server: uptime and pending restart, last update,
    disk space, memory, stopped automatic services, installed roles and their services,
    critical events, time synchronization and expiring certificates.

.DESCRIPTION
    Checks
      Server                     Edition, build, role (domain controller, member, workgroup),
                                 last restart.
      Uptime                     More than 60 days = WARN Low (monthly updates need a restart).
      Restart pending            WARN Medium.
      Last update installed      Newest update (Get-HotFix): more than 45 days WARN, 75 FAIL.
      System drive space /       Every fixed volume, same rule as B1: under 10 % (or 5 GB) free
      Disk space <drive>         FAIL, under 20 % (or 15 GB) WARN, 100 GB or more free is fine.
      Memory                     90 % or more in use = WARN.
      Stopped automatic services Services set to start automatically that are not running,
                                 except ones that stop by design (update services, triggered
                                 services). WARN Medium.
      Server roles               Installed roles (Server Manager); for AD DS, DNS, DHCP, IIS,
                                 Hyper-V, File Server and Print Server, their main service
                                 stopped = FAIL High.
      Critical events            System log, last 24 hours: critical events WARN Medium; error
                                 count listed by source.
      Time synchronization       w32tm: time source and last sync. Free-running or CMOS clock,
                                 or no sync for 7 days = WARN (High on a domain controller).
      Certificates               Computer certificates expiring within 30 days = WARN Medium.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with Disks, StoppedServices
    and Certificates tables.

.EXAMPLE
    .\Get-ServerHealthReport.ps1

.EXAMPLE
    .\Get-ServerHealthReport.ps1 -OutputPath D:\Reports\Server1

.NOTES
    Purpose       : One-screen "is this server healthy?" for monthly checks and tickets.
    Use Case      : Small-business servers (domain controller, file/print, Hyper-V host).
    Scope         : This server only. Reads WMI/CIM, services, the System log, the computer
                    certificate store and w32tm status; no network traffic of its own.
    Risk Level    : Read-Only -- changes nothing.
    Prerequisites : Windows PowerShell 5.1 on Windows Server 2016 or later (also runs on Windows
                    10/11, without the roles check) | Admin: No (recommended: Yes) | Modules:
                    built-in (ServerManager on Windows Server)
    Version       : 1.0.0
    Limitations   : A snapshot, not monitoring. Role health is judged by the main service
                    only (no dcdiag, replication or DHCP scope checks). w32tm output is read in
                    English; on other display languages the time check may say it could not
                    read the result. Linux version: get-server-health-report.sh.
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

$ScriptVersion = '1.0.0'
Initialize-MSPRun -ScriptName 'Get-ServerHealthReport' -ScriptVersion $ScriptVersion -CheckId 'E4' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Windows Server health: updates, disks, services, roles, events, time, certificates (read-only)'

$now = Get-Date
$isDc = $false

function Get-DiskStatus {
    <# PASS/WARN/FAIL for free space, same rule as B1 on every platform. #>
    param([double]$FreeGB, [double]$PercentFree)
    if ($FreeGB -ge 100) { return 'PASS' }
    if ($PercentFree -lt 10 -or $FreeGB -lt 5) { return 'FAIL' }
    if ($PercentFree -lt 20 -or $FreeGB -lt 15) { return 'WARN' }
    return 'PASS'
}

# =========================================================================================
Write-MSPSection -Title 'System'
# =========================================================================================
$os = $null
Invoke-MSPCheck -Name 'Server' -Category 'System' -ScriptBlock {
    $script:os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $roles = @{ 0 = 'standalone workstation'; 1 = 'domain member workstation'; 2 = 'standalone server'; 3 = 'member server'; 4 = 'backup domain controller'; 5 = 'primary domain controller' }
    $script:isDc = ([int]$cs.DomainRole -ge 4)
    $text = '{0} (build {1}), {2}{3}.' -f $os.Caption, $os.BuildNumber, $roles[[int]$cs.DomainRole], $(if ($cs.PartOfDomain) { ' of {0}' -f $cs.Domain } else { '' })
    if ([int]$os.ProductType -eq 1) { $text += ' This is not a server edition; the roles check does not apply.' }
    Add-MSPFinding -Check 'Server' -Category 'System' -Status INFO -Detail $text -Evidence @{ Caption = [string]$os.Caption; Build = [string]$os.BuildNumber; DomainRole = [int]$cs.DomainRole }
}

Invoke-MSPCheck -Name 'Uptime' -Category 'System' -ScriptBlock {
    if (-not $os) { throw 'The operating system information could not be read.' }
    $days = [int][math]::Floor(($now - $os.LastBootUpTime).TotalDays)
    $text = 'Up {0} day(s), since {1:yyyy-MM-dd HH:mm}.' -f $days, $os.LastBootUpTime
    if ($days -gt 60) {
        Add-MSPFinding -Check 'Uptime' -Category 'System' -Status WARN -Severity Low -Detail $text `
            -Recommendation 'Monthly updates only take effect after a restart. Schedule one in the next maintenance window.'
    }
    else { Add-MSPFinding -Check 'Uptime' -Category 'System' -Status PASS -Detail $text }
}

Invoke-MSPCheck -Name 'Restart pending' -Category 'System' -ScriptBlock {
    $reasons = @(Get-MSPPendingReboot)
    if ($reasons.Count -gt 0) {
        Add-MSPFinding -Check 'Restart pending' -Category 'System' -Status WARN -Severity Medium -Detail ('Waiting for a restart: {0}.' -f ($reasons -join ', ')) `
            -Recommendation 'Restart in the next maintenance window (tell users first; on a domain controller or host, check what depends on it).'
    }
    else { Add-MSPFinding -Check 'Restart pending' -Category 'System' -Status PASS -Detail 'No restart pending.' }
}

Invoke-MSPCheck -Name 'Last update installed' -Category 'Updates' -ScriptBlock {
    $hotfixes = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    if ($hotfixes.Count -eq 0) { throw 'No installed update reports an install date.' }
    $last = [datetime]$hotfixes[0].InstalledOn
    $age = [int]($now - $last).TotalDays
    $text = '{0} installed {1:yyyy-MM-dd} ({2} days ago).' -f $hotfixes[0].HotFixID, $last, $age
    if ($age -gt 75) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status FAIL -Severity High -Detail ('{0} At least two monthly security releases are missing.' -f $text) `
            -Recommendation 'Install the latest cumulative update in the next maintenance window; find out why updates stopped (WSUS, RMM policy, disk space).'
    }
    elseif ($age -gt 45) {
        Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status WARN -Severity Medium -Detail $text -Recommendation 'Install last month''s cumulative update.'
    }
    else { Add-MSPFinding -Check 'Last update installed' -Category 'Updates' -Status PASS -Detail $text }
}

# =========================================================================================
Write-MSPSection -Title 'Resources'
# =========================================================================================
Invoke-MSPCheck -Name 'Disk space' -Category 'Storage' -ScriptBlock {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }
    $rows = foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        if (-not $d.Size) { continue }
        $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
        $sizeGB = [math]::Round($d.Size / 1GB, 1)
        $pct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1)
        $status = Get-DiskStatus -FreeGB $freeGB -PercentFree $pct
        $check = 'Disk space {0}' -f $d.DeviceID
        if ($d.DeviceID -eq $systemDrive) { $check = 'System drive space' }
        $text = '{0} {1} GB free of {2} GB ({3} %).' -f $d.DeviceID, $freeGB, $sizeGB, $pct
        switch ($status) {
            'FAIL' { Add-MSPFinding -Check $check -Category 'Storage' -Status FAIL -Severity High -Detail $text -Recommendation 'Free space now: a full system drive stops updates, logging and databases. Check for old logs, shadow copies and backups stored on the server.' }
            'WARN' { Add-MSPFinding -Check $check -Category 'Storage' -Status WARN -Severity Medium -Detail $text -Recommendation 'Plan a cleanup or more storage before it fills.' }
            default { Add-MSPFinding -Check $check -Category 'Storage' -Status PASS -Detail $text }
        }
        [pscustomobject]@{ Drive = [string]$d.DeviceID; Label = [string]$d.VolumeName; SizeGB = $sizeGB; FreeGB = $freeGB; PercentFree = $pct; Status = $status }
    }
    Add-MSPData -Name 'Disks' -Rows @($rows)
}

Invoke-MSPCheck -Name 'Memory' -Category 'Resources' -ScriptBlock {
    if (-not $os) { throw 'The operating system information could not be read.' }
    $total = [double]$os.TotalVisibleMemorySize
    $used = [math]::Round(100 * ($total - [double]$os.FreePhysicalMemory) / $total, 1)
    $text = '{0} % of {1} GB in use.' -f $used, [math]::Round($total / 1MB, 1)
    if ($used -ge 90) {
        Add-MSPFinding -Check 'Memory' -Category 'Resources' -Status WARN -Severity Medium -Detail $text `
            -Recommendation 'Find what uses the memory (Task Manager > Details). SQL Server and Hyper-V hosts use most memory by design; check their limits before adding RAM.'
    }
    else { Add-MSPFinding -Check 'Memory' -Category 'Resources' -Status PASS -Detail $text }
}

# =========================================================================================
Write-MSPSection -Title 'Services and roles'
# =========================================================================================
# Automatic services that stop on their own by design (triggered, updaters, one-shot tasks).
$expectedStopped = @('gupdate', 'gupdatem', 'GoogleUpdater*', 'edgeupdate', 'edgeupdatem', 'MicrosoftEdgeElevationService', 'MapsBroker', 'sppsvc',
    'RemoteRegistry', 'tiledatamodelsvc', 'CDPSvc', 'ShellHWDetection', 'WbioSrvc', 'BITS', 'UsoSvc', 'DoSvc', 'wuauserv', 'TrustedInstaller',
    'clr_optimization_*', 'gpsvc', 'Sense', 'WaaSMedicSvc', 'sedsvc', 'TabletInputService', 'IntelAudioService', 'AdobeARMservice', 'ccmsetup', 'stisvc')
Invoke-MSPCheck -Name 'Stopped automatic services' -Category 'Services' -ScriptBlock {
    $stopped = @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction Stop | Where-Object {
            $n = [string]$_.Name
            @($expectedStopped | Where-Object { $n -like $_ }).Count -eq 0
        })
    Add-MSPData -Name 'StoppedServices' -Rows @($stopped | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; DisplayName = [string]$_.DisplayName; State = [string]$_.State; ExitCode = [int]$_.ExitCode } })
    if ($stopped.Count -eq 0) { Add-MSPFinding -Check 'Stopped automatic services' -Category 'Services' -Status PASS -Detail 'Every automatic service that should be running is running.'; return }
    Add-MSPFinding -Check 'Stopped automatic services' -Category 'Services' -Status WARN -Severity Medium `
        -Detail ((@($stopped | ForEach-Object { '{0} ({1})' -f $_.DisplayName, $_.Name })) -join '; ') `
        -Recommendation 'Check each in services.msc and the System log: start it if it should run, or set it to Manual if it is no longer needed.'
}

$roleServices = [ordered]@{
    'AD-Domain-Services' = @('NTDS', 'Netlogon', 'DFSR', 'KDC')
    'DNS'                = @('DNS')
    'DHCP'               = @('DHCPServer')
    'Web-Server'         = @('W3SVC', 'WAS')
    'Hyper-V'            = @('vmms')
    'FS-FileServer'      = @('LanmanServer')
    'Print-Services'     = @('Spooler')
}
Invoke-MSPCheck -Name 'Server roles' -Category 'Services' -ScriptBlock {
    if (-not (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        Add-MSPFinding -Check 'Server roles' -Category 'Services' -Status INFO -Detail 'Server Manager is not available (not Windows Server); roles not checked.'
        return
    }
    $installed = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -and ($_.FeatureType -eq 'Role' -or $roleServices.Contains([string]$_.Name)) })
    $names = @($installed | ForEach-Object { [string]$_.Name })
    $down = New-Object System.Collections.Generic.List[string]
    foreach ($role in $roleServices.Keys) {
        if ($names -notcontains $role) { continue }
        foreach ($svcName in $roleServices[$role]) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcName) -ErrorAction SilentlyContinue
            if ($svc -and [string]$svc.State -ne 'Running' -and [string]$svc.StartMode -ne 'Disabled') { $down.Add(('{0}: {1} is {2}' -f $role, $svcName, $svc.State)) }
        }
    }
    $list = (@($installed | Where-Object { $_.FeatureType -eq 'Role' } | ForEach-Object { [string]$_.DisplayName })) -join ', '
    if ($down.Count -gt 0) {
        Add-MSPFinding -Check 'Server roles' -Category 'Services' -Status FAIL -Severity High -Detail ('Roles: {0}. Not running: {1}.' -f $list, ($down -join '; ')) `
            -Recommendation 'A role''s main service is down: users are probably affected. Check the service and its event log now (Event Viewer > Applications and Services Logs).'
    }
    else { Add-MSPFinding -Check 'Server roles' -Category 'Services' -Status PASS -Detail ('Roles: {0}. Their main services are running.' -f $(if ($list) { $list } else { 'none' })) }
}

# =========================================================================================
Write-MSPSection -Title 'Events, time and certificates'
# =========================================================================================
Invoke-MSPCheck -Name 'Critical events' -Category 'Events' -ScriptBlock {
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $now.AddHours(-24) } -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' -and $_.Exception.Message -notmatch 'No events were found') { throw } }
    $critical = @($events | Where-Object { $_.Level -eq 1 })
    $bySource = (@($events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })) -join ', '
    $text = '{0} critical and {1} error event(s) in the System log in the last 24 hours{2}.' -f $critical.Count, ($events.Count - $critical.Count), $(if ($bySource) { ': ' + $bySource } else { '' })
    if ($critical.Count -gt 0) {
        Add-MSPFinding -Check 'Critical events' -Category 'Events' -Status WARN -Severity Medium -Detail $text `
            -Recommendation 'Open Event Viewer > System, filter on Critical, and check each (unexpected restarts, disk or controller errors).'
    }
    else { Add-MSPFinding -Check 'Critical events' -Category 'Events' -Status PASS -Detail $text }
}

Invoke-MSPCheck -Name 'Time synchronization' -Category 'Time' -ScriptBlock {
    $out = @(& w32tm.exe /query /status 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ('w32tm: {0}' -f (($out | Select-Object -First 1) -join '')) }
    $source = (($out | Where-Object { $_ -match '^Source:' } | Select-Object -First 1) -replace '^Source:\s*', '').Trim()
    $lastText = (($out | Where-Object { $_ -match '^Last Successful Sync Time:' } | Select-Object -First 1) -replace '^Last Successful Sync Time:\s*', '').Trim()
    if (-not $source) { Skip-MSPCheck -Reason 'The w32tm result could not be read (non-English display language?).' -Recommendation 'Run w32tm /query /status and check the source and last sync time by hand.' }
    $last = $null
    if ($lastText) { try { $last = [datetime]::Parse($lastText) } catch { $last = $null } }
    $severity = 'Medium'
    if ($isDc) { $severity = 'High' }
    if ($source -match 'Local CMOS Clock|Free-running System Clock') {
        Add-MSPFinding -Check 'Time synchronization' -Category 'Time' -Status WARN -Severity $severity -Detail ('Time source: {0} (not synchronized with anything).' -f $source) `
            -Recommendation 'Set a time source: on the domain controller holding the PDC emulator role, w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update; other machines follow the domain. Kerberos sign-in fails when clocks drift more than 5 minutes.'
    }
    elseif ($last -and ($now - $last).TotalDays -gt 7) {
        Add-MSPFinding -Check 'Time synchronization' -Category 'Time' -Status WARN -Severity $severity -Detail ('Source {0}; last successful sync {1:yyyy-MM-dd HH:mm}.' -f $source, $last) `
            -Recommendation 'The time source has not answered for over a week. Check that it is reachable (UDP 123) and run w32tm /resync.'
    }
    else { Add-MSPFinding -Check 'Time synchronization' -Category 'Time' -Status PASS -Detail ('Source {0}; last sync {1}.' -f $source, $(if ($last) { $last.ToString('yyyy-MM-dd HH:mm') } else { $lastText })) }
}

Invoke-MSPCheck -Name 'Certificates' -Category 'Certificates' -ScriptBlock {
    $certs = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop)
    $rows = @($certs | ForEach-Object { [pscustomobject]@{ Subject = [string]$_.Subject; Expires = $_.NotAfter.ToString('yyyy-MM-dd'); DaysLeft = [int]($_.NotAfter - $now).TotalDays; Thumbprint = [string]$_.Thumbprint } })
    Add-MSPData -Name 'Certificates' -Rows $rows
    $soon = @($rows | Where-Object { $_.DaysLeft -ge 0 -and $_.DaysLeft -le 30 })
    $expired = @($rows | Where-Object { $_.DaysLeft -lt 0 })
    $note = ''
    if ($expired.Count -gt 0) { $note = ' {0} expired certificate(s) are still in the store (usually harmless leftovers).' -f $expired.Count }
    if ($soon.Count -gt 0) {
        Add-MSPFinding -Check 'Certificates' -Category 'Certificates' -Status WARN -Severity Medium `
            -Detail ('Expiring within 30 days: {0}.{1}' -f ((@($soon | ForEach-Object { '{0} ({1})' -f $_.Subject, $_.Expires })) -join '; '), $note) `
            -Recommendation 'Renew before they expire: websites, RDP gateways, VPNs and Exchange stop working for users when their certificate expires.'
    }
    else { Add-MSPFinding -Check 'Certificates' -Category 'Certificates' -Status PASS -Detail ('{0} computer certificate(s); none expire within 30 days.{1}' -f $rows.Count, $note) }
}

Complete-MSPRun -OutputPath $OutputPath
