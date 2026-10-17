<#
.SYNOPSIS
    Read-only inventory of this PC: hardware and Windows details, user accounts with last
    logon, and installed software, flagging remote-access tools and peer-to-peer (torrent)
    software for the client to confirm.

.DESCRIPTION
    Device     Manufacturer, model, serial number, Windows edition/version/build, install date,
               last restart, CPU, memory, system drive space, and how the PC is joined
               (workgroup, Active Directory domain, Microsoft Entra ID).
    Users      Local accounts (enabled, last logon, password required, administrator) and
               user profiles on disk with when each was last used. Unused enabled accounts and
               accounts allowed to have no password are flagged.
    Software   Programs from Apps & Features (64-bit, 32-bit and per-user). Flags:
                 - Remote-access tools (TeamViewer, AnyDesk, UltraViewer, ScreenConnect, VNC...).
                   Tech-support scammers install these; a recently installed one is High.
                   Tools the MSP itself uses are listed in approved-remote-tools.txt (next to
                   this script) and reported as INFO; -ApprovedRemoteTool overrides the list.
                 - Peer-to-peer / torrent clients (malware and copyright-notice risk).
               Running processes are also checked, because portable remote tools (common in
               scams) run without being installed.

    Overlaps on purpose with other scripts but stays an inventory: security ratings for local
    administrators, Guest and the built-in Administrator are in Get-EndpointSecurityStatus.ps1.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0), with Device, Users, Profiles,
    Software and FlaggedSoftware tables.

.PARAMETER IncludeOtherUsers
    Also list per-user software of other signed-in users. Requires administrator.

.PARAMETER ApprovedRemoteTool
    Names (or parts of names) of remote-access tools the MSP or client uses on purpose, for
    example "ScreenConnect","NinjaOne". Matching tools are reported as INFO, not WARN.
    When given, this list REPLACES approved-remote-tools.txt for this run (include the MSP's
    own tools again if they should stay approved). When omitted, the file is used; if the
    file is missing, no tool is approved.

.PARAMETER StaleAccountDays
    Enabled accounts not used for this many days are flagged. Default 90.

.EXAMPLE
    .\Get-HomeDeviceInventory.ps1

.EXAMPLE
    .\Get-HomeDeviceInventory.ps1 -ApprovedRemoteTool 'Kaseya','ScreenConnect' -OutputPath C:\Temp\Audit
    Approves Kaseya and ScreenConnect for this run instead of the approved-remote-tools.txt list.

.NOTES
    Purpose       : Know what this PC is, who uses it, and what is installed on it.
    Use Case      : Home network security audits; onboarding; "someone has been on my computer" tickets.
    Scope         : Local computer only. No network scanning.
    Risk Level    : Read-Only -- reads WMI/CIM, registry and the process list; changes nothing.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (Yes for -IncludeOtherUsers) | Modules: built-in only
    Version       : 1.2.1
    Limitations   : Microsoft Store apps and portable programs that are not running are not
                    listed. "Last logon" for local accounts comes from Windows and can be blank
                    for accounts that sign in with a Microsoft/Entra account; profile "last used"
                    is updated by Windows itself and is approximate. Name matching can miss
                    renamed tools. Replaces the local part of _archive\...\Get-DeviceInventory.ps1.
                    macOS/Linux version: get-home-device-inventory.sh (same checks and IDs).
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$IncludeOtherUsers,
    [string[]]$ApprovedRemoteTool = @(),
    [ValidateRange(14, 3650)][int]$StaleAccountDays = 90
)

#region MSPToolkit (generated) Sections=Core,LocalAdmin,Software
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,LocalAdmin,Software | SHA256: df5f12912e5ea226edd910435c8b10a57cd1c675b6c57e692bdbc76f4e221e3e
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

#region MSPHelper:LocalAdmin
function Get-MSPLocalAdminMember {
    <#
        Members of the local Administrators group (found by its well-known SID S-1-5-32-544, so it
        works on non-English Windows). Get-LocalGroupMember fails on some PCs with Entra ID or
        orphaned members; the ADSI fallback still lists them.
    #>
    [CmdletBinding()]
    param()
    $members = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($m in (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
            $members.Add([pscustomobject]@{
                    Name        = $m.Name
                    ObjectClass = [string]$m.ObjectClass
                    Source      = [string]$m.PrincipalSource
                    SID         = [string]$m.SID
                    Method      = 'Get-LocalGroupMember'
                })
        }
    }
    catch {
        Write-MSPLog -Level WARN -Message ('Get-LocalGroupMember failed ({0}); using ADSI fallback.' -f $_.Exception.Message)
        $groupName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]('WinNT://{0}/{1},group' -f $env:COMPUTERNAME, $groupName)
        foreach ($member in @($group.Invoke('Members'))) {
            $path = $member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
            $class = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)
            $sidText = ''
            try {
                $sidBytes = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
                $sidText = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            }
            catch {
                $sidText = ''
            }
            $name = ($path -replace '^WinNT://', '') -replace '/', '\'
            $source = 'Unknown'
            if ($sidText -like 'S-1-12-1-*') { $source = 'AzureAD' }
            elseif ($name -like ('{0}\*' -f $env:COMPUTERNAME)) { $source = 'Local' }
            elseif ($name -match '^S-1-') { $source = 'Unknown (orphaned SID)' }
            else { $source = 'ActiveDirectory' }
            $members.Add([pscustomobject]@{ Name = $name; ObjectClass = $class; Source = $source; SID = $sidText; Method = 'ADSI' })
        }
    }
    # Enabled state is only knowable for local accounts; others are left blank, not guessed.
    foreach ($member in $members) {
        $enabled = ''
        if ($member.Source -eq 'Local' -and $member.ObjectClass -eq 'User' -and $member.SID) {
            $localUser = Get-LocalUser -SID $member.SID -ErrorAction SilentlyContinue
            if ($localUser) { $enabled = [string]$localUser.Enabled }
        }
        $member | Add-Member -NotePropertyName Enabled -NotePropertyValue $enabled -Force
        $member | Add-Member -NotePropertyName IsBuiltinAdministrator -NotePropertyValue ($member.SID -like 'S-1-5-21-*-500') -Force
    }
    return $members.ToArray()
}
#endregion MSPHelper:LocalAdmin

#region MSPHelper:Software
function Get-MSPInstalledSoftware {
    <#
        Installed programs as listed in Apps & Features: 64-bit and 32-bit machine-wide uninstall
        keys plus the current user's per-user installs. With -IncludeOtherUsers (requires admin),
        also reads per-user installs of other users who are currently signed in.
        Store (AppX) apps and portable programs are NOT included.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([switch]$IncludeOtherUsers)
    $sources = New-Object System.Collections.Generic.List[object]
    $sources.Add(@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine (64-bit)' })
    $sources.Add(@{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine (32-bit)' })
    $sources.Add(@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = ('User: {0}' -f $env:USERNAME) })
    if ($IncludeOtherUsers) {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        foreach ($hive in (Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            $sid = $hive.PSChildName
            if ($sid -notmatch '^S-1-(5-21|12-1)-[\d-]+$' -or $sid -eq $currentSid) { continue }
            $userName = $sid
            try { $userName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $userName = $sid }
            $sources.Add(@{ Path = ('Registry::HKEY_USERS\{0}\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -f $sid); Scope = ('User: {0}' -f $userName) })
        }
    }

    $seen = @{}
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($source in $sources) {
        if (-not (Test-Path -LiteralPath $source.Path)) { continue }
        foreach ($key in (Get-ChildItem -LiteralPath $source.Path -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not $p.DisplayName) { continue }
            # Hide what Apps & Features hides: system components and individual update entries.
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.ReleaseType -match 'Update|Hotfix') { continue }
            $installDate = $null
            if ($p.InstallDate -match '^\d{8}$') {
                try { $installDate = [datetime]::ParseExact($p.InstallDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd') } catch { $installDate = $null }
            }
            $dedupeKey = '{0}|{1}|{2}' -f $p.DisplayName, $p.DisplayVersion, $source.Scope
            if ($seen.ContainsKey($dedupeKey)) { continue }
            $seen[$dedupeKey] = $true
            $items.Add([pscustomobject]@{
                    Name        = [string]$p.DisplayName
                    Version     = [string]$p.DisplayVersion
                    Publisher   = [string]$p.Publisher
                    InstallDate = $installDate
                    Scope       = $source.Scope
                })
        }
    }
    return @($items | Sort-Object -Property Name)
}
#endregion MSPHelper:Software
#endregion MSPToolkit (generated)

$ScriptVersion = '1.2.1'
Initialize-MSPRun -ScriptName 'Get-HomeDeviceInventory' -ScriptVersion $ScriptVersion -CheckId 'A8' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Device, user and software inventory (read-only)'

# "powershell.exe -File" (used by Invoke-HomeAuditBundle.ps1) passes a list as one "a,b" string.
$ApprovedRemoteTool = @($ApprovedRemoteTool | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Approved remote tools: -ApprovedRemoteTool replaces the list file; otherwise read the file next to this script.
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$approvedFile = Join-Path -Path $here -ChildPath 'approved-remote-tools.txt'
$approvedSource = '-ApprovedRemoteTool'
if (-not $PSBoundParameters.ContainsKey('ApprovedRemoteTool')) {
    $approvedSource = $approvedFile
    if (Test-Path -LiteralPath $approvedFile -PathType Leaf) {
        try {
            $ApprovedRemoteTool = @(Get-Content -LiteralPath $approvedFile -ErrorAction Stop |
                    ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
        }
        catch {
            Add-MSPFinding -Check 'Approved remote tools' -Category 'Setup' -Status ERROR -Detail ('Could not read {0}: {1}' -f $approvedFile, $_.Exception.Message) `
                -Recommendation 'Every remote-access tool will be flagged. Fix the file, or pass -ApprovedRemoteTool.'
            $ApprovedRemoteTool = @()
        }
    }
    else {
        $approvedSource = '{0} - file not found' -f $approvedFile
    }
}
$approvedText = 'none'
if ($ApprovedRemoteTool.Count -gt 0) { $approvedText = $ApprovedRemoteTool -join ', ' }
Add-MSPFinding -Check 'Approved remote tools' -Category 'Setup' -Status INFO -Evidence @{ Source = $approvedSource; Tools = $approvedText } `
    -Detail ('{0} (from {1})' -f $approvedText, $approvedSource)

# Remote-access tools: program-name pattern, and process names for portable/running copies.
$remoteTools = @(
    @{ Name = 'TeamViewer'; Pattern = 'TeamViewer'; Process = @('TeamViewer', 'TeamViewer_Service', 'tv_w32', 'tv_x64') }
    @{ Name = 'AnyDesk'; Pattern = 'AnyDesk'; Process = @('AnyDesk') }
    @{ Name = 'UltraViewer'; Pattern = 'UltraViewer'; Process = @('UltraViewer_Desktop', 'UltraViewer_Service') }
    @{ Name = 'RustDesk'; Pattern = 'RustDesk'; Process = @('rustdesk') }
    @{ Name = 'HopToDesk'; Pattern = 'HopToDesk'; Process = @('HopToDesk') }
    @{ Name = 'Splashtop'; Pattern = 'Splashtop'; Process = @('SRServer', 'SRService', 'SRManager') }
    @{ Name = 'LogMeIn / GoTo'; Pattern = 'LogMeIn|GoTo(Assist|Resolve|MyPC| Opener)|GoToAssist'; Process = @('LogMeIn', 'LMIGuardianSvc', 'GoToAssist', 'g2ax_*') }
    @{ Name = 'ConnectWise ScreenConnect'; Pattern = 'ScreenConnect|ConnectWise Control'; Process = @('ScreenConnect.ClientService', 'ScreenConnect.WindowsClient') }
    @{ Name = 'Chrome Remote Desktop'; Pattern = 'Chrome Remote Desktop'; Process = @('remoting_host') }
    @{ Name = 'VNC (UltraVNC/TightVNC/RealVNC/TigerVNC)'; Pattern = 'UltraVNC|TightVNC|RealVNC|TigerVNC|VNC Server|VNC Viewer'; Process = @('winvnc', 'tvnserver', 'vncserver', 'vncagent') }
    @{ Name = 'Supremo'; Pattern = 'Supremo'; Process = @('Supremo', 'SupremoService') }
    @{ Name = 'Ammyy Admin'; Pattern = 'Ammyy'; Process = @('AA_v3', 'Ammyy_Admin') }
    @{ Name = 'AeroAdmin'; Pattern = 'AeroAdmin'; Process = @('AeroAdmin') }
    @{ Name = 'Remote Utilities'; Pattern = 'Remote Utilities'; Process = @('rutserv', 'rfusclient') }
    @{ Name = 'RemotePC'; Pattern = 'RemotePC'; Process = @('RemotePCService', 'RPCService') }
    @{ Name = 'Zoho Assist'; Pattern = 'Zoho Assist'; Process = @('ZohoMeeting', 'ZA_Connect') }
    @{ Name = 'Radmin'; Pattern = 'Radmin'; Process = @('rserver3') }
    @{ Name = 'DWService'; Pattern = 'DWAgent|DWService'; Process = @('dwagent', 'dwagsvc') }
    @{ Name = 'SimpleHelp'; Pattern = 'SimpleHelp'; Process = @('Remote Access', 'SimpleService') }
    @{ Name = 'MeshCentral agent'; Pattern = 'Mesh Agent|MeshCentral'; Process = @('MeshAgent') }
    @{ Name = 'NoMachine'; Pattern = 'NoMachine'; Process = @('nxservice', 'nxnode') }
    @{ Name = 'Parsec'; Pattern = '^Parsec'; Process = @('parsecd') }
    @{ Name = 'Getscreen.me'; Pattern = 'Getscreen'; Process = @('getscreen') }
    @{ Name = 'Iperius Remote'; Pattern = 'Iperius Remote'; Process = @('IperiusRemote') }
    @{ Name = 'BeyondTrust / Bomgar'; Pattern = 'BeyondTrust|Bomgar'; Process = @('bomgar-scc') }
    @{ Name = 'Dameware'; Pattern = 'DameWare'; Process = @('DWRCS') }
    @{ Name = 'Atera'; Pattern = 'Atera'; Process = @('AteraAgent') }
    @{ Name = 'NinjaOne'; Pattern = 'NinjaRMM|NinjaOne'; Process = @('NinjaRMMAgent') }
    @{ Name = 'N-able / Take Control'; Pattern = 'N-able|N-central|Take Control|SolarWinds MSP|BASupport'; Process = @('BASupSrvc', 'BASupApp') }
    @{ Name = 'Kaseya'; Pattern = 'Kaseya'; Process = @('AgentMon') }
    @{ Name = 'Datto RMM'; Pattern = 'Datto RMM|CentraStage'; Process = @('CagService', 'AEMAgent') }
    @{ Name = 'Action1'; Pattern = 'Action1'; Process = @('action1_agent') }
)
$p2pPattern = 'uTorrent|\u00b5Torrent|BitTorrent|qBittorrent|Vuze|Azureus|Deluge|Transmission|BitComet|Tixati|FrostWire|eMule|aMule|LimeWire|Shareaza|Soulseek|BiglyBT|WebTorrent|Popcorn Time|Halite'

function Test-ApprovedTool {
    param([string]$Name)
    foreach ($a in $ApprovedRemoteTool) { if ($a -and $Name -like ('*{0}*' -f $a)) { return $true } }
    return $false
}

$now = Get-Date

# =========================================================================================
Write-MSPSection -Title 'Device'
# =========================================================================================
Invoke-MSPCheck -Name 'Device details' -Category 'Device' -ScriptBlock {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction SilentlyContinue

    # dsregcmd works without admin and is the only reliable way to see Entra ID join.
    $join = 'Workgroup'
    if ($cs.PartOfDomain) { $join = 'Active Directory domain: {0}' -f $cs.Domain }
    try {
        $dsreg = @(dsregcmd.exe /status 2>$null)
        if (($dsreg -join "`n") -match 'AzureAdJoined\s*:\s*YES') { $join = '{0}; Microsoft Entra ID joined' -f $join }
        elseif (($dsreg -join "`n") -match 'WorkplaceJoined\s*:\s*YES') { $join = '{0}; work/school account registered' -f $join }
    }
    catch {
        Write-MSPLog -Level WARN -Message ('dsregcmd failed: {0}' -f $_.Exception.Message)
    }

    $displayVersion = [string]$cv.DisplayVersion
    if (-not $displayVersion) { $displayVersion = [string]$cv.ReleaseId }
    $device = [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        Manufacturer   = [string]$cs.Manufacturer
        Model          = [string]$cs.Model
        SerialNumber   = [string]$bios.SerialNumber
        OS             = [string]$os.Caption
        Version        = $displayVersion
        Build          = ('{0}.{1}' -f $cv.CurrentBuildNumber, $cv.UBR)
        Architecture   = [string]$os.OSArchitecture
        InstallDate    = $os.InstallDate.ToString('yyyy-MM-dd')
        LastBoot       = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
        CPU            = ([string]$cpu.Name).Trim()
        MemoryGB       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        SystemDriveGB  = $(if ($disk) { [math]::Round($disk.Size / 1GB, 0) } else { '' })
        SystemFreeGB   = $(if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { '' })
        JoinType       = $join
    }
    Write-Host (($device | Format-List | Out-String).Trim())
    Add-MSPData -Name 'Device' -Rows @($device)
    Add-MSPFinding -Check 'Device' -Category 'Device' -Status INFO `
        -Detail ('{0} {1} (S/N {2}); {3} {4} build {5}; {6} GB RAM; {7}' -f $device.Manufacturer, $device.Model, $device.SerialNumber, $device.OS, $device.Version, $device.Build, $device.MemoryGB, $join) `
        -Evidence @{ Manufacturer = $device.Manufacturer; Model = $device.Model; SerialNumber = $device.SerialNumber; OS = $device.OS; Build = $device.Build }
    if ($disk -and $disk.Size -gt 0) {
        $freePct = [math]::Round(100 * $disk.FreeSpace / $disk.Size, 0)
        if ($freePct -lt 10) {
            Add-MSPFinding -Check 'System drive space' -Category 'Device' -Status WARN -Severity Low `
                -Detail ('{0} has {1} GB free ({2}%). Windows updates can fail with little free space.' -f $env:SystemDrive, $device.SystemFreeGB, $freePct) `
                -Recommendation 'Free up space (Settings > System > Storage > Cleanup recommendations).'
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'User accounts'
# =========================================================================================
$adminSids = @()
Invoke-MSPCheck -Name 'Administrators group' -Category 'Users' -ScriptBlock {
    $script:adminSids = @(Get-MSPLocalAdminMember | ForEach-Object { $_.SID } | Where-Object { $_ })
}

Invoke-MSPCheck -Name 'Local accounts' -Category 'Users' -ScriptBlock {
    $users = @(Get-LocalUser -ErrorAction Stop)
    $rows = foreach ($u in $users) {
        $lastLogon = ''
        if ($u.LastLogon) { $lastLogon = $u.LastLogon.ToString('yyyy-MM-dd HH:mm') }
        [pscustomobject]@{
            Name             = $u.Name
            FullName         = $u.FullName
            Enabled          = $u.Enabled
            IsAdmin          = ($adminSids -contains $u.SID.Value)
            LastLogon        = $lastLogon
            PasswordRequired = $u.PasswordRequired
            PasswordLastSet  = $(if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { '' })
            Source           = [string]$u.PrincipalSource
            SID              = $u.SID.Value
        }
    }
    $rows = @($rows)
    Write-Host (($rows | Select-Object Name, Enabled, IsAdmin, LastLogon, PasswordRequired, Source | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    Add-MSPData -Name 'Users' -Rows $rows
    $enabled = @($rows | Where-Object { $_.Enabled })
    Add-MSPFinding -Check 'Local accounts' -Category 'Users' -Status INFO `
        -Detail ('{0} local account(s), {1} enabled: {2}' -f $rows.Count, $enabled.Count, (($enabled | ForEach-Object { if ($_.IsAdmin) { '{0} (admin)' -f $_.Name } else { $_.Name } }) -join ', '))

    foreach ($u in $enabled) {
        # Built-in accounts (Administrator -500, Guest -501) are rated by Get-EndpointSecurityStatus.ps1.
        if ($u.SID -match '-50[01]$') { continue }
        # Microsoft-account sign-ins routinely show PasswordRequired = False, so only plain local accounts are flagged.
        if (-not $u.PasswordRequired -and $u.Source -eq 'Local') {
            Add-MSPFinding -Check ('Account "{0}" password' -f $u.Name) -Category 'Users' -Status WARN -Severity Low `
                -Detail ('Windows allows local account "{0}" to have a blank password (PasswordRequired = False). Whether it actually has one cannot be checked safely.' -f $u.Name) `
                -Recommendation 'Make sure the account has a password (or PIN with a Microsoft account). Ask the client; never type their password into a script.'
        }
        if ($u.LastLogon) {
            $idle = [int]($now - [datetime]$u.LastLogon).TotalDays
            if ($idle -gt $StaleAccountDays) {
                Add-MSPFinding -Check ('Account "{0}" unused' -f $u.Name) -Category 'Users' -Status WARN -Severity Low `
                    -Detail ('Enabled account "{0}" last signed in {1} ({2} days ago).' -f $u.Name, $u.LastLogon, $idle) `
                    -Recommendation 'If nobody uses this account, disable it (with the client''s agreement).'
            }
        }
    }
}

Invoke-MSPCheck -Name 'User profiles' -Category 'Users' -ScriptBlock {
    $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special = FALSE' -ErrorAction Stop)
    $rows = foreach ($p in $profiles) {
        $account = $p.SID
        try { $account = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch { $account = '{0} (account no longer exists)' -f $p.SID }
        $type = 'Local'
        if ($p.SID -like 'S-1-12-1-*') { $type = 'Microsoft Entra ID' }
        elseif ($account -notlike ('{0}\*' -f $env:COMPUTERNAME) -and $account -notmatch 'no longer exists') { $type = 'Domain / Microsoft account' }
        [pscustomobject]@{
            Account   = $account
            Type      = $type
            Path      = $p.LocalPath
            LastUsed  = $(if ($p.LastUseTime) { $p.LastUseTime.ToString('yyyy-MM-dd') } else { '' })
            SignedIn  = [bool]$p.Loaded
        }
    }
    $rows = @($rows | Sort-Object -Property LastUsed -Descending)
    Write-Host (($rows | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    Add-MSPData -Name 'Profiles' -Rows $rows
    Add-MSPFinding -Check 'User profiles' -Category 'Users' -Status INFO -Detail ('{0} user profile(s) on this PC: {1}' -f $rows.Count, (($rows | ForEach-Object { $_.Account }) -join ', '))
    $orphans = @($rows | Where-Object { $_.Account -match 'no longer exists' })
    if ($orphans.Count -gt 0) {
        Add-MSPFinding -Check 'Orphaned profiles' -Category 'Users' -Status INFO -Detail ('{0} profile folder(s) belong to deleted accounts and use disk space: {1}' -f $orphans.Count, (($orphans | ForEach-Object { $_.Path }) -join ', '))
    }
}

# =========================================================================================
Write-MSPSection -Title 'Installed software'
# =========================================================================================
$software = @()
if ($IncludeOtherUsers -and -not (Test-MSPIsAdmin)) {
    Add-MSPFinding -Check 'Other users'' software' -Category 'Software' -Status SKIPPED -Detail 'Skipped: requires administrator. Only machine-wide and current-user programs are listed.' `
        -Recommendation 'Re-run as administrator with -IncludeOtherUsers to include programs installed only for other users.'
}
Invoke-MSPCheck -Name 'Installed software' -Category 'Software' -ScriptBlock {
    $other = [bool]($IncludeOtherUsers -and (Test-MSPIsAdmin))
    $script:software = @(Get-MSPInstalledSoftware -IncludeOtherUsers:$other)
    Add-MSPData -Name 'Software' -Rows $script:software
    Add-MSPFinding -Check 'Installed software' -Category 'Software' -Status INFO -Detail ('{0} program(s) installed (Apps & Features; Store apps not included).' -f $script:software.Count)
}

Invoke-MSPCheck -Name 'Remote-access and P2P software' -Category 'Software' -ScriptBlock {
    $flagged = New-Object System.Collections.Generic.List[object]
    $running = @(Get-Process -ErrorAction SilentlyContinue)

    foreach ($tool in $remoteTools) {
        $installed = @($software | Where-Object { $_.Name -match $tool.Pattern })
        $procs = @($running | Where-Object { $name = $_.ProcessName; @($tool.Process | Where-Object { $name -like $_ }).Count -gt 0 })
        if ($installed.Count -eq 0 -and $procs.Count -eq 0) { continue }

        $newest = $null
        foreach ($i in $installed) { if ($i.InstallDate -and (-not $newest -or [datetime]$i.InstallDate -gt $newest)) { $newest = [datetime]$i.InstallDate } }
        $versions = ($installed | ForEach-Object { '{0} {1}' -f $_.Name, $_.Version }) -join '; '
        $where = @()
        if ($installed.Count -gt 0) { $where += ('installed: {0}' -f $versions) }
        if ($procs.Count -gt 0) {
            $procText = ($procs | Select-Object -First 3 | ForEach-Object { $path = ''; try { $path = $_.Path } catch { $path = '' }; if ($path) { '{0} ({1})' -f $_.ProcessName, $path } else { $_.ProcessName } }) -join ', '
            $where += ('running now: {0}' -f $procText)
        }
        if ($installed.Count -eq 0) { $where += 'NOT installed - a portable copy is running' }
        $installedText = ''
        if ($newest) { $installedText = $newest.ToString('yyyy-MM-dd') }
        $flagged.Add([pscustomobject]@{ Type = 'Remote access'; Tool = $tool.Name; Detail = ($where -join '; '); InstallDate = $installedText; Running = ($procs.Count -gt 0) })

        $check = 'Remote-access tool: {0}' -f $tool.Name
        $evidence = @{ Tool = $tool.Name; Installed = $versions; Running = ($procs.Count -gt 0); InstallDate = $installedText }
        if ((Test-ApprovedTool -Name $tool.Name) -or @($installed | Where-Object { Test-ApprovedTool -Name $_.Name }).Count -gt 0) {
            Add-MSPFinding -Check $check -Category 'Software' -Status INFO -Evidence $evidence -Detail ('{0} (approved remote tool).' -f ($where -join '; '))
            continue
        }
        $severity = 'Medium'
        $why = 'Remote-access software lets someone control this PC. Fine if the client or their IT uses it; tech-support scammers install it too.'
        if (($newest -and ($now - $newest).TotalDays -le 30) -or ($installed.Count -eq 0 -and $procs.Count -gt 0)) {
            $severity = 'High'
            $why = 'Installed in the last 30 days, or running without being installed - both are typical of a tech-support scam.'
        }
        Add-MSPFinding -Check $check -Category 'Software' -Status WARN -Severity $severity -Evidence $evidence `
            -Detail ('{0}. {1}' -f ($where -join '; '), $why) `
            -Recommendation 'Ask the client who installed it and whether they still use it. If nobody knows, uninstall it, change the client''s important passwords, and check bank accounts (escalate as a possible scam).'
    }

    $p2p = @($software | Where-Object { $_.Name -match $p2pPattern })
    $p2pProcs = @($running | Where-Object { $_.ProcessName -match $p2pPattern })
    foreach ($item in $p2p) {
        $flagged.Add([pscustomobject]@{ Type = 'Peer-to-peer'; Tool = $item.Name; Detail = ('version {0}, {1}' -f $item.Version, $item.Scope); InstallDate = $item.InstallDate; Running = [bool]($p2pProcs | Where-Object { $item.Name -match [regex]::Escape($_.ProcessName) }) })
        Add-MSPFinding -Check ('Peer-to-peer software: {0}' -f $item.Name) -Category 'Software' -Status WARN -Severity Low `
            -Detail ('{0} {1} is installed. Torrent downloads are a common source of malware, and sharing can expose personal folders or trigger copyright notices from the ISP.' -f $item.Name, $item.Version) `
            -Recommendation 'Confirm the client uses it. If not, uninstall it. If yes, make sure it only shares its own download folder.' `
            -Evidence @{ Name = $item.Name; Version = $item.Version; InstallDate = $item.InstallDate }
    }
    if ($p2p.Count -eq 0 -and $p2pProcs.Count -gt 0) {
        Add-MSPFinding -Check 'Peer-to-peer software running' -Category 'Software' -Status WARN -Severity Low `
            -Detail ('A torrent/P2P program is running without being installed: {0}.' -f (($p2pProcs | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ', ')) `
            -Recommendation 'Confirm the client uses it; if not, close it and delete the portable copy.'
    }

    Add-MSPData -Name 'FlaggedSoftware' -Rows $flagged.ToArray()
    if ($flagged.Count -eq 0) {
        Add-MSPFinding -Check 'Remote-access and P2P software' -Category 'Software' -Status PASS -Detail 'No remote-access tools or peer-to-peer software found (installed or running).'
    }
    else {
        Write-Host ''
        Write-Host (($flagged | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    }
}

Complete-MSPRun -OutputPath $OutputPath
