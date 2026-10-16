<#
.SYNOPSIS
    Read-only Wi-Fi security audit: the network this PC is on, saved Wi-Fi profiles and nearby
    networks, flagging open, WEP and WPA/TKIP security. Wi-Fi passwords are never read.

.DESCRIPTION
    Uses the built-in "netsh wlan" commands:
      Current connection  SSID, authentication, cipher, band/channel, signal
      Saved profiles      Authentication type, cipher, auto-connect, and whether a password is
                          saved ("Security key: Present"). The command that reveals saved Wi-Fi
                          passwords (key=clear) is NEVER used.
      Nearby networks     From Windows' most recent Wi-Fi scan: security of networks in range,
                          and networks using the same name as the home network with weaker
                          security (possible "evil twin" or a misconfigured extra access point).

    Ratings: WPA3 / WPA2 with AES (CCMP/GCMP) = good. WPA2 with TKIP, or WPA (v1) = weak.
    WEP or Open (no encryption) = insecure.

    On Windows 11 24H2 and later, Windows only shows Wi-Fi names to apps when Location is
    allowed for desktop apps. If it is not, those parts are SKIPPED with instructions; this
    script never changes the setting.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 1.0).

.PARAMETER HomeSsid
    Name of the client's home Wi-Fi. Use when the PC is wired or connected elsewhere, so the
    home network is still rated from the nearby-network scan.

.EXAMPLE
    .\Get-WiFiSecurityAudit.ps1

.EXAMPLE
    .\Get-WiFiSecurityAudit.ps1 -HomeSsid "Smith-Home" -OutputPath C:\Temp\Audit

.NOTES
    Purpose       : Confirm the home Wi-Fi is encrypted properly and the PC won't auto-join unsafe networks.
    Use Case      : Home network security audits; travelling users; "slow/unsafe Wi-Fi" tickets.
    Scope         : This PC's Wi-Fi adapter and saved profiles; passive list of nearby networks.
    Risk Level    : Read-Only -- reads Wi-Fi status only. Never reads or shows Wi-Fi passwords; changes nothing.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: none (uses netsh) |
                    Wi-Fi adapter with WLAN AutoConfig service running
    Version       : 1.1.0
    Limitations   : netsh output is parsed in English; on other display languages some fields
                    may show as unknown. Nearby networks come from Windows' last scan, not a
                    new active scan. Cannot verify router-side settings (WPS, guest isolation):
                    see Get-RouterSecurityCheck.ps1. Replaces _archive\...\Check-WifiSecurity.ps1.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$HomeSsid
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
Initialize-MSPRun -ScriptName 'Get-WiFiSecurityAudit' -ScriptVersion $ScriptVersion -CheckId 'A3' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Wi-Fi security audit (read-only; passwords are never read)'

function Get-NetshValue {
    <# First "Name : value" match from netsh output lines. Value is returned without padding. #>
    param([string[]]$Lines, [string]$Name)
    foreach ($line in $Lines) {
        if ($line -match ('^\s*{0}\s*:\s?(.*)$' -f [regex]::Escape($Name))) { return $Matches[1].Trim() }
    }
    return ''
}

function Get-WifiRating {
    <# Classifies authentication + cipher. Returns Level (Good/Weak/Insecure/Unknown) and a label. #>
    param([string]$Authentication, [string]$Cipher)
    $auth = $Authentication.Trim()
    $ciph = $Cipher.Trim()
    if (-not $auth) { return [pscustomobject]@{ Level = 'Unknown'; Label = 'Unknown security' } }
    if ($auth -match 'OWE|Enhanced Open') { return [pscustomobject]@{ Level = 'Good'; Label = 'Enhanced Open (encrypted, no password)' } }
    if ($auth -eq 'Open' -and ($ciph -eq 'WEP')) { return [pscustomobject]@{ Level = 'Insecure'; Label = 'WEP (crackable in minutes)' } }
    if ($auth -eq 'Open') { return [pscustomobject]@{ Level = 'Insecure'; Label = 'Open (no encryption)' } }
    if ($auth -match 'Shared' -or $ciph -eq 'WEP') { return [pscustomobject]@{ Level = 'Insecure'; Label = 'WEP (crackable in minutes)' } }
    if ($auth -match 'WPA3') { return [pscustomobject]@{ Level = 'Good'; Label = ('{0} / {1}' -f $auth, $ciph) } }
    if ($auth -match 'WPA2') {
        if ($ciph -match 'TKIP') { return [pscustomobject]@{ Level = 'Weak'; Label = ('{0} with TKIP (outdated cipher)' -f $auth) } }
        return [pscustomobject]@{ Level = 'Good'; Label = ('{0} / {1}' -f $auth, $ciph) }
    }
    if ($auth -match '^WPA-|^WPA$') { return [pscustomobject]@{ Level = 'Weak'; Label = ('{0} (original WPA, outdated)' -f $auth) } }
    return [pscustomobject]@{ Level = 'Unknown'; Label = ('{0} / {1}' -f $auth, $ciph) }
}

$locationMessage = 'location permission|location services'
$locationAdvice = 'Windows 11 24H2+ hides Wi-Fi names from apps unless Settings > Privacy & security > Location > "Let desktop apps access your location" is on. Turn it on temporarily only with the client''s agreement, re-run, then turn it back off.'

# =========================================================================================
Write-MSPSection -Title 'Wi-Fi adapter'
# =========================================================================================
$interfaceLines = @()
$wifiAvailable = $false
Invoke-MSPCheck -Name 'Wi-Fi adapter' -Category 'Adapter' -ScriptBlock {
    $service = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
    if (-not $service) {
        Add-MSPFinding -Check 'Wi-Fi adapter' -Category 'Adapter' -Status INFO -Detail 'This PC has no Wi-Fi support (WLAN AutoConfig service not installed). Wi-Fi checks do not apply.'
        return
    }
    if ($service.Status -ne 'Running') {
        Add-MSPFinding -Check 'Wi-Fi adapter' -Category 'Adapter' -Status WARN -Severity Low `
            -Detail ('WLAN AutoConfig service is {0}, so Wi-Fi details are unavailable.' -f $service.Status) `
            -Recommendation 'If the PC should use Wi-Fi, start the "WLAN AutoConfig" service (requires admin), then re-run.'
        return
    }
    $output = @(netsh.exe wlan show interfaces)
    $text = $output -join "`n"
    if ($text -match 'There is no wireless interface') {
        Add-MSPFinding -Check 'Wi-Fi adapter' -Category 'Adapter' -Status INFO -Detail 'No Wi-Fi adapter is present or enabled. Wi-Fi checks do not apply.'
        return
    }
    $script:interfaceLines = $output
    $script:wifiAvailable = $true
    $name = Get-NetshValue -Lines $output -Name 'Description'
    Add-MSPFinding -Check 'Wi-Fi adapter' -Category 'Adapter' -Status INFO -Detail ('{0} (state: {1})' -f $name, (Get-NetshValue -Lines $output -Name 'State'))
}

$connectedSsid = ''
$connectedRating = $null
if ($wifiAvailable) {
    # =====================================================================================
    Write-MSPSection -Title 'Current connection'
    # =====================================================================================
    Invoke-MSPCheck -Name 'Current Wi-Fi connection' -Category 'Connection' -ScriptBlock {
        $text = $interfaceLines -join "`n"
        if ($text -match $locationMessage) {
            Add-MSPFinding -Check 'Current Wi-Fi connection' -Category 'Connection' -Status SKIPPED `
                -Detail 'Skipped: Windows requires Location permission to show the Wi-Fi name.' -Recommendation $locationAdvice
            return
        }
        $state = Get-NetshValue -Lines $interfaceLines -Name 'State'
        if ($state -ne 'connected') {
            $detail = 'This PC is not connected to Wi-Fi (state: {0}).' -f $state
            if ($HomeSsid) { $detail += (' The home network "{0}" is rated from the nearby scan below.' -f $HomeSsid) }
            else { $detail += ' Use -HomeSsid "<name>" to rate the home network from the nearby scan.' }
            Add-MSPFinding -Check 'Current Wi-Fi connection' -Category 'Connection' -Status INFO -Detail $detail
            return
        }
        $ssid = Get-NetshValue -Lines $interfaceLines -Name 'SSID'
        $auth = Get-NetshValue -Lines $interfaceLines -Name 'Authentication'
        $cipher = Get-NetshValue -Lines $interfaceLines -Name 'Cipher'
        $band = Get-NetshValue -Lines $interfaceLines -Name 'Band'
        $channel = Get-NetshValue -Lines $interfaceLines -Name 'Channel'
        $signal = Get-NetshValue -Lines $interfaceLines -Name 'Signal'
        $script:connectedSsid = $ssid
        $rating = Get-WifiRating -Authentication $auth -Cipher $cipher
        $script:connectedRating = $rating
        $evidence = @{ SSID = $ssid; Authentication = $auth; Cipher = $cipher; Band = $band; Channel = $channel; Signal = $signal }
        $where = '"{0}" ({1}, channel {2}, signal {3})' -f $ssid, $band, $channel, $signal
        switch ($rating.Level) {
            'Good' {
                Add-MSPFinding -Check 'Current Wi-Fi security' -Category 'Connection' -Status PASS -Evidence $evidence -Detail ('{0}: {1}' -f $where, $rating.Label)
                if ($auth -notmatch 'WPA3') {
                    Add-MSPFinding -Check 'WPA3 available?' -Category 'Connection' -Status INFO `
                        -Detail 'WPA2 with AES is acceptable. If the router and all devices support it, WPA3 (or WPA2/WPA3 mixed) is stronger.'
                }
            }
            'Weak' {
                Add-MSPFinding -Check 'Current Wi-Fi security' -Category 'Connection' -Status FAIL -Severity High -Evidence $evidence `
                    -Detail ('{0}: {1}' -f $where, $rating.Label) `
                    -Recommendation 'In the router''s Wi-Fi settings choose WPA2-AES (or WPA2/WPA3) and set a long passphrase.'
            }
            'Insecure' {
                Add-MSPFinding -Check 'Current Wi-Fi security' -Category 'Connection' -Status FAIL -Severity Critical -Evidence $evidence `
                    -Detail ('{0}: {1}. Anyone nearby can join or read traffic.' -f $where, $rating.Label) `
                    -Recommendation 'If this is the home network: switch the router to WPA2-AES or WPA3 with a long passphrase now. If public: use a VPN and avoid sensitive work.'
            }
            default {
                Add-MSPFinding -Check 'Current Wi-Fi security' -Category 'Connection' -Status WARN -Severity Low -Evidence $evidence `
                    -Detail ('{0}: could not classify "{1} / {2}".' -f $where, $auth, $cipher) -Recommendation 'Check the router''s Wi-Fi security setting manually.'
            }
        }
    }

    # =====================================================================================
    Write-MSPSection -Title 'Saved Wi-Fi profiles'
    # =====================================================================================
    Invoke-MSPCheck -Name 'Saved Wi-Fi profiles' -Category 'Profiles' -ScriptBlock {
        $listing = @(netsh.exe wlan show profiles)
        $names = @()
        foreach ($line in $listing) {
            # Profile names are kept exactly as listed (some genuinely end in spaces).
            if ($line -match '^\s*(All User Profile|User Profile|Current User Profile)\s*:\s(.*)$') { $names += $Matches[2].TrimEnd("`r") }
        }
        if ($names.Count -eq 0) {
            Add-MSPFinding -Check 'Saved Wi-Fi profiles' -Category 'Profiles' -Status INFO -Detail 'No saved Wi-Fi profiles.'
            return
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($name in $names) {
            # Deliberately WITHOUT "key=clear": the output only says whether a key is Present.
            $detail = @(netsh.exe wlan show profile name="$name")
            if (($detail -join ' ') -match 'is not found on the system' -and $name -ne $name.Trim()) {
                $detail = @(netsh.exe wlan show profile name="$($name.Trim())")
            }
            $auths = @($detail | Where-Object { $_ -match '^\s*Authentication\s*:' } | ForEach-Object { ($_ -split ':', 2)[1].Trim() } | Select-Object -Unique)
            $ciphers = @($detail | Where-Object { $_ -match '^\s*Cipher\s*:' } | ForEach-Object { ($_ -split ':', 2)[1].Trim() } | Select-Object -Unique)
            $mode = Get-NetshValue -Lines $detail -Name 'Connection mode'
            $keyState = Get-NetshValue -Lines $detail -Name 'Security key'
            # A profile may list several auth/cipher pairs; judge it by its weakest.
            $worst = $null
            for ($i = 0; $i -lt [math]::Max(1, $auths.Count); $i++) {
                $a = ''; $c = ''
                if ($i -lt $auths.Count) { $a = $auths[$i] }
                if ($i -lt $ciphers.Count) { $c = $ciphers[$i] } elseif ($ciphers.Count -gt 0) { $c = $ciphers[-1] }
                $r = Get-WifiRating -Authentication $a -Cipher $c
                $rank = @{ 'Insecure' = 0; 'Weak' = 1; 'Unknown' = 2; 'Good' = 3 }[$r.Level]
                if (-not $worst -or $rank -lt $worst.Rank) { $worst = [pscustomobject]@{ Rank = $rank; Rating = $r } }
            }
            $autoConnect = ($mode -match 'automatically')
            $rows.Add([pscustomobject]@{
                    Profile        = $name.Trim()
                    Authentication = ($auths -join ', ')
                    Cipher         = ($ciphers -join ', ')
                    Rating         = $worst.Rating.Level
                    AutoConnect    = $autoConnect
                    PasswordSaved  = ($keyState -eq 'Present')
                })
            if ($worst.Rating.Level -in @('Insecure', 'Weak')) {
                if ($autoConnect) {
                    Add-MSPFinding -Check 'Unsafe saved network (auto-connect)' -Category 'Profiles' -Status WARN -Severity Medium -Target $name.Trim() `
                        -Id ('A3.Profile.{0}' -f (ConvertTo-MSPIdPart -Text $name.Trim())) `
                        -Detail ('"{0}" ({1}) is set to connect automatically. Anyone can create a network with this name and the PC will join it.' -f $name.Trim(), $worst.Rating.Label) `
                        -Recommendation ('Forget this network, or untick "Connect automatically": netsh wlan set profileparameter name="{0}" connectionmode=manual (technician action, with client agreement).' -f $name.Trim())
                }
                else {
                    Add-MSPFinding -Check 'Unsafe saved network' -Category 'Profiles' -Status WARN -Severity Low -Target $name.Trim() `
                        -Id ('A3.Profile.{0}' -f (ConvertTo-MSPIdPart -Text $name.Trim())) `
                        -Detail ('"{0}" ({1}) is saved (manual connect only).' -f $name.Trim(), $worst.Rating.Label) `
                        -Recommendation 'Forget it if no longer needed.'
                }
            }
        }
        Add-MSPData -Name 'SavedProfiles' -Rows $rows.ToArray()
        $good = @($rows | Where-Object { $_.Rating -eq 'Good' }).Count
        Add-MSPFinding -Check 'Saved Wi-Fi profiles' -Category 'Profiles' -Status INFO `
            -Detail ('{0} saved profile(s); {1} use good security. Passwords were not read.' -f $rows.Count, $good)
        Write-Host (($rows | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    }

    # =====================================================================================
    Write-MSPSection -Title 'Nearby networks'
    # =====================================================================================
    Invoke-MSPCheck -Name 'Nearby networks' -Category 'Nearby' -ScriptBlock {
        $output = @(netsh.exe wlan show networks mode=bssid)
        $text = $output -join "`n"
        if ($text -match $locationMessage) {
            Add-MSPFinding -Check 'Nearby networks' -Category 'Nearby' -Status SKIPPED `
                -Detail 'Skipped: Windows requires Location permission to list nearby Wi-Fi networks.' -Recommendation $locationAdvice
            return
        }
        $networks = New-Object System.Collections.Generic.List[object]
        $current = $null
        foreach ($line in $output) {
            if ($line -match '^SSID \d+ : ?(.*)$') {
                if ($current) { $networks.Add($current) }
                $ssidName = $Matches[1].Trim()
                if (-not $ssidName) { $ssidName = '(hidden network)' }
                $current = [pscustomobject]@{ SSID = $ssidName; Authentication = ''; Encryption = ''; APs = 0; BestSignal = 0; Bands = @(); Channels = @() }
                continue
            }
            if (-not $current) { continue }
            if ($line -match '^\s+Authentication\s*:\s*(.+)$') { $current.Authentication = $Matches[1].Trim() }
            elseif ($line -match '^\s+Encryption\s*:\s*(.+)$') { $current.Encryption = $Matches[1].Trim() }
            elseif ($line -match '^\s+BSSID \d+\s*:') { $current.APs++ }
            elseif ($line -match '^\s+Signal\s*:\s*(\d+)%') { $current.BestSignal = [math]::Max($current.BestSignal, [int]$Matches[1]) }
            elseif ($line -match '^\s+Band\s*:\s*(.+)$') { if ($current.Bands -notcontains $Matches[1].Trim()) { $current.Bands += $Matches[1].Trim() } }
            elseif ($line -match '^\s+Channel\s*:\s*(\d+)') { if ($current.Channels -notcontains $Matches[1]) { $current.Channels += $Matches[1] } }
        }
        if ($current) { $networks.Add($current) }

        $rows = foreach ($n in $networks) {
            $r = Get-WifiRating -Authentication $n.Authentication -Cipher $n.Encryption
            [pscustomobject]@{
                SSID = $n.SSID; Authentication = $n.Authentication; Encryption = $n.Encryption; Rating = $r.Level
                AccessPoints = $n.APs; BestSignalPct = $n.BestSignal; Bands = ($n.Bands -join ', '); Channels = ($n.Channels -join ', ')
            }
        }
        $rows = @($rows | Sort-Object -Property BestSignalPct -Descending)
        Add-MSPData -Name 'NearbyNetworks' -Rows $rows
        if ($rows.Count -eq 0) {
            Add-MSPFinding -Check 'Nearby networks' -Category 'Nearby' -Status INFO -Detail 'No networks in Windows'' last scan (adapter off, or radio disabled).'
            return
        }
        Write-Host (($rows | Select-Object -First 25 | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
        $open = @($rows | Where-Object { $_.Rating -eq 'Insecure' })
        Add-MSPFinding -Check 'Nearby networks' -Category 'Nearby' -Status INFO `
            -Detail ('{0} network(s) in range; {1} open/WEP (neighbours'' networks are not the client''s responsibility).' -f $rows.Count, $open.Count)

        # Rate the home network from the scan when we know its name.
        $homeName = $HomeSsid
        if (-not $homeName) { $homeName = $connectedSsid }
        if ($homeName) {
            $sameName = @($rows | Where-Object { $_.SSID -eq $homeName })
            if ($sameName.Count -eq 0) {
                Add-MSPFinding -Check 'Home network in scan' -Category 'Nearby' -Status INFO -Detail ('"{0}" was not in Windows'' last scan.' -f $homeName)
            }
            else {
                $levels = @($sameName | ForEach-Object { $_.Rating } | Select-Object -Unique)
                if ($HomeSsid -and -not $connectedRating) {
                    $worstHome = $sameName | Sort-Object -Property @{ Expression = { @{ 'Insecure' = 0; 'Weak' = 1; 'Unknown' = 2; 'Good' = 3 }[$_.Rating] } } | Select-Object -First 1
                    $status = 'PASS'; $severity = 'Info'; $advice = ''
                    if ($worstHome.Rating -eq 'Insecure') { $status = 'FAIL'; $severity = 'Critical'; $advice = 'Switch the router to WPA2-AES or WPA3 with a long passphrase.' }
                    elseif ($worstHome.Rating -eq 'Weak') { $status = 'FAIL'; $severity = 'High'; $advice = 'Switch the router to WPA2-AES (not TKIP) or WPA3.' }
                    Add-MSPFinding -Check 'Home Wi-Fi security (from scan)' -Category 'Nearby' -Status $status -Severity $severity -Target $homeName `
                        -Detail ('"{0}": {1} / {2}' -f $homeName, $worstHome.Authentication, $worstHome.Encryption) -Recommendation $advice
                }
                if ($levels.Count -gt 1) {
                    Add-MSPFinding -Check 'Same network name, different security' -Category 'Nearby' -Status WARN -Severity High -Target $homeName `
                        -Detail ('Networks named "{0}" are broadcasting with different security ({1}). This can be a misconfigured extra access point or an impersonating ("evil twin") network.' -f $homeName, (($sameName | ForEach-Object { '{0}/{1}' -f $_.Authentication, $_.Encryption }) -join '; ')) `
                        -Recommendation 'Check every router/extender/mesh unit uses the same WPA2/WPA3 settings. If one cannot be explained, escalate.'
                }
            }
        }
    }
}

Complete-MSPRun -OutputPath $OutputPath
