<#
.SYNOPSIS
    Lists the TCP ports this PC is listening on (with the program that owns each one) and,
    optionally, checks other devices on the local network for a short list of risky ports.

.DESCRIPTION
    Part 1 - this PC (always runs):
      Every listening TCP port, the owning process and Windows service, and whether it is
      reachable from the network or only from this PC (bound to 127.0.0.1 / ::1). Risky
      services that are reachable from the network are flagged (Telnet, FTP, VNC, databases,
      WinRM, Remote Desktop). Standard Windows ports (135, 139, 445) are reported as INFO.

    Part 2 - local network (only with -ScanLan):
      Finds devices on the PC's own subnet (ping + ARP, same method as Get-HomeNetworkMap.ps1),
      then tries a TCP connection to each of these ports on each device:
        21 FTP, 22 SSH, 23 Telnet, 80 HTTP, 135 RPC, 139 NetBIOS, 443 HTTPS, 445 SMB,
        3389 Remote Desktop, 5900 VNC, 8080 HTTP-alt
      A connection that opens is closed immediately; nothing is sent, no logins are tried.
      The scope is printed before any traffic is sent, and only addresses inside the PC's own
      subnet are ever contacted (subnets larger than /22 are refused).

    Only scan a network with the owner's permission. A home network audit the client asked
    for is fine; a hotel, office or coffee-shop network is not.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 1.0), including ListeningPorts and
    LanOpenPorts tables.

.PARAMETER ScanLan
    Also scan other devices on the local subnet for the ports listed above.

.PARAMETER Target
    With -ScanLan: scan only these IPv4 addresses instead of every device found. Each must be
    inside the local subnet; others are refused.

.PARAMETER TimeoutMs
    TCP connect timeout per port in milliseconds (200-3000). Default 500.

.PARAMETER ThrottleLimit
    Maximum simultaneous connection attempts (1-32). Default 32.

.EXAMPLE
    .\Get-OpenPortScan.ps1
    Lists this PC's listening ports only. Sends no network traffic.

.EXAMPLE
    .\Get-OpenPortScan.ps1 -ScanLan -OutputPath C:\Temp\Audit
    Also checks every device on the home network for risky open ports, and saves JSON/CSV.

.EXAMPLE
    .\Get-OpenPortScan.ps1 -ScanLan -Target 192.168.1.1,192.168.1.50
    Checks only the router and one other device.

.NOTES
    Purpose       : Show what this PC and other home devices expose on the local network.
    Use Case      : Home network security audits; "is anything open that shouldn't be?" tickets.
    Scope         : This PC's listening ports. With -ScanLan: the local IPv4 subnet only, 11 TCP ports.
    Risk Level    : Read-Only -- reads connection tables; -ScanLan opens and immediately closes
                    TCP connections. Nothing is changed and no logins are attempted.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (admin shows more process paths) |
                    Modules: built-in only (NetTCPIP)
    Version       : 2.1.0
    Limitations   : TCP only (UDP services such as SSDP/UPnP are covered by Get-RouterSecurityCheck.ps1).
                    "Reachable from the network" means the port is bound to a network address;
                    Windows Firewall may still block it (see Get-EndpointSecurityStatus.ps1).
                    The LAN scan shows what devices expose INSIDE the home network, not what is
                    exposed to the internet. Devices that are asleep or on a guest network are
                    not seen. Version 1 scanned remote PCs over WinRM with no subnet limit; that
                    mode was removed.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$ScanLan,
    [string[]]$Target,
    [ValidateRange(200, 3000)][int]$TimeoutMs = 500,
    [ValidateRange(1, 32)][int]$ThrottleLimit = 32
)

#region MSPToolkit (generated) Sections=Core,Net
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Net | SHA256: bf6dce6d92ae4d8ddff0f420e35361b2585150a0dcaf82fc1fadb85113b314c2
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
        Add-Content -LiteralPath $script:MSPRun.LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
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
            $null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop
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
        $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
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
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $dataPaths = @()
    foreach ($name in $run.Data.Keys) {
        $rows = @($run.Data[$name])
        if ($rows.Count -eq 0) { continue }
        $dataPath = Join-Path -Path $folder -ChildPath ('{0}_{1}.csv' -f $base, ($name -replace '[^A-Za-z0-9]+', ''))
        $rows | Export-Csv -LiteralPath $dataPath -NoTypeInformation -Encoding UTF8
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

#region MSPHelper:Net
function ConvertTo-MSPIPv4Number {
    <# "192.168.1.10" -> 3232235786 (so subnets can be compared with plain arithmetic). #>
    param([Parameter(Mandatory)][string]$IPAddress)
    $bytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-MSPIPv4Number {
    param([Parameter(Mandatory)][uint32]$Number)
    $bytes = [BitConverter]::GetBytes($Number)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-MSPLocalSubnet {
    <#
        Returns the IPv4 subnet of the adapter Windows uses for internet traffic (lowest-metric
        default route). VPN and virtual adapters are never used, so scans stay on the client's
        real LAN: when only such adapters have a gateway, the calling check ends as SKIPPED
        (Skip-MSPCheck) instead of scanning the VPN's network.
    #>
    [CmdletBinding()]
    param()
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
    if ($routes.Count -eq 0) {
        throw 'No IPv4 default gateway was found. The computer does not appear to be connected to a network.'
    }
    $virtualPattern = 'Hyper-V|VMware|VirtualBox|TAP-|WireGuard|Wintun|VPN|Tailscale|ZeroTier|Fortinet|AnyConnect|Juniper|Npcap|Loopback'
    $candidates = foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter -or $adapter.Status -ne 'Up') { continue }
        $ipInterface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $metric = [int]$route.RouteMetric
        if ($ipInterface) { $metric += [int]$ipInterface.InterfaceMetric }
        [pscustomobject]@{
            Route     = $route
            Adapter   = $adapter
            Metric    = $metric
            IsVirtual = ($adapter.InterfaceDescription -match $virtualPattern -or $adapter.Name -match 'vEthernet|VPN')
        }
    }
    $candidates = @($candidates)
    if ($candidates.Count -eq 0) { throw 'No connected network adapter with a default gateway was found.' }
    $pick = @($candidates | Where-Object { -not $_.IsVirtual } | Sort-Object -Property Metric) | Select-Object -First 1
    if (-not $pick) {
        $names = ($candidates | ForEach-Object { '{0} ({1})' -f $_.Adapter.Name, $_.Adapter.InterfaceDescription }) -join '; '
        Skip-MSPCheck -Reason ('Only a VPN or virtual adapter has a default gateway ({0}). Nothing was scanned, so no traffic went over the VPN.' -f $names) `
            -Recommendation 'Disconnect the VPN (or connect the PC to the home network by Wi-Fi or cable), then re-run.'
    }

    $address = Get-NetIPAddress -InterfaceIndex $pick.Adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.PrefixLength -ge 1 -and $_.PrefixLength -le 30 } |
        Select-Object -First 1
    if (-not $address) { throw ('Adapter "{0}" has no usable IPv4 address.' -f $pick.Adapter.Name) }

    $prefix = [int]$address.PrefixLength
    $blockSize = [math]::Pow(2, 32 - $prefix)
    $mask = [uint32]([math]::Pow(2, 32) - $blockSize)
    $ipNumber = ConvertTo-MSPIPv4Number -IPAddress $address.IPAddress
    $network = [uint32]([int64]$ipNumber -band [int64]$mask)
    $broadcast = [uint32]([int64]$network + [int64]$blockSize - 1)

    $dns = @()
    try {
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $pick.Adapter.ifIndex -ErrorAction Stop |
                ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
    }
    catch {
        $dns = @()
    }

    return [pscustomobject]@{
        InterfaceAlias       = $pick.Adapter.Name
        InterfaceIndex       = $pick.Adapter.ifIndex
        InterfaceDescription = $pick.Adapter.InterfaceDescription
        IsVirtual            = $pick.IsVirtual
        MacAddress           = ($pick.Adapter.MacAddress -replace '-', ':').ToUpper()
        IPAddress            = $address.IPAddress
        PrefixLength         = $prefix
        Cidr                 = ('{0}/{1}' -f (ConvertFrom-MSPIPv4Number -Number $network), $prefix)
        NetworkAddress       = (ConvertFrom-MSPIPv4Number -Number $network)
        BroadcastAddress     = (ConvertFrom-MSPIPv4Number -Number $broadcast)
        NetworkNumber        = $network
        BroadcastNumber      = $broadcast
        HostCount            = [int]([math]::Max(0, $blockSize - 2))
        Gateway              = $pick.Route.NextHop
        DnsServers           = $dns
    }
}

function Test-MSPIPInSubnet {
    <# True when an IPv4 address is a usable host address inside the given subnet. #>
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)]$Subnet
    )
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $number = ConvertTo-MSPIPv4Number -IPAddress $IPAddress
    return ($number -gt $Subnet.NetworkNumber -and $number -lt $Subnet.BroadcastNumber)
}

function Get-MSPSubnetHostList {
    <# All usable host addresses in the subnet (network and broadcast addresses excluded). #>
    param([Parameter(Mandatory)]$Subnet)
    $list = New-Object System.Collections.Generic.List[string]
    for ($n = [int64]$Subnet.NetworkNumber + 1; $n -lt [int64]$Subnet.BroadcastNumber; $n++) {
        $list.Add((ConvertFrom-MSPIPv4Number -Number ([uint32]$n)))
    }
    return $list.ToArray()
}

function Invoke-MSPRunspacePool {
    <#
        Runs a script block once per input item, at most -ThrottleLimit at a time, using a
        runspace pool (works on Windows PowerShell 5.1; no PowerShell 7 features needed).
        The script block receives the item as its first argument, then -ArgumentList values.
        Items still running at -TimeoutSeconds are stopped and produce no output.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [ValidateRange(1, 32)][int]$ThrottleLimit = 32,
        [int]$TimeoutSeconds = 300,
        [string]$Activity = 'Working'
    )
    if ($InputObject.Count -eq 0) { return @() }
    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    try {
        # Pass the script text, not the script block, so it binds cleanly inside each runspace.
        $code = $ScriptBlock.ToString()
        foreach ($item in $InputObject) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            $null = $ps.AddScript($code).AddArgument($item)
            foreach ($arg in $ArgumentList) { $null = $ps.AddArgument($arg) }
            $jobs.Add([pscustomobject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() })
        }
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $done = 0
        foreach ($job in $jobs) {
            while (-not $job.Handle.IsCompleted -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 25 }
            if ($job.Handle.IsCompleted) {
                try {
                    foreach ($r in $job.PowerShell.EndInvoke($job.Handle)) { $results.Add($r) }
                }
                catch {
                    Write-MSPLog -Level WARN -Message ('Runspace item failed: {0}' -f $_.Exception.Message)
                }
            }
            else {
                $job.PowerShell.Stop()
                Write-MSPLog -Level WARN -Message ('{0}: an item was stopped after the {1}s time limit.' -f $Activity, $TimeoutSeconds)
            }
            $job.PowerShell.Dispose()
            $done++
            if ($done % 8 -eq 0 -or $done -eq $jobs.Count) {
                Write-Progress -Activity $Activity -Status ('{0} of {1}' -f $done, $jobs.Count) -PercentComplete ([int](100 * $done / $jobs.Count))
            }
        }
    }
    finally {
        Write-Progress -Activity $Activity -Completed
        $pool.Close()
        $pool.Dispose()
    }
    return $results.ToArray()
}

function Get-MSPLiveHost {
    <#
        Finds devices on the local subnet: a parallel ping of every host address, then the
        Windows neighbor (ARP) table. Devices that block ping still answer ARP, so they are
        found too. Only addresses inside the given subnet are ever contacted or returned.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]$Subnet,
        [ValidateRange(100, 5000)][int]$TimeoutMs = 500,
        [ValidateRange(1, 32)][int]$ThrottleLimit = 32,
        [switch]$SkipPing
    )
    $replies = @{}
    if (-not $SkipPing) {
        $pingScript = {
            param($ip, $timeoutMs)
            $ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $reply = $ping.Send($ip, $timeoutMs)
                if ($reply.Status -eq 'Success') { [pscustomobject]@{ IP = $ip; RoundTripMs = $reply.RoundtripTime } }
            }
            catch {
                $null = $_   # unreachable or invalid: treated as no reply
            }
            finally {
                $ping.Dispose()
            }
        }
        $hostList = Get-MSPSubnetHostList -Subnet $Subnet
        foreach ($r in (Invoke-MSPRunspacePool -InputObject $hostList -ScriptBlock $pingScript -ArgumentList $TimeoutMs -ThrottleLimit $ThrottleLimit -Activity 'Ping sweep' -TimeoutSeconds 180)) {
            $replies[$r.IP] = $r.RoundTripMs
        }
        # Give late ARP replies a moment to land in the neighbor cache.
        Start-Sleep -Milliseconds 750
    }

    $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $Subnet.InterfaceIndex -ErrorAction SilentlyContinue |
            Where-Object {
                $_.State -notin @('Unreachable', 'Incomplete') -and
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -notmatch '^(00-){5}00$|^(FF-){5}FF$' -and
                (Test-MSPIPInSubnet -IPAddress $_.IPAddress -Subnet $Subnet)
            })

    $byIp = @{}
    foreach ($n in $neighbors) {
        $byIp[$n.IPAddress] = [pscustomobject]@{
            IPAddress       = $n.IPAddress
            MacAddress      = ($n.LinkLayerAddress -replace '-', ':').ToUpper()
            RespondedToPing = $replies.ContainsKey($n.IPAddress)
            RoundTripMs     = $replies[$n.IPAddress]
            NeighborState   = [string]$n.State
            IsSelf          = $false
            IsGateway       = ($n.IPAddress -eq $Subnet.Gateway)
        }
    }
    foreach ($ip in $replies.Keys) {
        if (-not $byIp.ContainsKey($ip) -and $ip -ne $Subnet.IPAddress) {
            $byIp[$ip] = [pscustomobject]@{
                IPAddress = $ip; MacAddress = ''; RespondedToPing = $true; RoundTripMs = $replies[$ip]
                NeighborState = 'NoArpEntry'; IsSelf = $false; IsGateway = ($ip -eq $Subnet.Gateway)
            }
        }
    }
    $byIp[$Subnet.IPAddress] = [pscustomobject]@{
        IPAddress = $Subnet.IPAddress; MacAddress = $Subnet.MacAddress; RespondedToPing = $true; RoundTripMs = 0
        NeighborState = 'Local'; IsSelf = $true; IsGateway = $false
    }
    return @($byIp.Values | Sort-Object -Property { ConvertTo-MSPIPv4Number -IPAddress $_.IPAddress })
}

# Small built-in MAC vendor table (OUI = first 3 bytes). Curated common home/SMB vendors only.
# Vendor is a HINT, never proof: unknown here does not mean suspicious, and vendors own
# thousands of prefixes not listed. No internet lookups are made.
# Format: OUI|Vendor|Device hint
$script:MSPOuiData = @'
00:50:56|VMware|Virtual machine
00:0C:29|VMware|Virtual machine
00:05:69|VMware|Virtual machine
08:00:27|Oracle VirtualBox|Virtual machine
00:15:5D|Microsoft Hyper-V|Virtual machine
52:54:00|QEMU/KVM|Virtual machine
B8:27:EB|Raspberry Pi|Single-board computer
DC:A6:32|Raspberry Pi|Single-board computer
E4:5F:01|Raspberry Pi|Single-board computer
D8:3A:DD|Raspberry Pi|Single-board computer
2C:CF:67|Raspberry Pi|Single-board computer
00:03:93|Apple|Apple device
00:0A:95|Apple|Apple device
00:17:F2|Apple|Apple device
00:1B:63|Apple|Apple device
00:1E:C2|Apple|Apple device
00:25:00|Apple|Apple device
28:CF:E9|Apple|Apple device
3C:07:54|Apple|Apple device
40:6C:8F|Apple|Apple device
7C:D1:C3|Apple|Apple device
A4:5E:60|Apple|Apple device
AC:BC:32|Apple|Apple device
D0:23:DB|Apple|Apple device
F0:18:98|Apple|Apple device
F4:5C:89|Apple|Apple device
BC:52:B7|Apple|Apple device
8C:85:90|Apple|Apple device
60:FB:42|Apple|Apple device
88:66:A5|Apple|Apple device
F0:99:BF|Apple|Apple device
44:65:0D|Amazon|Smart speaker / streaming / IoT
74:C2:46|Amazon|Smart speaker / streaming / IoT
F0:D2:F1|Amazon|Smart speaker / streaming / IoT
FC:65:DE|Amazon|Smart speaker / streaming / IoT
68:54:FD|Amazon|Smart speaker / streaming / IoT
84:D6:D0|Amazon|Smart speaker / streaming / IoT
F4:F5:D8|Google|Smart speaker / Chromecast / phone
F4:F5:E8|Google|Smart speaker / Chromecast / phone
54:60:09|Google|Smart speaker / Chromecast / phone
3C:5A:B4|Google|Smart speaker / Chromecast / phone
1C:F2:9A|Google|Smart speaker / Chromecast / phone
20:DF:B9|Google|Smart speaker / Chromecast / phone
48:D6:D5|Google|Smart speaker / Chromecast / phone
18:B4:30|Google Nest|Thermostat / camera / IoT
64:16:66|Google Nest|Thermostat / camera / IoT
00:0E:58|Sonos|Speaker
5C:AA:FD|Sonos|Speaker
94:9F:3E|Sonos|Speaker
48:A6:B8|Sonos|Speaker
B8:E9:37|Sonos|Speaker
54:2A:1B|Sonos|Speaker
B0:A7:37|Roku|TV / streaming
DC:3A:5E|Roku|TV / streaming
CC:6D:A0|Roku|TV / streaming
08:05:81|Roku|TV / streaming
AC:3A:7A|Roku|TV / streaming
D8:31:34|Roku|TV / streaming
00:17:88|Philips Hue (Signify)|Smart lighting
EC:B5:FA|Philips Hue (Signify)|Smart lighting
24:0A:C4|Espressif|IoT device (smart plug, bulb, sensor)
30:AE:A4|Espressif|IoT device (smart plug, bulb, sensor)
84:CC:A8|Espressif|IoT device (smart plug, bulb, sensor)
A4:CF:12|Espressif|IoT device (smart plug, bulb, sensor)
BC:DD:C2|Espressif|IoT device (smart plug, bulb, sensor)
CC:50:E3|Espressif|IoT device (smart plug, bulb, sensor)
24:62:AB|Espressif|IoT device (smart plug, bulb, sensor)
3C:71:BF|Espressif|IoT device (smart plug, bulb, sensor)
5C:CF:7F|Espressif|IoT device (smart plug, bulb, sensor)
60:01:94|Espressif|IoT device (smart plug, bulb, sensor)
80:7D:3A|Espressif|IoT device (smart plug, bulb, sensor)
84:F3:EB|Espressif|IoT device (smart plug, bulb, sensor)
A0:20:A6|Espressif|IoT device (smart plug, bulb, sensor)
AC:67:B2|Espressif|IoT device (smart plug, bulb, sensor)
C4:4F:33|Espressif|IoT device (smart plug, bulb, sensor)
DC:4F:22|Espressif|IoT device (smart plug, bulb, sensor)
EC:FA:BC|Espressif|IoT device (smart plug, bulb, sensor)
18:FE:34|Espressif|IoT device (smart plug, bulb, sensor)
2C:3A:E8|Espressif|IoT device (smart plug, bulb, sensor)
68:C6:3A|Espressif|IoT device (smart plug, bulb, sensor)
98:F4:AB|Espressif|IoT device (smart plug, bulb, sensor)
B4:E6:2D|Espressif|IoT device (smart plug, bulb, sensor)
D8:BF:C0|Espressif|IoT device (smart plug, bulb, sensor)
E8:DB:84|Espressif|IoT device (smart plug, bulb, sensor)
7C:9E:BD|Espressif|IoT device (smart plug, bulb, sensor)
08:3A:F2|Espressif|IoT device (smart plug, bulb, sensor)
C8:2B:96|Espressif|IoT device (smart plug, bulb, sensor)
50:C7:BF|TP-Link|Router / Wi-Fi / smart plug
14:CC:20|TP-Link|Router / Wi-Fi / smart plug
98:DA:C4|TP-Link|Router / Wi-Fi / smart plug
B0:BE:76|TP-Link|Router / Wi-Fi / smart plug
C0:4A:00|TP-Link|Router / Wi-Fi / smart plug
EC:08:6B|TP-Link|Router / Wi-Fi / smart plug
F4:F2:6D|TP-Link|Router / Wi-Fi / smart plug
60:32:B1|TP-Link|Router / Wi-Fi / smart plug
AC:84:C6|TP-Link|Router / Wi-Fi / smart plug
54:AF:97|TP-Link|Router / Wi-Fi / smart plug
1C:3B:F3|TP-Link|Router / Wi-Fi / smart plug
30:DE:4B|TP-Link|Router / Wi-Fi / smart plug
84:16:F9|TP-Link|Router / Wi-Fi / smart plug
00:09:5B|Netgear|Router / Wi-Fi
00:14:6C|Netgear|Router / Wi-Fi
00:1B:2F|Netgear|Router / Wi-Fi
00:1E:2A|Netgear|Router / Wi-Fi
00:22:3F|Netgear|Router / Wi-Fi
00:24:B2|Netgear|Router / Wi-Fi
00:26:F2|Netgear|Router / Wi-Fi
20:4E:7F|Netgear|Router / Wi-Fi
28:C6:8E|Netgear|Router / Wi-Fi
2C:B0:5D|Netgear|Router / Wi-Fi
30:46:9A|Netgear|Router / Wi-Fi
44:94:FC|Netgear|Router / Wi-Fi
6C:B0:CE|Netgear|Router / Wi-Fi
84:1B:5E|Netgear|Router / Wi-Fi
A0:40:A0|Netgear|Router / Wi-Fi
A0:63:91|Netgear|Router / Wi-Fi
C0:3F:0E|Netgear|Router / Wi-Fi
E0:46:9A|Netgear|Router / Wi-Fi
9C:D3:6D|Netgear|Router / Wi-Fi
00:06:25|Linksys|Router / Wi-Fi
00:0C:41|Linksys|Router / Wi-Fi
00:12:17|Linksys|Router / Wi-Fi
00:13:10|Linksys|Router / Wi-Fi
00:14:BF|Linksys|Router / Wi-Fi
00:16:B6|Linksys|Router / Wi-Fi
00:18:39|Linksys|Router / Wi-Fi
00:1A:70|Linksys|Router / Wi-Fi
00:1C:10|Linksys|Router / Wi-Fi
00:1D:7E|Linksys|Router / Wi-Fi
00:1E:E5|Linksys|Router / Wi-Fi
00:21:29|Linksys|Router / Wi-Fi
00:22:6B|Linksys|Router / Wi-Fi
00:23:69|Linksys|Router / Wi-Fi
00:25:9C|Linksys|Router / Wi-Fi
20:AA:4B|Linksys|Router / Wi-Fi
58:6D:8F|Linksys|Router / Wi-Fi
C0:C1:C0|Linksys|Router / Wi-Fi
48:F8:B3|Linksys|Router / Wi-Fi
00:15:6D|Ubiquiti|Router / Wi-Fi access point
00:27:22|Ubiquiti|Router / Wi-Fi access point
04:18:D6|Ubiquiti|Router / Wi-Fi access point
24:A4:3C|Ubiquiti|Router / Wi-Fi access point
44:D9:E7|Ubiquiti|Router / Wi-Fi access point
68:72:51|Ubiquiti|Router / Wi-Fi access point
78:8A:20|Ubiquiti|Router / Wi-Fi access point
80:2A:A8|Ubiquiti|Router / Wi-Fi access point
B4:FB:E4|Ubiquiti|Router / Wi-Fi access point
DC:9F:DB|Ubiquiti|Router / Wi-Fi access point
F0:9F:C2|Ubiquiti|Router / Wi-Fi access point
FC:EC:DA|Ubiquiti|Router / Wi-Fi access point
74:83:C2|Ubiquiti|Router / Wi-Fi access point
E0:63:DA|Ubiquiti|Router / Wi-Fi access point
18:E8:29|Ubiquiti|Router / Wi-Fi access point
24:5A:4C|Ubiquiti|Router / Wi-Fi access point
68:D7:9A|Ubiquiti|Router / Wi-Fi access point
78:45:58|Ubiquiti|Router / Wi-Fi access point
AC:8B:A9|Ubiquiti|Router / Wi-Fi access point
D0:21:F9|Ubiquiti|Router / Wi-Fi access point
00:1A:92|ASUS|Router / computer
00:1D:60|ASUS|Router / computer
00:22:15|ASUS|Router / computer
00:23:54|ASUS|Router / computer
00:24:8C|ASUS|Router / computer
00:26:18|ASUS|Router / computer
08:60:6E|ASUS|Router / computer
10:BF:48|ASUS|Router / computer
14:DA:E9|ASUS|Router / computer
1C:87:2C|ASUS|Router / computer
2C:56:DC|ASUS|Router / computer
30:5A:3A|ASUS|Router / computer
38:D5:47|ASUS|Router / computer
40:16:7E|ASUS|Router / computer
50:46:5D|ASUS|Router / computer
54:04:A6|ASUS|Router / computer
60:45:CB|ASUS|Router / computer
70:4D:7B|ASUS|Router / computer
74:D0:2B|ASUS|Router / computer
AC:22:0B|ASUS|Router / computer
BC:EE:7B|ASUS|Router / computer
D8:50:E6|ASUS|Router / computer
F4:6D:04|ASUS|Router / computer
04:D9:F5|ASUS|Router / computer
00:09:0F|Fortinet|Firewall
08:5B:0E|Fortinet|Firewall
70:4C:A5|Fortinet|Firewall
90:6C:AC|Fortinet|Firewall
00:06:B1|SonicWall|Firewall
00:17:C5|SonicWall|Firewall
C0:EA:E4|SonicWall|Firewall
18:B1:69|SonicWall|Firewall
00:18:0A|Cisco Meraki|Network device
0C:8D:DB|Cisco Meraki|Network device
34:56:FE|Cisco Meraki|Network device
88:15:44|Cisco Meraki|Network device
AC:17:C8|Cisco Meraki|Network device
E0:55:3D|Cisco Meraki|Network device
E0:CB:BC|Cisco Meraki|Network device
00:1B:21|Intel|Computer (PC/laptop network card)
00:1E:67|Intel|Computer (PC/laptop network card)
00:1F:3B|Intel|Computer (PC/laptop network card)
3C:A9:F4|Intel|Computer (PC/laptop network card)
7C:7A:91|Intel|Computer (PC/laptop network card)
80:86:F2|Intel|Computer (PC/laptop network card)
A0:A8:CD|Intel|Computer (PC/laptop network card)
B4:96:91|Intel|Computer (PC/laptop network card)
F8:63:3F|Intel|Computer (PC/laptop network card)
8C:8D:28|Intel|Computer (PC/laptop network card)
34:13:E8|Intel|Computer (PC/laptop network card)
48:51:B7|Intel|Computer (PC/laptop network card)
5C:87:9C|Intel|Computer (PC/laptop network card)
64:5D:86|Intel|Computer (PC/laptop network card)
70:9C:D1|Intel|Computer (PC/laptop network card)
9C:B6:D0|Intel|Computer (PC/laptop network card)
A4:34:D9|Intel|Computer (PC/laptop network card)
AC:ED:5C|Intel|Computer (PC/laptop network card)
D0:57:7B|Intel|Computer (PC/laptop network card)
DC:21:5C|Intel|Computer (PC/laptop network card)
F8:94:C2|Intel|Computer (PC/laptop network card)
00:E0:4C|Realtek|Computer (network card)
00:14:22|Dell|Computer
18:03:73|Dell|Computer
18:DB:F2|Dell|Computer
24:B6:FD|Dell|Computer
34:17:EB|Dell|Computer
54:BF:64|Dell|Computer
74:86:7A|Dell|Computer
84:7B:EB|Dell|Computer
98:90:96|Dell|Computer
B8:2A:72|Dell|Computer
B8:CA:3A|Dell|Computer
D4:81:D7|Dell|Computer
D4:BE:D9|Dell|Computer
F8:B1:56|Dell|Computer
F8:BC:12|Dell|Computer
A4:BB:6D|Dell|Computer
6C:2B:59|Dell|Computer
E4:54:E8|Dell|Computer
00:1B:78|HP|Computer / printer
00:1E:0B|HP|Computer / printer
00:21:5A|HP|Computer / printer
00:23:7D|HP|Computer / printer
00:25:B3|HP|Computer / printer
10:60:4B|HP|Computer / printer
14:58:D0|HP|Computer / printer
1C:C1:DE|HP|Computer / printer
2C:44:FD|HP|Computer / printer
30:E1:71|HP|Computer / printer
3C:D9:2B|HP|Computer / printer
40:B0:34|HP|Computer / printer
64:51:06|HP|Computer / printer
70:5A:0F|HP|Computer / printer
80:CE:62|HP|Computer / printer
94:57:A5|HP|Computer / printer
9C:8E:99|HP|Computer / printer
A0:D3:C1|HP|Computer / printer
B0:5A:DA|HP|Computer / printer
D4:C9:EF|HP|Computer / printer
EC:B1:D7|HP|Computer / printer
F4:CE:46|HP|Computer / printer
FC:15:B4|HP|Computer / printer
00:1E:8F|Canon|Printer
18:0C:AC|Canon|Printer
2C:9E:FC|Canon|Printer
F4:81:39|Canon|Printer
88:87:17|Canon|Printer
00:BB:C1|Canon|Printer
00:26:AB|Epson|Printer
64:EB:8C|Epson|Printer
A4:EE:57|Epson|Printer
AC:18:26|Epson|Printer
B0:E8:92|Epson|Printer
38:1A:52|Epson|Printer
44:D2:44|Epson|Printer
9C:AE:D3|Epson|Printer
E0:BB:9E|Epson|Printer
DC:CD:2F|Epson|Printer
00:1B:A9|Brother|Printer
00:80:77|Brother|Printer
30:05:5C|Brother|Printer
3C:2A:F4|Brother|Printer
00:12:FB|Samsung|Phone / TV / appliance
00:15:99|Samsung|Phone / TV / appliance
00:16:32|Samsung|Phone / TV / appliance
00:1D:25|Samsung|Phone / TV / appliance
00:21:19|Samsung|Phone / TV / appliance
00:23:39|Samsung|Phone / TV / appliance
08:D4:2B|Samsung|Phone / TV / appliance
10:1D:C0|Samsung|Phone / TV / appliance
14:49:E0|Samsung|Phone / TV / appliance
18:3A:2D|Samsung|Phone / TV / appliance
1C:62:B8|Samsung|Phone / TV / appliance
24:4B:03|Samsung|Phone / TV / appliance
28:BA:B5|Samsung|Phone / TV / appliance
30:CD:A7|Samsung|Phone / TV / appliance
34:23:BA|Samsung|Phone / TV / appliance
38:01:97|Samsung|Phone / TV / appliance
40:0E:85|Samsung|Phone / TV / appliance
4C:BC:A5|Samsung|Phone / TV / appliance
50:01:BB|Samsung|Phone / TV / appliance
5C:49:7D|Samsung|Phone / TV / appliance
64:B3:10|Samsung|Phone / TV / appliance
78:BD:BC|Samsung|Phone / TV / appliance
84:25:DB|Samsung|Phone / TV / appliance
8C:71:F8|Samsung|Phone / TV / appliance
90:F1:AA|Samsung|Phone / TV / appliance
94:35:0A|Samsung|Phone / TV / appliance
A0:0B:BA|Samsung|Phone / TV / appliance
B4:79:A7|Samsung|Phone / TV / appliance
BC:14:85|Samsung|Phone / TV / appliance
C0:97:27|Samsung|Phone / TV / appliance
CC:07:AB|Samsung|Phone / TV / appliance
D0:22:BE|Samsung|Phone / TV / appliance
E4:7C:F9|Samsung|Phone / TV / appliance
F0:25:B7|Samsung|Phone / TV / appliance
F4:7B:5E|Samsung|Phone / TV / appliance
F8:04:2E|Samsung|Phone / TV / appliance
FC:A1:3E|Samsung|Phone / TV / appliance
00:1E:75|LG Electronics|TV / phone / appliance
10:68:3F|LG Electronics|TV / phone / appliance
20:3D:BD|LG Electronics|TV / phone / appliance
34:4D:F7|LG Electronics|TV / phone / appliance
38:8C:50|LG Electronics|TV / phone / appliance
58:A2:B5|LG Electronics|TV / phone / appliance
64:99:5D|LG Electronics|TV / phone / appliance
78:5D:C8|LG Electronics|TV / phone / appliance
88:C9:D0|LG Electronics|TV / phone / appliance
A8:16:B2|LG Electronics|TV / phone / appliance
C4:36:6C|LG Electronics|TV / phone / appliance
CC:2D:8C|LG Electronics|TV / phone / appliance
E8:5B:5B|LG Electronics|TV / phone / appliance
00:04:1F|Sony|Game console / TV
00:13:15|Sony|Game console / TV
00:15:C1|Sony|Game console / TV
00:19:C5|Sony|Game console / TV
00:1D:0D|Sony|Game console / TV
00:1F:A7|Sony|Game console / TV
00:24:8D|Sony|Game console / TV
28:0D:FC|Sony|Game console / TV
70:9E:29|Sony|Game console / TV
A8:E3:EE|Sony|Game console / TV
BC:60:A7|Sony|Game console / TV
F8:46:1C|Sony|Game console / TV
FC:0F:E6|Sony|Game console / TV
00:50:F2|Microsoft|Xbox / Surface
28:18:78|Microsoft|Xbox / Surface
30:59:B7|Microsoft|Xbox / Surface
60:45:BD|Microsoft|Xbox / Surface
7C:1E:52|Microsoft|Xbox / Surface
98:5F:D3|Microsoft|Xbox / Surface
C8:3F:26|Microsoft|Xbox / Surface
DC:B4:C4|Microsoft|Xbox / Surface
58:82:A8|Microsoft|Xbox / Surface
00:17:FA|Microsoft|Xbox / Surface
00:22:48|Microsoft|Xbox / Surface
00:25:AE|Microsoft|Xbox / Surface
7C:ED:8D|Microsoft|Xbox / Surface
00:09:BF|Nintendo|Game console
00:16:56|Nintendo|Game console
00:17:AB|Nintendo|Game console
00:19:1D|Nintendo|Game console
00:1A:E9|Nintendo|Game console
00:1B:EA|Nintendo|Game console
00:1C:BE|Nintendo|Game console
00:1D:BC|Nintendo|Game console
00:1E:35|Nintendo|Game console
00:1F:32|Nintendo|Game console
00:21:47|Nintendo|Game console
00:22:4C|Nintendo|Game console
00:23:31|Nintendo|Game console
00:24:1E|Nintendo|Game console
00:24:44|Nintendo|Game console
00:25:A0|Nintendo|Game console
04:03:D6|Nintendo|Game console
18:2A:7B|Nintendo|Game console
2C:10:C1|Nintendo|Game console
34:AF:2C|Nintendo|Game console
40:F4:07|Nintendo|Game console
58:BD:A3|Nintendo|Game console
7C:BB:8A|Nintendo|Game console
8C:56:C5|Nintendo|Game console
98:B6:E9|Nintendo|Game console
A4:C0:E1|Nintendo|Game console
B8:AE:6E|Nintendo|Game console
CC:FB:65|Nintendo|Game console
D8:6B:F7|Nintendo|Game console
DC:68:EB|Nintendo|Game console
E0:E7:51|Nintendo|Game console
E8:4E:CE|Nintendo|Game console
64:B5:C6|Nintendo|Game console
00:11:32|Synology|NAS / file server
90:09:D0|Synology|NAS / file server
00:08:9B|QNAP|NAS / file server
24:5E:BE|QNAP|NAS / file server
44:19:B6|Hikvision|Security camera / recorder
4C:BD:8F|Hikvision|Security camera / recorder
C0:56:E3|Hikvision|Security camera / recorder
BC:AD:28|Hikvision|Security camera / recorder
28:57:BE|Hikvision|Security camera / recorder
54:C4:15|Hikvision|Security camera / recorder
18:68:CB|Hikvision|Security camera / recorder
C4:2F:90|Hikvision|Security camera / recorder
A4:14:37|Hikvision|Security camera / recorder
8C:E7:48|Hikvision|Security camera / recorder
3C:EF:8C|Dahua|Security camera / recorder
4C:11:BF|Dahua|Security camera / recorder
90:02:A9|Dahua|Security camera / recorder
14:A7:8B|Dahua|Security camera / recorder
2C:AA:8E|Wyze|Security camera / IoT
7C:78:B2|Wyze|Security camera / IoT
D0:3F:27|Wyze|Security camera / IoT
44:61:32|ecobee|Thermostat
64:52:99|Chamberlain (myQ)|Garage door opener
08:86:3B|Belkin|Smart plug / router
94:10:3E|Belkin|Smart plug / router
B4:75:0E|Belkin|Smart plug / router
C0:56:27|Belkin|Smart plug / router
EC:1A:59|Belkin|Smart plug / router
28:6C:07|Xiaomi|Phone / IoT
34:CE:00|Xiaomi|Phone / IoT
64:09:80|Xiaomi|Phone / IoT
78:11:DC|Xiaomi|Phone / IoT
7C:49:EB|Xiaomi|Phone / IoT
28:D2:44|Lenovo|Computer
54:EE:75|Lenovo|Computer
8C:16:45|Lenovo|Computer
E8:6A:64|Lenovo|Computer
98:FA:9B|Lenovo|Computer
50:7B:9D|Lenovo|Computer
C8:5B:76|Lenovo|Computer
'@
$script:MSPOuiTable = $null

function Get-MSPMacVendor {
    <#
        Vendor hint for a MAC address from the built-in table. Detects randomized ("private")
        MACs, which phones, tablets and laptops use by default for Wi-Fi privacy.
    #>
    param([AllowEmptyString()][string]$MacAddress)
    if (-not $script:MSPOuiTable) {
        $script:MSPOuiTable = @{}
        foreach ($line in ($script:MSPOuiData -split "`r?`n")) {
            $parts = $line.Split('|')
            if ($parts.Count -eq 3) { $script:MSPOuiTable[$parts[0].Trim().ToUpper()] = @{ Vendor = $parts[1].Trim(); Hint = $parts[2].Trim() } }
        }
    }
    $hex = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($hex.Length -lt 6) { return [pscustomobject]@{ Vendor = 'Unknown'; Hint = ''; Randomized = $false } }
    $oui = '{0}:{1}:{2}' -f $hex.Substring(0, 2), $hex.Substring(2, 2), $hex.Substring(4, 2)
    if ($script:MSPOuiTable.ContainsKey($oui)) {
        $entry = $script:MSPOuiTable[$oui]
        return [pscustomobject]@{ Vendor = $entry.Vendor; Hint = $entry.Hint; Randomized = $false }
    }
    # Second-lowest bit of the first byte = "locally administered" = randomized/private MAC.
    $firstByte = [Convert]::ToByte($hex.Substring(0, 2), 16)
    if (($firstByte -band 2) -eq 2) {
        return [pscustomobject]@{ Vendor = 'Private/randomized MAC'; Hint = 'Phone, tablet or laptop using Wi-Fi privacy'; Randomized = $true }
    }
    return [pscustomobject]@{ Vendor = 'Unknown'; Hint = ''; Randomized = $false }
}
#endregion MSPHelper:Net
#endregion MSPToolkit (generated)

$ScriptVersion = '2.1.0'
Initialize-MSPRun -ScriptName 'Get-OpenPortScan' -ScriptVersion $ScriptVersion -CheckId 'A4' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Listening ports on this PC; optional local-network port check (read-only)'

# What each well-known port is, and how worried to be when it is reachable from the network.
# Level: Risky (FAIL), Review (WARN), Windows (INFO: normal for Windows), Web (INFO), Other (INFO).
$knownPorts = @{
    21    = @{ Name = 'FTP'; Level = 'Risky'; Why = 'FTP sends usernames and passwords unencrypted.' }
    22    = @{ Name = 'SSH'; Level = 'Other'; Why = 'Encrypted remote shell. Fine if intentional.' }
    23    = @{ Name = 'Telnet'; Level = 'Risky'; Why = 'Telnet is unencrypted and a top target for automated attacks.' }
    80    = @{ Name = 'HTTP web server'; Level = 'Web'; Why = 'Web page (often an admin page).' }
    135   = @{ Name = 'Windows RPC'; Level = 'Windows'; Why = 'Standard on every Windows PC.' }
    139   = @{ Name = 'NetBIOS file sharing'; Level = 'Windows'; Why = 'Legacy Windows file sharing.' }
    443   = @{ Name = 'HTTPS web server'; Level = 'Web'; Why = 'Encrypted web page.' }
    445   = @{ Name = 'SMB file sharing'; Level = 'Windows'; Why = 'Windows file and printer sharing.' }
    1433  = @{ Name = 'Microsoft SQL Server'; Level = 'Review'; Why = 'A database open to the network is rarely needed on a home PC.' }
    3306  = @{ Name = 'MySQL / MariaDB'; Level = 'Review'; Why = 'A database open to the network is rarely needed on a home PC.' }
    3389  = @{ Name = 'Remote Desktop'; Level = 'Review'; Why = 'Remote control of this PC. Fine if the client uses it; dangerous if forwarded to the internet.' }
    5432  = @{ Name = 'PostgreSQL'; Level = 'Review'; Why = 'A database open to the network is rarely needed on a home PC.' }
    5900  = @{ Name = 'VNC remote control'; Level = 'Risky'; Why = 'VNC often has weak or no authentication and no encryption.' }
    5901  = @{ Name = 'VNC remote control'; Level = 'Risky'; Why = 'VNC often has weak or no authentication and no encryption.' }
    5902  = @{ Name = 'VNC remote control'; Level = 'Risky'; Why = 'VNC often has weak or no authentication and no encryption.' }
    5985  = @{ Name = 'WinRM (PowerShell remoting)'; Level = 'Review'; Why = 'Remote administration; unusual on a home PC.' }
    5986  = @{ Name = 'WinRM over HTTPS'; Level = 'Review'; Why = 'Remote administration; unusual on a home PC.' }
    8080  = @{ Name = 'HTTP (alternate)'; Level = 'Web'; Why = 'Web page or proxy.' }
    8443  = @{ Name = 'HTTPS (alternate)'; Level = 'Web'; Why = 'Encrypted web page.' }
    27017 = @{ Name = 'MongoDB'; Level = 'Review'; Why = 'A database open to the network is rarely needed on a home PC.' }
}
$lanPorts = @(21, 22, 23, 80, 135, 139, 443, 445, 3389, 5900, 8080)

function Test-LoopbackAddress {
    param([string]$Address)
    return ($Address -like '127.*' -or $Address -eq '::1')
}

# =========================================================================================
Write-MSPSection -Title 'Listening ports on this PC'
# =========================================================================================
Invoke-MSPCheck -Name 'Listening TCP ports' -Category 'LocalPorts' -ScriptBlock {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    if ($listeners.Count -eq 0) {
        Add-MSPFinding -Check 'Listening TCP ports' -Category 'LocalPorts' -Status INFO -Detail 'No listening TCP ports.'
        return
    }

    # Map process IDs to names and Windows services (svchost.exe hosts many services).
    $processes = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $path = ''
        try { $path = $p.Path } catch { $path = '' }
        $processes[[int]$p.Id] = @{ Name = $p.ProcessName; Path = $path }
    }
    $services = @{}
    foreach ($s in (Get-CimInstance -ClassName Win32_Service -Filter 'ProcessId > 0' -ErrorAction SilentlyContinue)) {
        $procId = [int]$s.ProcessId
        if (-not $services.ContainsKey($procId)) { $services[$procId] = New-Object System.Collections.Generic.List[string] }
        $services[$procId].Add($s.Name)
    }

    # One row per port: a port bound to both IPv4 and IPv6 is shown once.
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($group in ($listeners | Group-Object -Property LocalPort)) {
        $port = [int]$group.Name
        $addresses = @($group.Group | ForEach-Object { $_.LocalAddress } | Select-Object -Unique)
        $networkAddresses = @($addresses | Where-Object { -not (Test-LoopbackAddress -Address $_) })
        $procId = [int]($group.Group | Select-Object -First 1).OwningProcess
        $procName = 'Unknown'
        $procPath = ''
        if ($procId -eq 4) { $procName = 'System (Windows kernel)' }
        elseif ($processes.ContainsKey($procId)) { $procName = $processes[$procId].Name; $procPath = $processes[$procId].Path }
        $serviceNames = ''
        if ($services.ContainsKey($procId)) { $serviceNames = (($services[$procId] | Select-Object -First 4) -join ', ') }
        $info = $knownPorts[$port]
        $label = ''
        if ($info) { $label = $info.Name }
        $rows.Add([pscustomobject]@{
                Port        = $port
                Service     = $label
                Reachable   = $(if ($networkAddresses.Count -gt 0) { 'Network' } else { 'This PC only' })
                BoundTo     = ($addresses -join ', ')
                Process     = $procName
                ProcessId   = $procId
                WinService  = $serviceNames
                ProcessPath = $procPath
            })
    }
    $sorted = @($rows | Sort-Object -Property Port)
    Write-Host (($sorted | Select-Object Port, Service, Reachable, Process, WinService | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    Add-MSPData -Name 'ListeningPorts' -Rows $sorted

    $networkRows = @($sorted | Where-Object { $_.Reachable -eq 'Network' })
    Add-MSPFinding -Check 'Listening TCP ports' -Category 'LocalPorts' -Status INFO `
        -Detail ('{0} listening port(s); {1} reachable from the network, {2} local-only.' -f $sorted.Count, $networkRows.Count, ($sorted.Count - $networkRows.Count))

    foreach ($row in $networkRows) {
        $info = $knownPorts[$row.Port]
        if (-not $info) { continue }
        $who = $row.Process
        if ($row.WinService) { $who = '{0} ({1})' -f $row.Process, $row.WinService }
        $check = 'Port {0} {1}' -f $row.Port, $info.Name
        $detail = 'Listening on the network, owned by {0}. {1}' -f $who, $info.Why
        $evidence = @{ Port = $row.Port; Process = $row.Process; BoundTo = $row.BoundTo }
        switch ($info.Level) {
            'Risky' {
                Add-MSPFinding -Check $check -Category 'LocalPorts' -Status FAIL -Severity High -Detail $detail -Evidence $evidence `
                    -Recommendation ('Unless the client knowingly uses {0}, uninstall or disable the program that provides it.' -f $info.Name)
            }
            'Review' {
                Add-MSPFinding -Check $check -Category 'LocalPorts' -Status WARN -Severity Medium -Detail $detail -Evidence $evidence `
                    -Recommendation 'Confirm the client needs this. If not, turn it off. Never forward this port on the router.'
            }
            'Windows' {
                Add-MSPFinding -Check $check -Category 'LocalPorts' -Status INFO -Detail ('{0} Normal for Windows; the firewall should block it on Public networks.' -f $detail) -Evidence $evidence
            }
            default {
                Add-MSPFinding -Check $check -Category 'LocalPorts' -Status INFO -Detail $detail -Evidence $evidence
            }
        }
    }
    $unknown = @($networkRows | Where-Object { -not $knownPorts.ContainsKey($_.Port) -and $_.Port -lt 49152 })
    if ($unknown.Count -gt 0) {
        $list = ($unknown | Select-Object -First 15 | ForEach-Object { '{0} ({1})' -f $_.Port, $_.Process }) -join ', '
        Add-MSPFinding -Check 'Other network-reachable ports' -Category 'LocalPorts' -Status INFO `
            -Detail ('{0}. Usually app or Windows features; review any program the client does not recognise.' -f $list)
    }
}

Invoke-MSPCheck -Name 'Current network type' -Category 'LocalPorts' -ScriptBlock {
    $profiles = @(Get-NetConnectionProfile -ErrorAction Stop)
    foreach ($p in $profiles) {
        $text = '"{0}" is set to {1}.' -f $p.Name, $p.NetworkCategory
        if ([string]$p.NetworkCategory -eq 'Public') { $text += ' Windows Firewall blocks file sharing and most inbound ports on Public networks.' }
        elseif ([string]$p.NetworkCategory -eq 'Private') { $text += ' On Private networks, other home devices can reach file sharing if it is turned on.' }
        Add-MSPFinding -Check 'Current network type' -Category 'LocalPorts' -Status INFO -Detail $text
    }
}

# =========================================================================================
if (-not $ScanLan) {
    if ($Target) {
        Add-MSPFinding -Check 'Local network port check' -Category 'LanScan' -Status INFO -Detail '-Target was given without -ScanLan, so no devices were scanned.'
    }
    else {
        Add-MSPFinding -Check 'Local network port check' -Category 'LanScan' -Status INFO -Detail 'Not run (use -ScanLan to check other home devices for risky open ports).'
    }
    Complete-MSPRun -OutputPath $OutputPath
    return
}

Write-MSPSection -Title 'Local network port check - scope'
# =========================================================================================
$subnet = $null
Invoke-MSPCheck -Name 'Local subnet' -Category 'LanScan' -ScriptBlock {
    $script:subnet = Get-MSPLocalSubnet
}
if (-not $subnet) {
    Complete-MSPRun -OutputPath $OutputPath
    return
}

$maxHosts = 1022
if ($subnet.HostCount -gt $maxHosts) {
    Add-MSPFinding -Check 'Local network port check' -Category 'LanScan' -Status SKIPPED `
        -Detail ('Subnet {0} has {1} addresses, above the {2}-address safety limit for port checks. Nothing was scanned.' -f $subnet.Cidr, $subnet.HostCount, $maxHosts) `
        -Recommendation 'Use -Target with the specific addresses to check.'
    Complete-MSPRun -OutputPath $OutputPath
    return
}

$targets = @()
if ($Target) {
    # "powershell.exe -File" passes -Target a,b as one string, so split on commas and spaces too.
    foreach ($t in @($Target | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ })) {
        if (Test-MSPIPInSubnet -IPAddress $t -Subnet $subnet) { $targets += $t }
        else {
            Add-MSPFinding -Check 'Target refused' -Category 'LanScan' -Status INFO -Target $t `
                -Detail ('{0} is not inside the local subnet {1}, so it was not contacted.' -f $t, $subnet.Cidr)
        }
    }
}

Write-Host '  Only the addresses below are contacted. Connections are closed immediately; no logins are tried.' -ForegroundColor White
Write-Host ('    Adapter : {0} ({1})' -f $subnet.InterfaceAlias, $subnet.InterfaceDescription)
Write-Host ('    Subnet  : {0}   This PC: {1}   Gateway: {2}' -f $subnet.Cidr, $subnet.IPAddress, $subnet.Gateway)
if ($Target) { Write-Host ('    Targets : {0}' -f ($targets -join ', ')) }
else { Write-Host ('    Targets : devices found on {0} by ping + ARP (this PC excluded)' -f $subnet.Cidr) }
Write-Host ('    Ports   : {0}' -f ($lanPorts -join ', '))
Write-Host ('    Timing  : {0} ms timeout, up to {1} connections at a time' -f $TimeoutMs, $ThrottleLimit)
Write-MSPLog -Message ('LAN scan scope: {0}; targets={1}; ports={2}' -f $subnet.Cidr, $(if ($Target) { $targets -join ',' } else { 'discovered' }), ($lanPorts -join ','))

$devices = @{}
if (-not $Target) {
    Invoke-MSPCheck -Name 'Device discovery' -Category 'LanScan' -ScriptBlock {
        foreach ($d in (Get-MSPLiveHost -Subnet $subnet -ThrottleLimit $ThrottleLimit)) {
            if (-not $d.IsSelf) { $script:devices[$d.IPAddress] = $d }
        }
    }
    $targets = @($devices.Keys | Sort-Object -Property { ConvertTo-MSPIPv4Number -IPAddress $_ })
}
else {
    # Fill in MAC addresses for the vendor hint from the neighbor table (no extra traffic).
    foreach ($n in (Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $subnet.InterfaceIndex -ErrorAction SilentlyContinue)) {
        if ($targets -contains $n.IPAddress) {
            $devices[$n.IPAddress] = [pscustomobject]@{ IPAddress = $n.IPAddress; MacAddress = ($n.LinkLayerAddress -replace '-', ':').ToUpper(); IsGateway = ($n.IPAddress -eq $subnet.Gateway) }
        }
    }
}
Add-MSPFinding -Check 'Port check scope' -Category 'LanScan' -Status INFO `
    -Detail ('{0} device(s) x {1} ports on {2}.' -f $targets.Count, $lanPorts.Count, $subnet.Cidr) `
    -Evidence @{ Cidr = $subnet.Cidr; Devices = $targets.Count; Ports = ($lanPorts -join ',') }

if ($targets.Count -eq 0) {
    Complete-MSPRun -OutputPath $OutputPath
    return
}

# =========================================================================================
Write-MSPSection -Title 'Local network port check - results'
# =========================================================================================
Invoke-MSPCheck -Name 'LAN port check' -Category 'LanScan' -ScriptBlock {
    $connectScript = {
        param($item, $timeoutMs)
        $parts = $item.Split('|')
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($parts[0], [int]$parts[1], $null, $null)
            if ($async.AsyncWaitHandle.WaitOne($timeoutMs) -and $client.Connected) {
                $client.EndConnect($async)
                [pscustomobject]@{ IP = $parts[0]; Port = [int]$parts[1] }
            }
        }
        catch {
            $null = $_   # refused or unreachable = closed
        }
        finally {
            $client.Close()
        }
    }
    $work = foreach ($ip in $targets) { foreach ($port in $lanPorts) { '{0}|{1}' -f $ip, $port } }
    $open = @(Invoke-MSPRunspacePool -InputObject @($work) -ScriptBlock $connectScript -ArgumentList $TimeoutMs `
            -ThrottleLimit $ThrottleLimit -Activity 'Port check' -TimeoutSeconds 600)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($group in ($open | Group-Object -Property IP)) {
        $ip = $group.Name
        $device = $devices[$ip]
        $mac = ''
        if ($device) { $mac = $device.MacAddress }
        $vendor = Get-MSPMacVendor -MacAddress $mac
        $isGateway = ($ip -eq $subnet.Gateway)
        $role = $vendor.Hint
        if ($isGateway) { $role = 'Router / gateway' }
        $ports = @($group.Group | ForEach-Object { $_.Port } | Sort-Object)
        $rows.Add([pscustomobject]@{
                IPAddress = $ip
                Vendor    = $vendor.Vendor
                Role      = $role
                OpenPorts = ($ports -join ', ')
            })

        foreach ($port in $ports) {
            $info = $knownPorts[$port]
            $check = 'Port {0} {1}' -f $port, $info.Name
            $who = '{0} ({1})' -f $ip, $vendor.Vendor
            if ($isGateway) { $who = '{0} (router)' -f $ip }
            $evidence = @{ IP = $ip; Port = $port; Vendor = $vendor.Vendor }
            switch ($port) {
                23 {
                    Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status FAIL -Severity High -Evidence $evidence `
                        -Detail ('{0} accepts Telnet. {1}' -f $who, $info.Why) `
                        -Recommendation 'Turn Telnet off in the device''s settings, or update its firmware. If it cannot be turned off, move it to a guest/IoT network.'
                }
                5900 {
                    Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status WARN -Severity High -Evidence $evidence `
                        -Detail ('{0} accepts VNC remote-control connections. {1}' -f $who, $info.Why) `
                        -Recommendation 'Confirm the client knows about this remote-control software. If not, treat as suspicious and remove it.'
                }
                21 {
                    Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status WARN -Severity Medium -Evidence $evidence `
                        -Detail ('{0} runs an FTP server. {1}' -f $who, $info.Why) `
                        -Recommendation 'Turn FTP off on the device unless it is needed; use SFTP or SMB with a password instead.'
                }
                3389 {
                    Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status WARN -Severity Medium -Evidence $evidence `
                        -Detail ('{0} accepts Remote Desktop.' -f $who) `
                        -Recommendation 'Confirm this is intended, that the account has a strong password, and that the router does not forward port 3389.'
                }
                { $_ -in @(139, 445) } {
                    if ($isGateway) {
                        Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status WARN -Severity Medium -Evidence $evidence `
                            -Detail ('The router shares files over SMB (often a USB drive plugged into it).') `
                            -Recommendation 'In the router settings, require a password for USB/file sharing and make sure it is not available from the internet.'
                    }
                    else {
                        Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status INFO -Evidence $evidence `
                            -Detail ('{0} shares files or printers (a Windows PC or NAS).' -f $who)
                    }
                }
                { $_ -in @(80, 443, 8080) } {
                    if ($vendor.Hint -match 'camera') {
                        Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status WARN -Severity Low -Evidence $evidence `
                            -Detail ('{0} (likely a camera/recorder) has a web page on port {1}.' -f $who, $port) `
                            -Recommendation 'Confirm the camera''s default password was changed and its firmware is current.'
                    }
                    elseif (-not $isGateway) {
                        Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status INFO -Evidence $evidence `
                            -Detail ('{0} has a web page on port {1} (admin page of a printer, NAS or smart device).' -f $who, $port)
                    }
                    # The router's admin page is assessed by Get-RouterSecurityCheck.ps1.
                }
                default {
                    Add-MSPFinding -Check $check -Category 'LanScan' -Target $ip -Status INFO -Evidence $evidence -Detail ('{0} accepts connections on port {1}.' -f $who, $port)
                }
            }
        }
    }
    $sortedRows = @($rows | Sort-Object -Property { ConvertTo-MSPIPv4Number -IPAddress $_.IPAddress })
    if ($sortedRows.Count -gt 0) {
        Write-Host ''
        Write-Host (($sortedRows | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    }
    Add-MSPData -Name 'LanOpenPorts' -Rows $sortedRows
    Add-MSPFinding -Check 'LAN port check' -Category 'LanScan' -Status INFO `
        -Detail ('{0} of {1} device(s) had at least one of the checked ports open.' -f $sortedRows.Count, $targets.Count)
}

Complete-MSPRun -OutputPath $OutputPath
