<#
.SYNOPSIS
    Layered network connectivity test that ends with one answer: the first layer that fails
    (adapter, IP address, gateway, DNS, internet, web) and what to do about it. -Passive checks
    the local configuration only and sends nothing.

.DESCRIPTION
    Layers, tested in order (same check names and IDs on macOS/Linux):
      Adapter    Network adapter      A connected, non-virtual adapter (Wi-Fi or Ethernet).
      Address    IP address           A usable IPv4 address (169.254.x.x = no answer from DHCP).
      Gateway    Default gateway      A default route; then 2 pings to the gateway.
      DNS        DNS servers          Configured DNS servers; then a lookup of
                 DNS lookup           www.msftconnecttest.com.
      Internet   Internet (IP)        TCP port 443 on 1.1.1.1 and 8.8.8.8 (no names involved).
      Web        Web access           http://www.msftconnecttest.com/connecttest.txt (detects a
                                      captive portal or filter), then HTTPS to each -Endpoint.
    Context: Proxy (system/WinHTTP proxy; reachability of the proxy) and VPN (configured and
    connected VPNs). Diagnosis: the first failing layer, as one finding with the fix.

    Before anything is sent, the script prints every address it will contact. With -Passive it
    contacts nothing: only the adapter, address, gateway, DNS, proxy and VPN configuration are
    read, and the diagnosis covers configuration only.

.PARAMETER Passive
    Read the local configuration only. No pings, lookups or connections.

.PARAMETER Endpoint
    Host names to test over HTTPS in the Web layer. Default: login.microsoftonline.com,
    outlook.office365.com, www.google.com. Any HTTP answer (even an error page) counts as
    reachable; only no answer, a timeout or a certificate failure counts against it.

.PARAMETER TimeoutSeconds
    Time limit for each connection or web request (2-30). Default 5.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with Adapters and Tests tables.

.EXAMPLE
    .\Get-NetworkConnectivityReport.ps1

.EXAMPLE
    .\Get-NetworkConnectivityReport.ps1 -Passive

.EXAMPLE
    .\Get-NetworkConnectivityReport.ps1 -Endpoint portal.example.com,www.google.com -OutputPath C:\Temp\Ticket123

.NOTES
    Purpose       : Find where a "no internet" / "can't reach X" problem starts, in one run.
    Use Case      : Connectivity tickets; after D2 (Reset-NetworkStack) to confirm the fix.
    Scope         : This computer, its gateway, its DNS servers, 1.1.1.1 / 8.8.8.8 (TCP 443),
                    www.msftconnecttest.com and the -Endpoint hosts. Nothing with -Passive.
    Risk Level    : Read-Only -- reads settings and makes ordinary outbound connections; changes
                    nothing and sends no credentials.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: built-in only (NetAdapter,
                    NetTCPIP, DnsClient, VpnClient)
    Version       : 2.0.0
    Limitations   : IPv4 only. A gateway that ignores ping is reported as a warning, not a
                    failure, when later layers work. Endpoint tests show reachability, not that
                    a sign-in works. macOS/Linux version: get-network-connectivity-report.sh.
#>
[CmdletBinding()]
param(
    [switch]$Passive,
    [string[]]$Endpoint = @('login.microsoftonline.com', 'outlook.office365.com', 'www.google.com'),
    [ValidateRange(2, 30)][int]$TimeoutSeconds = 5,
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

$ScriptVersion = '2.0.0'
Initialize-MSPRun -ScriptName 'Get-NetworkConnectivityReport' -ScriptVersion $ScriptVersion -CheckId 'B2' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Layered connectivity test with the first failing layer (read-only)'

# "powershell.exe -File" passes a list as one "a,b" string; split so both forms work.
$Endpoint = @($Endpoint | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$probeHost = 'www.msftconnecttest.com'
$ipTargets = @('1.1.1.1', '8.8.8.8')
$timeoutMs = $TimeoutSeconds * 1000
# Layer results in test order: ok / warn / fail / untested. The diagnosis reads this.
$layerOrder = @('Adapter', 'Address', 'Gateway', 'DNS', 'Internet', 'Web')
$layer = @{}
foreach ($l in $layerOrder) { $layer[$l] = 'untested' }
$tests = New-Object System.Collections.Generic.List[object]
$gateway = ''
$dnsServers = @()

function Add-LayerResult {
    <# Records a layer result; a worse result never gets overwritten by a better one. #>
    param([string]$Name, [ValidateSet('ok', 'warn', 'fail')][string]$Result)
    $rank = @{ untested = 0; ok = 1; warn = 2; fail = 3 }
    if ($rank[$Result] -gt $rank[$script:layer[$Name]]) { $script:layer[$Name] = $Result }
}

function Add-TestRow {
    param([string]$Layer, [string]$Test, [string]$Target, [string]$Result, [int]$Ms = 0)
    $script:tests.Add([pscustomobject]@{ Layer = $Layer; Test = $Test; Target = $Target; Result = $Result; Milliseconds = $Ms })
}

function Test-TcpConnect {
    <# True when a TCP connection opens within the time limit; it is closed at once, nothing sent. #>
    param([string]$Address, [int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $attempt = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $attempt.AsyncWaitHandle.WaitOne($timeoutMs)) { return $false }
        $client.EndConnect($attempt)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Invoke-WebProbe {
    <# Returns @{ Ok; Status; Body; Error }. Any HTTP answer, including 4xx/5xx, is Ok. #>
    param([string]$Uri, [string]$Method = 'Get')
    try {
        $r = Invoke-WebRequest -Uri $Uri -Method $Method -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        return @{ Ok = $true; Status = [int]$r.StatusCode; Body = [string]$r.Content; Error = '' }
    }
    catch {
        $resp = $null
        if ($_.Exception.PSObject.Properties['Response']) { $resp = $_.Exception.Response }
        if ($resp) {
            return @{ Ok = $true; Status = [int]$resp.StatusCode; Body = ''; Error = '' }
        }
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        return @{ Ok = $false; Status = 0; Body = ''; Error = $msg }
    }
}

# Windows PowerShell 5.1 may not offer TLS 1.2 by default; this process only.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-MSPLog -Message 'TLS 1.2 could not be enabled for this process.' }

# =========================================================================================
Write-MSPSection -Title 'Adapter and address'
# =========================================================================================
$virtualPattern = 'VPN|Virtual|Hyper-V|VMware|VirtualBox|TAP-|Wintun|WireGuard|Tailscale|ZeroTier|Cisco AnyConnect|Fortinet|Loopback|Bluetooth'
$upAdapters = @()
Invoke-MSPCheck -Name 'Network adapter' -Category 'Adapter' -ScriptBlock {
    $all = @(Get-NetAdapter -ErrorAction Stop)
    Add-MSPData -Name 'Adapters' -Rows @($all | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Description = $_.InterfaceDescription; Status = [string]$_.Status; LinkSpeed = [string]$_.LinkSpeed; MacAddress = [string]$_.MacAddress; Virtual = [bool]($_.Virtual -or $_.InterfaceDescription -match $virtualPattern) }
        })
    $script:upAdapters = @($all | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual -and $_.InterfaceDescription -notmatch $virtualPattern })
    if ($upAdapters.Count -eq 0) {
        Add-LayerResult -Name 'Adapter' -Result fail
        $disconnected = @($all | Where-Object { -not $_.Virtual -and $_.InterfaceDescription -notmatch $virtualPattern } | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Status })
        Add-MSPFinding -Check 'Network adapter' -Category 'Adapter' -Status FAIL -Severity High `
            -Detail ('No connected Wi-Fi or Ethernet adapter. Adapters: {0}.' -f $(if ($disconnected) { $disconnected -join ', ' } else { 'none found' })) `
            -Recommendation 'Connect to Wi-Fi or plug in the cable; check the Wi-Fi switch / airplane mode and that the adapter is enabled in Network Connections.'
        return
    }
    Add-LayerResult -Name 'Adapter' -Result ok
    Add-MSPFinding -Check 'Network adapter' -Category 'Adapter' -Status PASS `
        -Detail (($upAdapters | ForEach-Object { '{0} ({1}, {2})' -f $_.Name, $_.InterfaceDescription, $_.LinkSpeed }) -join '; ')
}

Invoke-MSPCheck -Name 'IP address' -Category 'Address' -ScriptBlock {
    if ($layer['Adapter'] -ne 'ok') { Skip-MSPCheck -Reason 'Skipped: no connected adapter.' }
    $indexes = @($upAdapters | ForEach-Object { $_.ifIndex })
    $addrs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $indexes -contains $_.InterfaceIndex })
    $good = @($addrs | Where-Object { $_.IPAddress -notlike '169.254.*' })
    if ($good.Count -gt 0) {
        Add-LayerResult -Name 'Address' -Result ok
        Add-MSPFinding -Check 'IP address' -Category 'Address' -Status PASS `
            -Detail (($good | ForEach-Object { '{0}/{1} on {2} ({3})' -f $_.IPAddress, $_.PrefixLength, $_.InterfaceAlias, $_.PrefixOrigin }) -join '; ')
    }
    elseif ($addrs.Count -gt 0) {
        Add-LayerResult -Name 'Address' -Result fail
        Add-MSPFinding -Check 'IP address' -Category 'Address' -Status FAIL -Severity High `
            -Detail ('Only a self-assigned address ({0}): the router did not answer the request for an address (DHCP).' -f (($addrs | ForEach-Object { $_.IPAddress }) -join ', ')) `
            -Recommendation 'Restart the router and reconnect; for Wi-Fi forget and rejoin the network. If other devices work, run Reset-NetworkStack.ps1 (D2) -WhatIf first.'
    }
    else {
        Add-LayerResult -Name 'Address' -Result fail
        Add-MSPFinding -Check 'IP address' -Category 'Address' -Status FAIL -Severity High -Detail 'The connected adapter has no IPv4 address.' `
            -Recommendation 'Disconnect and reconnect; check the adapter''s IPv4 settings are "Obtain an IP address automatically".'
    }
}

Invoke-MSPCheck -Name 'Default gateway' -Category 'Gateway' -ScriptBlock {
    if ($layer['Address'] -ne 'ok') { Skip-MSPCheck -Reason 'Skipped: no usable IP address.' }
    $indexes = @($upAdapters | ForEach-Object { $_.ifIndex })
    $route = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' -and $indexes -contains $_.InterfaceIndex } | Sort-Object -Property RouteMetric) | Select-Object -First 1
    if (-not $route) {
        Add-LayerResult -Name 'Gateway' -Result fail
        Add-MSPFinding -Check 'Default gateway' -Category 'Gateway' -Status FAIL -Severity High -Detail 'No default gateway: the computer has no route to anything outside its own network.' `
            -Recommendation 'Reconnect to the network; if the address is set by hand, add the router''s address as the default gateway.'
        return
    }
    $script:gateway = $route.NextHop
    Add-LayerResult -Name 'Gateway' -Result ok
    Add-MSPFinding -Check 'Default gateway' -Category 'Gateway' -Status INFO -Detail ('{0} via {1}.' -f $gateway, $route.InterfaceAlias)
}

Invoke-MSPCheck -Name 'DNS servers' -Category 'DNS' -ScriptBlock {
    $indexes = @($upAdapters | ForEach-Object { $_.ifIndex })
    $script:dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $indexes -contains $_.InterfaceIndex } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
    if ($dnsServers.Count -eq 0) {
        Add-LayerResult -Name 'DNS' -Result fail
        Add-MSPFinding -Check 'DNS servers' -Category 'DNS' -Status FAIL -Severity High -Detail 'No DNS servers are configured, so names (websites) cannot be looked up.' `
            -Recommendation 'Set DNS to "Obtain DNS server address automatically" on the adapter, then reconnect.'
        return
    }
    Add-MSPFinding -Check 'DNS servers' -Category 'DNS' -Status INFO -Detail ($dnsServers -join ', ')
}

Invoke-MSPCheck -Name 'Proxy' -Category 'Proxy' -ScriptBlock {
    $ie = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $parts = @()
    if ($ie -and $ie.ProxyEnable -eq 1 -and $ie.ProxyServer) { $parts += ('system proxy {0}' -f $ie.ProxyServer) }
    if ($ie -and $ie.AutoConfigURL) { $parts += ('automatic configuration script {0}' -f $ie.AutoConfigURL) }
    $winhttp = (& netsh.exe winhttp show proxy 2>$null) -join ' '
    if ($winhttp -match 'Proxy Server\(s\)\s*:\s*(\S+)') { $parts += ('WinHTTP proxy {0}' -f $Matches[1]) }
    if ($parts.Count -eq 0) {
        Add-MSPFinding -Check 'Proxy' -Category 'Proxy' -Status INFO -Detail 'No proxy configured (direct connection).'
        return
    }
    $detail = 'Proxy in use: {0}.' -f ($parts -join '; ')
    if (-not $Passive -and $ie -and $ie.ProxyEnable -eq 1 -and $ie.ProxyServer -match '^(?:https?://)?([^:;=]+):(\d+)$') {
        $ok = Test-TcpConnect -Address $Matches[1] -Port ([int]$Matches[2])
        Add-TestRow -Layer 'Proxy' -Test 'TCP' -Target $ie.ProxyServer -Result $(if ($ok) { 'ok' } else { 'no answer' })
        if (-not $ok) {
            Add-MSPFinding -Check 'Proxy' -Category 'Proxy' -Status FAIL -Severity High -Detail ('{0} The proxy does not answer, so web traffic cannot get out.' -f $detail) `
                -Recommendation 'If the client does not use a proxy (home PCs normally do not), turn it off: Settings > Network & internet > Proxy. Unexpected proxies can also be malware.'
            return
        }
    }
    Add-MSPFinding -Check 'Proxy' -Category 'Proxy' -Status WARN -Severity Low -Detail $detail `
        -Recommendation 'Home PCs normally use no proxy. Confirm the client or their employer set it; an unexpected proxy can be malware or adware.'
}

Invoke-MSPCheck -Name 'VPN' -Category 'VPN' -ScriptBlock {
    $vpns = @(Get-VpnConnection -ErrorAction SilentlyContinue)
    $vpnAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'VPN|TAP-|Wintun|WireGuard|Tailscale|ZeroTier|AnyConnect|Fortinet|PANGP' })
    $connected = @($vpns | Where-Object { $_.ConnectionStatus -eq 'Connected' } | ForEach-Object { $_.Name }) + @($vpnAdapters | ForEach-Object { $_.InterfaceDescription })
    if ($connected.Count -gt 0) {
        Add-MSPFinding -Check 'VPN' -Category 'VPN' -Status INFO -Detail ('VPN connected: {0}. Traffic may go through the VPN; if the internet fails, test again with it disconnected.' -f ($connected -join ', '))
    }
    elseif ($vpns.Count -gt 0) {
        Add-MSPFinding -Check 'VPN' -Category 'VPN' -Status INFO -Detail ('VPN configured but not connected: {0}.' -f (($vpns | ForEach-Object { $_.Name }) -join ', '))
    }
    else {
        Add-MSPFinding -Check 'VPN' -Category 'VPN' -Status INFO -Detail 'No VPN connected.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Connectivity'
# =========================================================================================
if ($Passive) {
    Add-MSPFinding -Check 'Connectivity tests' -Category 'Scope' -Status SKIPPED -Detail 'Passive: nothing was sent. Gateway, DNS, internet and web tests were not run.' `
        -Recommendation 'Run without -Passive to test the connection itself.'
}
else {
    $targets = @()
    if ($gateway) { $targets += ('gateway {0} (ping)' -f $gateway) }
    if ($dnsServers) { $targets += ('DNS {0} (lookup of {1})' -f ($dnsServers -join ', '), $probeHost) }
    $targets += ('{0} (TCP 443)' -f ($ipTargets -join ', '))
    $targets += ('http://{0}/connecttest.txt' -f $probeHost)
    $targets += @($Endpoint | ForEach-Object { 'https://{0}' -f $_ })
    Write-Host ('  Will contact: {0}' -f ($targets -join '; ')) -ForegroundColor DarkGray
    Write-MSPLog -Message ('Will contact: {0}' -f ($targets -join '; '))

    Invoke-MSPCheck -Name 'Gateway reachable' -Category 'Gateway' -ScriptBlock {
        if (-not $gateway) { Skip-MSPCheck -Reason 'Skipped: no default gateway.' }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $ok = Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue
        Add-TestRow -Layer 'Gateway' -Test 'Ping x2' -Target $gateway -Result $(if ($ok) { 'ok' } else { 'no answer' }) -Ms $watch.ElapsedMilliseconds
        if ($ok) {
            Add-MSPFinding -Check 'Gateway reachable' -Category 'Gateway' -Status PASS -Detail ('{0} answers ping.' -f $gateway)
        }
        else {
            Add-LayerResult -Name 'Gateway' -Result warn
            Add-MSPFinding -Check 'Gateway reachable' -Category 'Gateway' -Status WARN -Severity Medium -Detail ('{0} did not answer ping. Some routers ignore ping; the next tests show whether traffic still gets through.' -f $gateway) `
                -Recommendation 'If the internet tests below also fail: restart the router, check the Wi-Fi signal or cable.'
        }
    }

    Invoke-MSPCheck -Name 'DNS lookup' -Category 'DNS' -ScriptBlock {
        if ($dnsServers.Count -eq 0) { Skip-MSPCheck -Reason 'Skipped: no DNS servers configured.' }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        try {
            $answer = @(Resolve-DnsName -Name $probeHost -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress })
        }
        catch {
            $answer = @()
            $why = $_.Exception.Message
        }
        Add-TestRow -Layer 'DNS' -Test 'Lookup' -Target $probeHost -Result $(if ($answer) { 'ok' } else { 'failed' }) -Ms $watch.ElapsedMilliseconds
        if ($answer.Count -gt 0) {
            Add-LayerResult -Name 'DNS' -Result ok
            Add-MSPFinding -Check 'DNS lookup' -Category 'DNS' -Status PASS -Detail ('{0} -> {1} ({2} ms).' -f $probeHost, $answer[0].IPAddress, $watch.ElapsedMilliseconds)
        }
        else {
            Add-LayerResult -Name 'DNS' -Result fail
            Add-MSPFinding -Check 'DNS lookup' -Category 'DNS' -Status FAIL -Severity High -Detail ('{0} could not be looked up via {1}: {2}' -f $probeHost, ($dnsServers -join ', '), $why) `
                -Recommendation 'Restart the router. If it persists, set the adapter''s DNS to automatic, or temporarily to 1.1.1.1 / 8.8.8.8 to confirm.'
        }
    }

    Invoke-MSPCheck -Name 'Internet (IP)' -Category 'Internet' -ScriptBlock {
        $reached = @()
        foreach ($ip in $ipTargets) {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $ok = Test-TcpConnect -Address $ip -Port 443
            Add-TestRow -Layer 'Internet' -Test 'TCP 443' -Target $ip -Result $(if ($ok) { 'ok' } else { 'no answer' }) -Ms $watch.ElapsedMilliseconds
            if ($ok) { $reached += $ip }
        }
        if ($reached.Count -gt 0) {
            Add-LayerResult -Name 'Internet' -Result ok
            Add-MSPFinding -Check 'Internet (IP)' -Category 'Internet' -Status PASS -Detail ('Reached {0} on port 443.' -f ($reached -join ', '))
        }
        else {
            Add-LayerResult -Name 'Internet' -Result fail
            Add-MSPFinding -Check 'Internet (IP)' -Category 'Internet' -Status FAIL -Severity High -Detail ('Could not reach {0} on port 443: no route to the internet.' -f ($ipTargets -join ' or ')) `
                -Recommendation 'Check the router''s internet light / app; restart the modem and router. If the router shows no internet, contact the ISP.'
        }
    }

    Invoke-MSPCheck -Name 'Web access' -Category 'Web' -ScriptBlock {
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $probe = Invoke-WebProbe -Uri ('http://{0}/connecttest.txt' -f $probeHost)
        Add-TestRow -Layer 'Web' -Test 'HTTP' -Target $probeHost -Result $(if ($probe.Ok) { 'HTTP {0}' -f $probe.Status } else { $probe.Error }) -Ms $watch.ElapsedMilliseconds
        if (-not $probe.Ok) {
            Add-LayerResult -Name 'Web' -Result fail
            Add-MSPFinding -Check 'Web access' -Category 'Web' -Status FAIL -Severity High -Detail ('http://{0} did not answer: {1}' -f $probeHost, $probe.Error) `
                -Recommendation 'Check firewall / security software and any proxy; try another browser.'
        }
        elseif ($probe.Status -eq 200 -and $probe.Body -match 'Microsoft Connect Test') {
            Add-LayerResult -Name 'Web' -Result ok
            Add-MSPFinding -Check 'Web access' -Category 'Web' -Status PASS -Detail 'Plain web access works (no captive portal or filter in the way).'
        }
        else {
            Add-LayerResult -Name 'Web' -Result warn
            Add-MSPFinding -Check 'Web access' -Category 'Web' -Status WARN -Severity Medium -Detail ('The test page came back changed (HTTP {0}): a captive portal (hotel/guest Wi-Fi sign-in), filter or proxy is answering instead.' -f $probe.Status) `
                -Recommendation 'Open a browser and complete any Wi-Fi sign-in page; otherwise check parental controls, security software or the proxy.'
        }
    }

    foreach ($ep in $Endpoint) {
        Invoke-MSPCheck -Name ('Endpoint {0}' -f $ep) -Category 'Web' -ScriptBlock {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-WebProbe -Uri ('https://{0}/' -f $ep) -Method Head
            Add-TestRow -Layer 'Web' -Test 'HTTPS' -Target $ep -Result $(if ($r.Ok) { 'HTTP {0}' -f $r.Status } else { $r.Error }) -Ms $watch.ElapsedMilliseconds
            if ($r.Ok) {
                Add-MSPFinding -Check ('Endpoint {0}' -f $ep) -Category 'Web' -Status PASS -Detail ('HTTPS answered (HTTP {0}, {1} ms).' -f $r.Status, $watch.ElapsedMilliseconds)
            }
            else {
                Add-LayerResult -Name 'Web' -Result warn
                Add-MSPFinding -Check ('Endpoint {0}' -f $ep) -Category 'Web' -Status WARN -Severity Medium -Detail ('HTTPS to {0} failed: {1}' -f $ep, $r.Error) `
                    -Recommendation 'If only this site fails, it may be down or blocked (security software, DNS filter). A certificate error can mean the PC''s clock is wrong.'
            }
        }
    }
}
Add-MSPData -Name 'Tests' -Rows $tests.ToArray()

# =========================================================================================
Write-MSPSection -Title 'Diagnosis'
# =========================================================================================
$advice = @{
    Adapter  = @('Adapter', 'The computer is not connected to any network (Wi-Fi off, cable out, or adapter disabled).', 'Connect to Wi-Fi or plug in the cable; check airplane mode and that the adapter is enabled.')
    Address  = @('IP address', 'The computer is connected but did not get an address from the router (DHCP).', 'Restart the router, forget and rejoin the Wi-Fi network; if only this PC is affected, run Reset-NetworkStack.ps1 -WhatIf (D2).')
    Gateway  = @('Gateway', 'The computer has an address but no working route to the router.', 'Restart the router; check the Wi-Fi signal or cable. If the address is set by hand, check the gateway.')
    DNS      = @('DNS', 'The internet is reachable by number but names do not resolve, so websites "do not load".', 'Restart the router; set DNS to automatic; test with 1.1.1.1 / 8.8.8.8 to confirm the DNS server is the problem.')
    Internet = @('Internet', 'The router answers but nothing beyond it does: the internet connection itself is down.', 'Check the modem/router internet light or app, restart modem and router, then contact the ISP.')
    Web      = @('Web', 'The internet works but web traffic is blocked or redirected (captive portal, proxy, filter or security software), or a site is down.', 'Complete any Wi-Fi sign-in page; check proxy, parental controls and security software.')
}
$firstFail = $layerOrder | Where-Object { $layer[$_] -eq 'fail' } | Select-Object -First 1
$firstWarn = $layerOrder | Where-Object { $layer[$_] -eq 'warn' } | Select-Object -First 1
$layerText = ($layerOrder | ForEach-Object { '{0}={1}' -f $_, $layer[$_] }) -join ', '
$evidence = @{ Layers = $layerText; FirstFailingLayer = [string]$firstFail; Passive = [bool]$Passive }
if ($firstFail) {
    $a = $advice[$firstFail]
    Add-MSPFinding -Check 'First failing layer' -Category 'Diagnosis' -Status FAIL -Severity High -Evidence $evidence `
        -Detail ('{0}: {1}' -f $a[0], $a[1]) -Recommendation $a[2]
}
elseif ($Passive) {
    Add-MSPFinding -Check 'First failing layer' -Category 'Diagnosis' -Status INFO -Evidence $evidence `
        -Detail 'No configuration problem found (adapter, address, gateway, DNS). The connection itself was not tested (-Passive).'
}
elseif ($firstWarn) {
    $a = $advice[$firstWarn]
    Add-MSPFinding -Check 'First failing layer' -Category 'Diagnosis' -Status WARN -Severity Medium -Evidence $evidence `
        -Detail ('No layer failed outright; first warning at {0}. {1}' -f $a[0], $a[1]) -Recommendation $a[2]
}
else {
    Add-MSPFinding -Check 'First failing layer' -Category 'Diagnosis' -Status PASS -Evidence $evidence `
        -Detail 'Every layer works: adapter, address, gateway, DNS, internet and web.'
}

Complete-MSPRun -OutputPath $OutputPath
