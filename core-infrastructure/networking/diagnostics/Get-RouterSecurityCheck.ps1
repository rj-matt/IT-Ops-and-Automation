<#
.SYNOPSIS
    Read-only home router check: gateway, DNS servers in use, whether the admin page uses
    HTTP or HTTPS, UPnP (and any port forwards it has opened), then a guided checklist for the
    settings only the router's admin page can show. Never logs in or guesses passwords.

.DESCRIPTION
    Automatic checks
      Gateway        The router address for the PC's active network adapter.
      DNS            The DNS servers this PC uses. Router/local addresses and well-known public
                     resolvers (Cloudflare, Google, Quad9, OpenDNS, ...) are fine. Unrecognised
                     public servers are flagged for confirmation: usually the ISP's own, but
                     DNS-changing malware sets these too. DNS typed in by hand on the PC is noted.
      Admin page     Requests "/" on the gateway over HTTP (80, 8080) and HTTPS (443, 8443)
                     WITHOUT credentials and records whether HTTP redirects to HTTPS. The page
                     title/server header helps identify the router model.
      Management     Whether the gateway accepts Telnet (23), FTP (21) or SSH (22) connections.
      UPnP           One SSDP discovery (UDP multicast to 239.255.255.250:1900, TTL 1 so it
                     never leaves the local network). If the router answers as an Internet
                     Gateway Device, UPnP is on. The script then asks the router - read-only -
                     for its external IP (to spot double NAT) and the port forwards UPnP has
                     opened.

    Guided checklist (interactive)
      Admin password changed, remote management off, WPS off, firmware current, UPnP off,
      guest network isolation. The technician checks each one in the router's admin page with
      the client and answers Y/N/U. With -SkipChecklistPrompt (or when no one can answer, e.g.
      run by an RMM tool) the items are recorded as "Not verified" with instructions.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0), with AdminPage, UpnpDevices and
    UpnpPortForwards tables.

.PARAMETER SkipChecklistPrompt
    Do not ask the checklist questions; record them as "Not verified".

.PARAMETER ExpectedDnsServer
    DNS server addresses the client uses on purpose (for example a filtering service), so they
    are not flagged as unrecognised.

.PARAMETER SsdpWaitSeconds
    How long to listen for UPnP answers (1-10 seconds). Default 3.

.EXAMPLE
    .\Get-RouterSecurityCheck.ps1
    Automatic checks, then the guided checklist.

.EXAMPLE
    .\Get-RouterSecurityCheck.ps1 -SkipChecklistPrompt -OutputPath C:\Temp\Audit

.NOTES
    Purpose       : Find the router settings that most often leave a home network exposed.
    Use Case      : Home network security audits; new router installs; "is my router safe?"
    Scope         : The default gateway only (TCP 21, 22, 23, 80, 443, 8080, 8443), plus one SSDP
                    multicast on the local network. Prints the scope before sending anything.
    Risk Level    : Read-Only -- unauthenticated GET requests and read-only UPnP queries
                    (GetExternalIPAddress, GetGenericPortMappingEntry). No logins, no password
                    guessing, no settings changed.
    Prerequisites : Windows PowerShell 5.1 | Admin: No | Modules: built-in only (NetTCPIP)
    Version       : 1.1.1
    Limitations   : Cannot see settings behind the admin login (that is what the checklist is
                    for). Routers managed only by a phone app (eero, Google/Nest Wifi, Orbi) may
                    expose no admin page. Port forwards created by hand in the admin page are
                    not always listed over UPnP. A router can have UPnP on but not answer SSDP.
                    Cannot test what is reachable from the internet. "Unrecognised DNS" needs a
                    human to confirm. Replaces _archive\...\Check-GatewaySecurity.ps1.
                    macOS/Linux version: get-router-security-check.sh (same checks and IDs).
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$SkipChecklistPrompt,
    [string[]]$ExpectedDnsServer = @(),
    [ValidateRange(1, 10)][int]$SsdpWaitSeconds = 3
)

#region MSPToolkit (generated) Sections=Core,Net
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Net | SHA256: f88b3ffddcb08c1921c139d10e6315edada8189a89d89ddb1c72ef5b7036cc8d
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

$ScriptVersion = '1.1.1'
Initialize-MSPRun -ScriptName 'Get-RouterSecurityCheck' -ScriptVersion $ScriptVersion -CheckId 'A7' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Home router security check (read-only; no logins)'

# "powershell.exe -File" passes a list as one "a,b" string.
$ExpectedDnsServer = @($ExpectedDnsServer | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Well-known public DNS resolvers. Filtering resolvers (Quad9, OpenDNS, CleanBrowsing...) are
# legitimate security choices and must not be flagged.
$knownResolvers = @(
    @{ Pattern = '^1\.1\.1\.[123]$|^1\.0\.0\.[123]$|^2606:4700:4700::'; Name = 'Cloudflare' }
    @{ Pattern = '^8\.8\.8\.8$|^8\.8\.4\.4$|^2001:4860:4860::'; Name = 'Google Public DNS' }
    @{ Pattern = '^9\.9\.9\.\d+$|^149\.112\.112\.\d+$|^2620:fe::'; Name = 'Quad9' }
    @{ Pattern = '^208\.67\.22[02]\.\d+$|^2620:119:'; Name = 'Cisco OpenDNS' }
    @{ Pattern = '^94\.140\.1[45]\.\d+$|^2a10:50c0::'; Name = 'AdGuard DNS' }
    @{ Pattern = '^185\.228\.16[89]\.\d+$|^2a0d:2a00:'; Name = 'CleanBrowsing' }
    @{ Pattern = '^8\.26\.56\.26$|^8\.20\.247\.20$'; Name = 'Comodo Secure DNS' }
    @{ Pattern = '^45\.90\.(28|30)\.\d+$|^2a07:a8c[01]::'; Name = 'NextDNS' }
    @{ Pattern = '^76\.76\.(2|10)\.\d+$|^2606:1a40:'; Name = 'Control D' }
    @{ Pattern = '^194\.242\.2\.\d+$|^2a07:e340::'; Name = 'Mullvad DNS' }
    @{ Pattern = '^4\.2\.2\.[1-6]$'; Name = 'Level3/Lumen' }
    @{ Pattern = '^156\.154\.70\.\d+$|^156\.154\.71\.\d+$'; Name = 'UltraDNS (Vercara)' }
)

function Test-PrivateAddress {
    <# RFC 1918 / link-local / IPv6 unique-local and link-local: answered inside the home network. #>
    param([string]$Address)
    return ($Address -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.)' -or $Address -match '^(fe80|fc|fd)[0-9a-f]*:' -or $Address -eq '::1')
}

function Test-TcpPort {
    param([string]$IPAddress, [int]$Port, [int]$TimeoutMs = 1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($IPAddress, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs) -and $client.Connected) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Invoke-GatewayHttp {
    <#
        One unauthenticated HTTP(S) request. Redirects are NOT followed (we want to see them).
        HTTPS certificate errors are ignored for this request only: home routers use
        self-signed certificates, and we only read the login page, never send credentials.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$Method = 'GET',
        [string]$Body,
        [hashtable]$Headers = @{},
        [int]$TimeoutMs = 4000
    )
    $result = [ordered]@{ Url = $Url; Reached = $false; StatusCode = $null; Location = ''; Server = ''; AuthHeader = ''; Title = ''; Content = ''; Error = '' }
    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = $Method
        $request.Timeout = $TimeoutMs
        $request.ReadWriteTimeout = $TimeoutMs
        $request.AllowAutoRedirect = $false
        $request.UserAgent = 'MSP-Toolkit-ReadOnly-Check'
        $request.Proxy = $null
        if ($Url -like 'https:*') { $request.ServerCertificateValidationCallback = { $true } }
        foreach ($k in $Headers.Keys) {
            if ($k -eq 'Content-Type') { $request.ContentType = $Headers[$k] } else { $request.Headers[$k] = $Headers[$k] }
        }
        if ($Body) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $request.ContentLength = $bytes.Length
            $stream = $request.GetRequestStream()
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
        }
        $response = $null
        try {
            $response = $request.GetResponse()
        }
        catch [System.Net.WebException] {
            # 401/403/404/500 still prove the server answered; keep the response.
            if ($_.Exception.Response) { $response = $_.Exception.Response } else { throw }
        }
        $result.Reached = $true
        $result.StatusCode = [int]$response.StatusCode
        $result.Location = [string]$response.Headers['Location']
        $result.Server = [string]$response.Headers['Server']
        $result.AuthHeader = [string]$response.Headers['WWW-Authenticate']
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $buffer = New-Object char[] 65536
        $read = $reader.Read($buffer, 0, $buffer.Length)
        $reader.Close()
        $response.Close()
        if ($read -gt 0) { $result.Content = New-Object string($buffer, 0, $read) }
        if ($result.Content -match '(?is)<title[^>]*>\s*(.*?)\s*</title>') { $result.Title = ($Matches[1] -replace '\s+', ' ').Trim() }
    }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        $result.Error = $inner.Message
    }
    return [pscustomobject]$result
}

$subnet = $null
$gateway = $null

# =========================================================================================
Write-MSPSection -Title 'Scope'
# =========================================================================================
Invoke-MSPCheck -Name 'Gateway' -Category 'Gateway' -ScriptBlock {
    $script:subnet = Get-MSPLocalSubnet
    $script:gateway = $script:subnet.Gateway
}
if ($subnet) {
    Write-Host '  Only the router below is contacted, plus one UPnP discovery message on the local network.' -ForegroundColor White
    Write-Host ('    Adapter : {0} ({1})' -f $subnet.InterfaceAlias, $subnet.InterfaceDescription)
    Write-Host ('    Router  : {0}   (this PC {1}, subnet {2})' -f $gateway, $subnet.IPAddress, $subnet.Cidr)
    Write-Host '    Contact : TCP 21, 22, 23, 80, 443, 8080, 8443 on the router (and any local HTTPS address it redirects to);'
    Write-Host '              SSDP multicast 239.255.255.250:1900 (TTL 1)'
    Write-Host '    Never   : logins, password guesses, or setting changes'
    Write-MSPLog -Message ('Scope: gateway {0} on {1}; TCP 21,22,23,80,443,8080,8443; SSDP multicast' -f $gateway, $subnet.Cidr)
    Add-MSPFinding -Check 'Gateway' -Category 'Gateway' -Status INFO -Detail ('Router {0} on {1} ({2}).' -f $gateway, $subnet.Cidr, $subnet.InterfaceAlias) `
        -Evidence @{ Gateway = $gateway; Cidr = $subnet.Cidr; Adapter = $subnet.InterfaceAlias }
}

# =========================================================================================
Write-MSPSection -Title 'DNS servers'
# =========================================================================================
if ($subnet) {
    Invoke-MSPCheck -Name 'DNS servers in use' -Category 'DNS' -ScriptBlock {
        $servers = @($subnet.DnsServers | Select-Object -Unique)
        if ($servers.Count -eq 0) {
            Add-MSPFinding -Check 'DNS servers in use' -Category 'DNS' -Status WARN -Severity Low -Detail 'No DNS servers are configured on the active adapter.' `
                -Recommendation 'Check the adapter is set to obtain DNS automatically.'
            return
        }
        # DNS typed in by hand on the PC overrides what the router hands out.
        $static = @()
        $adapter = Get-NetAdapter -InterfaceIndex $subnet.InterfaceIndex -ErrorAction SilentlyContinue
        if ($adapter) {
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0}' -f $adapter.InterfaceGuid
            $nameServer = (Get-ItemProperty -LiteralPath $regPath -Name NameServer -ErrorAction SilentlyContinue).NameServer
            if ($nameServer) { $static = @($nameServer -split '[,\s]+' | Where-Object { $_ }) }
        }
        $isStatic = ($static.Count -gt 0)
        $howSet = 'from the router (automatic)'
        if ($isStatic) { $howSet = 'typed in by hand on this PC (static)' }
        Add-MSPFinding -Check 'DNS configuration' -Category 'DNS' -Status INFO -Detail ('DNS servers {0}: {1}' -f $howSet, ($servers -join ', '))

        foreach ($dns in $servers) {
            $evidence = @{ Server = $dns; Static = $isStatic }
            if ($ExpectedDnsServer -contains $dns) {
                Add-MSPFinding -Check ('DNS {0}' -f $dns) -Category 'DNS' -Status PASS -Target $dns -Evidence $evidence -Detail 'Listed as expected by the technician.'
                continue
            }
            if (Test-PrivateAddress -Address $dns) {
                $where = 'a device on the home network (for example Pi-hole or a second router)'
                if ($dns -eq $gateway) { $where = 'the router, which forwards to its upstream DNS' }
                Add-MSPFinding -Check ('DNS {0}' -f $dns) -Category 'DNS' -Status PASS -Target $dns -Evidence $evidence -Detail ('Local DNS: {0}.' -f $where)
                continue
            }
            $known = $knownResolvers | Where-Object { $dns -match $_.Pattern } | Select-Object -First 1
            if ($known) {
                Add-MSPFinding -Check ('DNS {0}' -f $dns) -Category 'DNS' -Status PASS -Target $dns -Evidence $evidence -Detail ('Well-known public resolver: {0}.' -f $known.Name)
                continue
            }
            $severity = 'Low'
            $why = 'Usually this is the internet provider''s own DNS.'
            if ($isStatic) {
                $severity = 'Medium'
                $why = 'It was typed in by hand on this PC, which DNS-changing malware also does.'
            }
            Add-MSPFinding -Check ('DNS {0}' -f $dns) -Category 'DNS' -Status WARN -Severity $severity -Target $dns -Evidence $evidence `
                -Detail ('Unrecognised public DNS server {0}. {1}' -f $dns, $why) `
                -Recommendation 'Confirm it belongs to the client''s internet provider (an IP lookup shows the owner). If it does not and the client did not set it, set DNS back to automatic and scan for malware.'
        }
        Add-MSPFinding -Check 'Router upstream DNS' -Category 'DNS' -Status INFO `
            -Detail 'The DNS servers the ROUTER uses are only visible in its admin page (Internet/WAN settings). Check them during the checklist; they should be automatic (ISP) or a resolver the client chose.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Router admin page and management ports'
# =========================================================================================
$adminRows = New-Object System.Collections.Generic.List[object]
if ($gateway) {
    Invoke-MSPCheck -Name 'Admin page' -Category 'AdminPage' -ScriptBlock {
        $probes = @(
            @{ Scheme = 'http'; Port = 80 }, @{ Scheme = 'http'; Port = 8080 },
            @{ Scheme = 'https'; Port = 443 }, @{ Scheme = 'https'; Port = 8443 }
        )
        foreach ($probe in $probes) {
            if (-not (Test-TcpPort -IPAddress $gateway -Port $probe.Port)) { continue }
            $url = '{0}://{1}:{2}/' -f $probe.Scheme, $gateway, $probe.Port
            $r = Invoke-GatewayHttp -Url $url
            # Routers redirect with a 3xx status, or with a page that refreshes / scripts to https.
            $redirect = ''
            if ($r.StatusCode -ge 300 -and $r.StatusCode -lt 400) { $redirect = $r.Location }
            elseif ($r.Content -match '(?is)(http-equiv\s*=\s*["'']?refresh[^>]*url\s*=\s*|location(\.href)?\s*=\s*["''])(https://[^"''>\s;]+)') { $redirect = $Matches[3] }
            $script:adminRows.Add([pscustomobject]@{
                    Url        = $url
                    Scheme     = $probe.Scheme
                    Port       = $probe.Port
                    Answered   = $r.Reached
                    StatusCode = $r.StatusCode
                    RedirectTo = $redirect
                    ToHttps    = ($redirect -like 'https:*')
                    BasicAuth  = ($r.AuthHeader -match '^Basic')
                    Title      = $r.Title
                    Server     = $r.Server
                    Error      = $r.Error
                })
        }
        # Follow each HTTPS redirect once to confirm the page answers (for example a firewall that
        # sends :8080 to https://<router>:4433/). Only addresses inside the local subnet are contacted.
        foreach ($row in @($adminRows | Where-Object { $_.ToHttps })) {
            $uri = $null
            if (-not [Uri]::TryCreate($row.RedirectTo, [UriKind]::Absolute, [ref]$uri)) { continue }
            if (-not (Test-MSPIPInSubnet -IPAddress $uri.Host -Subnet $subnet)) { continue }
            if (@($adminRows | Where-Object { $_.Scheme -eq 'https' -and $_.Port -eq $uri.Port }).Count -gt 0) { continue }
            Write-MSPLog -Message ('Following HTTPS redirect to {0}' -f $uri.AbsoluteUri)
            $r = Invoke-GatewayHttp -Url $uri.AbsoluteUri
            $script:adminRows.Add([pscustomobject]@{
                    Url = $uri.AbsoluteUri; Scheme = 'https'; Port = $uri.Port; Answered = $r.Reached; StatusCode = $r.StatusCode
                    RedirectTo = $r.Location; ToHttps = $false; BasicAuth = ($r.AuthHeader -match '^Basic'); Title = $r.Title; Server = $r.Server; Error = $r.Error
                })
        }
        $rows = $adminRows.ToArray()
        if ($rows.Count -gt 0) { Write-Host (($rows | Select-Object Url, StatusCode, ToHttps, Title, Server | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()) }
        Add-MSPData -Name 'AdminPage' -Rows $rows

        $http = @($rows | Where-Object { $_.Scheme -eq 'http' -and $_.Answered })
        $https = @($rows | Where-Object { $_.Scheme -eq 'https' -and $_.Answered })
        $plainHttp = @($http | Where-Object { -not $_.ToHttps })
        $identity = @($rows | ForEach-Object { $_.Title; $_.Server } | Where-Object { $_ } | Select-Object -Unique) -join ' | '
        if ($identity) {
            Add-MSPFinding -Check 'Router identification' -Category 'AdminPage' -Status INFO -Detail ('Admin page reports: {0}' -f $identity)
        }
        if ($http.Count -eq 0 -and $https.Count -eq 0) {
            Add-MSPFinding -Check 'Admin page encryption' -Category 'AdminPage' -Status INFO `
                -Detail 'No web admin page answered on ports 80/443/8080/8443. The router may be managed only through a phone app (common for mesh systems).'
            return
        }
        $basic = @($plainHttp | Where-Object { $_.BasicAuth })
        if ($plainHttp.Count -gt 0 -and $https.Count -eq 0) {
            $detail = 'The admin page is only available over unencrypted HTTP ({0}). The admin password crosses the network in clear text.' -f (($plainHttp | ForEach-Object { $_.Url }) -join ', ')
            if ($basic.Count -gt 0) { $detail += ' It uses HTTP Basic authentication, which is trivially readable.' }
            Add-MSPFinding -Check 'Admin page encryption' -Category 'AdminPage' -Status WARN -Severity Medium -Detail $detail `
                -Recommendation 'If the router offers it, enable HTTPS for the admin page. Only log in from a wired or trusted device, and make sure the Wi-Fi is WPA2/WPA3.'
        }
        elseif ($plainHttp.Count -gt 0) {
            Add-MSPFinding -Check 'Admin page encryption' -Category 'AdminPage' -Status WARN -Severity Low `
                -Detail ('HTTPS is available ({0}), but the admin page also loads over plain HTTP without redirecting ({1}).' -f (($https | ForEach-Object { $_.Url }) -join ', '), (($plainHttp | ForEach-Object { $_.Url }) -join ', ')) `
                -Recommendation 'Use the https:// address to log in. If the router has a "redirect HTTP to HTTPS" or "HTTPS only" option, turn it on.'
        }
        else {
            $httpsText = ($https | ForEach-Object { $_.Url }) -join ', '
            if (-not $httpsText) { $httpsText = ('redirect target {0} did not answer' -f (($http | ForEach-Object { $_.RedirectTo }) -join ', ')) }
            Add-MSPFinding -Check 'Admin page encryption' -Category 'AdminPage' -Status PASS `
                -Detail ('Admin page uses HTTPS ({0}); plain HTTP only redirects to it.' -f $httpsText)
        }
    }

    Invoke-MSPCheck -Name 'Router management ports' -Category 'AdminPage' -ScriptBlock {
        $found = 0
        if (Test-TcpPort -IPAddress $gateway -Port 23) {
            $found++
            Add-MSPFinding -Check 'Router Telnet' -Category 'AdminPage' -Status FAIL -Severity High -Target $gateway `
                -Detail 'The router accepts Telnet (port 23): unencrypted remote login, heavily targeted by router malware.' `
                -Recommendation 'Turn Telnet off in the router''s administration settings, and update the firmware. If it cannot be turned off, consider replacing the router.'
        }
        if (Test-TcpPort -IPAddress $gateway -Port 21) {
            $found++
            Add-MSPFinding -Check 'Router FTP' -Category 'AdminPage' -Status WARN -Severity Medium -Target $gateway `
                -Detail 'The router runs an FTP server (port 21), usually for a USB drive. FTP passwords are not encrypted.' `
                -Recommendation 'Turn off FTP/USB sharing unless the client uses it; if used, set a strong password and make sure it is not reachable from the internet.'
        }
        if (Test-TcpPort -IPAddress $gateway -Port 22) {
            $found++
            Add-MSPFinding -Check 'Router SSH' -Category 'AdminPage' -Status INFO -Target $gateway `
                -Detail 'The router accepts SSH (port 22). Encrypted; normal on some routers (UniFi, OpenWrt). Confirm it is not enabled on the internet side.'
        }
        if ($found -eq 0) {
            Add-MSPFinding -Check 'Router management ports' -Category 'AdminPage' -Status PASS -Target $gateway -Detail 'No Telnet, FTP or SSH on the router.'
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'UPnP'
# =========================================================================================
$upnpOn = $false
$upnpRows = New-Object System.Collections.Generic.List[object]
$mappingRows = New-Object System.Collections.Generic.List[object]
if ($subnet) {
    Invoke-MSPCheck -Name 'UPnP discovery' -Category 'UPnP' -ScriptBlock {
        $localEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($subnet.IPAddress), 0)
        $udp = New-Object System.Net.Sockets.UdpClient($localEndpoint)
        $responses = @{}
        try {
            # TTL 1: the discovery message cannot be routed off the local network.
            $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastTimeToLive, 1)
            $udp.Client.ReceiveTimeout = 300
            $multicast = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('239.255.255.250'), 1900)
            $targets = @('urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'urn:schemas-upnp-org:device:InternetGatewayDevice:2', 'ssdp:all')
            foreach ($st in $targets) {
                $message = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: $st`r`n`r`n"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($message)
                $null = $udp.Send($bytes, $bytes.Length, $multicast)
            }
            $deadline = (Get-Date).AddSeconds($SsdpWaitSeconds)
            while ((Get-Date) -lt $deadline) {
                $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                try {
                    $data = $udp.Receive([ref]$remote)
                }
                catch [System.Net.Sockets.SocketException] {
                    continue   # receive timeout; keep listening until the deadline
                }
                $ip = $remote.Address.ToString()
                if (-not (Test-MSPIPInSubnet -IPAddress $ip -Subnet $subnet)) { continue }
                $text = [System.Text.Encoding]::ASCII.GetString($data)
                $headers = @{}
                foreach ($line in ($text -split "`r?`n")) {
                    if ($line -match '^([A-Za-z0-9\-]+):\s*(.*)$') { $headers[$Matches[1].ToUpper()] = $Matches[2].Trim() }
                }
                if (-not $responses.ContainsKey($ip)) { $responses[$ip] = New-Object System.Collections.Generic.List[object] }
                $responses[$ip].Add($headers)
            }
        }
        finally {
            $udp.Close()
        }

        $igdLocation = $null
        foreach ($ip in $responses.Keys) {
            $all = $responses[$ip]
            $types = @($all | ForEach-Object { $_['ST'] } | Where-Object { $_ } | Select-Object -Unique)
            $isIgd = [bool]($types | Where-Object { $_ -match 'InternetGatewayDevice|WANIPConnection|WANPPPConnection' })
            $server = @($all | ForEach-Object { $_['SERVER'] } | Where-Object { $_ } | Select-Object -First 1)
            $location = @($all | Where-Object { $_['ST'] -match 'InternetGatewayDevice' } | ForEach-Object { $_['LOCATION'] } | Select-Object -First 1)
            if (-not $location) { $location = @($all | ForEach-Object { $_['LOCATION'] } | Where-Object { $_ } | Select-Object -First 1) }
            $script:upnpRows.Add([pscustomobject]@{
                    IPAddress       = $ip
                    IsGateway       = ($ip -eq $gateway)
                    InternetGateway = $isIgd
                    Server          = ($server -join '')
                    Location        = ($location -join '')
                    DeviceTypes     = (($types | Select-Object -First 6) -join '; ')
                })
            if ($isIgd -and ($ip -eq $gateway -or -not $igdLocation)) { $igdLocation = ($location -join '') }
        }
        $rows = @($upnpRows | Sort-Object -Property { ConvertTo-MSPIPv4Number -IPAddress $_.IPAddress })
        Add-MSPData -Name 'UpnpDevices' -Rows $rows
        $igd = @($rows | Where-Object { $_.InternetGateway })
        $others = @($rows | Where-Object { -not $_.InternetGateway })
        if ($others.Count -gt 0) {
            Add-MSPFinding -Check 'UPnP devices' -Category 'UPnP' -Status INFO `
                -Detail ('{0} other device(s) announce themselves over UPnP (TVs, speakers, printers, NAS): {1}' -f $others.Count, (($others | ForEach-Object { $_.IPAddress }) -join ', '))
        }
        if ($igd.Count -eq 0) {
            Add-MSPFinding -Check 'Router UPnP' -Category 'UPnP' -Status PASS `
                -Detail ('No device answered as a UPnP Internet Gateway within {0}s, so UPnP port opening appears to be off. (Some routers stay silent even with UPnP on; confirm in the checklist.)' -f $SsdpWaitSeconds)
            return
        }
        $script:upnpOn = $true
        $where = ($igd | ForEach-Object { $_.IPAddress }) -join ', '
        Add-MSPFinding -Check 'Router UPnP' -Category 'UPnP' -Status WARN -Severity Medium -Target $gateway `
            -Detail ('UPnP is ON ({0} answered as an Internet Gateway Device). Any program or device on the network - including malware - can open ports to the internet without a password.' -f $where) `
            -Recommendation 'Turn UPnP off in the router unless the client needs it (some game consoles do). If it stays on, keep every device updated.'

        if (-not $igdLocation) { return }
        $locationUri = [Uri]$igdLocation
        if (-not (Test-MSPIPInSubnet -IPAddress $locationUri.Host -Subnet $subnet)) { return }
        $description = Invoke-GatewayHttp -Url $igdLocation
        if (-not $description.Content) { return }
        [xml]$xml = $description.Content
        $friendly = $xml.SelectSingleNode("//*[local-name()='device']/*[local-name()='friendlyName']")
        $maker = $xml.SelectSingleNode("//*[local-name()='device']/*[local-name()='manufacturer']")
        $model = $xml.SelectSingleNode("//*[local-name()='device']/*[local-name()='modelName']")
        $modelNumber = $xml.SelectSingleNode("//*[local-name()='device']/*[local-name()='modelNumber']")
        $parts = @($friendly, $maker, $model, $modelNumber) | Where-Object { $_ } | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ } | Select-Object -Unique
        if ($parts) { Add-MSPFinding -Check 'Router model (UPnP)' -Category 'UPnP' -Status INFO -Target $gateway -Detail (($parts) -join ' / ') }

        # Find the WAN connection service so we can ask (read-only) for external IP and port forwards.
        $service = $null
        foreach ($node in $xml.SelectNodes("//*[local-name()='service']")) {
            $type = $node.SelectSingleNode("*[local-name()='serviceType']").InnerText
            if ($type -match 'WANIPConnection|WANPPPConnection') {
                $service = @{ Type = $type.Trim(); Control = $node.SelectSingleNode("*[local-name()='controlURL']").InnerText.Trim() }
                break
            }
        }
        if (-not $service) { return }
        $baseNode = $xml.SelectSingleNode("//*[local-name()='URLBase']")
        $baseUri = $locationUri
        if ($baseNode -and $baseNode.InnerText.Trim()) { $baseUri = [Uri]$baseNode.InnerText.Trim() }
        $controlUrl = (New-Object Uri($baseUri, $service.Control)).AbsoluteUri
        if (-not (Test-MSPIPInSubnet -IPAddress ([Uri]$controlUrl).Host -Subnet $subnet)) { return }

        $invokeSoap = {
            param([string]$Action, [string]$Arguments)
            $body = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{0} xmlns:u="{1}">{2}</u:{0}></s:Body></s:Envelope>' -f $Action, $service.Type, $Arguments
            $headers = @{ 'Content-Type' = 'text/xml; charset="utf-8"'; 'SOAPAction' = ('"{0}#{1}"' -f $service.Type, $Action) }
            $r = Invoke-GatewayHttp -Url $controlUrl -Method POST -Body $body -Headers $headers
            if ($r.StatusCode -ne 200 -or -not $r.Content) { return $null }
            return [xml]$r.Content
        }

        $ipReply = & $invokeSoap 'GetExternalIPAddress' ''
        if ($ipReply) {
            $external = $ipReply.SelectSingleNode("//*[local-name()='NewExternalIPAddress']").InnerText
            if ($external -match '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.') {
                Add-MSPFinding -Check 'Internet address' -Category 'UPnP' -Status INFO -Evidence @{ ExternalIP = $external } `
                    -Detail ('The router''s internet address {0} is shared provider address space (carrier-grade NAT). Unsolicited connections from the internet generally cannot reach this network.' -f $external)
            }
            elseif ($external -and (Test-PrivateAddress -Address $external)) {
                Add-MSPFinding -Check 'Internet address' -Category 'UPnP' -Status WARN -Severity Low -Evidence @{ ExternalIP = $external } `
                    -Detail ('The router''s "internet" address is private ({0}): it sits behind another router or ISP modem (double NAT).' -f $external) `
                    -Recommendation 'Check the security settings of BOTH devices, or put the ISP modem in bridge mode.'
            }
            elseif ($external) {
                Add-MSPFinding -Check 'Internet address' -Category 'UPnP' -Status INFO -Evidence @{ ExternalIP = $external } -Detail ('The router''s public internet address is {0}.' -f $external)
            }
        }

        for ($index = 0; $index -lt 64; $index++) {
            $entry = & $invokeSoap 'GetGenericPortMappingEntry' ('<NewPortMappingIndex>{0}</NewPortMappingIndex>' -f $index)
            if (-not $entry) { break }
            $get = { param($n) $node = $entry.SelectSingleNode("//*[local-name()='$n']"); if ($node) { $node.InnerText } else { '' } }
            $script:mappingRows.Add([pscustomobject]@{
                    ExternalPort = & $get 'NewExternalPort'
                    Protocol     = & $get 'NewProtocol'
                    InternalIP   = & $get 'NewInternalClient'
                    InternalPort = & $get 'NewInternalPort'
                    Enabled      = & $get 'NewEnabled'
                    Description  = & $get 'NewPortMappingDescription'
                    LeaseSeconds = & $get 'NewLeaseDuration'
                })
        }
        $maps = $mappingRows.ToArray()
        Add-MSPData -Name 'UpnpPortForwards' -Rows $maps
        if ($maps.Count -eq 0) {
            Add-MSPFinding -Check 'UPnP port forwards' -Category 'UPnP' -Status PASS -Target $gateway -Detail 'The router reports no ports opened through UPnP right now.'
            return
        }
        Write-Host (($maps | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
        $risky = @(21, 22, 23, 80, 445, 3389, 5900, 8080)
        foreach ($m in $maps) {
            $severity = 'Medium'
            if ([int]$m.InternalPort -in $risky -or [int]$m.ExternalPort -in $risky) { $severity = 'High' }
            Add-MSPFinding -Check ('UPnP port forward {0}/{1}' -f $m.ExternalPort, $m.Protocol) -Category 'UPnP' -Status WARN -Severity $severity -Target $m.InternalIP `
                -Detail ('Internet port {0}/{1} is forwarded to {2}:{3} ("{4}").' -f $m.ExternalPort, $m.Protocol, $m.InternalIP, $m.InternalPort, $m.Description) `
                -Recommendation 'Identify the device and program. Remove the forward (turn UPnP off, or delete it in the router) unless the client needs it.' `
                -Evidence @{ ExternalPort = $m.ExternalPort; Protocol = $m.Protocol; InternalIP = $m.InternalIP; InternalPort = $m.InternalPort }
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'Router checklist (check in the admin page with the client)'
# =========================================================================================
$adminUrl = ($adminRows | Where-Object { $_.Answered } | Sort-Object -Property @{ Expression = { if ($_.Scheme -eq 'https') { 0 } else { 1 } } } | Select-Object -First 1).Url
$upnpHint = 'automatic check: UPnP appears OFF'
if ($upnpOn) { $upnpHint = 'automatic check: UPnP is ON' }
$checklist = @(
    @{ Id = 'AdminPassword'; Question = 'Has the router admin password been changed from the default on the router''s label?'; Severity = 'Critical'; NoStatus = 'FAIL'
        Fix = 'Change the router admin password to a unique passphrase and store it in the client''s password manager.'; Where = 'Administration / System / Management' }
    @{ Id = 'RemoteManagement'; Question = 'Is remote management (admin access from the internet / WAN) turned OFF?'; Severity = 'High'; NoStatus = 'FAIL'
        Fix = 'Turn off remote/WAN management. If the client relies on the vendor''s app, make sure that account has a strong password and 2FA.'; Where = 'Administration / Remote Management' }
    @{ Id = 'WPS'; Question = 'Is WPS (push-button or PIN pairing) turned OFF?'; Severity = 'Medium'; NoStatus = 'WARN'
        Fix = 'Turn WPS off; the PIN method can be brute-forced.'; Where = 'Wireless / WPS' }
    @{ Id = 'Firmware'; Question = 'Is the firmware current (updated in the last 12 months, or automatic updates on)?'; Severity = 'High'; NoStatus = 'FAIL'
        Fix = 'Update the firmware and turn on automatic updates. If the vendor no longer releases updates for this model, plan to replace the router.'; Where = 'Administration / Firmware Update'; AskText = 'Firmware version or date (optional, Enter to skip)' }
    @{ Id = 'UPnP'; Question = ('Is UPnP turned OFF (or knowingly left on for a game console)? [{0}]' -f $upnpHint); Severity = 'Medium'; NoStatus = 'WARN'
        Fix = 'Turn UPnP off unless a device the client uses needs it.'; Where = 'Advanced / NAT / UPnP' }
    @{ Id = 'GuestIsolation'; Question = 'Do visitors and smart-home devices use a guest network that cannot reach the PCs?'; Severity = 'Low'; NoStatus = 'WARN'
        Fix = 'Create a guest network with "allow access to local network" OFF, and move visitors and IoT devices to it.'; Where = 'Wireless / Guest Network' }
)

# Ask only when a person is at the console; otherwise record items as not verified.
$canPrompt = (-not $SkipChecklistPrompt) -and [Environment]::UserInteractive -and ($Host.Name -eq 'ConsoleHost')
try { if ([Console]::IsInputRedirected) { $canPrompt = $false } } catch { $canPrompt = $false }

if ($adminUrl) { Write-Host ('  Router admin page: {0}' -f $adminUrl) -ForegroundColor White }
else { Write-Host '  Router admin page: not found on common ports - try the address on the router''s label, or the vendor''s app.' -ForegroundColor White }
if ($canPrompt) {
    Write-Host '  Log in WITH THE CLIENT (they type the password; this script never asks for it).' -ForegroundColor White
    Write-Host '  Answer each question: Y = yes, N = no, U = unknown / could not check (Enter = U).' -ForegroundColor White
}
else {
    Write-Host '  Checklist questions are not being asked (-SkipChecklistPrompt or no interactive console).' -ForegroundColor DarkGray
    Write-Host '  Each item is recorded as "Not verified"; run this script on its own to answer them.' -ForegroundColor DarkGray
}

foreach ($item in $checklist) {
    $check = 'Checklist: {0}' -f $item.Id
    $answer = 'U'
    $note = ''
    if ($canPrompt) {
        Write-Host ''
        Write-Host ('  {0}' -f $item.Question) -ForegroundColor Cyan
        Write-Host ('     (usually under: {0})' -f $item.Where) -ForegroundColor DarkGray
        while ($true) {
            $raw = ([string](Read-Host '     Y/N/U')).Trim()
            if (-not $raw) { $raw = 'U' }
            $raw = $raw.Substring(0, 1).ToUpper()
            if ($raw -in @('Y', 'N', 'U')) { $answer = $raw; break }
            Write-Host '     Please type Y, N or U.' -ForegroundColor Yellow
        }
        if ($item.AskText) { $note = ([string](Read-Host ('     {0}' -f $item.AskText))).Trim() }
    }
    $evidence = @{ Answer = $answer; Prompted = $canPrompt }
    if ($note) { $evidence.Note = $note }
    switch ($answer) {
        'Y' {
            $detail = 'Confirmed by technician.'
            if ($note) { $detail = 'Confirmed by technician ({0}).' -f $note }
            Add-MSPFinding -Check $check -Category 'Checklist' -Status PASS -Target $gateway -Evidence $evidence -Detail $detail
        }
        'N' {
            $detail = 'Technician answered No: {0}' -f $item.Question
            if ($note) { $detail += (' ({0})' -f $note) }
            Add-MSPFinding -Check $check -Category 'Checklist' -Status $item.NoStatus -Severity $item.Severity -Target $gateway -Evidence $evidence `
                -Detail $detail -Recommendation $item.Fix
        }
        default {
            $how = 'Not verified.'
            if ($canPrompt) { $how = 'Could not be checked.' }
            Add-MSPFinding -Check $check -Category 'Checklist' -Status INFO -Target $gateway -Evidence $evidence `
                -Detail ('{0} {1} Look under {2}. If not: {3}' -f $how, $item.Question, $item.Where, $item.Fix)
        }
    }
}

Complete-MSPRun -OutputPath $OutputPath
