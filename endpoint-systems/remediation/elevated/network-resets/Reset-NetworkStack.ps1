<#
.SYNOPSIS
    Resets the Windows network stack (Winsock catalog, TCP/IP settings, DNS cache) after
    pre-flight diagnostics and a saved copy of the current settings. Requires a restart.

    THIS CANNOT BE FULLY ROLLED BACK. The saved copy is a record for re-entering settings by
    hand, not an automatic undo.

.DESCRIPTION
    Use only when basic troubleshooting (restart, Get-NetworkConnectivityReport.ps1) points to a
    damaged network stack: every app fails to connect while the adapter shows connected, errors
    such as "Winsock" / "LSP" / "No such host is known" everywhere, after malware or VPN removal.

    What it does, in order:
      1. Pre-flight (read-only): adapters, IPv4 settings and whether they are static, DNS servers,
         proxy, VPN adapters, remote-session tools, Winsock catalog (third-party entries), and -
         unless -SkipConnectivityTest - a gateway ping, a DNS lookup and one TCP connection to
         Microsoft's connectivity-test host to show which layer fails.
      2. Prints the plan, including what will be lost, and asks you to type YES (-Force skips
         the question; -WhatIf shows the plan only; -BackupOnly saves settings and stops).
      3. Saves the current settings to %ProgramData%\MSP-Toolkit\NetworkStackBackup_<host>_<time>\
         (ipconfig /all, Winsock catalog, IPv4 configuration, routes, proxy, DNS) plus a text file
         with the netsh commands to re-enter any static IP/DNS settings.
      4. Runs  netsh winsock reset   and checks its exit code and output.
         Runs  netsh int ip reset    (log saved next to the backup) and checks each line.
         Flushes the DNS client cache.
      5. Tells you to restart. It never restarts the PC itself.

    Deliberately NOT done (each would cut off a remote session mid-script, and none is part of a
    stack reset): ipconfig /release and /renew, disabling/restarting adapters, firewall reset,
    proxy changes.

    What is lost and cannot be restored automatically:
      - Third-party Winsock entries (some VPN clients, web filters, security products). Repair
        or reinstall those programs after the restart.
      - Static IPv4 addresses and static DNS servers on any adapter (they return to DHCP).
        Re-enter them from static-settings-restore.txt in the backup folder.
      - Other TCP/IP registry tuning made by software or by hand.

.PARAMETER Force
    Do not ask for confirmation. Required for non-interactive runs; without it a non-interactive
    run changes nothing.

.PARAMETER BackupOnly
    Run the pre-flight and save the current settings, then stop. Changes nothing. No admin needed.

.PARAMETER SkipConnectivityTest
    Do not send the pre-flight connectivity probes (gateway ping, DNS lookup, TCP connection).
    The rest of the pre-flight only reads this PC's own settings.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0).

.EXAMPLE
    .\Reset-NetworkStack.ps1 -WhatIf
    Pre-flight and the exact plan; changes nothing. No admin needed.

.EXAMPLE
    .\Reset-NetworkStack.ps1 -BackupOnly -OutputPath C:\Temp\Ticket123
    Pre-flight plus a saved copy of the settings; changes nothing.

.EXAMPLE
    .\Reset-NetworkStack.ps1
    Run as administrator. Pre-flight, plan, type YES, backup, reset. Then restart the PC.

.NOTES
    Purpose       : Repair a damaged Winsock / TCP/IP configuration as a last resort before
                    escalation.
    Use Case      : Persistent "nothing connects" tickets after basic troubleshooting.
    Scope         : Local computer. Network stack registry settings. Connectivity tests (optional)
                    contact the default gateway, the configured DNS server and
                    www.msftconnecttest.com (Windows' own connectivity-test host).
    Risk Level    : Elevated -- changes system networking; needs a restart; NOT fully reversible.
    Prerequisites : Windows PowerShell 5.1 | Admin: Yes for the reset (No for -WhatIf/-BackupOnly) |
                    Modules: built-in only
    Exit codes    : 0 reset done (restart required), or -WhatIf/-BackupOnly completed; 1 nothing
                    changed (not admin, not confirmed, non-interactive without -Force); 2 a step
                    failed (see findings; backup failure means nothing was changed)
    Version       : 2.0.1
    Limitations   : Cannot verify the result until after the restart (run
                    Get-NetworkConnectivityReport.ps1 then). Does not fix driver, hardware, router or
                    ISP problems. Static settings are detected for IPv4 only.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [switch]$BackupOnly,
    [switch]$SkipConnectivityTest,
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core,Change
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Change | SHA256: ab51e62fe464996b1ba69106b38fcdc5cc974c2d2f441c6448772439d56c35e0
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

$ScriptVersion = '2.0.1'
# Read -WhatIf into our own flag, then switch it off so it cannot reach the log writes and
# module loading. The dry run prints its own "What if:" lines with Write-MSPWhatIf.
$dryRun = [bool]$WhatIfPreference
$WhatIfPreference = $false
Initialize-MSPRun -ScriptName 'Reset-NetworkStack' -ScriptVersion $ScriptVersion -CheckId 'D2' -RiskLevel 'Elevated' `
    -Parameters $PSBoundParameters -Description 'Winsock / TCP/IP reset with pre-flight checks and a saved copy of settings (needs a restart; not fully reversible)' `
    -AdminSections 'the reset itself (not needed for -WhatIf or -BackupOnly)'

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$exitCode = 0
$virtualPattern = 'Hyper-V|VMware|VirtualBox|TAP-|WireGuard|Wintun|VPN|Tailscale|ZeroTier|Fortinet|AnyConnect|Juniper|GlobalProtect|Pulse|Loopback'
$remoteToolProcesses = @('ScreenConnect.ClientService', 'ScreenConnect.WindowsClient', 'TeamViewer_Service', 'TeamViewer', 'AnyDesk', 'AgentMon',
    'SRService', 'LMIGuardianSvc', 'remoting_host', 'rustdesk', 'NinjaRMMAgent', 'AteraAgent', 'BASupSrvc')

# Microsoft's own Winsock providers; anything else in the catalog came from other software.
$microsoftProviderPattern = '\\(mswsock|napinsp|pnrpnsp|nlaapi|winrnr|wshbth|wshqos|vsocklib|hvsocket|wshhyperv|wshtcpip|wship6)\.dll$'

$staticAdapters = New-Object System.Collections.Generic.List[object]
$thirdPartyProviders = @()

# =========================================================================================
Write-MSPSection -Title 'Pre-flight: this PC''s network settings (read-only)'
# =========================================================================================
$upAdapters = @()
Invoke-MSPCheck -Name 'Network adapters' -Category 'Preflight' -ScriptBlock {
    $all = @(Get-NetAdapter -ErrorAction Stop)
    $script:upAdapters = @($all | Where-Object { $_.Status -eq 'Up' })
    Add-MSPData -Name 'Adapters' -Rows @($all | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Description = $_.InterfaceDescription; Status = [string]$_.Status; LinkSpeed = [string]$_.LinkSpeed; Virtual = ($_.InterfaceDescription -match $virtualPattern) }
        })
    if ($script:upAdapters.Count -eq 0) {
        Add-MSPFinding -Check 'Network adapters' -Category 'Preflight' -Status FAIL -Severity High -Detail 'No network adapter is connected.' `
            -Recommendation 'A stack reset will not help. Check the cable / Wi-Fi connection, airplane mode and the adapter driver first.'
    }
    else {
        Add-MSPFinding -Check 'Network adapters' -Category 'Preflight' -Status INFO -Detail ('Connected: {0}' -f (($script:upAdapters | ForEach-Object { '{0} ({1})' -f $_.Name, $_.InterfaceDescription }) -join '; '))
    }
}

Invoke-MSPCheck -Name 'IPv4 settings' -Category 'Preflight' -ScriptBlock {
    foreach ($a in $upAdapters) {
        if ($a.InterfaceDescription -match $virtualPattern) {
            # Hyper-V/WSL/VPN adapters get their addresses from their own software, which sets
            # them up again; they are not settings a technician re-enters.
            Add-MSPFinding -Check ('IPv4: {0}' -f $a.Name) -Category 'Preflight' -Status INFO -Detail ('{0}: virtual or VPN adapter ({1}); its settings come from its own software.' -f $a.Name, $a.InterfaceDescription)
            continue
        }
        # 2>$null as well: on an adapter without IPv4, Get-NetIPConfiguration's internal
        # Get-NetIPInterface call writes "No MSFT_NetIPInterface objects found" despite -ErrorAction.
        $ipIf = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue 2>$null
        $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue 2>$null
        $addr = @($cfg.IPv4Address | Where-Object { $_ })
        $gw = @($cfg.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
        $dns = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
        # Static DNS servers are stored in the interface's NameServer value; DHCP ones are not.
        $guid = $a.InterfaceGuid
        $nameServer = ''
        if ($guid) {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0}' -f $guid
            $nameServer = [string](Get-ItemProperty -LiteralPath $key -Name NameServer -ErrorAction SilentlyContinue).NameServer
        }
        $staticIp = ($ipIf -and [string]$ipIf.Dhcp -eq 'Disabled')
        $detail = '{0}: {1} gateway {2}; DNS {3}; address from {4}; DNS {5}' -f $a.Name,
            (($addr | ForEach-Object { '{0}/{1}' -f $_.IPAddress, $_.PrefixLength }) -join ', '), ($gw -join ', '), ($dns -join ', '),
            $(if ($staticIp) { 'STATIC setting' } else { 'DHCP' }), $(if ($nameServer) { 'STATIC setting' } else { 'automatic' })
        if ($staticIp -or $nameServer) {
            $staticAdapters.Add([pscustomobject]@{ Alias = $a.Name; StaticIp = $staticIp; Address = $addr; Gateway = $gw; StaticDns = ($nameServer -split '[,\s]+' | Where-Object { $_ }) })
            Add-MSPFinding -Check ('Static settings: {0}' -f $a.Name) -Category 'Preflight' -Status WARN -Severity Medium -Detail $detail `
                -Recommendation 'The IP reset returns these to automatic (DHCP). They are saved with re-entry commands in the backup folder; re-enter them after the restart.'
        }
        else {
            Add-MSPFinding -Check ('IPv4: {0}' -f $a.Name) -Category 'Preflight' -Status INFO -Detail $detail
        }
    }
}

Invoke-MSPCheck -Name 'Winsock catalog' -Category 'Preflight' -ScriptBlock {
    $catalog = @(& netsh.exe winsock show catalog 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ('netsh winsock show catalog failed (exit {0}): {1}' -f $LASTEXITCODE, (($catalog | Select-Object -First 2) -join ' ')) }
    $paths = @($catalog | Where-Object { $_ -match '^\s*Provider Path:\s*(.+)$' } | ForEach-Object { ($_ -replace '^\s*Provider Path:\s*', '').Trim() })
    $script:thirdPartyProviders = @($paths | Where-Object { $_ -notmatch $microsoftProviderPattern } | Select-Object -Unique)
    if ($script:thirdPartyProviders.Count -gt 0) {
        Add-MSPFinding -Check 'Winsock catalog' -Category 'Preflight' -Status WARN -Severity Medium `
            -Detail ('{0} entries; {1} from other software: {2}' -f $paths.Count, $script:thirdPartyProviders.Count, ($script:thirdPartyProviders -join '; ')) `
            -Recommendation 'These entries are removed by the Winsock reset. If one belongs to software the client needs (VPN, filter, security), repair or reinstall it after the restart. A broken one may also be the cause of the problem.'
    }
    else {
        Add-MSPFinding -Check 'Winsock catalog' -Category 'Preflight' -Status INFO -Detail ('{0} entries, all Microsoft.' -f $paths.Count)
    }
}

Invoke-MSPCheck -Name 'Proxy' -Category 'Preflight' -ScriptBlock {
    $winhttp = ((& netsh.exe winhttp show proxy 2>&1) -join ' ') -replace '\s+', ' '
    $ie = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $user = 'none'
    if ($ie.ProxyEnable -eq 1) { $user = [string]$ie.ProxyServer }
    if ($ie.AutoConfigURL) { $user = '{0}; PAC {1}' -f $user, $ie.AutoConfigURL }
    $status = 'INFO'
    if ($user -ne 'none' -or $winhttp -notmatch 'Direct access') { $status = 'WARN' }
    Add-MSPFinding -Check 'Proxy' -Category 'Preflight' -Status $status -Severity Low -Detail ('User proxy: {0}. System (WinHTTP): {1}' -f $user, $winhttp.Trim()) `
        -Recommendation $(if ($status -eq 'WARN') { 'A proxy is set. The reset does NOT change proxy settings; a wrong proxy is a common cause of "nothing connects". Check it before resetting.' } else { '' })
}

Invoke-MSPCheck -Name 'VPN and virtual adapters' -Category 'Preflight' -ScriptBlock {
    $vpn = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceDescription -match $virtualPattern -and $_.InterfaceDescription -notmatch 'Loopback' })
    if ($vpn.Count -gt 0) {
        Add-MSPFinding -Check 'VPN and virtual adapters' -Category 'Preflight' -Status WARN -Severity Low -Detail ('Present: {0}' -f (($vpn | ForEach-Object { $_.InterfaceDescription }) -join '; ')) `
            -Recommendation 'VPN clients often need a repair or reinstall after a Winsock/IP reset. Note which ones the client uses.'
    }
    else {
        Add-MSPFinding -Check 'VPN and virtual adapters' -Category 'Preflight' -Status INFO -Detail 'None.'
    }
}

Invoke-MSPCheck -Name 'Remote session' -Category 'Preflight' -ScriptBlock {
    $tools = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $remoteToolProcesses -contains $_.ProcessName } | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
    $rdp = ([string]$env:SESSIONNAME -like 'RDP-*')
    if ($tools.Count -gt 0 -or $rdp) {
        $what = @($tools)
        if ($rdp) { $what += 'Remote Desktop session' }
        Add-MSPFinding -Check 'Remote session' -Category 'Preflight' -Status WARN -Severity Low -Detail ('Remote access in use: {0}.' -f ($what -join ', ')) `
            -Recommendation 'The reset itself normally keeps the session, but the required restart disconnects it. Make sure the remote tool starts as a service and reconnects, or have the client restart while you wait.'
    }
    else {
        Add-MSPFinding -Check 'Remote session' -Category 'Preflight' -Status INFO -Detail 'No remote-access tool detected.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Pre-flight: connectivity'
# =========================================================================================
if ($SkipConnectivityTest) {
    Add-MSPFinding -Check 'Connectivity test' -Category 'Preflight' -Status SKIPPED -Detail 'Not tested (-SkipConnectivityTest). No traffic was sent.' `
        -Recommendation 'Run Get-NetworkConnectivityReport.ps1 if you need to see which layer fails.'
}
else {
    $gateway = $null
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1
    if ($route) { $gateway = $route.NextHop }
    Write-Host ('  Contacting: gateway {0} (1 ping), the configured DNS server (1 lookup), www.msftconnecttest.com TCP 80 (1 connection).' -f $(if ($gateway) { $gateway } else { '(none)' }))
    $layers = [ordered]@{}
    $layers['Gateway reachable'] = $false
    if ($gateway) {
        try { $layers['Gateway reachable'] = ((New-Object System.Net.NetworkInformation.Ping).Send($gateway, 1000).Status -eq 'Success') } catch { $layers['Gateway reachable'] = $false }
    }
    $layers['DNS lookup'] = $false
    try { $layers['DNS lookup'] = [bool](Resolve-DnsName -Name 'www.msftconnecttest.com' -DnsOnly -QuickTimeout -ErrorAction Stop) } catch { $layers['DNS lookup'] = $false }
    $layers['Internet TCP connection'] = $false
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('www.msftconnecttest.com', 80, $null, $null)
        $layers['Internet TCP connection'] = ($async.AsyncWaitHandle.WaitOne(3000) -and $client.Connected)
    }
    catch { $layers['Internet TCP connection'] = $false }
    finally { $client.Close() }

    $firstFail = @($layers.Keys | Where-Object { -not $layers[$_] }) | Select-Object -First 1
    $text = ($layers.Keys | ForEach-Object { '{0}: {1}' -f $_, $(if ($layers[$_]) { 'yes' } else { 'NO' }) }) -join '; '
    if (-not $firstFail) {
        Add-MSPFinding -Check 'Connectivity test' -Category 'Preflight' -Status WARN -Severity Medium -Detail ('All layers work right now ({0}).' -f $text) `
            -Recommendation 'A stack reset is probably NOT needed. Look at the specific app, site, proxy or VPN instead.'
    }
    elseif ($firstFail -eq 'Gateway reachable') {
        Add-MSPFinding -Check 'Connectivity test' -Category 'Preflight' -Status FAIL -Detail ('First failing layer: gateway ({0}).' -f $text) `
            -Recommendation 'Check the Wi-Fi/cable, router and adapter first. Some routers ignore ping; if DNS and internet also fail, a reset may help.'
    }
    else {
        Add-MSPFinding -Check 'Connectivity test' -Category 'Preflight' -Status FAIL -Detail ('First failing layer: {0} ({1}).' -f $firstFail, $text) `
            -Recommendation 'The local network works but higher layers fail; a Winsock/IP reset is a reasonable next step if a proxy or VPN is not the cause.'
    }
}

# =========================================================================================
# Plan
# =========================================================================================
$backupRoot = Join-Path $env:ProgramData 'MSP-Toolkit'
$backupDir = Join-Path $backupRoot ('NetworkStackBackup_{0}_{1}' -f $script:MSPRun.Host, $stamp)
$staticNames = @($staticAdapters | ForEach-Object { $_.Alias })
$plan = @(
    ('Save current settings to {0}' -f $backupDir)
)
if (-not $BackupOnly) {
    $winsockNote = 'no third-party entries to lose'
    if ($thirdPartyProviders.Count -gt 0) { $winsockNote = 'REMOVES {0} third-party entr{1}' -f $thirdPartyProviders.Count, $(if ($thirdPartyProviders.Count -eq 1) { 'y' } else { 'ies' }) }
    $ipNote = 'no static settings found'
    if ($staticNames.Count -gt 0) { $ipNote = 'static IP/DNS settings on {0} return to DHCP' -f ($staticNames -join ', ') }
    $plan += ('netsh winsock reset   ({0})' -f $winsockNote)
    $plan += ('netsh int ip reset    ({0})' -f $ipNote)
    $plan += 'Flush the DNS client cache'
    $plan += 'YOU restart the PC afterwards (this script never restarts it)'
    $plan += 'Not done: ipconfig /release or /renew, adapter restarts, firewall or proxy changes'
}
Write-MSPChangePlan -Step $plan -Title $(if ($BackupOnly) { 'Planned actions (-BackupOnly: nothing is changed)' } else { 'Planned changes (cannot be fully rolled back)' })

if ($dryRun) {
    Write-MSPWhatIf -Target ($backupDir) -Action ('Save current network settings')
    if (-not $BackupOnly) {
        Write-MSPWhatIf -Target ('Winsock catalog') -Action ('netsh winsock reset')
        Write-MSPWhatIf -Target ('TCP/IP settings') -Action ('netsh int ip reset')
        Write-MSPWhatIf -Target ('DNS client cache') -Action ('Flush')
    }
    Add-MSPFinding -Check 'Dry run' -Category 'Safety' -Status INFO -Detail '-WhatIf: the pre-flight ran and the plan was shown; nothing was saved or changed.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}

if (-not $BackupOnly -and -not $script:MSPRun.IsAdmin) {
    Add-MSPFinding -Check 'Administrator' -Category 'Safety' -Status SKIPPED -Detail 'No changes made: the network stack reset requires administrator.' `
        -Recommendation 'Open PowerShell with "Run as administrator" and run again. -WhatIf and -BackupOnly work without admin.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}

if (-not $BackupOnly) {
    $question = 'Reset Winsock and TCP/IP on {0}? This needs a restart and cannot be fully undone.' -f $script:MSPRun.Host
    if (-not (Confirm-MSPChange -Question $question -Force:$Force)) {
        Complete-MSPRun -OutputPath $OutputPath
        exit 1
    }
}

# =========================================================================================
Write-MSPSection -Title 'Saving current settings'
# =========================================================================================
$backupOk = $false
if ($PSCmdlet.ShouldProcess($backupDir, 'Save current network settings')) {
    try {
        try {
            $null = New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop
        }
        catch {
            # ProgramData is normally writable; fall back to the user's temp folder (-BackupOnly without admin).
            $backupDir = Join-Path (Get-MSPLogFolder) ('NetworkStackBackup_{0}_{1}' -f $script:MSPRun.Host, $stamp)
            $null = New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop
        }
        $captures = [ordered]@{
            'ipconfig_all.txt'     = { & ipconfig.exe /all }
            'winsock_catalog.txt'  = { & netsh.exe winsock show catalog }
            'ipv4_config.txt'      = { & netsh.exe interface ipv4 show config }
            'routes.txt'           = { & route.exe print -4 }
            'winhttp_proxy.txt'    = { & netsh.exe winhttp show proxy }
            'dns_servers.txt'      = { Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize InterfaceAlias, ServerAddresses | Out-String -Width 200 }
        }
        foreach ($name in $captures.Keys) {
            $text = (& $captures[$name] 2>&1 | Out-String -Width 200)
            [System.IO.File]::WriteAllText((Join-Path $backupDir $name), $text, (New-Object System.Text.UTF8Encoding($false)))
        }
        Get-NetIPConfiguration -ErrorAction SilentlyContinue | Export-Clixml -LiteralPath (Join-Path $backupDir 'ipconfiguration.clixml')

        # Re-entry commands for static settings: the one part of the old setup a technician can restore.
        $restore = New-Object System.Collections.Generic.List[string]
        $restore.Add('Static network settings found before the reset, with commands to re-enter them.')
        $restore.Add('Run in an elevated Command Prompt or PowerShell AFTER the restart. Check each line first.')
        $restore.Add('')
        if ($staticAdapters.Count -eq 0) { $restore.Add('None: every adapter used automatic (DHCP) settings. Nothing to re-enter.') }
        foreach ($s in $staticAdapters) {
            $restore.Add(('Adapter: {0}' -f $s.Alias))
            if ($s.StaticIp) {
                foreach ($a in $s.Address) {
                    # Prefix length -> dotted mask (24 -> 255.255.255.0).
                    $bits = ('1' * [int]$a.PrefixLength).PadRight(32, '0')
                    $mask = (0..3 | ForEach-Object { [Convert]::ToInt32($bits.Substring($_ * 8, 8), 2) }) -join '.'
                    $gwText = ''
                    if ($s.Gateway.Count -gt 0) { $gwText = ' {0}' -f $s.Gateway[0] }
                    $restore.Add(('  netsh interface ipv4 set address name="{0}" static {1} {2}{3}' -f $s.Alias, $a.IPAddress, $mask, $gwText))
                }
            }
            $first = $true
            foreach ($d in $s.StaticDns) {
                if ($first) { $restore.Add(('  netsh interface ipv4 set dnsservers name="{0}" static {1} primary' -f $s.Alias, $d)); $first = $false }
                else { $restore.Add(('  netsh interface ipv4 add dnsservers name="{0}" {1}' -f $s.Alias, $d)) }
            }
            $restore.Add('')
        }
        [System.IO.File]::WriteAllText((Join-Path $backupDir 'static-settings-restore.txt'), ($restore -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        $backupOk = $true
        Add-MSPFinding -Check 'Settings saved' -Category 'Backup' -Status PASS -Detail ('Saved to {0}' -f $backupDir) -Evidence @{ Folder = $backupDir }
    }
    catch {
        Add-MSPFinding -Check 'Settings saved' -Category 'Backup' -Status FAIL -Detail ('Could not save the current settings: {0}. Nothing was changed.' -f $_.Exception.Message) `
            -Recommendation 'Free disk space or fix the folder permission, then run again. The reset is never done without a saved copy.'
    }
}

if (-not $backupOk) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 2
}
if ($BackupOnly) {
    Add-MSPFinding -Check 'Backup only' -Category 'Safety' -Status INFO -Detail '-BackupOnly: settings saved; the network stack was not changed.'
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}

# =========================================================================================
Write-MSPSection -Title 'Resetting'
# =========================================================================================
if ($PSCmdlet.ShouldProcess('Winsock catalog', 'netsh winsock reset')) {
    $out = @(& netsh.exe winsock reset 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    Write-MSPLog -Message ('netsh winsock reset exit {0}: {1}' -f $code, ($out -join ' | '))
    if ($code -eq 0 -and ($out -join ' ') -match 'Successfully reset') {
        Add-MSPFinding -Check 'Winsock reset' -Category 'Change' -Status PASS -Detail 'Winsock catalog reset (takes effect after the restart).'
    }
    else {
        $exitCode = 2
        Add-MSPFinding -Check 'Winsock reset' -Category 'Change' -Status FAIL -Detail ('netsh winsock reset did not report success (exit code {0}): {1}' -f $code, (($out | Where-Object { $_ }) -join ' ')) `
            -Recommendation 'Restart and run again. If it keeps failing, security software may be protecting the Winsock catalog; escalate with the log.'
    }
}

if ($PSCmdlet.ShouldProcess('TCP/IP settings', 'netsh int ip reset')) {
    $ipLog = Join-Path $backupDir 'netsh-int-ip-reset.log'
    $out = @(& netsh.exe int ip reset $ipLog 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    Write-MSPLog -Message ('netsh int ip reset exit {0}: {1}' -f $code, ($out -join ' | '))
    $failed = @($out | Where-Object { $_ -match 'failed' })
    $denied = @($failed | Where-Object { $_ -match 'Access is denied' })
    if ($code -eq 0 -and $failed.Count -eq 0) {
        Add-MSPFinding -Check 'TCP/IP reset' -Category 'Change' -Status PASS -Detail ('TCP/IP settings reset (takes effect after the restart). Log: {0}' -f $ipLog)
    }
    elseif ($failed.Count -gt 0 -and $failed.Count -eq $denied.Count) {
        # Windows commonly refuses one or two protected keys even for administrators while
        # resetting everything else; report it honestly rather than as success or failure.
        Add-MSPFinding -Check 'TCP/IP reset' -Category 'Change' -Status WARN -Severity Low `
            -Detail ('Reset done except {0} protected setting(s) Windows would not change ("Access is denied"): {1}' -f $failed.Count, ($failed -join ' ')) `
            -Recommendation ('This is common and usually harmless. If the problem remains after the restart, escalate with {0}.' -f $ipLog)
    }
    else {
        $exitCode = 2
        Add-MSPFinding -Check 'TCP/IP reset' -Category 'Change' -Status FAIL -Detail ('netsh int ip reset reported problems (exit code {0}): {1}' -f $code, $(if ($failed) { $failed -join ' ' } else { ($out | Where-Object { $_ }) -join ' ' })) `
            -Recommendation ('Restart and check connectivity; escalate with {0} if it is still broken.' -f $ipLog)
    }
}

if ($PSCmdlet.ShouldProcess('DNS client cache', 'Flush')) {
    try {
        Clear-DnsClientCache -ErrorAction Stop
        Add-MSPFinding -Check 'DNS cache flush' -Category 'Change' -Status PASS -Detail 'DNS client cache cleared.'
    }
    catch {
        $out = @(& ipconfig.exe /flushdns 2>&1 | ForEach-Object { "$_" })
        if ($LASTEXITCODE -eq 0) { Add-MSPFinding -Check 'DNS cache flush' -Category 'Change' -Status PASS -Detail 'DNS client cache cleared (ipconfig /flushdns).' }
        else {
            $exitCode = 2
            Add-MSPFinding -Check 'DNS cache flush' -Category 'Change' -Status FAIL -Detail ('Could not clear the DNS cache: {0}' -f ($out -join ' '))
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'After'
# =========================================================================================
Add-MSPFinding -Check 'Restart required' -Category 'After' -Status WARN -Severity High `
    -Detail 'The reset is not active until the PC restarts. Until then the old settings stay in use.' `
    -Recommendation 'Restart the PC now (warn the client first if you are connected remotely), then run Get-NetworkConnectivityReport.ps1 to confirm.'
$lost = @()
if ($thirdPartyProviders.Count -gt 0) { $lost += ('third-party Winsock entries ({0}): repair/reinstall that software' -f ($thirdPartyProviders -join '; ')) }
if ($staticNames.Count -gt 0) { $lost += ('static IP/DNS on {0}: re-enter from {1}' -f ($staticNames -join ', '), (Join-Path $backupDir 'static-settings-restore.txt')) }
if ($lost.Count -eq 0) { $lost += 'nothing known (no third-party Winsock entries, no static settings)' }
Add-MSPFinding -Check 'Cannot be undone automatically' -Category 'After' -Status INFO `
    -Detail ('There is no automatic rollback. To restore by hand: {0}. Full record of the old settings: {1}' -f ($lost -join '; '), $backupDir)

Complete-MSPRun -OutputPath $OutputPath
exit $exitCode
