<#
.SYNOPSIS
    Read-only audit of RC4 use in Kerberos on this domain controller: which accounts still get
    RC4 tickets or have only RC4 keys, and whether the KDC is already warning about or refusing
    RC4 requests (CVE-2026-20833 / KB5073381).

.DESCRIPTION
    Microsoft is removing RC4 from Kerberos by default (KB5073381: enforcement from the April
    2026 updates, rollback removed with the July 2026 updates). Accounts and devices that still
    depend on RC4 stop authenticating. Run this on each domain controller to find them first.

    Checks
      Domain controller        The script only reads data on a domain controller (SKIPPED elsewhere).
      Kerberos events          Security log events 4768 (TGT) and 4769 (service ticket) in the
                               last -Days days (administrator). None = WARN: Kerberos auditing
                               is probably off. Events without key details (servers missing the
                               January 2025 or later updates) = SKIPPED.
      RC4 tickets issued       Requests whose ticket or session key used RC4. Any = WARN High.
      Accounts with only RC4 keys     Accounts seen with no AES keys = FAIL High: they will fail
                                      once RC4 is refused. Usually a password last set before
                                      AES existed in the domain.
      Accounts with RC4 and AES keys  Listed for information (most accounts have both).
      RC4 use by account       Top accounts by RC4 requests, with the devices (IP addresses)
                               asking (RC4UsageByAccount table).
      KDC RC4 events           System log, source Kdcsvc, events 201-209 from KB5073381:
                               203/204/208/209 = requests already DENIED (FAIL High);
                               201/202/206/207 = warnings (WARN Medium); 205 = insecure
                               DefaultDomainSupportedEncTypes (WARN Medium).
      KDC encryption settings  DefaultDomainSupportedEncTypes and RC4DefaultDisablementPhase.
                               RC4 allowed by default = WARN Medium.

    Account names are client data. They are only written to disk with -OutputPath; choose a
    folder outside the toolkit, a repository or a USB stick that moves between clients.

.PARAMETER Days
    How far back to read the event logs (1-90, default 30).

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with RC4UsageByAccount and
    AccountKeys tables.

.EXAMPLE
    .\Get-KerberosRC4Usage.ps1

.EXAMPLE
    .\Get-KerberosRC4Usage.ps1 -Days 7 -OutputPath D:\Reports\RC4

.NOTES
    Purpose       : Find what still depends on RC4 before (or after) Microsoft turns it off.
    Use Case      : Domains with older service accounts, NAS / printer / Linux devices using
                    Kerberos keytabs, after KB5073381 updates.
    Scope         : This domain controller's Security and System logs and its KDC settings.
                    Run on every domain controller: each logs only the tickets it issued.
    Risk Level    : Read-Only -- reads event logs and the registry; changes nothing.
    Prerequisites : Windows PowerShell 5.1 on a domain controller (Windows Server 2016 with the
                    January 2025 or later update, or 2019+) | Admin: Yes (Security log) |
                    Modules: built-in only. Kerberos auditing must be on: "Audit Kerberos
                    Authentication Service" and "Audit Kerberos Service Ticket Operations"
                    (Success).
    Version       : 3.0.0 (was Invoke-RC4AuditReport-SelfContained-v2.ps1)
    Limitations   : Sees only what this DC logged in the window. Key lists come from event
                    metadata, not from the directory. Does not change accounts or policy.

    The event parsing is based on Microsoft's open-source scripts Get-KerbEncryptionUsage.ps1 and
    List-AccountKeys.ps1 (https://github.com/microsoft/Kerberos-Crypto; original author Will
    Aftring, Microsoft), used under the MIT License:

        MIT License

        Copyright (c) Microsoft Corporation.

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)][int]$Days = 30,
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

$ScriptVersion = '3.0.0'
Initialize-MSPRun -ScriptName 'Get-KerberosRC4Usage' -ScriptVersion $ScriptVersion -CheckId 'RC4' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'RC4 use in Kerberos on this domain controller (read-only)' `
    -AdminSections @('the Security log')

$since = (Get-Date).AddDays(-$Days)
$sinceUtc = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
# Events with fewer properties come from servers without the January 2025 (2016) update.
$minPropertyCount = 21
$rc4Names = @('RC4', 'RC4-EXP')

# Kerberos encryption type numbers (RFC 3961/4757/8009), as in Get-KerbEncryptionUsage.ps1.
$etypes = @{ 1 = 'DES-CRC'; 3 = 'DES-MD5'; 17 = 'AES128-SHA96'; 18 = 'AES256-SHA96'; 19 = 'AES128-SHA256'; 20 = 'AES256-SHA384'; 23 = 'RC4'; 24 = 'RC4-EXP'; 255 = 'Unknown' }
function Get-ETypeName {
    param($Value)
    # The value arrives as a number, or as text such as "0x12".
    $n = 0
    $text = [string]$Value
    if ($text -match '^0x([0-9a-fA-F]+)$') { $n = [Convert]::ToInt32($Matches[1], 16) }
    elseif (-not [int]::TryParse($text, [ref]$n)) { $n = 255 }
    if ($etypes.ContainsKey($n)) { return $etypes[$n] }
    return ('Unknown(0x{0:x})' -f $n)
}
function ConvertFrom-KeyList {
    <# "AES-SHA1, RC4" (Windows Server 2022 wording) -> AES128-SHA96, AES256-SHA96, RC4. #>
    param([string]$Text)
    $keys = foreach ($k in ($Text -split ',')) {
        $k = $k.Trim()
        if (-not $k -or $k -eq '-') { continue }
        if ($k -eq 'AES-SHA1') { 'AES128-SHA96'; 'AES256-SHA96' } else { $k }
    }
    return @($keys)
}

# =========================================================================================
Write-MSPSection -Title 'Domain controller'
# =========================================================================================
$isDc = $false
Invoke-MSPCheck -Name 'Domain controller' -Category 'Setup' -ScriptBlock {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$cs.DomainRole -lt 4) {
        Skip-MSPCheck -Reason 'This computer is not a domain controller; Kerberos tickets are issued and logged by domain controllers only.' `
            -Recommendation 'Run this script on each domain controller.'
    }
    $script:isDc = $true
    Add-MSPFinding -Check 'Domain controller' -Category 'Setup' -Status INFO -Detail ('Domain controller of {0}; reading the last {1} day(s).' -f $cs.Domain, $Days)
}
if (-not $isDc) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 0
}

# =========================================================================================
Write-MSPSection -Title 'Kerberos tickets (Security log)'
# =========================================================================================
$requests = New-Object System.Collections.Generic.List[object]
$accounts = @{}
$eventsOk = $false
Invoke-MSPCheck -Name 'Kerberos events' -Category 'Events' -RequiresAdmin -AdminReason 'The Security log can only be read as administrator.' -ScriptBlock {
    $query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4768 or EventID=4769) and TimeCreated[@SystemTime &gt;= '$sinceUtc']]]</Select>
  </Query>
</QueryList>
"@
    $events = @()
    try { $events = @(Get-WinEvent -FilterXml ([xml]$query) -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' -and $_.Exception.Message -notmatch 'No events were found') { throw } }
    if ($events.Count -eq 0) {
        Add-MSPFinding -Check 'Kerberos events' -Category 'Events' -Status WARN -Severity Medium `
            -Detail ('No Kerberos ticket events (4768/4769) in the last {0} day(s): Kerberos auditing is probably off, so RC4 use cannot be measured.' -f $Days) `
            -Recommendation 'Turn on Success auditing for "Kerberos Authentication Service" and "Kerberos Service Ticket Operations" (Default Domain Controllers Policy > Advanced Audit Policy > Account Logon), wait a few days, and run again.'
        return
    }
    if ($events[0].Properties.Count -lt $minPropertyCount) {
        Skip-MSPCheck -Reason ('The events have no key details ({0} fields): this domain controller is missing the January 2025 or later update (Windows Server 2016) or is older than 2016.' -f $events[0].Properties.Count) `
            -Recommendation 'Install the latest cumulative update on the domain controllers, then run again.'
    }
    foreach ($e in $events) {
        $p = $e.Properties
        if ($e.Id -eq 4769) {
            $req = [pscustomobject]@{ Type = 'TGS'; Account = [string]$p[0].Value; Target = [string]$p[2].Value; Ticket = (Get-ETypeName $p[5].Value); SessionKey = (Get-ETypeName $p[20].Value); Address = [string]$p[6].Value; Time = $e.TimeCreated }
            $keyAccount = [string]$p[2].Value
            $keyType = 'Service'
        }
        else {
            $req = [pscustomobject]@{ Type = 'AS'; Account = [string]$p[0].Value; Target = [string]$p[3].Value; Ticket = (Get-ETypeName $p[7].Value); SessionKey = (Get-ETypeName $p[22].Value); Address = [string]$p[9].Value; Time = $e.TimeCreated }
            $keyAccount = [string]$p[0].Value
            $keyType = 'User'
        }
        $req.Address = $req.Address -replace '^::ffff:', ''
        $script:requests.Add($req)
        if ($keyAccount.EndsWith('$')) { $keyType = 'Computer' }
        $k = $keyAccount.ToLowerInvariant()
        if (-not $script:accounts.ContainsKey($k)) { $script:accounts[$k] = [pscustomobject]@{ Name = $keyAccount; Type = $keyType; Keys = @{}; Events = 0; First = $e.TimeCreated; Last = $e.TimeCreated } }
        $a = $script:accounts[$k]
        foreach ($key in (ConvertFrom-KeyList -Text ([string]$p[16].Value))) { $a.Keys[$key] = $true }
        $a.Events++
        if ($e.TimeCreated -lt $a.First) { $a.First = $e.TimeCreated }
        if ($e.TimeCreated -gt $a.Last) { $a.Last = $e.TimeCreated }
    }
    $script:eventsOk = $true
    Add-MSPFinding -Check 'Kerberos events' -Category 'Events' -Status INFO `
        -Detail ('{0} Kerberos ticket request(s) for {1} account(s) since {2:yyyy-MM-dd}.' -f $script:requests.Count, $script:accounts.Count, $since)
}

$rc4 = @($requests | Where-Object { $rc4Names -contains $_.Ticket -or $rc4Names -contains $_.SessionKey })
$accountRows = @($accounts.Values | Sort-Object Name | ForEach-Object {
        $keys = @($_.Keys.Keys | Sort-Object)
        $hasRc4 = @($keys | Where-Object { $rc4Names -contains $_ }).Count -gt 0
        $hasAes = @($keys | Where-Object { $_ -like 'AES*' }).Count -gt 0
        $class = 'AES only'
        if ($hasRc4 -and -not $hasAes) { $class = 'RC4 only' } elseif ($hasRc4) { $class = 'RC4 and AES' } elseif ($keys.Count -eq 0) { $class = 'No keys logged' }
        [pscustomobject]@{ Account = $_.Name; Type = $_.Type; Classification = $class; Events = $_.Events; FirstSeen = $_.First.ToString('yyyy-MM-dd HH:mm'); LastSeen = $_.Last.ToString('yyyy-MM-dd HH:mm'); Keys = ($keys -join '; ') }
    })
if ($eventsOk) { Add-MSPData -Name 'AccountKeys' -Rows $accountRows }

function Format-ItemList {
    param([object[]]$Items, [int]$Max = 10)
    $text = (@($Items | Select-Object -First $Max)) -join '; '
    if (@($Items).Count -gt $Max) { $text += ('; and {0} more (see the tables)' -f (@($Items).Count - $Max)) }
    return $text
}

if ($eventsOk) {
    Invoke-MSPCheck -Name 'RC4 tickets issued' -Category 'RC4' -ScriptBlock {
        if ($rc4.Count -eq 0) { Add-MSPFinding -Check 'RC4 tickets issued' -Category 'RC4' -Status PASS -Detail ('None of the {0} ticket request(s) used RC4.' -f $requests.Count); return }
        $pct = [math]::Round(100 * $rc4.Count / $requests.Count, 1)
        Add-MSPFinding -Check 'RC4 tickets issued' -Category 'RC4' -Status WARN -Severity High -Evidence @{ RC4 = $rc4.Count; Total = $requests.Count; AS = @($rc4 | Where-Object Type -eq 'AS').Count; TGS = @($rc4 | Where-Object Type -eq 'TGS').Count } `
            -Detail ('{0} of {1} ticket request(s) ({2} %) used RC4 ({3} sign-in tickets, {4} service tickets).' -f $rc4.Count, $requests.Count, $pct, @($rc4 | Where-Object Type -eq 'AS').Count, @($rc4 | Where-Object Type -eq 'TGS').Count) `
            -Recommendation 'Fix the accounts and devices in "RC4 use by account" before RC4 is refused: reset old service account passwords (creates AES keys), set msDS-SupportedEncryptionTypes to include AES, and re-export keytabs on non-Windows devices with AES keys.'
    }

    Invoke-MSPCheck -Name 'Accounts with only RC4 keys' -Category 'RC4' -ScriptBlock {
        $only = @($accountRows | Where-Object { $_.Classification -eq 'RC4 only' } | Sort-Object Events -Descending)
        if ($only.Count -eq 0) { Add-MSPFinding -Check 'Accounts with only RC4 keys' -Category 'RC4' -Status PASS -Detail 'Every account seen has AES keys.'; return }
        Add-MSPFinding -Check 'Accounts with only RC4 keys' -Category 'RC4' -Status FAIL -Severity High `
            -Detail (Format-ItemList @($only | ForEach-Object { '{0} ({1}, last seen {2})' -f $_.Account, $_.Type, $_.LastSeen })) `
            -Recommendation 'These accounts stop working once RC4 is refused. Reset each password (twice for krbtgt, with a wait between) to create AES keys, and check msDS-SupportedEncryptionTypes. Plan service account resets with the application owner.'
    }

    Invoke-MSPCheck -Name 'Accounts with RC4 and AES keys' -Category 'RC4' -ScriptBlock {
        $both = @($accountRows | Where-Object { $_.Classification -eq 'RC4 and AES' })
        Add-MSPFinding -Check 'Accounts with RC4 and AES keys' -Category 'RC4' -Status INFO `
            -Detail ('{0} account(s) have both key types (normal: every password also has an RC4 key). Only those in "RC4 use by account" actually use RC4.' -f $both.Count)
    }

    Invoke-MSPCheck -Name 'RC4 use by account' -Category 'RC4' -ScriptBlock {
        $rows = @($rc4 | Group-Object Account | Sort-Object Count -Descending | ForEach-Object {
                $g = @($_.Group)
                [pscustomobject]@{
                    Account = $_.Name; RC4Requests = $_.Count; Types = ((@($g | ForEach-Object { $_.Type }) | Sort-Object -Unique) -join ', ')
                    Targets = ((@($g | ForEach-Object { $_.Target }) | Sort-Object -Unique | Select-Object -First 5) -join '; ')
                    Addresses = ((@($g | ForEach-Object { $_.Address }) | Where-Object { $_ -and $_ -ne '-' } | Sort-Object -Unique | Select-Object -First 5) -join '; ')
                    LastRC4 = (@($g | Sort-Object Time -Descending)[0].Time).ToString('yyyy-MM-dd HH:mm')
                }
            })
        Add-MSPData -Name 'RC4UsageByAccount' -Rows $rows
        if ($rows.Count -eq 0) { Add-MSPFinding -Check 'RC4 use by account' -Category 'RC4' -Status INFO -Detail 'No account used RC4.'; return }
        Add-MSPFinding -Check 'RC4 use by account' -Category 'RC4' -Status INFO `
            -Detail (Format-ItemList @($rows | ForEach-Object { '{0}: {1} request(s) from {2}' -f $_.Account, $_.RC4Requests, $(if ($_.Addresses) { $_.Addresses } else { 'unknown address' }) }))
    }
}

# =========================================================================================
Write-MSPSection -Title 'KDC (KB5073381)'
# =========================================================================================
Invoke-MSPCheck -Name 'KDC RC4 events' -Category 'KDC' -ScriptBlock {
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Kdcsvc'; Id = 201, 202, 203, 204, 205, 206, 207, 208, 209; StartTime = $since } -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' -and $_.Exception.Message -notmatch 'No events were found') { throw } }
    $denied = @($events | Where-Object { $_.Id -in 203, 204, 208, 209 })
    $warned = @($events | Where-Object { $_.Id -in 201, 202, 206, 207 })
    $config = @($events | Where-Object { $_.Id -eq 205 })
    $byId = (@($events | Group-Object Id | Sort-Object Name | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count })) -join ', '
    if ($denied.Count -gt 0) {
        Add-MSPFinding -Check 'KDC RC4 events' -Category 'KDC' -Status FAIL -Severity High -Detail ('The KDC REFUSED {0} request(s) that needed RC4 (events {1}).' -f $denied.Count, $byId) `
            -Recommendation 'Something is failing to sign in now. Open each event (System log, source Kdcsvc) for the account and service, then give that account AES keys (password reset) or, as a stopgap per KB5073381, set its msDS-SupportedEncryptionTypes to 0x24.'
    }
    elseif ($warned.Count -gt 0 -or $config.Count -gt 0) {
        Add-MSPFinding -Check 'KDC RC4 events' -Category 'KDC' -Status WARN -Severity Medium -Detail ('KDC warnings about RC4 (events {0}).' -f $byId) `
            -Recommendation 'Each event names an account or setting that will break, or is unsafe, under RC4 enforcement. Fix them using KB5073381.'
    }
    else {
        Add-MSPFinding -Check 'KDC RC4 events' -Category 'KDC' -Status PASS -Detail ('No KDC RC4 warnings or refusals (events 201-209) in the last {0} day(s).' -f $Days)
    }
}

Invoke-MSPCheck -Name 'KDC encryption settings' -Category 'KDC' -ScriptBlock {
    $kdc = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -ErrorAction SilentlyContinue
    $phaseKey = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -ErrorAction SilentlyContinue
    $default = $null
    if ($kdc -and $null -ne $kdc.DefaultDomainSupportedEncTypes) { $default = [int]$kdc.DefaultDomainSupportedEncTypes }
    $phase = $null
    if ($phaseKey -and $null -ne $phaseKey.RC4DefaultDisablementPhase) { $phase = [int]$phaseKey.RC4DefaultDisablementPhase }
    $text = 'DefaultDomainSupportedEncTypes: {0}; RC4DefaultDisablementPhase: {1}.' -f $(if ($null -eq $default) { 'not set (Windows default)' } else { '0x{0:X}' -f $default }), $(if ($null -eq $phase) { 'not set' } else { $phase })
    $evidence = @{ DefaultDomainSupportedEncTypes = $default; RC4DefaultDisablementPhase = $phase }
    if ($null -ne $default -and ($default -band 0x4)) {
        Add-MSPFinding -Check 'KDC encryption settings' -Category 'KDC' -Status WARN -Severity Medium -Evidence $evidence -Detail ('{0} RC4 is allowed by default for accounts without their own setting.' -f $text) `
            -Recommendation 'KB5073381 calls this a last resort that leaves every account exposed to CVE-2026-20833. Fix the accounts that need RC4 individually, then remove RC4 from DefaultDomainSupportedEncTypes (or delete the value) on every domain controller.'
    }
    else {
        Add-MSPFinding -Check 'KDC encryption settings' -Category 'KDC' -Status PASS -Evidence $evidence -Detail $text
    }
}

Complete-MSPRun -OutputPath $OutputPath
