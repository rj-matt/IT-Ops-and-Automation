<#
.SYNOPSIS
    Read-only security check of a Windows PC: antivirus, firewall, disk encryption, updates,
    local administrators, UAC, SMBv1, Secure Boot, Remote Desktop and Guest account.

.DESCRIPTION
    Runs independent checks and reports each one as PASS / WARN / FAIL / INFO, or SKIPPED
    (needs administrator) / ERROR (the check itself could not run). Every check is wrapped so
    one failure never stops the rest.

    Works without administrator rights. As administrator, BitLocker and SMBv1 use the
    authoritative Windows cmdlets, and TPM is checked; without admin those use registry or
    Explorer-based detection, or are SKIPPED, and the output says so.

    Checks:
      Antivirus      Active antivirus (Windows Security Center), definitions, Defender real-time
                     protection, signature age and tamper protection
      Firewall       Windows Firewall per profile; third-party firewall awareness; current network type
      Encryption     BitLocker / Device Encryption on the Windows drive (stricter on laptops)
      Updates        Pending updates as of Windows' last update scan; last successful install
      Accounts       Local Administrators members, daily account is admin, built-in Administrator, Guest
      UAC            User Account Control on and prompting
      SMBv1          Legacy SMBv1 file-sharing protocol (exploited by WannaCry)
      Boot           Secure Boot; TPM (administrator only)
      Remote access  Remote Desktop enabled / Network Level Authentication

    Enterprise-only checks from version 1 (password expiry policy, audit policy, screensaver
    lock) were removed: on home PCs they produced misleading FAILs. Use Group Policy reporting
    for domain PCs.

.PARAMETER OutputPath
    Optional folder. Results are also saved there as JSON and CSV (toolkit schema 1.0) for
    Export-SecurityAuditReport.ps1. The folder is created if it does not exist.

.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1
    Runs all checks and prints results plus a ticket-ready summary.

.EXAMPLE
    .\Get-EndpointSecurityStatus.ps1 -OutputPath "$env:USERPROFILE\Desktop\Audit"
    Same, and saves JSON/CSV for the HTML report.

.NOTES
    Purpose       : One-screen answer to "is this PC protected?" for tickets and home audits.
    Use Case      : Home network security audits, new-client onboarding, security tickets.
    Scope         : Local computer only. No network scanning. No changes of any kind.
    Risk Level    : Read-Only -- reads settings only; nothing is changed, installed or enabled.
    Prerequisites : Windows PowerShell 5.1 | Admin: No (optional: adds TPM and authoritative
                    BitLocker/SMBv1 results) | Modules: built-in only | Permissions: local user
    Version       : 2.1.0
    Limitations   : Pending updates come from Windows' last update scan (date shown), not a live
                    search; use Get-WindowsUpdateCompliance.ps1 for a live check. Third-party
                    antivirus is detected via Windows Security Center only. Not an EDR.
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)

#region MSPToolkit (generated) Sections=Core,Updates,LocalAdmin
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/MSPToolkit.Common.psm1 | Sections: Core,Updates,LocalAdmin | SHA256: dbb66086c1017e128760d00712a79d734e86b3a23b8310c72adc15b2c8773963
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
#endregion MSPToolkit (generated)

$ScriptVersion = '2.1.0'
Initialize-MSPRun -ScriptName 'Get-EndpointSecurityStatus' -ScriptVersion $ScriptVersion -CheckId 'A1' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Endpoint security posture (read-only)'

# Facts several checks need. Collected once; failures here only reduce detail.
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$isServer = ($osInfo -and $osInfo.ProductType -ne 1)
$editionId = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
$isHomeEdition = ($editionId -like 'Core*')
# Laptops/tablets leave the house, so missing disk encryption matters more on them.
$chassis = @((Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue).ChassisTypes)
$isPortable = ($computerSystem -and $computerSystem.PCSystemType -eq 2) -or (@($chassis | Where-Object { $_ -in 8, 9, 10, 14, 30, 31, 32 }).Count -gt 0)

# =========================================================================================
Write-MSPSection -Title 'Antivirus'
# =========================================================================================
Invoke-MSPCheck -Name 'Antivirus product' -Category 'Antivirus' -ScriptBlock {
    if ($isServer) {
        Add-MSPFinding -Check 'Antivirus product' -Category 'Antivirus' -Status INFO `
            -Detail 'Windows Server has no Security Center; see the Microsoft Defender result below. Third-party server AV must be checked in its own console.'
        return
    }
    # Windows Security Center lists every registered antivirus. productState is a bit field:
    # bits 12-15 = 1 when real-time protection is on; bits 4-7 = 0 when definitions are current.
    $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct)
    $registrations = foreach ($p in $products) {
        $state = [int]$p.productState
        [pscustomobject]@{
            Name               = $p.displayName
            Enabled            = ((($state -shr 12) -band 0xF) -eq 1)
            DefinitionsCurrent = ((($state -shr 4) -band 0xF) -eq 0)
        }
    }
    # Some products (e.g. Sophos) register several components under one name: merge them.
    $rows = foreach ($group in ($registrations | Group-Object -Property Name)) {
        $enabledParts = @($group.Group | Where-Object { $_.Enabled })
        [pscustomobject]@{
            Name               = $group.Name
            Enabled            = ($enabledParts.Count -gt 0)
            DefinitionsCurrent = (@($enabledParts | Where-Object { -not $_.DefinitionsCurrent }).Count -eq 0)
        }
    }
    $active = @($rows | Where-Object { $_.Enabled })
    $evidence = @{ Registered = (($rows | ForEach-Object { '{0} (on={1})' -f $_.Name, $_.Enabled }) -join '; ') }
    if ($active.Count -eq 0) {
        Add-MSPFinding -Check 'Antivirus product' -Category 'Antivirus' -Status FAIL -Severity Critical `
            -Detail 'No antivirus with real-time protection is turned on.' -Evidence $evidence `
            -Recommendation 'Turn on Microsoft Defender (Windows Security > Virus & threat protection) or renew/repair the installed antivirus.'
        return
    }
    $names = ($active | ForEach-Object { $_.Name }) -join ', '
    Add-MSPFinding -Check 'Antivirus product' -Category 'Antivirus' -Status PASS -Detail ('Active: {0}' -f $names) -Evidence $evidence
    $stale = @($active | Where-Object { -not $_.DefinitionsCurrent })
    if ($stale.Count -gt 0) {
        Add-MSPFinding -Check 'Antivirus definitions' -Category 'Antivirus' -Status WARN -Severity High `
            -Detail ('Windows reports out-of-date definitions for: {0}' -f (($stale | ForEach-Object { $_.Name }) -join ', ')) `
            -Recommendation 'Open the antivirus and run an update; check the PC can reach the internet.'
    }
    else {
        Add-MSPFinding -Check 'Antivirus definitions' -Category 'Antivirus' -Status PASS -Detail 'Windows reports definitions as up to date.'
    }
    if ($active.Count -gt 1) {
        Add-MSPFinding -Check 'Multiple antivirus products' -Category 'Antivirus' -Status WARN -Severity Low `
            -Detail ('Windows reports more than one antivirus as active: {0}' -f $names) `
            -Recommendation 'Two real-time scanners can slow the PC and conflict. Keep one, unless the products are designed to run together (some EDR tools are).'
    }
}

Invoke-MSPCheck -Name 'Microsoft Defender' -Category 'Antivirus' -ScriptBlock {
    $mp = Get-MpComputerStatus
    $mode = [string]$mp.AMRunningMode
    if ($mode -and $mode -ne 'Normal') {
        # Passive / EDR block mode = another antivirus is primary; Defender's switches do not apply.
        Add-MSPFinding -Check 'Microsoft Defender' -Category 'Antivirus' -Status INFO `
            -Detail ('Defender is in "{0}" (another antivirus is primary).' -f $mode)
        return
    }
    if (-not $mp.RealTimeProtectionEnabled) {
        Add-MSPFinding -Check 'Defender real-time protection' -Category 'Antivirus' -Status FAIL -Severity Critical `
            -Detail 'Microsoft Defender is the active antivirus but real-time protection is OFF.' `
            -Recommendation 'Windows Security > Virus & threat protection > Manage settings > turn Real-time protection on.'
    }
    else {
        Add-MSPFinding -Check 'Defender real-time protection' -Category 'Antivirus' -Status PASS -Detail 'On'
    }
    $age = [int]$mp.AntivirusSignatureAge
    $sigEvidence = @{ SignatureAgeDays = $age; LastUpdated = [string]$mp.AntivirusSignatureLastUpdated }
    if ($age -gt 7) {
        Add-MSPFinding -Check 'Defender signature age' -Category 'Antivirus' -Status FAIL -Severity High -Evidence $sigEvidence `
            -Detail ('Definitions are {0} days old.' -f $age) -Recommendation 'Run Windows Update or "Check for updates" in Windows Security; investigate why updates are not arriving.'
    }
    elseif ($age -gt 3) {
        Add-MSPFinding -Check 'Defender signature age' -Category 'Antivirus' -Status WARN -Severity Medium -Evidence $sigEvidence `
            -Detail ('Definitions are {0} days old.' -f $age) -Recommendation 'Check for updates in Windows Security.'
    }
    else {
        Add-MSPFinding -Check 'Defender signature age' -Category 'Antivirus' -Status PASS -Detail ('{0} day(s) old' -f $age) -Evidence $sigEvidence
    }
    if ($null -ne $mp.IsTamperProtected) {
        if ($mp.IsTamperProtected) {
            Add-MSPFinding -Check 'Defender tamper protection' -Category 'Antivirus' -Status PASS -Detail 'On'
        }
        else {
            Add-MSPFinding -Check 'Defender tamper protection' -Category 'Antivirus' -Status WARN -Severity Medium `
                -Detail 'Off: malware can switch Defender off.' `
                -Recommendation 'Windows Security > Virus & threat protection > Manage settings > turn Tamper Protection on.'
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'Firewall'
# =========================================================================================
Invoke-MSPCheck -Name 'Windows Firewall' -Category 'Firewall' -ScriptBlock {
    # A registered third-party firewall legitimately replaces Windows Firewall.
    $thirdParty = @()
    if (-not $isServer) {
        $thirdParty = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction SilentlyContinue |
                Where-Object { ((([int]$_.productState) -shr 12) -band 0xF) -eq 1 } | ForEach-Object { $_.displayName })
    }
    # ActiveStore = the settings actually in effect, including Group Policy.
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    foreach ($fwProfile in $profiles) {
        $check = 'Firewall profile: {0}' -f $fwProfile.Name
        $evidence = @{ Enabled = [string]$fwProfile.Enabled; DefaultInboundAction = [string]$fwProfile.DefaultInboundAction }
        if ($fwProfile.Enabled -eq $true -or [string]$fwProfile.Enabled -eq 'True') {
            if ([string]$fwProfile.DefaultInboundAction -eq 'Allow') {
                Add-MSPFinding -Check $check -Category 'Firewall' -Status WARN -Severity High -Evidence $evidence `
                    -Detail 'Firewall is on but allows all inbound connections by default.' `
                    -Recommendation 'Reset the profile to block inbound connections by default (Windows Defender Firewall > Advanced settings).'
            }
            else {
                Add-MSPFinding -Check $check -Category 'Firewall' -Status PASS -Detail 'On' -Evidence $evidence
            }
        }
        elseif ($thirdParty.Count -gt 0) {
            Add-MSPFinding -Check $check -Category 'Firewall' -Status WARN -Severity Low -Evidence $evidence `
                -Detail ('Windows Firewall is off; a third-party firewall is registered: {0}.' -f ($thirdParty -join ', ')) `
                -Recommendation 'Confirm the third-party firewall is licensed and active.'
        }
        else {
            Add-MSPFinding -Check $check -Category 'Firewall' -Status FAIL -Severity High -Evidence $evidence `
                -Detail 'Off, and no other firewall is registered.' `
                -Recommendation ('Turn Windows Firewall on for the {0} profile (Windows Security > Firewall & network protection).' -f $fwProfile.Name)
        }
    }
}

Invoke-MSPCheck -Name 'Current network type' -Category 'Firewall' -ScriptBlock {
    foreach ($connection in @(Get-NetConnectionProfile)) {
        # Public = Windows treats the network as untrusted (strictest firewall rules).
        Add-MSPFinding -Check ('Network type: {0}' -f $connection.InterfaceAlias) -Category 'Firewall' -Status INFO `
            -Detail ('"{0}" is set to {1}.' -f $connection.Name, $connection.NetworkCategory) -NoConsole:$false
    }
}

# =========================================================================================
Write-MSPSection -Title 'Disk encryption'
# =========================================================================================
Invoke-MSPCheck -Name 'Windows drive encryption' -Category 'Encryption' -ScriptBlock {
    $drive = $env:SystemDrive
    $deviceText = 'desktop'
    if ($isPortable) { $deviceText = 'laptop/tablet' }
    $method = ''
    $isOn = $null
    $statusText = ''
    $evidence = @{ Drive = $drive; DeviceType = $deviceText }

    if ($script:MSPRun.IsAdmin -and (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        $method = 'Get-BitLockerVolume (administrator)'
        $volume = Get-BitLockerVolume -MountPoint $drive
        $statusText = '{0}, {1}% encrypted' -f $volume.VolumeStatus, $volume.EncryptionPercentage
        $isOn = ([string]$volume.ProtectionStatus -eq 'On')
        # Report only whether a recovery key exists -- never the key itself.
        $evidence['RecoveryPasswordProtector'] = (@($volume.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0)
        $evidence['ProtectionStatus'] = [string]$volume.ProtectionStatus
    }
    else {
        # Without admin, Explorer exposes the same BitLocker state the drive icon shows.
        $method = 'Explorer drive property (non-admin)'
        $value = (New-Object -ComObject Shell.Application).NameSpace($drive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
        $evidence['ExplorerBitLockerValue'] = [string]$value
        switch ([string]$value) {
            '1' { $isOn = $true; $statusText = 'BitLocker on' }
            '3' { $isOn = $true; $statusText = 'Encryption in progress' }
            '6' { $isOn = $true; $statusText = 'BitLocker on (locked)' }
            '2' { $isOn = $false; $statusText = 'BitLocker off' }
            '4' { $isOn = $false; $statusText = 'Decryption in progress' }
            '5' { $isOn = $false; $statusText = 'BitLocker suspended' }
            '' { $isOn = $null; $statusText = 'Not reported (BitLocker/Device Encryption not available on this edition or hardware)' }
            default { $isOn = $null; $statusText = ('Unrecognized state code {0}' -f $value) }
        }
    }
    $evidence['Method'] = $method

    if ($isOn -eq $true) {
        Add-MSPFinding -Check 'Windows drive encryption' -Category 'Encryption' -Status PASS -Detail ('{0} ({1}).' -f $statusText, $method) -Evidence $evidence
        if ($evidence.ContainsKey('RecoveryPasswordProtector') -and -not $evidence['RecoveryPasswordProtector']) {
            Add-MSPFinding -Check 'BitLocker recovery key' -Category 'Encryption' -Status WARN -Severity Medium `
                -Detail 'No recovery password protector found on the Windows drive.' `
                -Recommendation 'Add and back up a recovery key (Microsoft account, or printed and stored safely) so the data is not lost after a hardware change.'
        }
    }
    elseif ($isOn -eq $false) {
        $status = 'WARN'; $severity = 'Medium'
        if ($isPortable) { $status = 'FAIL'; $severity = 'High' }
        $advice = 'Turn on BitLocker (Pro) or Device encryption (Home, if supported) and save the recovery key.'
        if ($isHomeEdition) { $advice = 'Check Settings > Privacy & security > Device encryption. If it is not offered, upgrading to Windows Pro enables BitLocker.' }
        Add-MSPFinding -Check 'Windows drive encryption' -Category 'Encryption' -Status $status -Severity $severity -Evidence $evidence `
            -Detail ('{0} on this {1} ({2}). If the device is lost or stolen, the data can be read.' -f $statusText, $deviceText, $method) `
            -Recommendation $advice
    }
    else {
        Add-MSPFinding -Check 'Windows drive encryption' -Category 'Encryption' -Status INFO -Evidence $evidence `
            -Detail ('{0} ({1}). Re-run as administrator for a definitive answer.' -f $statusText, $method)
    }
}

# =========================================================================================
Write-MSPSection -Title 'Windows Update'
# =========================================================================================
Invoke-MSPCheck -Name 'Pending updates' -Category 'Updates' -ScriptBlock {
    # Cached mode reads Windows' own last scan: fast and works offline. A6 does a live search.
    $wu = Get-MSPWindowsUpdateInfo
    $asOf = 'never'
    if ($wu.LastSearchSuccess) { $asOf = $wu.LastSearchSuccess.ToString('yyyy-MM-dd HH:mm') }
    $evidence = @{ LastScan = $asOf; Pending = $wu.PendingCount; SecurityPending = $wu.SecurityPendingCount }
    if (-not $wu.LastSearchSuccess -or ((Get-Date) - $wu.LastSearchSuccess).TotalDays -gt 14) {
        Add-MSPFinding -Check 'Windows Update last scan' -Category 'Updates' -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('Windows last checked for updates successfully: {0}.' -f $asOf) `
            -Recommendation 'Open Settings > Windows Update and click "Check for updates"; run Get-WindowsUpdateCompliance.ps1 for a live check.'
    }
    if ($wu.SecurityPendingCount -gt 0) {
        Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('{0} security update(s) waiting ({1} pending in total, as of {2}).' -f $wu.SecurityPendingCount, $wu.PendingCount, $asOf) `
            -Recommendation 'Install updates now (Settings > Windows Update) and restart.'
    }
    elseif (($wu.PendingCount - $wu.DriverPendingCount) -gt 0) {
        Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('{0} non-security update(s) waiting (as of {1}).' -f ($wu.PendingCount - $wu.DriverPendingCount), $asOf) `
            -Recommendation 'Install pending updates at the next convenient time.'
    }
    else {
        Add-MSPFinding -Check 'Pending updates' -Category 'Updates' -Status PASS -Evidence $evidence `
            -Detail ('None pending as of Windows'' last scan ({0}).' -f $asOf)
    }

    if ($wu.LastInstallSuccess) {
        $days = [int]((Get-Date) - $wu.LastInstallSuccess).TotalDays
        $installText = '{0} ({1} days ago)' -f $wu.LastInstallSuccess.ToString('yyyy-MM-dd'), $days
        if ($days -gt 60) {
            Add-MSPFinding -Check 'Last update install' -Category 'Updates' -Status FAIL -Severity High -Detail $installText `
                -Recommendation 'Updates have not installed for over two months; run Get-WindowsUpdateCompliance.ps1 and fix Windows Update.'
        }
        elseif ($days -gt 35) {
            Add-MSPFinding -Check 'Last update install' -Category 'Updates' -Status WARN -Severity Medium -Detail $installText `
                -Recommendation 'Monthly updates appear to have been missed; install pending updates.'
        }
        else {
            Add-MSPFinding -Check 'Last update install' -Category 'Updates' -Status PASS -Detail $installText
        }
    }
    else {
        Add-MSPFinding -Check 'Last update install' -Category 'Updates' -Status WARN -Severity Medium `
            -Detail 'Windows reports no successful update installation date.' -Recommendation 'Run Get-WindowsUpdateCompliance.ps1 for details.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Accounts'
# =========================================================================================
Invoke-MSPCheck -Name 'Local administrators' -Category 'Accounts' -ScriptBlock {
    $members = @(Get-MSPLocalAdminMember)
    $list = ($members | ForEach-Object {
            $state = ''
            if ($_.Enabled -eq 'False') { $state = ', disabled' }
            '{0} ({1}, {2}{3})' -f $_.Name, $_.ObjectClass, $_.Source, $state
        }) -join '; '
    Add-MSPData -Name 'LocalAdmins' -Rows ($members | Select-Object Name, ObjectClass, Source, Enabled, SID)
    # Count accounts that can actually sign in: disabled local accounts don't add risk.
    $activeUsers = @($members | Where-Object { $_.ObjectClass -eq 'User' -and $_.Enabled -ne 'False' })
    if ($activeUsers.Count -gt 3) {
        Add-MSPFinding -Check 'Local administrators' -Category 'Accounts' -Status WARN -Severity Medium -Evidence @{ Members = $list } `
            -Detail ('{0} enabled user accounts have administrator rights: {1}' -f $activeUsers.Count, $list) `
            -Recommendation 'Confirm each account needs admin rights; make the others standard users.'
    }
    else {
        Add-MSPFinding -Check 'Local administrators' -Category 'Accounts' -Status INFO -Detail $list -Evidence @{ Members = $list }
    }
}

Invoke-MSPCheck -Name 'Daily account has admin rights' -Category 'Accounts' -ScriptBlock {
    # whoami lists Administrators even when UAC has filtered it ("Group used for deny only"),
    # which tells us the signed-in account is an administrator even in a non-elevated window.
    $groups = @(whoami.exe /groups /fo csv | ConvertFrom-Csv)
    $isMember = (@($groups | Where-Object { $_.SID -eq 'S-1-5-32-544' }).Count -gt 0)
    if ($isMember) {
        Add-MSPFinding -Check 'Daily account has admin rights' -Category 'Accounts' -Status WARN -Severity Medium `
            -Detail ('The signed-in account ({0}) is an administrator.' -f $env:USERNAME) `
            -Recommendation 'Best practice: use a standard account day to day and a separate admin account only when installing software. Most malware needs admin rights to dig in.'
    }
    else {
        Add-MSPFinding -Check 'Daily account has admin rights' -Category 'Accounts' -Status PASS -Detail ('{0} is a standard user.' -f $env:USERNAME)
    }
}

Invoke-MSPCheck -Name 'Built-in accounts' -Category 'Accounts' -ScriptBlock {
    # Identified by well-known RIDs (-500 Administrator, -501 Guest) so renamed accounts are caught.
    $users = @(Get-LocalUser)
    $builtinAdmin = $users | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' } | Select-Object -First 1
    $guest = $users | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } | Select-Object -First 1
    if ($builtinAdmin) {
        if ($builtinAdmin.Enabled) {
            Add-MSPFinding -Check 'Built-in Administrator account' -Category 'Accounts' -Status WARN -Severity Medium `
                -Detail ('"{0}" is enabled. It is a well-known target for password guessing.' -f $builtinAdmin.Name) `
                -Recommendation 'Disable it unless it is deliberately used, and use a named admin account instead.'
        }
        else {
            Add-MSPFinding -Check 'Built-in Administrator account' -Category 'Accounts' -Status PASS -Detail 'Disabled'
        }
    }
    if ($guest) {
        if ($guest.Enabled) {
            Add-MSPFinding -Check 'Guest account' -Category 'Accounts' -Status FAIL -Severity Medium `
                -Detail ('"{0}" is enabled: anyone can sign in without a password.' -f $guest.Name) `
                -Recommendation 'Disable the Guest account (Computer Management > Local Users and Groups).'
        }
        else {
            Add-MSPFinding -Check 'Guest account' -Category 'Accounts' -Status PASS -Detail 'Disabled'
        }
    }
}

# =========================================================================================
Write-MSPSection -Title 'User Account Control'
# =========================================================================================
Invoke-MSPCheck -Name 'User Account Control' -Category 'UAC' -ScriptBlock {
    $uac = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $evidence = @{ EnableLUA = $uac.EnableLUA; ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop = $uac.PromptOnSecureDesktop }
    if ($uac.EnableLUA -eq 0) {
        Add-MSPFinding -Check 'User Account Control' -Category 'UAC' -Status FAIL -Severity High -Evidence $evidence `
            -Detail 'UAC is turned off: every program runs with full admin rights without asking.' `
            -Recommendation 'Turn UAC back on (Control Panel > User Accounts > Change User Account Control settings) and restart.'
        return
    }
    if ($uac.ConsentPromptBehaviorAdmin -eq 0) {
        Add-MSPFinding -Check 'User Account Control' -Category 'UAC' -Status FAIL -Severity High -Evidence $evidence `
            -Detail 'UAC is set to "Never notify": admin programs elevate silently.' `
            -Recommendation 'Set UAC to the default level ("Notify me only when apps try to make changes").'
    }
    elseif ($uac.PromptOnSecureDesktop -eq 0) {
        Add-MSPFinding -Check 'User Account Control' -Category 'UAC' -Status WARN -Severity Low -Evidence $evidence `
            -Detail 'UAC prompts, but not on the secure desktop (screen does not dim).' `
            -Recommendation 'Use the default UAC level so prompts appear on the secure desktop.'
    }
    else {
        Add-MSPFinding -Check 'User Account Control' -Category 'UAC' -Status PASS -Detail 'On and prompting' -Evidence $evidence
    }
}

# =========================================================================================
Write-MSPSection -Title 'SMBv1'
# =========================================================================================
Invoke-MSPCheck -Name 'SMBv1 protocol' -Category 'SMBv1' -ScriptBlock {
    $recommendation = 'Remove SMB 1.0/CIFS File Sharing Support (Turn Windows features on or off). Only very old NAS/printers need it; replace or update those instead.'
    if ($script:MSPRun.IsAdmin) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        $state = [string]$feature.State
        if ($state -eq 'Enabled') {
            Add-MSPFinding -Check 'SMBv1 protocol' -Category 'SMBv1' -Status FAIL -Severity High -Detail 'SMB 1.0 feature is installed (WannaCry-era protocol).' -Recommendation $recommendation -Evidence @{ FeatureState = $state }
        }
        else {
            Add-MSPFinding -Check 'SMBv1 protocol' -Category 'SMBv1' -Status PASS -Detail ('SMB 1.0 feature state: {0}' -f $state) -Evidence @{ FeatureState = $state }
        }
        return
    }
    # Non-admin: the SMB1 client (mrxsmb10) and server (srv) drivers only exist when the
    # feature is installed; Start = 4 means the driver is disabled.
    $client = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -ErrorAction SilentlyContinue
    $server = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\srv' -Name Start -ErrorAction SilentlyContinue
    $clientOn = ($client -and $client.Start -ne 4)
    $serverOn = ($server -and $server.Start -ne 4)
    $evidence = @{ ClientDriverStart = [string]$client.Start; ServerDriverStart = [string]$server.Start; Method = 'Driver registry keys (non-admin)' }
    if ($clientOn -or $serverOn) {
        $parts = @()
        if ($clientOn) { $parts += 'client' }
        if ($serverOn) { $parts += 'server' }
        Add-MSPFinding -Check 'SMBv1 protocol' -Category 'SMBv1' -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('SMB 1.0 {0} driver is installed and enabled (detected from the registry).' -f ($parts -join ' and ')) -Recommendation $recommendation
    }
    else {
        Add-MSPFinding -Check 'SMBv1 protocol' -Category 'SMBv1' -Status PASS -Evidence $evidence `
            -Detail 'SMB 1.0 drivers are not installed or are disabled (registry check; run as administrator to confirm via Windows Features).'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Secure Boot and TPM'
# =========================================================================================
Invoke-MSPCheck -Name 'Secure Boot' -Category 'Boot' -ScriptBlock {
    # This registry value is readable without admin and matches Confirm-SecureBootUEFI.
    $state = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
    if ($null -eq $state) {
        Add-MSPFinding -Check 'Secure Boot' -Category 'Boot' -Status WARN -Severity Low `
            -Detail 'Secure Boot state not reported: the PC probably starts in legacy BIOS mode.' `
            -Recommendation 'Not urgent. Secure Boot needs UEFI mode; changing boot mode needs care (disk conversion) - escalate if required.'
    }
    elseif ($state.UEFISecureBootEnabled -eq 1) {
        Add-MSPFinding -Check 'Secure Boot' -Category 'Boot' -Status PASS -Detail 'On'
    }
    else {
        Add-MSPFinding -Check 'Secure Boot' -Category 'Boot' -Status WARN -Severity Medium `
            -Detail 'Supported (UEFI) but turned off.' `
            -Recommendation 'Turn Secure Boot on in the UEFI/BIOS setup; it blocks boot-level malware.'
    }
}

Invoke-MSPCheck -Name 'TPM' -Category 'Boot' -RequiresAdmin -AdminReason 'Windows only reports TPM status to administrators.' -ScriptBlock {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent -and $tpm.TpmReady) {
        Add-MSPFinding -Check 'TPM' -Category 'Boot' -Status PASS -Detail 'Present and ready'
    }
    elseif ($tpm.TpmPresent) {
        Add-MSPFinding -Check 'TPM' -Category 'Boot' -Status WARN -Severity Low -Detail 'Present but not ready for use.' `
            -Recommendation 'Initialize the TPM (tpm.msc) if BitLocker or Windows Hello needs it.'
    }
    else {
        Add-MSPFinding -Check 'TPM' -Category 'Boot' -Status WARN -Severity Low -Detail 'No TPM detected (or disabled in firmware).' `
            -Recommendation 'Check the UEFI/BIOS setup for TPM / PTT / fTPM.'
    }
}

# =========================================================================================
Write-MSPSection -Title 'Remote Desktop'
# =========================================================================================
Invoke-MSPCheck -Name 'Remote Desktop' -Category 'Remote access' -ScriptBlock {
    if ($isHomeEdition) {
        Add-MSPFinding -Check 'Remote Desktop' -Category 'Remote access' -Status INFO -Detail 'Windows Home cannot accept Remote Desktop connections.'
        return
    }
    $ts = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
    if ($ts.fDenyTSConnections -eq 1) {
        Add-MSPFinding -Check 'Remote Desktop' -Category 'Remote access' -Status PASS -Detail 'Off'
        return
    }
    $rdp = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
    $evidence = @{ Port = $rdp.PortNumber; NLA = $rdp.UserAuthentication }
    if ($rdp -and $rdp.UserAuthentication -eq 0) {
        Add-MSPFinding -Check 'Remote Desktop' -Category 'Remote access' -Status FAIL -Severity High -Evidence $evidence `
            -Detail ('On WITHOUT Network Level Authentication (port {0}).' -f $rdp.PortNumber) `
            -Recommendation 'Turn Remote Desktop off if unused; otherwise require Network Level Authentication and never forward its port on the router.'
    }
    else {
        Add-MSPFinding -Check 'Remote Desktop' -Category 'Remote access' -Status WARN -Severity Medium -Evidence $evidence `
            -Detail ('On, with Network Level Authentication (port {0}).' -f $rdp.PortNumber) `
            -Recommendation 'Fine if the client uses it on purpose. Turn it off if not, and never expose it to the internet via port forwarding.'
    }
}

Complete-MSPRun -OutputPath $OutputPath
