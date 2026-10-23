<#
.SYNOPSIS
    Read-only Microsoft 365 license report for one or more users (or every licensed user):
    licenses, service plan problems, account state, last sign-in, and the tenant's
    subscriptions.

.DESCRIPTION
    Uses Microsoft Graph with read-only delegated scopes and only Get- cmdlets. Nothing in the
    tenant is changed.

    Checks (per user; Target = the user's UPN)
      Account enabled     A disabled account that still holds licenses = WARN (paid seat unused).
      Licenses            Assigned licenses by name and part number. No license = WARN for a
                          named user (no mailbox, no Office apps).
      Service plans       Plans in an error or pending state = WARN; plans switched off by the
                          admin are listed (INFO). Every plan with -IncludeServicePlans.
      Last sign-in        Newest of interactive and successful sign-in. More than -StaleDays
                          (default 90) with licenses = WARN; never signed in = INFO. Needs an
                          Entra ID P1 or P2 license in the tenant; without one it is SKIPPED.
    Checks (tenant)
      Subscriptions       Each subscription's seats used / bought. Seats over-assigned or a
                          subscription in the Warning (expired, in grace) or Suspended state =
                          WARN / FAIL. Users who hold a license from a lapsed subscription
                          lose access when it is disabled.

    Sign-in: uses an existing Microsoft Graph connection when there is one. Otherwise it signs
    in (browser, or -DeviceCode for a code to type on another device) with only these scopes:
      User.Read.All          read users and their assigned licenses
      Organization.Read.All  read the tenant's subscriptions (subscribedSkus)
      AuditLog.Read.All      read sign-in activity (last sign-in)
    The token is kept for this PowerShell process only (-ContextScope Process) and the
    connection is closed at the end unless -KeepConnection is given.

.PARAMETER UserPrincipalName
    One or more users to report on (comma separated or an array).

.PARAMETER All
    Every user who holds at least one license. Can take minutes in large tenants.

.PARAMETER IncludeServicePlans
    Also list every service plan of every license (ServicePlans table).

.PARAMETER StaleDays
    Licensed users without a sign-in for this many days are flagged (30-365, default 90).

.PARAMETER DeviceCode
    Sign in with a device code (works over SSH and on computers without a browser).

.PARAMETER KeepConnection
    Leave the Microsoft Graph connection open at the end.

.PARAMETER OutputPath
    Optional folder for JSON/CSV results (toolkit schema 2.0) with Users, Licenses,
    Subscriptions (and ServicePlans) tables.

.EXAMPLE
    pwsh -File .\Get-UserLicenseReport.ps1 -UserPrincipalName alice@contoso.com

.EXAMPLE
    pwsh -File .\Get-UserLicenseReport.ps1 -All -OutputPath ~/Desktop/LicenseAudit -DeviceCode

.NOTES
    Purpose       : Answer "what is this user licensed for, and is any of it broken or wasted?"
    Use Case      : Access problems after onboarding, departed users still holding paid licenses,
                    monthly license reconciliation.
    Scope         : The signed-in admin's Microsoft 365 tenant, read through Microsoft Graph.
                    Nothing on this computer is read or changed.
    Risk Level    : Read-Only -- read-only Graph scopes, Get- cmdlets only.
    Prerequisites : PowerShell 7 (Windows, macOS, Linux) | Modules: Microsoft.Graph.Authentication,
                    Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement
                    (Install-Module Microsoft.Graph -Scope CurrentUser) | Account: Global Reader
                    (or User Administrator plus Reports Reader for sign-in data). An admin must
                    consent to the three scopes once per tenant.
    Version       : 2.0.0
    Limitations   : Last sign-in needs Entra ID P1/P2 in the tenant and can lag by hours.
                    Friendly license names cover common SKUs only; the part number is always
                    shown. Group-based licensing is reported as assigned, not by group.
#>
#Requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Users')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Users')][string[]]$UserPrincipalName,
    [Parameter(Mandatory, ParameterSetName = 'All')][switch]$All,
    [switch]$IncludeServicePlans,
    [ValidateRange(30, 365)][int]$StaleDays = 90,
    [switch]$DeviceCode,
    [switch]$KeepConnection,
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

$ScriptVersion = '2.0.0'
Initialize-MSPRun -ScriptName 'Get-UserLicenseReport' -ScriptVersion $ScriptVersion -CheckId 'C2' -RiskLevel 'Read-Only' `
    -Parameters $PSBoundParameters -Description 'Microsoft 365 licenses, service plans, sign-in and subscriptions (read-only)'

# "pwsh -File" passes a list as one "a,b" string; split so both forms work.
$UserPrincipalName = @($UserPrincipalName | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$requiredScopes = @('User.Read.All', 'Organization.Read.All', 'AuditLog.Read.All')
$now = Get-Date

# Common license part numbers (Microsoft's "Product names and service plan identifiers for
# licensing" list). Anything else is shown by its part number.
$skuNames = @{
    'O365_BUSINESS_ESSENTIALS' = 'Microsoft 365 Business Basic'
    'O365_BUSINESS_PREMIUM'    = 'Microsoft 365 Business Standard'
    'SPB'                      = 'Microsoft 365 Business Premium'
    'O365_BUSINESS'            = 'Microsoft 365 Apps for business'
    'OFFICESUBSCRIPTION'       = 'Microsoft 365 Apps for enterprise'
    'SPE_E3'                   = 'Microsoft 365 E3'
    'SPE_E5'                   = 'Microsoft 365 E5'
    'SPE_F1'                   = 'Microsoft 365 F3'
    'ENTERPRISEPACK'           = 'Office 365 E3'
    'ENTERPRISEPREMIUM'        = 'Office 365 E5'
    'STANDARDPACK'             = 'Office 365 E1'
    'EXCHANGESTANDARD'         = 'Exchange Online (Plan 1)'
    'EXCHANGEENTERPRISE'       = 'Exchange Online (Plan 2)'
    'EXCHANGEARCHIVE_ADDON'    = 'Exchange Online Archiving'
    'AAD_PREMIUM'              = 'Microsoft Entra ID P1'
    'AAD_PREMIUM_P2'           = 'Microsoft Entra ID P2'
    'INTUNE_A'                 = 'Microsoft Intune Plan 1'
    'EMS'                      = 'Enterprise Mobility + Security E3'
    'EMSPREMIUM'               = 'Enterprise Mobility + Security E5'
    'POWER_BI_STANDARD'        = 'Power BI (free)'
    'POWER_BI_PRO'             = 'Power BI Pro'
    'FLOW_FREE'                = 'Power Automate Free'
    'TEAMS_EXPLORATORY'        = 'Microsoft Teams Exploratory'
    'VISIOCLIENT'              = 'Visio Plan 2'
    'PROJECTPROFESSIONAL'      = 'Project Plan 3'
    'DEVELOPERPACK_E5'         = 'Microsoft 365 E5 Developer'
}
function Get-SkuLabel {
    <# "Microsoft 365 Business Standard (O365_BUSINESS_PREMIUM)" or the part number alone. #>
    param([string]$PartNumber)
    if ($skuNames.ContainsKey($PartNumber)) { return ('{0} ({1})' -f $skuNames[$PartNumber], $PartNumber) }
    return $PartNumber
}

function Invoke-TargetCheck {
    <#
        Invoke-MSPCheck for a check about one user or mailbox: a SKIPPED or ERROR finding it
        records gets that user as its Target (instead of this computer), like the others.
    #>
    param([string]$CheckTarget, [string]$Name, [string]$Category, [scriptblock]$ScriptBlock)
    $before = $script:MSPRun.Findings.Count
    Invoke-MSPCheck -Name $Name -Category $Category -ScriptBlock $ScriptBlock
    for ($i = $before; $i -lt $script:MSPRun.Findings.Count; $i++) {
        $f = $script:MSPRun.Findings[$i]
        if ($f.Status -in @('SKIPPED', 'ERROR') -and $f.Target -eq $script:MSPRun.Host) { $f.Target = $CheckTarget }
    }
}

function Test-AccessDenied {
    <# True for Graph's "not allowed" answers (missing role, scope or consent). #>
    param($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'Authorization_RequestDenied|Insufficient privileges|Forbidden|403|Access is denied|AccessDenied')
}

# =========================================================================================
Write-MSPSection -Title 'Microsoft Graph connection'
# =========================================================================================
$connected = $false
$weConnected = $false
$tenantId = ''
Invoke-MSPCheck -Name 'Graph connection' -Category 'Connection' -ScriptBlock {
    if (-not (Get-Command -Name Get-MgUser -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Get-MgSubscribedSku -ErrorAction SilentlyContinue)) {
        Skip-MSPCheck -Reason 'The Microsoft Graph PowerShell modules are not installed, so nothing could be read.' `
            -Recommendation 'Install them once (no admin rights needed): Install-Module Microsoft.Graph -Scope CurrentUser'
    }
    $context = Get-MgContext
    if (-not $context) {
        if (-not $DeviceCode -and -not (Test-MSPInteractive)) {
            Skip-MSPCheck -Reason 'Not signed in to Microsoft Graph, and this session cannot show a sign-in window.' `
                -Recommendation 'Run from a terminal, add -DeviceCode, or run Connect-MgGraph -Scopes User.Read.All,Organization.Read.All,AuditLog.Read.All first.'
        }
        Write-Host ('  Signing in to Microsoft Graph with read-only scopes: {0}' -f ($requiredScopes -join ', ')) -ForegroundColor Cyan
        $connectArgs = @{ Scopes = $requiredScopes; NoWelcome = $true; ContextScope = 'Process'; ErrorAction = 'Stop' }
        if ($DeviceCode) { $connectArgs['UseDeviceCode'] = $true }
        Connect-MgGraph @connectArgs
        $script:weConnected = $true
        $context = Get-MgContext
    }
    if (-not $context) { throw 'The sign-in did not complete.' }
    $script:connected = $true
    $script:tenantId = [string]$context.TenantId
    $scopes = @($context.Scopes)
    $missing = @($requiredScopes | Where-Object { $scopes -notcontains $_ })
    $writeScopes = @($scopes | Where-Object { $_ -match 'ReadWrite|\.Write' })
    $text = 'Signed in as {0} (tenant {1}); scopes: {2}.' -f $context.Account, $context.TenantId, ($scopes -join ', ')
    if ($writeScopes.Count -gt 0) { $text += ' The connection also allows changes; this script only reads.' }
    Add-MSPFinding -Check 'Graph connection' -Category 'Connection' -Status INFO -Detail $text `
        -Evidence @{ Account = [string]$context.Account; TenantId = [string]$context.TenantId; Scopes = ($scopes -join ' '); ConnectedByScript = $script:weConnected }
    if ($missing.Count -gt 0) {
        Add-MSPFinding -Check 'Graph scopes' -Category 'Connection' -Status WARN -Severity Low `
            -Detail ('The connection is missing {0}; the checks that need it are SKIPPED.' -f ($missing -join ', ')) `
            -Recommendation ('Disconnect-MgGraph, then run again so the script signs in with {0}.' -f ($requiredScopes -join ', '))
    }
}
if (-not $connected) {
    Complete-MSPRun -OutputPath $OutputPath
    exit 1
}
$scopesNow = @((Get-MgContext).Scopes)

# =========================================================================================
Write-MSPSection -Title 'Subscriptions'
# =========================================================================================
$skuById = @{}
Invoke-MSPCheck -Name 'Subscriptions' -Category 'Tenant' -ScriptBlock {
    if ($scopesNow -notcontains 'Organization.Read.All' -and $scopesNow -notcontains 'Directory.Read.All') {
        Skip-MSPCheck -Reason 'Needs the Organization.Read.All scope, which this connection does not have.'
    }
    try { $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop) }
    catch {
        if (Test-AccessDenied $_) { Skip-MSPCheck -Reason 'The signed-in account may not read subscriptions.' -Recommendation 'Sign in with a Global Reader account.' }
        throw
    }
    $rows = foreach ($s in $skus) {
        $script:skuById[[string]$s.SkuId] = $s
        $enabled = [int]$s.PrepaidUnits.Enabled
        $used = [int]$s.ConsumedUnits
        $label = Get-SkuLabel -PartNumber ([string]$s.SkuPartNumber)
        $state = [string]$s.CapabilityStatus
        $evidence = @{ SkuPartNumber = [string]$s.SkuPartNumber; Enabled = $enabled; Consumed = $used; Warning = [int]$s.PrepaidUnits.Warning; Suspended = [int]$s.PrepaidUnits.Suspended; CapabilityStatus = $state }
        $check = 'Subscription: {0}' -f $s.SkuPartNumber
        if ($state -eq 'Suspended') {
            Add-MSPFinding -Check $check -Category 'Tenant' -Status FAIL -Severity High -Evidence $evidence -Target $tenantId `
                -Detail ('{0} is suspended; {1} user(s) hold it and have lost or will lose access.' -f $label, $used) `
                -Recommendation 'Renew the subscription in the Microsoft 365 admin center (Billing > Your products), or move the users to another license.'
        }
        elseif ($state -eq 'Warning') {
            Add-MSPFinding -Check $check -Category 'Tenant' -Status WARN -Severity High -Evidence $evidence -Target $tenantId `
                -Detail ('{0} has expired and is in its grace period; {1} user(s) hold it.' -f $label, $used) `
                -Recommendation 'Renew it before the grace period ends (Billing > Your products).'
        }
        elseif ($used -gt $enabled -and $enabled -gt 0) {
            Add-MSPFinding -Check $check -Category 'Tenant' -Status WARN -Severity Medium -Evidence $evidence -Target $tenantId `
                -Detail ('{0}: {1} assigned but only {2} bought.' -f $label, $used, $enabled) `
                -Recommendation 'Buy more seats or remove the license from users who do not need it.'
        }
        else {
            Add-MSPFinding -Check $check -Category 'Tenant' -Status INFO -Evidence $evidence -Target $tenantId -NoConsole:$All `
                -Detail ('{0}: {1} of {2} used ({3}).' -f $label, $used, $enabled, $state)
        }
        [pscustomobject]@{ SkuPartNumber = [string]$s.SkuPartNumber; Name = $label; Status = $state; Enabled = $enabled; Consumed = $used; Available = ($enabled - $used) }
    }
    Add-MSPData -Name 'Subscriptions' -Rows @($rows)
}

# =========================================================================================
Write-MSPSection -Title 'Users'
# =========================================================================================
$baseProps = 'id', 'displayName', 'userPrincipalName', 'accountEnabled', 'assignedLicenses', 'userType', 'createdDateTime'
$signInOk = $scopesNow -contains 'AuditLog.Read.All'
$signInReason = 'Needs the AuditLog.Read.All scope, which this connection does not have.'
$users = @()
Invoke-MSPCheck -Name 'Read users' -Category 'Input' -ScriptBlock {
    function Read-User {
        param([bool]$WithSignIn)
        $props = $baseProps
        if ($WithSignIn) { $props = $baseProps + 'signInActivity' }
        if ($All) {
            return @(Get-MgUser -All -Filter 'assignedLicenses/$count ne 0' -ConsistencyLevel eventual -CountVariable licensedCount -Property $props -ErrorAction Stop)
        }
        return @(foreach ($upn in $UserPrincipalName) {
                try { Get-MgUser -UserId $upn -Property $props -ErrorAction Stop }
                catch {
                    if ([string]$_.Exception.Message -match 'Request_ResourceNotFound|does not exist|NotFound|404') {
                        Add-MSPFinding -Check 'User found' -Category 'Input' -Target $upn -Status FAIL -Severity Medium `
                            -Detail ('No user {0} in this tenant.' -f $upn) -Recommendation 'Check the spelling of the address, or whether the account was deleted (Entra ID > Deleted users).'
                    }
                    else { throw }
                }
            })
    }
    try { $script:users = Read-User -WithSignIn $signInOk }
    catch {
        # Tenants without Entra ID P1/P2 refuse signInActivity; read the rest without it.
        if ($signInOk -and [string]$_.Exception.Message -match 'NonPremiumTenant|premium|P1|signInActivity') {
            $script:signInOk = $false
            $script:signInReason = 'Sign-in activity needs an Entra ID P1 or P2 license in the tenant, which it does not have.'
            $script:users = Read-User -WithSignIn $false
        }
        elseif (Test-AccessDenied $_) {
            Skip-MSPCheck -Reason 'The signed-in account may not read users.' -Recommendation 'Sign in with a Global Reader account.'
        }
        else { throw }
    }
    Add-MSPFinding -Check 'Users read' -Category 'Input' -Status INFO -Detail ('{0} user(s) to report.' -f @($script:users).Count)
}

$userRows = New-Object System.Collections.Generic.List[object]
$licenseRows = New-Object System.Collections.Generic.List[object]
$planRows = New-Object System.Collections.Generic.List[object]
foreach ($u in @($users)) {
    $upn = [string]$u.UserPrincipalName
    $licenses = @($u.AssignedLicenses)
    $quiet = [bool]$All
    $labels = @(foreach ($l in $licenses) {
            $sku = $skuById[[string]$l.SkuId]
            if ($sku) { Get-SkuLabel -PartNumber ([string]$sku.SkuPartNumber) } else { [string]$l.SkuId }
        })

    Invoke-TargetCheck -CheckTarget $upn -Name 'Account enabled' -Category 'Account' -ScriptBlock {
        if ($u.AccountEnabled) {
            Add-MSPFinding -Check 'Account enabled' -Category 'Account' -Target $upn -Status PASS -Detail 'Sign-in allowed.' -NoConsole:$quiet
        }
        elseif ($licenses.Count -gt 0) {
            Add-MSPFinding -Check 'Account enabled' -Category 'Account' -Target $upn -Status WARN -Severity Medium `
                -Detail ('Sign-in is blocked but the account still holds {0} license(s): {1}.' -f $licenses.Count, ($labels -join ', ')) `
                -Recommendation 'If the person has left, convert the mailbox to a shared mailbox if it is still needed, then remove the licenses (admin center > Users > Active users > Licenses and apps).'
        }
        else {
            Add-MSPFinding -Check 'Account enabled' -Category 'Account' -Target $upn -Status INFO -Detail 'Sign-in is blocked; no licenses assigned.'
        }
    }

    Invoke-TargetCheck -CheckTarget $upn -Name 'Licenses' -Category 'Licenses' -ScriptBlock {
        foreach ($l in $licenses) {
            $sku = $skuById[[string]$l.SkuId]
            $part = ''
            if ($sku) { $part = [string]$sku.SkuPartNumber }
            $licenseRows.Add([pscustomobject]@{ UserPrincipalName = $upn; SkuPartNumber = $part; Name = $(if ($part) { Get-SkuLabel -PartNumber $part } else { [string]$l.SkuId }); DisabledPlans = @($l.DisabledPlans).Count })
        }
        if ($licenses.Count -eq 0) {
            Add-MSPFinding -Check 'Licenses' -Category 'Licenses' -Target $upn -Status WARN -Severity Medium -Detail 'No licenses assigned: no mailbox, OneDrive or Office apps.' `
                -Recommendation 'Assign the license the client pays for this person (admin center > Users > Active users > Licenses and apps).'
        }
        else {
            Add-MSPFinding -Check 'Licenses' -Category 'Licenses' -Target $upn -Status INFO -Detail ($labels -join '; ') -NoConsole:$quiet
        }
    }

    if ($licenses.Count -gt 0) {
        Invoke-TargetCheck -CheckTarget $upn -Name 'Service plans' -Category 'Licenses' -ScriptBlock {
            try { $details = @(Get-MgUserLicenseDetail -UserId ([string]$u.Id) -All -ErrorAction Stop) }
            catch {
                if (Test-AccessDenied $_) { Skip-MSPCheck -Reason 'The signed-in account may not read license details.' -Recommendation 'Sign in with a Global Reader account.' }
                throw
            }
            $problems = New-Object System.Collections.Generic.List[string]
            $off = New-Object System.Collections.Generic.List[string]
            foreach ($d in $details) {
                foreach ($p in @($d.ServicePlans)) {
                    $state = [string]$p.ProvisioningStatus
                    if ($state -in @('Error', 'PendingInput', 'PendingActivation', 'PendingProvisioning')) { $problems.Add(('{0}: {1} ({2})' -f $d.SkuPartNumber, $p.ServicePlanName, $state)) }
                    elseif ($state -eq 'Disabled') { $off.Add(('{0}: {1}' -f $d.SkuPartNumber, $p.ServicePlanName)) }
                    if ($IncludeServicePlans) {
                        $planRows.Add([pscustomobject]@{ UserPrincipalName = $upn; SkuPartNumber = [string]$d.SkuPartNumber; ServicePlan = [string]$p.ServicePlanName; AppliesTo = [string]$p.AppliesTo; Status = $state })
                    }
                }
            }
            if ($problems.Count -gt 0) {
                Add-MSPFinding -Check 'Service plans' -Category 'Licenses' -Target $upn -Status WARN -Severity Medium `
                    -Detail ('Not working yet or failed: {0}.' -f ($problems -join '; ')) `
                    -Recommendation 'Pending plans usually finish within an hour of assignment. If one stays in Error, remove and re-add the license, or check for a conflicting license (two Exchange plans, for example).'
            }
            elseif ($off.Count -gt 0) {
                Add-MSPFinding -Check 'Service plans' -Category 'Licenses' -Target $upn -Status INFO -NoConsole:$quiet `
                    -Detail ('All active plans are working. Switched off by an admin: {0}.' -f ($off -join '; '))
            }
            else {
                Add-MSPFinding -Check 'Service plans' -Category 'Licenses' -Target $upn -Status PASS -Detail 'Every service plan is active.' -NoConsole:$quiet
            }
        }
    }

    $lastSignIn = $null
    Invoke-TargetCheck -CheckTarget $upn -Name 'Last sign-in' -Category 'Activity' -ScriptBlock {
        if (-not $signInOk) { Skip-MSPCheck -Reason $signInReason -Recommendation 'Check sign-ins in the Entra admin center (Users > the user > Sign-in logs) instead.' }
        $activity = $u.SignInActivity
        $dates = @()
        if ($activity) { $dates = @($activity.LastSignInDateTime, $activity.LastSuccessfulSignInDateTime) | Where-Object { $_ } | ForEach-Object { [datetime]$_ } }
        if ($dates.Count -eq 0) {
            Add-MSPFinding -Check 'Last sign-in' -Category 'Activity' -Target $upn -Status INFO -NoConsole:$quiet `
                -Detail ('No sign-in recorded (account created {0}).' -f $(if ($u.CreatedDateTime) { ([datetime]$u.CreatedDateTime).ToString('yyyy-MM-dd') } else { 'on an unknown date' }))
            return
        }
        $script:lastSignIn = ($dates | Sort-Object | Select-Object -Last 1)
        $age = [int]($now - $script:lastSignIn).TotalDays
        $evidence = @{ LastSignIn = $script:lastSignIn.ToString('yyyy-MM-dd HH:mm'); DaysAgo = $age }
        if ($age -gt $StaleDays -and $licenses.Count -gt 0) {
            Add-MSPFinding -Check 'Last sign-in' -Category 'Activity' -Target $upn -Status WARN -Severity Medium -Evidence $evidence `
                -Detail ('Last sign-in {0:yyyy-MM-dd} ({1} days ago) while holding {2} license(s).' -f $script:lastSignIn, $age, $licenses.Count) `
                -Recommendation 'Confirm with the client whether this person still needs the account; if not, block sign-in and remove the licenses.'
        }
        else {
            Add-MSPFinding -Check 'Last sign-in' -Category 'Activity' -Target $upn -Status PASS -Evidence $evidence -NoConsole:$quiet `
                -Detail ('{0:yyyy-MM-dd} ({1} days ago).' -f $script:lastSignIn, $age)
        }
    }
    $userRows.Add([pscustomobject]@{
            UserPrincipalName = $upn; DisplayName = [string]$u.DisplayName; Enabled = [bool]$u.AccountEnabled; UserType = [string]$u.UserType
            Licenses = ($labels -join '; '); LastSignIn = $(if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd HH:mm') } else { '' })
        })
}
Add-MSPData -Name 'Users' -Rows $userRows.ToArray()
Add-MSPData -Name 'Licenses' -Rows $licenseRows.ToArray()
if ($IncludeServicePlans) { Add-MSPData -Name 'ServicePlans' -Rows $planRows.ToArray() }

if ($All -and $userRows.Count -gt 0) {
    Write-Host ''
    Write-Host (($userRows | Sort-Object UserPrincipalName | Format-Table UserPrincipalName, Enabled, LastSignIn, Licenses -AutoSize | Out-String -Width 200).TrimEnd())
}

if ($weConnected -and -not $KeepConnection) {
    try { $null = Disconnect-MgGraph -ErrorAction Stop; Write-MSPLog -Message 'Disconnected from Microsoft Graph.' }
    catch { Write-MSPLog -Level WARN -Message ('Disconnect-MgGraph failed: {0}' -f $_.Exception.Message) }
}
Complete-MSPRun -OutputPath $OutputPath
