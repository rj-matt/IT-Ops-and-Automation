<#
.SYNOPSIS
    Tests that A9 (Export-SecurityAuditReport.ps1) reports a check once when results from older
    script versions and other platforms are mixed.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux).

      1. Unit: loads Get-NormalizedFinding and its two tables from the script through the
         parser (the script is not run) and checks schema 1.0 IDs, the A1 2.2.0 check renames,
         current IDs and IDs set on purpose.
      2. End to end: writes three made-up results to a temporary folder - a schema 1.0 Windows
         A1 result, a schema 2.0 Windows A1 2.1.0 result (old check names) and a macOS A1 result
         (new names) - runs A9 on them and checks the remediation plan lists "System drive
         encryption" and "Last update scan" once each, affecting all three computers, and never
         the old names.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-ExportSecurityAuditReportIds.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-Equal / Assert-True (Name, Expected, Actual) are one-line test assertions used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$scriptPath = (Resolve-Path -LiteralPath (Join-Path $here '../security-operations/diagnostics/Export-SecurityAuditReport.ps1')).ProviderPath
$modulePath = (Resolve-Path -LiteralPath (Join-Path $here '../endpoint-systems/utilities/MSPToolkit.Common.psm1')).ProviderPath

$script:passed = 0
$script:failed = 0
function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    if ("$Expected" -ceq "$Actual") { $script:passed++ }
    else { $script:failed++; Write-Host ("FAIL: {0}`n  expected: [{1}]`n  actual:   [{2}]" -f $Name, $Expected, $Actual) -ForegroundColor Red }
}
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

# --- 1. Unit: the function and its tables, loaded without running the script ---------------
$moduleText = [System.IO.File]::ReadAllText($modulePath) -replace '(?m)^Export-ModuleMember.*$', ''
. ([scriptblock]::Create($moduleText))   # ConvertTo-MSPIdPart, as embedded in the script
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-Equal 'A9 parses' 0 $parseErrors.Count
$pieces = $ast.FindAll({
        param($n)
        ($n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-NormalizedFinding') -or
        ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Parent -eq $ast.EndBlock -and
        $n.Left.Extent.Text -in @('$scriptCheckIds', '$renamedChecks'))
    }, $true)
Assert-Equal 'function and both tables found' 3 @($pieces).Count
foreach ($p in $pieces) { . ([scriptblock]::Create($p.Extent.Text)) }

function Get-Case {
    param([string]$Id, [string]$Category, [string]$Check, [string]$ScriptName, [string]$CheckId = '')
    return (Get-NormalizedFinding -Id $Id -Category $Category -Check $Check -ScriptName $ScriptName -CheckId $CheckId)
}
$r = Get-Case 'Get-EndpointSecurityStatus:Encryption:Windows-drive-encryption' 'Encryption' 'Windows drive encryption' 'Get-EndpointSecurityStatus'
Assert-Equal 'schema 1.0 + renamed check: ID' 'A1.Encryption.System-drive-encryption' $r.Id
Assert-Equal 'schema 1.0 + renamed check: name' 'System drive encryption' $r.Check
$r = Get-Case 'A1.Updates.Windows-Update-last-scan' 'Updates' 'Windows Update last scan' 'Get-EndpointSecurityStatus' 'A1'
Assert-Equal 'schema 2.0, A1 2.1.0 name: ID' 'A1.Updates.Last-update-scan' $r.Id
Assert-Equal 'schema 2.0, A1 2.1.0 name: name' 'Last update scan' $r.Check
$r = Get-Case 'A1.Encryption.System-drive-encryption' 'Encryption' 'System drive encryption' 'get-endpoint-security-status-macos' 'A1'
Assert-Equal 'current macOS result: ID unchanged' 'A1.Encryption.System-drive-encryption' $r.Id
Assert-True 'current result: not counted as changed' (-not $r.Changed)
$r = Get-Case 'Get-OpenPortScan:LocalPorts:Port-3389-Remote-Desktop' 'LocalPorts' 'Port 3389 Remote Desktop' 'Get-OpenPortScan'
Assert-Equal 'schema 1.0, other script: 2.0 ID' 'A4.LocalPorts.Port-3389-Remote-Desktop' $r.Id
$r = Get-Case 'Get-EndpointSecurityStatus:Remote-access:Remote-Desktop' 'Remote access' 'Remote Desktop' 'Get-EndpointSecurityStatus'
Assert-Equal 'schema 1.0, category with a space' 'A1.Remote-access.Remote-Desktop' $r.Id
$r = Get-Case 'A2.Unidentified.AA-BB-CC-00-11-22' 'Discovery' 'Unidentified device' 'Get-HomeNetworkMap' 'A2'
Assert-Equal 'ID set on purpose is kept' 'A2.Unidentified.AA-BB-CC-00-11-22' $r.Id
$r = Get-Case 'Get-HomeNetworkMap:Discovery:Devices-found' 'Discovery' 'Devices found' 'Get-HomeNetworkMap'
Assert-Equal 'schema 1.0 A2' 'A2.Discovery.Devices-found' $r.Id
$r = Get-Case 'Some-Other-Tool:X:Y' 'X' 'Y' 'Some-Other-Tool'
Assert-Equal 'unknown script without CheckId: kept' 'Some-Other-Tool:X:Y' $r.Id
$r = Get-Case 'A1.Encryption.Windows-drive-encryption' 'Encryption' 'Windows drive encryption' 'Get-EndpointSecurityStatus' 'A1'
Assert-Equal 'renamed check, 2.0 ID' 'A1.Encryption.System-drive-encryption' $r.Id

# --- 2. End to end: three result versions, one report --------------------------------------
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-a9-ids-{0}' -f [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force
function Get-FakeFinding {
    param([string]$Id, [string]$Category, [string]$Check, [string]$Status, [string]$Severity, [string]$Target)
    return [ordered]@{ Id = $Id; Category = $Category; Check = $Check; Status = $Status; Severity = $Severity; Target = $Target; Detail = 'test'; Recommendation = 'Fix it.'; Evidence = $null }
}
function Write-Result {
    param([string]$Name, $Object)
    [System.IO.File]::WriteAllText((Join-Path $work $Name), ($Object | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
}
$summary = [ordered]@{ PASS = 0; WARN = 1; FAIL = 1; INFO = 0; SKIPPED = 0; ERROR = 0 }
# Schema 1.0, Windows, A1 1.x naming.
Write-Result 'old10.json' ([ordered]@{
        SchemaVersion = '1.0'; ScriptName = 'Get-EndpointSecurityStatus'; ScriptVersion = '2.0.0'; RiskLevel = 'Read-Only'
        Computer = 'TEST-PC1'; User = 'TEST\user'; IsAdmin = $false; PSVersion = '5.1'
        StartTime = '2026-01-10T10:00:00+00:00'; EndTime = '2026-01-10T10:00:30+00:00'; Parameters = @{}; Summary = $summary
        Findings = @(
            (Get-FakeFinding 'Get-EndpointSecurityStatus:Encryption:Windows-drive-encryption' 'Encryption' 'Windows drive encryption' 'FAIL' 'High' 'TEST-PC1'),
            (Get-FakeFinding 'Get-EndpointSecurityStatus:Updates:Windows-Update-last-scan' 'Updates' 'Windows Update last scan' 'WARN' 'Medium' 'TEST-PC1'))
        Data = @{}
    })
# Schema 2.0, Windows, A1 2.1.0 (old names, new ID format).
Write-Result 'old20.json' ([ordered]@{
        SchemaVersion = '2.0'; CheckId = 'A1'; ScriptName = 'Get-EndpointSecurityStatus'; Version = '2.1.0'; Platform = 'Windows'
        OSVersion = 'Windows 11 Pro'; Shell = 'Windows PowerShell 5.1'; Host = 'TEST-PC2'; User = 'TEST\user'; IsAdmin = $false; RiskLevel = 'Read-Only'
        Parameters = @{}; Timestamp = '2026-10-01T10:00:00+00:00'; EndTime = '2026-10-01T10:00:30+00:00'; Summary = $summary
        Findings = @(
            (Get-FakeFinding 'A1.Encryption.Windows-drive-encryption' 'Encryption' 'Windows drive encryption' 'FAIL' 'High' 'TEST-PC2'),
            (Get-FakeFinding 'A1.Updates.Windows-Update-last-scan' 'Updates' 'Windows Update last scan' 'WARN' 'Medium' 'TEST-PC2'))
        Data = @{}
    })
# Schema 2.0, macOS, current names.
Write-Result 'mac.json' ([ordered]@{
        SchemaVersion = '2.0'; CheckId = 'A1'; ScriptName = 'get-endpoint-security-status-macos'; Version = '1.0.0'; Platform = 'macOS'
        OSVersion = 'macOS 15.1'; Shell = 'bash 3.2.57'; Host = 'TEST-MAC'; User = 'user'; IsAdmin = $false; RiskLevel = 'Read-Only'
        Parameters = @{}; Timestamp = '2026-10-16T10:00:00+00:00'; EndTime = '2026-10-16T10:00:30+00:00'; Summary = $summary
        Findings = @(
            (Get-FakeFinding 'A1.Encryption.System-drive-encryption' 'Encryption' 'System drive encryption' 'FAIL' 'High' 'TEST-MAC'),
            (Get-FakeFinding 'A1.Updates.Last-update-scan' 'Updates' 'Last update scan' 'WARN' 'Medium' 'TEST-MAC'))
        Data = @{}
    })

try {
    $report = Join-Path $work 'report.html'
    $psExe = (Get-Process -Id $PID).Path
    $console = (& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptPath -InputPath $work -TechnicianName 'Test' -ReportPath $report 2>&1 | Out-String)
    Assert-Equal 'A9 exit code' 0 $LASTEXITCODE
    Assert-True 'report written' (Test-Path -LiteralPath $report)
    $html = [System.IO.File]::ReadAllText($report)
    $plan = $html.Substring($html.IndexOf('id="plan"'), $html.IndexOf('id="coverage"') - $html.IndexOf('id="plan"'))
    Assert-Equal 'plan: "System drive encryption" listed once' 1 ([regex]::Matches($plan, '<b>System drive encryption</b>')).Count
    Assert-Equal 'plan: "Last update scan" listed once' 1 ([regex]::Matches($plan, '<b>Last update scan</b>')).Count
    Assert-Equal 'plan: old encryption name gone' 0 ([regex]::Matches($plan, 'Windows drive encryption')).Count
    Assert-Equal 'plan: old update name gone' 0 ([regex]::Matches($plan, 'Windows Update last scan')).Count
    $affects = [regex]::Match($plan, '<b>System drive encryption</b>(?s:.*?)Affects: ([^<]*)<').Groups[1].Value
    foreach ($c in 'TEST-PC1', 'TEST-PC2', 'TEST-MAC') { Assert-True ('encryption item affects {0}' -f $c) ($affects -like ('*{0}*' -f $c)) $affects }
    Assert-True 'A9 notes that older results were matched (4 findings)' ($console -match 'Older result formats - 4 finding\(s\)') 'not in console output'
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
