<#
.SYNOPSIS
    Unit tests for MSPToolkit.Common.psm1 (development side only).

.DESCRIPTION
    Imports the module and checks schema 2.0 output, finding IDs, SKIPPED/ERROR handling and
    the local-subnet picker. Network cmdlets are replaced with fakes (global functions take
    precedence over cmdlets), so no traffic is sent and no real adapter is needed - this is how
    the "only a VPN has a gateway" case is tested.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-MSPToolkitCommon.ps1
    pwsh -NoProfile -File tests/Test-MSPToolkitCommon.ps1          (macOS / Linux)

.NOTES
    Risk Level    : Safe -- writes a log under the toolkit log folder and a temporary export folder
    Prerequisites : Windows PowerShell 5.1, or PowerShell 7 on Windows, macOS or Linux | Admin: No
                    (the network cmdlets are faked, so the subnet tests also run off Windows)
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-True (Name, Condition, Detail) is a one-line test assertion used throughout.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Fake network cmdlets must be global functions to shadow the real cmdlets; they are removed at the end.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Fake cmdlets declare the real cmdlets'' parameters so calls bind; most are deliberately ignored.')]
[CmdletBinding()]
param()

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
# Load the helpers the way scripts embed them: in this script's own scope. Dynamic scoping of
# $ErrorActionPreference inside Invoke-MSPCheck depends on that, as it does in real scripts.
$modulePath = (Resolve-Path -LiteralPath (Join-Path $here '../endpoint-systems/utilities/MSPToolkit.Common.psm1')).ProviderPath
$moduleText = [System.IO.File]::ReadAllText($modulePath)
# Export-ModuleMember only works inside a real module; scripts never contain it.
. ([scriptblock]::Create(($moduleText -replace '(?m)^Export-ModuleMember.*$', '')))

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}



function Get-Run { return $script:MSPRun }
# Child sessions use the same PowerShell as this test (powershell.exe on 5.1, pwsh on 7).
$psExe = (Get-Process -Id $PID).Path
$onWindows = ($PSVersionTable.PSEdition -ne 'Core') -or $IsWindows

# --- Run setup and result object ---------------------------------------------------------
$null = Initialize-MSPRun -ScriptName 'Test-MSPToolkitCommon' -ScriptVersion '1.0.0' -CheckId 'T2' -RiskLevel 'Read-Only' `
    -Parameters @{ Switch = [switch]$true; List = @('a', 'b') } -AdminSections 'TPM' 6>$null
$run = Get-Run
if ($onWindows) {
    Assert-True 'platform is Windows' ($run.Platform -eq 'Windows') $run.Platform
    Assert-True 'OS version mentions Windows' ($run.OSVersion -like 'Windows*') $run.OSVersion
    Assert-True 'log under %TEMP%\MSP-Toolkit' ($run.LogPath -like (Join-Path $env:TEMP 'MSP-Toolkit\Test-MSPToolkitCommon_*')) $run.LogPath
}
elseif ($IsMacOS) {
    Assert-True 'platform is macOS' ($run.Platform -eq 'macOS') $run.Platform
    Assert-True 'OS version like the bash helper (macOS x.y)' ($run.OSVersion -match '^macOS \d+(\.\d+)*$') $run.OSVersion
}
else {
    Assert-True 'platform is Linux' ($run.Platform -eq 'Linux') $run.Platform
}
if (-not $onWindows) {
    $base = $env:TMPDIR
    if (-not $base) { $base = '/tmp' }
    Assert-True 'log under ${TMPDIR:-/tmp}/msp-toolkit (same as bash)' ($run.LogPath -like (Join-Path $base 'msp-toolkit/Test-MSPToolkitCommon_*')) $run.LogPath
}
Assert-True 'shell names PowerShell' ($run.Shell -like '*PowerShell*') $run.Shell
Assert-True 'host is short name' ($run.Host -notmatch '\.') $run.Host
Assert-True 'switch parameter stored as text' ($run.Parameters['Switch'] -eq 'True') $run.Parameters['Switch']
Assert-True 'array parameter joined' ($run.Parameters['List'] -eq 'a, b') $run.Parameters['List']

Add-MSPFinding -Check 'Remote-access tool: Kaseya' -Category 'Software' -Status INFO -NoConsole
Add-MSPFinding -Check 'Explicit' -Category 'X' -Status WARN -Id 'T2.Custom.Key' -NoConsole
$ids = @((Get-Run).Findings.ToArray() | ForEach-Object { $_.Id })
Assert-True 'generated ID format' ($ids -contains 'T2.Software.Remote-access-tool-Kaseya') ($ids -join ', ')
Assert-True 'explicit ID kept' ($ids -contains 'T2.Custom.Key')
Assert-True 'WARN default severity Medium' (((Get-Run).Findings | Where-Object Check -eq 'Explicit').Severity -eq 'Medium')
Assert-True 'ID part: empty becomes General' ((ConvertTo-MSPIdPart -Text '!!') -eq 'General')

# --- Invoke-MSPCheck: ERROR vs SKIPPED ---------------------------------------------------
Invoke-MSPCheck -Name 'Throws' -Category 'C' -ScriptBlock { throw 'boom' } 6>$null
Invoke-MSPCheck -Name 'Skips' -Category 'C' -ScriptBlock { Skip-MSPCheck -Reason 'Not here' -Recommendation 'Do X' } 6>$null
Invoke-MSPCheck -Name 'Cmdlet error' -Category 'C' -ScriptBlock { Get-Item -LiteralPath 'C:\definitely\not\here' } 6>$null
$f = (Get-Run).Findings.ToArray()
$throws = $f | Where-Object Check -eq 'Throws'
$skips = $f | Where-Object Check -eq 'Skips'
$cmdlet = $f | Where-Object Check -eq 'Cmdlet error'
Assert-True 'thrown error -> ERROR' ($throws.Status -eq 'ERROR') $throws.Status
Assert-True 'Skip-MSPCheck -> SKIPPED' ($skips.Status -eq 'SKIPPED' -and $skips.Detail -eq 'Not here' -and $skips.Recommendation -eq 'Do X') ('{0} {1}' -f $skips.Status, $skips.Detail)
Assert-True 'non-terminating cmdlet error -> ERROR' ($cmdlet.Status -eq 'ERROR') $cmdlet.Status

# --- Result object and export ------------------------------------------------------------
$result = Get-MSPResultObject
$keys = @($result.Keys)
$expected = @('SchemaVersion', 'CheckId', 'ScriptName', 'Version', 'Platform', 'OSVersion', 'Shell', 'Host', 'User', 'IsAdmin', 'RiskLevel', 'Parameters', 'Timestamp', 'EndTime', 'Summary', 'Findings', 'Data')
Assert-True 'result fields and order' (($keys -join ',') -eq ($expected -join ',')) ($keys -join ',')
Assert-True 'schema 2.0' ($result.SchemaVersion -eq '2.0')
Assert-True 'timestamp ISO with offset' ($result.Timestamp -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$') $result.Timestamp
Add-MSPData -Name 'Rows' -Rows @([pscustomobject]@{ A = 1; B = 'x' })
$out = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-common-test-{0}' -f $PID)
$null = Export-MSPResult -OutputPath $out 6>$null
$json = @(Get-ChildItem -LiteralPath $out -Filter '*.json')
Assert-True 'export wrote JSON' ($json.Count -eq 1)
$csvHeader = (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out -Filter '*_findings.csv').FullName -TotalCount 1)
Assert-True 'findings CSV header matches bash' ($csvHeader -eq '"CheckId","ScriptName","Platform","Host","Timestamp","Id","Category","Check","Status","Severity","Target","Detail","Recommendation"') $csvHeader
$validator = Join-Path $here 'Test-MSPResultSchema.ps1'
$null = & $psExe -NoProfile -ExecutionPolicy Bypass -File $validator -Path $out
Assert-True 'export passes schema validation' ($LASTEXITCODE -eq 0)
Remove-Item -LiteralPath $out -Recurse -Force

# --- Local subnet picker with fake network cmdlets ---------------------------------------
function global:Get-NetIPInterface { param($InterfaceIndex, $AddressFamily, $ErrorAction) [pscustomobject]@{ InterfaceMetric = 10 } }
function global:Get-DnsClientServerAddress { param($InterfaceIndex, $ErrorAction) [pscustomobject]@{ ServerAddresses = @('192.168.1.1') } }
function global:Get-NetIPAddress {
    param($InterfaceIndex, $AddressFamily, $ErrorAction)
    switch ($InterfaceIndex) {
        1 { [pscustomobject]@{ IPAddress = '192.168.1.50'; PrefixLength = 24 } }
        2 { [pscustomobject]@{ IPAddress = '10.8.0.5'; PrefixLength = 24 } }
    }
}
function global:Get-NetAdapter {
    param($InterfaceIndex, $ErrorAction)
    switch ($InterfaceIndex) {
        1 { [pscustomobject]@{ Name = 'Wi-Fi'; InterfaceDescription = 'Intel Wi-Fi 6'; Status = 'Up'; ifIndex = 1; MacAddress = 'AA-BB-CC-DD-EE-01' } }
        2 { [pscustomobject]@{ Name = 'VPN'; InterfaceDescription = 'WireGuard Tunnel'; Status = 'Up'; ifIndex = 2; MacAddress = '' } }
    }
}
# Both adapters have a default route; the VPN's metric is lower (it would win on metric alone).
$global:FakeRoutes = @(
    [pscustomobject]@{ NextHop = '10.8.0.1'; InterfaceIndex = 2; RouteMetric = 0 },
    [pscustomobject]@{ NextHop = '192.168.1.1'; InterfaceIndex = 1; RouteMetric = 25 }
)
function global:Get-NetRoute { param($AddressFamily, $DestinationPrefix, $ErrorAction) $global:FakeRoutes }

$subnet = Get-MSPLocalSubnet
Assert-True 'physical adapter chosen over lower-metric VPN' ($subnet.InterfaceAlias -eq 'Wi-Fi' -and $subnet.Cidr -eq '192.168.1.0/24') ('{0} {1}' -f $subnet.InterfaceAlias, $subnet.Cidr)
Assert-True 'host count /24' ($subnet.HostCount -eq 254)

$global:FakeRoutes = @([pscustomobject]@{ NextHop = '10.8.0.1'; InterfaceIndex = 2; RouteMetric = 0 })
$before = (Get-Run).Findings.ToArray().Count
Invoke-MSPCheck -Name 'Local subnet' -Category 'Scope' -ScriptBlock { $script:vpnSubnet = Get-MSPLocalSubnet } 6>$null
$last = (Get-Run).Findings.ToArray()[-1]
Assert-True 'VPN-only -> SKIPPED, nothing scanned' ($last.Status -eq 'SKIPPED' -and $last.Detail -like '*VPN or virtual adapter*' -and (Get-Run).Findings.ToArray().Count -eq $before + 1) ('{0}: {1}' -f $last.Status, $last.Detail)

$global:FakeRoutes = @()
Invoke-MSPCheck -Name 'No gateway' -Category 'Scope' -ScriptBlock { $null = Get-MSPLocalSubnet } 6>$null
$last = (Get-Run).Findings.ToArray()[-1]
Assert-True 'no gateway -> ERROR with plain reason' ($last.Status -eq 'ERROR' -and $last.Detail -like '*default gateway*') ('{0}: {1}' -f $last.Status, $last.Detail)

foreach ($name in 'Get-NetRoute', 'Get-NetAdapter', 'Get-NetIPAddress', 'Get-NetIPInterface', 'Get-DnsClientServerAddress') { Remove-Item -Path ('function:global:{0}' -f $name) }

# --- Confirmation for state changes (Change section) -------------------------------------
# Each case runs in a child PowerShell of the same version so the session type is controlled exactly.
$childTemplate = @'
$t = [System.IO.File]::ReadAllText('{0}') -replace '(?m)^Export-ModuleMember.*$', ''
. ([scriptblock]::Create($t))
$null = Initialize-MSPRun -ScriptName 'confirm-test' -ScriptVersion '1.0.0' -CheckId 'T3' -RiskLevel 'Safe' 6>$null
$ok = Confirm-MSPChange -Question 'Test?' {1} 6>$null
$f = $MSPRun.Findings.ToArray()[-1]
'RESULT={{0}}|{{1}}|{{2}}' -f $ok, $f.Status, (Test-MSPInteractive)
'@
$nonInteractive = & $psExe -NoProfile -NonInteractive -Command ($childTemplate -f $modulePath, '') 2>&1 | Where-Object { "$_" -like 'RESULT=*' }
Assert-True 'confirm refuses a -NonInteractive session' ($nonInteractive -eq 'RESULT=False|SKIPPED|False') "$nonInteractive"
$piped = 'YES' | & $psExe -NoProfile -Command ($childTemplate -f $modulePath, '') 2>&1 | Where-Object { "$_" -like 'RESULT=*' }
Assert-True 'confirm ignores YES piped into the session' ($piped -eq 'RESULT=False|SKIPPED|False') "$piped"
$forced = & $psExe -NoProfile -NonInteractive -Command ($childTemplate -f $modulePath, '-Force') 2>&1 | Where-Object { "$_" -like 'RESULT=*' }
Assert-True 'confirm with -Force proceeds and is recorded' ($forced -eq 'RESULT=True|INFO|False') "$forced"

# --- Runspace pool cap -------------------------------------------------------------------
$capped = $false
try { $null = Invoke-MSPRunspacePool -InputObject @(1) -ScriptBlock { $args[0] } -ThrottleLimit 33 }
catch { $capped = $true }
Assert-True 'runspace pool refuses more than 32' $capped
$items = Invoke-MSPRunspacePool -InputObject @(1..10) -ScriptBlock { param($n) $n * 2 } -ThrottleLimit 4 -Activity 'test'
Assert-True 'runspace pool returns all results' (@($items).Count -eq 10 -and (($items | Measure-Object -Sum).Sum -eq 110))

Write-Host ''
Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
