<#
.SYNOPSIS
    Logic tests for D1 (Clear-WindowsUpdateCache.ps1) repeat runs, on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. Loads only the backup-naming
    functions from the script (Get-FreeBackupName, Get-CacheRenamePlan) through the PowerShell
    parser, without running the script, and calls them against mocked SoftwareDistribution /
    catroot2 folders in a temporary directory. Nothing under C:\Windows is touched, so it runs
    on macOS and Linux (pwsh) as well as Windows.

    Cases:
      - first run: <Name>.old-<stamp>
      - leftover plain SoftwareDistribution.old / catroot2.old from a manual fix: not reused
      - earlier timestamped backups: never reused or overwritten
      - same-second rerun: -2, then -3
      - a FILE with the backup name counts as taken
      - folder missing: not in the plan
      - every planned name is free before any service would be stopped, and is unique
      - the script calls the planner before its "Stopping services" section and re-checks the
        name right before Rename-Item

.EXAMPLE
    pwsh -NoProfile -File tests/Test-ClearWindowsUpdateCacheLogic.ps1

.NOTES
    Risk Level    : Safe -- creates and removes folders in a temporary directory only
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
$scriptPath = Join-Path -Path $here -ChildPath '../endpoint-systems/remediation/safe/clear-caches/Clear-WindowsUpdateCache.ps1'
$scriptPath = (Resolve-Path -LiteralPath $scriptPath).ProviderPath

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

# --- Load the two functions from the script without running it -----------------------------
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-True 'script parses' ($parseErrors.Count -eq 0) (($parseErrors | ForEach-Object { $_.Message }) -join '; ')
$wanted = @('Get-FreeBackupName', 'Get-CacheRenamePlan')
$definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wanted -contains $n.Name }, $true)
Assert-Equal 'both functions found' 2 @($definitions).Count
foreach ($d in $definitions) { . ([scriptblock]::Create($d.Extent.Text)) }

# --- Mocked folders ---------------------------------------------------------------------------
$root = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('msp-d1-test-{0}' -f [guid]::NewGuid().ToString('N'))
$windows = Join-Path $root 'Windows'
$system32 = Join-Path $windows 'System32'
$null = New-Item -ItemType Directory -Path $system32 -Force
$folders = @(
    [pscustomobject]@{ Name = 'SoftwareDistribution'; Path = (Join-Path $windows 'SoftwareDistribution') },
    [pscustomobject]@{ Name = 'catroot2'; Path = (Join-Path $system32 'catroot2') }
)
$stamp = '20261016-101010'

try {
    # Folder missing -> nothing planned.
    Assert-Equal 'no cache folders: empty plan' 0 @(Get-CacheRenamePlan -Folder $folders -Stamp $stamp).Count

    foreach ($f in $folders) { $null = New-Item -ItemType Directory -Path $f.Path -Force }

    # First run.
    $plan = @(Get-CacheRenamePlan -Folder $folders -Stamp $stamp)
    Assert-Equal 'first run: SoftwareDistribution name' 'SoftwareDistribution.old-20261016-101010' $plan[0].NewName
    Assert-Equal 'first run: catroot2 name' 'catroot2.old-20261016-101010' $plan[1].NewName

    # Leftover plain .old folders from a manual fix are not reused (and not touched).
    $null = New-Item -ItemType Directory -Path (Join-Path $windows 'SoftwareDistribution.old') -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $system32 'catroot2.old') -Force
    $marker = Join-Path $windows 'SoftwareDistribution.old/keep.txt'
    Set-Content -LiteralPath $marker -Value 'earlier backup'
    $plan = @(Get-CacheRenamePlan -Folder $folders -Stamp $stamp)
    Assert-Equal 'plain .old present: SoftwareDistribution name' 'SoftwareDistribution.old-20261016-101010' $plan[0].NewName
    Assert-Equal 'plain .old present: catroot2 name' 'catroot2.old-20261016-101010' $plan[1].NewName

    # Simulate the first run's renames, then Windows recreating fresh folders.
    foreach ($p in $plan) { Rename-Item -LiteralPath $p.Folder.Path -NewName $p.NewName }
    foreach ($f in $folders) { $null = New-Item -ItemType Directory -Path $f.Path -Force }

    # Earlier timestamped backup from another day: a new stamp gives a new name.
    $plan = @(Get-CacheRenamePlan -Folder $folders -Stamp '20261017-090000')
    Assert-Equal 'second day: new stamp' 'SoftwareDistribution.old-20261017-090000' $plan[0].NewName

    # Same-second rerun: -2, then -3.
    $plan = @(Get-CacheRenamePlan -Folder $folders -Stamp $stamp)
    Assert-Equal 'same stamp rerun: SoftwareDistribution -2' 'SoftwareDistribution.old-20261016-101010-2' $plan[0].NewName
    Assert-Equal 'same stamp rerun: catroot2 -2' 'catroot2.old-20261016-101010-2' $plan[1].NewName
    $null = New-Item -ItemType Directory -Path (Join-Path $windows 'SoftwareDistribution.old-20261016-101010-2') -Force
    Assert-Equal 'third same stamp: -3' 'SoftwareDistribution.old-20261016-101010-3' (Get-FreeBackupName -Parent $windows -Name 'SoftwareDistribution' -Stamp $stamp)

    # A file (not a folder) with the backup name also counts as taken.
    Set-Content -LiteralPath (Join-Path $system32 'catroot2.old-20261016-101010-2') -Value 'x'
    Assert-Equal 'file with the name is taken' 'catroot2.old-20261016-101010-3' (Get-FreeBackupName -Parent $system32 -Name 'catroot2' -Stamp $stamp)

    # Every planned name is free and the plan never points two folders at one name.
    $plan = @(Get-CacheRenamePlan -Folder $folders -Stamp $stamp)
    foreach ($p in $plan) {
        Assert-True ('planned name free: {0}' -f $p.NewName) (-not (Test-Path -LiteralPath (Join-Path (Split-Path $p.Folder.Path -Parent) $p.NewName)))
    }
    Assert-Equal 'planned names unique' $plan.Count @($plan | ForEach-Object { Join-Path (Split-Path $_.Folder.Path -Parent) $_.NewName } | Select-Object -Unique).Count

    # Earlier backups are untouched.
    Assert-True 'plain .old backup untouched' ((Get-Content -LiteralPath $marker) -eq 'earlier backup')
    Assert-True 'first timestamped backup still there' (Test-Path -LiteralPath (Join-Path $windows 'SoftwareDistribution.old-20261016-101010'))

    # Exhaustion throws (the script turns that into a refusal before stopping anything).
    $null = New-Item -ItemType Directory -Path (Join-Path $root 'x/Cache.old-1') -Force
    2..99 | ForEach-Object { $null = New-Item -ItemType Directory -Path (Join-Path $root ('x/Cache.old-1-{0}' -f $_)) -Force }
    $threw = $false
    try { $null = Get-FreeBackupName -Parent (Join-Path $root 'x') -Name 'Cache' -Stamp '1' } catch { $threw = $true }
    Assert-True 'no free name: throws instead of overwriting' $threw
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Order in the script: plan before stopping, re-check before renaming ---------------------
$text = [System.IO.File]::ReadAllText($scriptPath)
$planAt = $text.IndexOf('Get-CacheRenamePlan -Folder $folders')
$stopAt = $text.IndexOf("Write-MSPSection -Title 'Stopping services'")
$renameAt = $text.IndexOf('Rename-Item -LiteralPath $r.Folder.Path')
$recheckAt = $text.IndexOf('$r.NewName = Get-FreeBackupName')
Assert-True 'names are planned before services are stopped' ($planAt -gt 0 -and $stopAt -gt $planAt) ('plan at {0}, stop at {1}' -f $planAt, $stopAt)
Assert-True 'name re-checked right before Rename-Item' ($recheckAt -gt $stopAt -and $recheckAt -lt $renameAt) ('recheck at {0}, rename at {1}' -f $recheckAt, $renameAt)
# The undo steps mention Remove-Item as printed text; an actual Remove-Item command must not exist.
$removeCalls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Remove-Item', 'rm', 'del', 'rmdir', 'ri') }, $true)
Assert-Equal 'script never runs Remove-Item' 0 @($removeCalls).Count

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
