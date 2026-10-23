<#
.SYNOPSIS
    Development-side verification for the toolkit: parsers, PSScriptAnalyzer, ShellCheck,
    bash 3.2 compatibility scan, embedded-helper check, unit and logic tests, JSON schema
    validation and runtime smoke tests. Never run on client machines.

.DESCRIPTION
    Runs on Windows (Windows PowerShell 5.1, bash steps through WSL) and on macOS / Linux
    (PowerShell 7, bash steps with the local bash). Each step reports PASS / FAIL / NOT RUN with
    the reason; a step that needs another platform says which, instead of failing.

      1  PowerShell parser on every .ps1/.psm1 (5.1 on Windows; 7 everywhere pwsh is installed)
      2  PSScriptAnalyzer (PSAvoidUsingWriteHost excluded: console tools print to the screen on purpose).
         Findings listed in tests/pssa-known-issues.txt (scripts not yet reworked) are reported as
         known; only new findings fail.
      3  bash -n on every .sh: macOS /bin/bash 3.2 and a newer bash if installed; Linux bash (and
         /opt/bash-3.2 if built); Windows: bash in WSL
      4  ShellCheck on every .sh
      5  bash 4+ / GNU-only construct scan (tests/bash/check-bash32-compat.sh)
      6  Sync-MSPEmbeddedHelper.ps1 -Check, plus a tamper test in a temporary copy
      7  bash helper unit tests as a normal user (and as root where that needs no password:
         WSL, or when the harness itself runs as root), under every bash found in step 3,
         cross-checked from PowerShell: JSON escaping round-trip, ID parity, MAC vendor table
         parity, schema validation
      8  PowerShell helper unit tests (tests/Test-MSPToolkitCommon.ps1) on 5.1 and 7
      9  Logic tests that use mocked paths and run on any platform:
         tests/Test-ClearWindowsUpdateCacheLogic.ps1 (D1 repeat runs),
         tests/Test-ExportSecurityAuditReportIds.ps1 (A9 old/new finding IDs),
         tests/Test-ExportSecurityAuditReportMixed.ps1 (A9 with Windows, macOS and Linux results),
         tests/Test-BatchBWindowsLogic.ps1 (B1-B3 Windows scripts against mocked cmdlets) and
         tests/bash/test-scripts-mocked.sh under every bash (Linux scripts, Linux branches and
         macOS paths not reachable here, with stub commands; no network traffic is possible)
     10  Runtime smoke tests of the scripts for THIS platform, results validated against schema
         2.0. Cases for another platform are listed as NOT RUN with the platform they need.
         PASSIVE BY DEFAULT: only cases that stay on this computer run (local diagnostics,
         remediation with -WhatIf, non-interactive refusal checks). Cases that send traffic beyond
         this computer (ping sweep, reverse DNS of neighbors, LAN port scan, router/SSDP checks,
         online update searches, connectivity probes) are listed as NOT RUN unless
         -AllowActiveNetwork is given.
    _archive/ is never scanned.

.PARAMETER Path
    Limit steps 1-5 to these files or folders (relative to the repository root). Default: all.

.PARAMETER Distro
    Windows only: WSL distribution used for bash steps. Default: Ubuntu.

.PARAMETER TestUser
    Windows only: non-root WSL account used to run tests as a normal user. Default: msptest.

.PARAMETER AllowActiveNetwork
    Also run the runtime cases that send network traffic beyond this computer (see step 10).
    The local subnet and the cases are printed first. Only use with approval for that network.

.PARAMETER SkipRuntime
    Skip step 10 (runtime smoke tests).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1

.EXAMPLE
    pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1          (macOS / Linux)

.EXAMPLE
    .\tests\Invoke-ToolkitTests.ps1 -Path endpoint-systems\utilities, tests

.NOTES
    Risk Level    : Safe -- reads repository files; writes only to a temporary folder
    Prerequisites : Windows: Windows PowerShell 5.1, WSL with bash, PowerShell 7 optional
                    macOS/Linux: PowerShell 7 and bash
                    All: PSScriptAnalyzer (module path or %LOCALAPPDATA%\PSModules), ShellCheck
    Exit code     : 0 when every step that ran passed, 1 otherwise
    Version       : 2.3.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Add-Result (Step, Result, Detail) is called ~50 times; positional calls keep each step on one readable line.')]
[CmdletBinding()]
param(
    [string[]]$Path = @(),
    [string]$Distro = 'Ubuntu',
    [string]$TestUser = 'msptest',
    [switch]$AllowActiveNetwork,
    [switch]$SkipRuntime
)

$ErrorActionPreference = 'Stop'
# "powershell.exe -File" passes a list as one "a,b" string; split so both forms work.
$Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$root = (Resolve-Path -LiteralPath (Join-Path -Path $here -ChildPath '..')).ProviderPath
$results = New-Object System.Collections.Generic.List[object]
$work = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('msp-toolkit-tests-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$null = New-Item -ItemType Directory -Path $work -Force

# --- Platform ------------------------------------------------------------------------------
$onWindows = ($PSVersionTable.PSEdition -ne 'Core') -or $IsWindows
$platform = 'Windows'
if (-not $onWindows) { $platform = $(if ($IsMacOS) { 'macOS' } else { 'Linux' }) }
# The PowerShell running this harness; child PowerShell steps use the same one where possible.
$psExe = (Get-Process -Id $PID).Path
$winPs = $null
if ($onWindows) { $winPs = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source }

function Add-Result {
    param([string]$Step, [ValidateSet('PASS', 'FAIL', 'NOT RUN')][string]$Result, [string]$Detail = '')
    $results.Add([pscustomobject]@{ Step = $Step; Result = $Result; Detail = $Detail })
    $color = @{ 'PASS' = 'Green'; 'FAIL' = 'Red'; 'NOT RUN' = 'Yellow' }[$Result]
    Write-Host ('[{0}] {1}' -f $Result, $Step) -ForegroundColor $color
    if ($Detail) { Write-Host ('        {0}' -f ($Detail -replace "`n", "`n        ")) -ForegroundColor DarkGray }
}

function Get-RepoFile {
    param([string[]]$Extension)
    $bases = @($root)
    if ($Path.Count -gt 0) { $bases = @($Path | ForEach-Object { Join-Path -Path $root -ChildPath ($_ -replace '[\\/]', [IO.Path]::DirectorySeparatorChar) }) }
    $files = foreach ($b in $bases) {
        if (Test-Path -LiteralPath $b -PathType Leaf) { Get-Item -LiteralPath $b }
        elseif (Test-Path -LiteralPath $b) { Get-ChildItem -LiteralPath $b -Recurse -File }
    }
    return @($files | Where-Object { $Extension -contains $_.Extension -and $_.FullName -notmatch '[\\/](_archive|\.git)[\\/]' } | Sort-Object FullName -Unique)
}

function Get-Relative { param([string]$Full) return ($Full.Substring($root.Length + 1) -replace '\\', '/') }

function Join-RepoPath {
    <# Repository-relative path with / separators -> full path on this platform. #>
    param([string]$Relative)
    return (Join-Path -Path $root -ChildPath ($Relative -replace '[\\/]', [IO.Path]::DirectorySeparatorChar))
}

# --- Tool discovery ----------------------------------------------------------------------
$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $pwsh -and $onWindows -and (Test-Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe")) { $pwsh = "$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe" }
$shellcheck = (Get-Command shellcheck -ErrorAction SilentlyContinue).Source
if (-not $shellcheck -and $onWindows) {
    $shellcheck = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter shellcheck.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}
$pssa = Get-Module -ListAvailable PSScriptAnalyzer | Select-Object -First 1
if (-not $pssa -and $onWindows -and (Test-Path "$env:LOCALAPPDATA\PSModules\PSScriptAnalyzer")) { $pssa = "$env:LOCALAPPDATA\PSModules\PSScriptAnalyzer" }

function Format-BashQuote { param([string]$Text) return ("'{0}'" -f ($Text -replace "'", "'\''")) }

function ConvertTo-BashPath {
    <# Path as the bash side sees it: /mnt/c/... in WSL, unchanged on macOS/Linux. #>
    param([string]$LocalPath)
    if (-not $onWindows) { return $LocalPath }
    $drive = $LocalPath.Substring(0, 1).ToLower()
    return ('/mnt/{0}{1}' -f $drive, ($LocalPath.Substring(2) -replace '\\', '/'))
}

# Bash environment. On Windows everything goes through WSL; elsewhere the local bash is used.
$bashOk = $false
$isRoot = $false
if ($onWindows) {
    try {
        $probe = (& wsl.exe -d $Distro -- bash -c 'echo ok' 2>$null) -join ''
        $bashOk = ($probe -replace "`0", '').Trim() -eq 'ok'
    }
    catch { $bashOk = $false }
    $bashWhy = "WSL distro '$Distro' not available"
}
else {
    $bashOk = [bool](Get-Command bash -ErrorAction SilentlyContinue)
    $isRoot = ((& id -u) -eq '0')
    $bashWhy = 'bash not found'
}

function Invoke-Bash {
    <#
        Runs a bash command line; returns @{ Code; Output }. -User root/normal and -Shell pick the
        account and the bash binary. Off Windows it runs as the current account (never sudo).
    #>
    param([string]$Command, [string]$User = '', [string]$Shell = 'bash')
    if ($onWindows) {
        if (-not $User) { $User = 'root' }
        $out = & wsl.exe -d $Distro -u $User -- $Shell -c $Command 2>&1
    }
    else {
        $out = & $Shell -c $Command 2>&1
    }
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Code = $code; Output = (($out | ForEach-Object { "$_" -replace "`0", '' }) -join "`n") }
}

$rootBash = ConvertTo-BashPath $root

# Every bash to test with: Label (shown in results), Shell (binary), and its version.
$bashShells = @()
if ($bashOk) {
    $candidates = @()
    if ($onWindows) { $candidates = @('bash', '/opt/bash-3.2/bin/bash') }
    elseif ($platform -eq 'macOS') { $candidates = @('/bin/bash', (Get-Command bash).Source, '/opt/homebrew/bin/bash', '/usr/local/bin/bash') }
    else { $candidates = @('bash', '/opt/bash-3.2/bin/bash') }
    $seen = @{}
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        $v = Invoke-Bash -Command ('test -x "$(command -v {0})" && {0} -c ''echo $BASH_VERSION''' -f $c)
        $ver = ($v.Output -split "`n" | Select-Object -Last 1).Trim()
        if ($v.Code -ne 0 -or -not $ver -or $seen.ContainsKey($ver)) { continue }
        $seen[$ver] = $true
        $bashShells += [pscustomobject]@{ Shell = $c; Version = $ver; Label = ('bash {0}' -f ($ver -replace '\(.*$', '')) }
    }
}
$has32 = [bool]($bashShells | Where-Object { $_.Version -like '3.2.*' })

$userOk = $false
if ($onWindows -and $bashOk) { $userOk = ((Invoke-Bash -Command ('id -u {0} >/dev/null 2>&1 && echo yes' -f $TestUser)).Output.Trim() -eq 'yes') }

$psFiles = Get-RepoFile -Extension @('.ps1', '.psm1')
$shFiles = Get-RepoFile -Extension @('.sh')
Write-Host ('Platform: {0} | PowerShell {1} | bash: {2} | ShellCheck: {3} | PSScriptAnalyzer: {4}' -f $platform, $PSVersionTable.PSVersion,
    $(if ($bashShells) { ($bashShells | ForEach-Object { '{0} ({1})' -f $_.Label, $_.Shell }) -join ', ' } else { 'none' }),
    $(if ($shellcheck) { 'yes' } else { 'no' }), $(if ($pssa) { 'yes' } else { 'no' })) -ForegroundColor Cyan

# --- 1 Parsers ---------------------------------------------------------------------------
function Get-ParseError {
    <# Parses every PowerShell file with the given PowerShell executable; returns error lines. #>
    param([string]$Exe)
    $list = Join-Path $work ('psfiles-{0}.txt' -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllLines($list, [string[]]@($psFiles.FullName))
    $code = '[System.IO.File]::ReadAllLines(''{0}'') | ForEach-Object {{ $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($_, [ref]$null, [ref]$e); foreach ($x in $e) {{ ''{{0}}:{{1}} {{2}}'' -f $_, $x.Extent.StartLineNumber, $x.Message }} }}' -f $list
    return @(& $Exe -NoProfile -Command $code)
}

if ($winPs) {
    $bad = Get-ParseError -Exe $winPs
    if ($bad) { Add-Result 'Parse (Windows PowerShell 5.1)' FAIL (($bad | Select-Object -First 20) -join "`n") }
    else { Add-Result 'Parse (Windows PowerShell 5.1)' PASS ('{0} file(s)' -f $psFiles.Count) }
}
else { Add-Result 'Parse (Windows PowerShell 5.1)' 'NOT RUN' 'Windows only: run this harness on a Windows PC' }

if ($pwsh) {
    $bad = Get-ParseError -Exe $pwsh
    if ($bad) { Add-Result 'Parse (PowerShell 7)' FAIL (($bad | Select-Object -First 20) -join "`n") }
    else { Add-Result 'Parse (PowerShell 7)' PASS ('{0} file(s)' -f $psFiles.Count) }
}
else { Add-Result 'Parse (PowerShell 7)' 'NOT RUN' 'pwsh not installed' }

# --- 2 PSScriptAnalyzer ------------------------------------------------------------------
# Findings in scripts not yet brought to standard are listed in tests/pssa-known-issues.txt
# (file|rule|max count). They are reported as known, not failed, so any NEW finding stands out.
# Remove a file's lines from that list when its batch is reworked.
if ($pssa) {
    Import-Module $pssa -ErrorAction Stop
    $raw = foreach ($f in $psFiles) {
        Invoke-ScriptAnalyzer -Path $f.FullName -ExcludeRule PSAvoidUsingWriteHost |
            ForEach-Object { [pscustomobject]@{ File = (Get-Relative $f.FullName); Line = $_.Line; Rule = $_.RuleName; Message = ($_.Message -split "`n")[0] } }
    }
    $raw = @($raw)
    $known = @{}
    $baselineFile = Join-Path $here 'pssa-known-issues.txt'
    if (Test-Path -LiteralPath $baselineFile) {
        foreach ($line in [System.IO.File]::ReadAllLines($baselineFile)) {
            if ($line -match '^\s*(#|$)') { continue }
            $parts = $line.Split('|')
            if ($parts.Count -eq 3) { $known['{0}|{1}' -f $parts[0].Trim(), $parts[1].Trim()] = [int]$parts[2] }
        }
    }
    $newIssues = New-Object System.Collections.Generic.List[string]
    $knownCount = 0
    $lowerable = New-Object System.Collections.Generic.List[string]
    foreach ($g in ($raw | Group-Object -Property File, Rule)) {
        $first = $g.Group[0]
        $key = '{0}|{1}' -f $first.File, $first.Rule
        $allowed = 0
        if ($known.ContainsKey($key)) { $allowed = $known[$key] }
        if ($g.Count -le $allowed) {
            $knownCount += $g.Count
            if ($g.Count -lt $allowed) { $lowerable.Add(('{0}: {1} now, list says {2}' -f $key, $g.Count, $allowed)) }
        }
        else {
            foreach ($i in $g.Group) { $newIssues.Add(('{0}:{1} [{2}] {3}' -f $i.File, $i.Line, $i.Rule, $i.Message)) }
            if ($allowed -gt 0) { $newIssues.Add(('  ({0}: {1} found, {2} known)' -f $key, $g.Count, $allowed)) }
        }
    }
    $scanned = @($psFiles | ForEach-Object { Get-Relative $_.FullName })
    foreach ($key in $known.Keys) {
        if ($scanned -notcontains $key.Split('|')[0]) { continue }
        if (-not ($raw | Where-Object { ('{0}|{1}' -f $_.File, $_.Rule) -eq $key })) { $lowerable.Add(('{0}: fixed, remove the line' -f $key)) }
    }
    $raw | ForEach-Object { '{0}:{1} [{2}] {3}' -f $_.File, $_.Line, $_.Rule, $_.Message } | Set-Content -LiteralPath (Join-Path $work 'pssa.txt') -Encoding UTF8
    $label = 'PSScriptAnalyzer (PowerShell {0})' -f $PSVersionTable.PSVersion.Major
    $note = ''
    if ($knownCount -gt 0) { $note = ('; {0} known finding(s) in scripts not yet reworked (tests/pssa-known-issues.txt)' -f $knownCount) }
    if ($lowerable.Count -gt 0) { $note += ("`nKnown-issues list can be tightened: " + ($lowerable -join '; ')) }
    if ($newIssues.Count -gt 0) {
        $newCount = @($newIssues | Where-Object { -not $_.StartsWith('  (') }).Count
        Add-Result $label FAIL (('{0} NEW finding(s){1}' -f $newCount, $note) + "`n" + (($newIssues | Select-Object -First 30) -join "`n") + "`nFull list: " + (Join-Path $work 'pssa.txt'))
    }
    else { Add-Result $label PASS ('{0} file(s), no new findings{1}' -f $psFiles.Count, $note) }
}
else { Add-Result 'PSScriptAnalyzer' 'NOT RUN' 'module not found' }

# --- 3 bash -n ---------------------------------------------------------------------------
if ($shFiles.Count -eq 0) { Add-Result 'bash -n' 'NOT RUN' 'no .sh files in scope' }
elseif (-not $bashOk) { Add-Result 'bash -n' 'NOT RUN' $bashWhy }
else {
    $quoted = ($shFiles | ForEach-Object { Format-BashQuote (ConvertTo-BashPath $_.FullName) }) -join ' '
    foreach ($b in $bashShells) {
        $r = Invoke-Bash -Command ('rc=0; for f in {0}; do {1} -n "$f" || rc=1; done; exit $rc' -f $quoted, $b.Shell)
        $label = 'bash -n ({0})' -f $b.Label
        if ($r.Code -eq 0) { Add-Result $label PASS ('{0} file(s)' -f $shFiles.Count) } else { Add-Result $label FAIL $r.Output }
    }
    if (-not $has32) {
        $why = 'bash 3.2 not built at /opt/bash-3.2'
        if ($platform -eq 'macOS') { $why = '/bin/bash is not 3.2 on this Mac' }
        Add-Result 'bash -n (bash 3.2.57)' 'NOT RUN' $why
    }
}

# --- 4 ShellCheck ------------------------------------------------------------------------
if ($shFiles.Count -eq 0) { Add-Result 'ShellCheck' 'NOT RUN' 'no .sh files in scope' }
elseif (-not $shellcheck) { Add-Result 'ShellCheck' 'NOT RUN' 'shellcheck not installed' }
else {
    Push-Location $root
    try {
        $rel = $shFiles | ForEach-Object { Get-Relative $_.FullName }
        $out = & $shellcheck -s bash -x @rel 2>&1
        $code = $LASTEXITCODE
    }
    finally { Pop-Location }
    if ($code -eq 0) { Add-Result 'ShellCheck' PASS ('{0} file(s), no findings' -f $shFiles.Count) }
    else { Add-Result 'ShellCheck' FAIL ((@($out) | Select-Object -First 40) -join "`n") }
}

# --- 5 bash 3.2 construct scan -----------------------------------------------------------
if ($shFiles.Count -eq 0) { Add-Result 'bash 3.2 construct scan' 'NOT RUN' 'no .sh files in scope' }
elseif (-not $bashOk) { Add-Result 'bash 3.2 construct scan' 'NOT RUN' $bashWhy }
else {
    # The scanner mentions the constructs it looks for, so skip it.
    $scan = @($shFiles | Where-Object { $_.Name -notin @('check-bash32-compat.sh') })
    $quoted = ($scan | ForEach-Object { Format-BashQuote (ConvertTo-BashPath $_.FullName) }) -join ' '
    $r = Invoke-Bash -Command ('bash {0}/tests/bash/check-bash32-compat.sh {1}' -f (Format-BashQuote $rootBash), $quoted)
    if ($r.Code -eq 0) { Add-Result 'bash 3.2 construct scan' PASS $r.Output } else { Add-Result 'bash 3.2 construct scan' FAIL $r.Output }
}

# --- 6 Embedded helpers ------------------------------------------------------------------
$sync = Join-RepoPath 'endpoint-systems/utilities/Sync-MSPEmbeddedHelper.ps1'
$out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $sync -Check 2>&1
if ($LASTEXITCODE -eq 0) { Add-Result 'Embedded helpers (Sync -Check)' PASS ((@($out) | Select-Object -Last 1) -join '') }
else { Add-Result 'Embedded helpers (Sync -Check)' FAIL ((@($out) | Where-Object { "$_" -match 'MISMATCH|PROBLEM' }) -join "`n") }

# Tamper test in a throwaway copy: generate, verify, hand-edit, verify again (must fail).
$fake = Join-Path $work 'synctest'
$util = Join-Path (Join-Path $fake 'endpoint-systems') 'utilities'
$null = New-Item -ItemType Directory -Path $util -Force
Copy-Item (Join-RepoPath 'endpoint-systems/utilities/MSPToolkit.Common.psm1'), (Join-RepoPath 'endpoint-systems/utilities/msp-toolkit-common.sh'), $sync -Destination $util
[System.IO.File]::WriteAllText((Join-Path $fake 'a.ps1'), "param()`r`n#region MSPToolkit (generated) Sections=Core`r`n#endregion MSPToolkit (generated)`r`n", (New-Object System.Text.UTF8Encoding($true)))
[System.IO.File]::WriteAllText((Join-Path $fake 'c.ps1'), "param()`n#region MSPToolkit (generated) Sections=Core`n#endregion MSPToolkit (generated)`n", (New-Object System.Text.UTF8Encoding($true)))
[System.IO.File]::WriteAllText((Join-Path $fake 'b.sh'), "#!/usr/bin/env bash`n#region MSPToolkit (generated) Sections=Core,Net`n#endregion MSPToolkit (generated)`n", (New-Object System.Text.UTF8Encoding($false)))
$fakeSync = Join-Path $util 'Sync-MSPEmbeddedHelper.ps1'
$null = & $psExe -NoProfile -ExecutionPolicy Bypass -File $fakeSync -Check; $c0 = $LASTEXITCODE
$null = & $psExe -NoProfile -ExecutionPolicy Bypass -File $fakeSync; $c1 = $LASTEXITCODE
$null = & $psExe -NoProfile -ExecutionPolicy Bypass -File $fakeSync -Check; $c2 = $LASTEXITCODE
$bBytes = [System.IO.File]::ReadAllBytes((Join-Path $fake 'b.sh'))
$hasCr = [array]::IndexOf($bBytes, [byte]13) -ge 0
$hasBom = $bBytes[0] -eq 0xEF
$aKeptCrlf = ([System.IO.File]::ReadAllText((Join-Path $fake 'a.ps1')) -split "`n" | Where-Object { $_ -and -not $_.EndsWith("`r") }).Count -le 1
$cKeptLf = -not ([System.IO.File]::ReadAllText((Join-Path $fake 'c.ps1'))).Contains("`r")
$bText = [System.IO.File]::ReadAllText((Join-Path $fake 'b.sh'))
[System.IO.File]::WriteAllText((Join-Path $fake 'b.sh'), ($bText -replace 'MSP_SCHEMA_VERSION=''2.0''', 'MSP_SCHEMA_VERSION=''9.9'''), (New-Object System.Text.UTF8Encoding($false)))
$null = & $psExe -NoProfile -ExecutionPolicy Bypass -File $fakeSync -Check; $c3 = $LASTEXITCODE
$ok = ($c0 -eq 1) -and ($c1 -eq 0) -and ($c2 -eq 0) -and (-not $hasCr) -and (-not $hasBom) -and $aKeptCrlf -and $cKeptLf -and ($c3 -eq 1) -and $bText.Contains('msp_json_escape')
$detail = 'empty region -Check={0} (want 1), generate={1}, -Check={2} (want 0), .sh LF-only={3}, no BOM={4}, CRLF .ps1 kept CRLF={5}, LF .ps1 kept LF={6}, hand-edited .sh -Check={7} (want 1)' -f $c0, $c1, $c2, (-not $hasCr), (-not $hasBom), $aKeptCrlf, $cKeptLf, $c3
if ($ok) { Add-Result 'Sync tamper test (.ps1 + .sh)' PASS $detail } else { Add-Result 'Sync tamper test (.ps1 + .sh)' FAIL $detail }

# --- 7 bash helper unit tests + PowerShell cross-checks -----------------------------------
$validator = Join-Path $here 'Test-MSPResultSchema.ps1'
if (-not $bashOk) { Add-Result 'bash helper unit tests' 'NOT RUN' $bashWhy }
else {
    $runs = @()
    foreach ($b in $bashShells) {
        if ($onWindows) {
            $runs += @{ Label = ('{0}, root' -f $b.Label); Shell = $b.Shell; User = 'root' }
            if ($userOk) { $runs += @{ Label = ('{0}, normal user ({1})' -f $b.Label, $TestUser); Shell = $b.Shell; User = $TestUser } }
        }
        elseif ($isRoot) { $runs += @{ Label = ('{0}, root' -f $b.Label); Shell = $b.Shell; User = '' } }
        else { $runs += @{ Label = ('{0}, normal user ({1})' -f $b.Label, [Environment]::UserName); Shell = $b.Shell; User = '' } }
    }
    if ($onWindows -and -not $userOk) { Add-Result 'bash helper unit tests (normal user)' 'NOT RUN' ("WSL account '$TestUser' does not exist") }
    if (-not $onWindows -and -not $isRoot) {
        Add-Result 'bash helper unit tests (root)' 'NOT RUN' ('needs sudo, which this harness never uses. By hand: sudo /bin/bash {0}/tests/bash/test-msp-helper.sh' -f $root)
    }
    if (-not $has32) { Add-Result 'bash helper unit tests (bash 3.2.57)' 'NOT RUN' 'no bash 3.2 on this computer' }

    $i = 0
    foreach ($run in $runs) {
        $i++
        $local = Join-Path $work ('emit{0}' -f $i)
        if ($onWindows) {
            # Emit into a Linux-side temp folder (writable by any user), then copy back for PowerShell.
            $emit = '/tmp/msp-emit-{0}-{1}' -f $PID, $i
            $cmd = 'rm -rf {0}; mkdir -p {0}; chmod 777 {0}; cd {1} && {2} tests/bash/test-msp-helper.sh --emit {0}' -f $emit, (Format-BashQuote $rootBash), $run.Shell
        }
        else {
            $emit = $local
            $cmd = 'mkdir -p {0} && cd {1} && {2} tests/bash/test-msp-helper.sh --emit {0}' -f (Format-BashQuote $emit), (Format-BashQuote $rootBash), $run.Shell
        }
        $r = Invoke-Bash -Command $cmd -User $run.User
        $last = ($r.Output -split "`n" | Where-Object { $_ -match 'passed, .* failed' } | Select-Object -Last 1)
        if ($r.Code -eq 0) { Add-Result ('bash helper unit tests ({0})' -f $run.Label) PASS $last }
        else { Add-Result ('bash helper unit tests ({0})' -f $run.Label) FAIL (($r.Output -split "`n" | Where-Object { $_ -match 'FAIL|passed' }) -join "`n") }

        if ($onWindows) {
            $null = New-Item -ItemType Directory -Path $local -Force
            $null = Invoke-Bash -Command ('cp -r {0}/. {1}/ && rm -rf {0}' -f $emit, (Format-BashQuote (ConvertTo-BashPath $local)))
        }

        # JSON escaping round-trip: decode bash's JSON in PowerShell and compare UTF-8 bytes.
        $casesFile = Join-Path $local 'escape-cases.json'
        if (Test-Path $casesFile) {
            # Windows PowerShell 5.1 returns a JSON array as one object; foreach unrolls it.
            $parsed = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($casesFile))
            $decoded = @(foreach ($item in $parsed) { $item })
            $hex = @(Get-Content -LiteralPath (Join-Path $local 'escape-cases.hex'))
            $mismatch = @()
            for ($n = 0; $n -lt $hex.Count; $n++) {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$decoded[$n])
                $got = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
                if ($got -ne $hex[$n].Trim()) { $mismatch += ('case {0}: expected {1}, decoded {2}' -f $n, $hex[$n].Trim(), $got) }
            }
            if ($decoded.Count -ne $hex.Count) { $mismatch += ('{0} decoded vs {1} expected' -f $decoded.Count, $hex.Count) }
            if ($mismatch.Count -eq 0) { Add-Result ('JSON escaping round-trip ({0})' -f $run.Label) PASS ('{0} strings decoded byte-for-byte by ConvertFrom-Json' -f $hex.Count) }
            else { Add-Result ('JSON escaping round-trip ({0})' -f $run.Label) FAIL ($mismatch -join "`n") }
        }

        if ($i -eq 1) {
            # Load the PowerShell helpers once for the parity checks.
            $moduleText = [System.IO.File]::ReadAllText((Join-RepoPath 'endpoint-systems/utilities/MSPToolkit.Common.psm1'))
            $null = New-Module -Name MSPParity -ScriptBlock ([scriptblock]::Create($moduleText)) | Import-Module -Force -PassThru

            # ID parity: bash msp_id_part vs PowerShell ConvertTo-MSPIdPart.
            $idFile = Join-Path $local 'id-cases.txt'
            if (Test-Path $idFile) {
                $diff = foreach ($line in [System.IO.File]::ReadAllLines($idFile, [System.Text.Encoding]::UTF8)) {
                    $parts = $line -split "`t", 2
                    $ps = ConvertTo-MSPIdPart -Text $parts[0]
                    if ($ps -ne $parts[1]) { '"{0}": bash {1}, PowerShell {2}' -f $parts[0], $parts[1], $ps }
                }
                if ($diff) { Add-Result 'Finding ID parity (bash vs PowerShell)' FAIL ($diff -join "`n") }
                else { Add-Result 'Finding ID parity (bash vs PowerShell)' PASS 'identical IDs for all cases' }
            }

            # MAC vendor parity: bash msp_mac_vendor vs PowerShell Get-MSPMacVendor.
            $vendorFile = Join-Path $local 'vendor-cases.txt'
            if (Test-Path $vendorFile) {
                $lines = [System.IO.File]::ReadAllLines($vendorFile, [System.Text.Encoding]::UTF8)
                $diff = foreach ($line in $lines) {
                    $parts = $line -split "`t"
                    $v = Get-MSPMacVendor -MacAddress $parts[0]
                    $ps = '{0}|{1}|{2}' -f $v.Vendor, $v.Hint, $(if ($v.Randomized) { 'true' } else { 'false' })
                    if ($ps -ne $parts[1]) { '{0}: bash {1}, PowerShell {2}' -f $parts[0], $parts[1], $ps }
                }
                if ($diff) { Add-Result 'MAC vendor table parity (bash vs PowerShell)' FAIL (($diff | Select-Object -First 10) -join "`n") }
                else { Add-Result 'MAC vendor table parity (bash vs PowerShell)' PASS ('{0} MAC addresses give the same vendor and hint' -f $lines.Count) }
            }
            Remove-Module MSPParity -ErrorAction SilentlyContinue
        }

        # Schema validation of the bash export.
        $export = Join-Path $local 'export'
        if (Test-Path $export) {
            $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $validator -Path $export 2>&1
            if ($LASTEXITCODE -eq 0) { Add-Result ('Schema 2.0 validation of bash export ({0})' -f $run.Label) PASS ((@($out) | Select-Object -Last 1) -join '') }
            else { Add-Result ('Schema 2.0 validation of bash export ({0})' -f $run.Label) FAIL ((@($out) | Where-Object { "$_" -match 'error|FAIL' }) -join "`n") }
        }
    }
}

# --- 8 PowerShell helper unit tests ------------------------------------------------------
$unit = Join-Path $here 'Test-MSPToolkitCommon.ps1'
$hosts = @()
if ($winPs) { $hosts += [pscustomobject]@{ Label = '5.1'; Exe = $winPs } }
else { Add-Result 'PowerShell helper unit tests (5.1)' 'NOT RUN' 'Windows only: run this harness on a Windows PC' }
if ($pwsh) { $hosts += [pscustomobject]@{ Label = '7'; Exe = $pwsh } }
foreach ($h in $hosts) {
    $out = & $h.Exe -NoProfile -ExecutionPolicy Bypass -File $unit 2>&1
    if ($LASTEXITCODE -eq 0) { Add-Result ('PowerShell helper unit tests ({0})' -f $h.Label) PASS ((@($out) | Select-Object -Last 1) -join '') }
    else { Add-Result ('PowerShell helper unit tests ({0})' -f $h.Label) FAIL ((@($out) | Where-Object { "$_" -match 'FAIL|passed' }) -join "`n") }
}

# --- 9 Logic tests (mocked paths, any platform) --------------------------------------------
$logic = @(
    @{ Name = 'D1 repeat runs: backup names never reused or overwritten'; File = 'Test-ClearWindowsUpdateCacheLogic.ps1' }
    @{ Name = 'A9 reports a check once across result versions and platforms'; File = 'Test-ExportSecurityAuditReportIds.ps1' }
    @{ Name = 'A9 coverage, router and device checklists from Windows, macOS and Linux results'; File = 'Test-ExportSecurityAuditReportMixed.ps1' }
    @{ Name = 'B1-B3 Windows scripts against mocked cmdlets'; File = 'Test-BatchBWindowsLogic.ps1' }
)
foreach ($t in $logic) {
    foreach ($h in $hosts) {
        $out = & $h.Exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here $t.File) 2>&1
        $label = 'Logic: {0} (PowerShell {1})' -f $t.Name, $h.Label
        if ($LASTEXITCODE -eq 0) { Add-Result $label PASS ((@($out) | Select-Object -Last 1) -join '') }
        else { Add-Result $label FAIL ((@($out) | Where-Object { "$_" -match 'FAIL|passed' }) -join "`n") }
    }
}

if (-not $bashOk) { Add-Result 'Logic: bash scripts with stubbed platform commands' 'NOT RUN' $bashWhy }
foreach ($b in $bashShells) {
    $r = Invoke-Bash -Command ('cd {0} && {1} tests/bash/test-scripts-mocked.sh' -f (Format-BashQuote $rootBash), $b.Shell)
    $label = 'Logic: bash scripts with stubbed platform commands ({0})' -f $b.Label
    $last = ($r.Output -split "`n" | Where-Object { $_ -match 'passed, .* failed' } | Select-Object -Last 1)
    if ($r.Code -eq 0) { Add-Result $label PASS $last }
    else { Add-Result $label FAIL (($r.Output -split "`n" | Where-Object { $_ -match 'FAIL|passed|pattern' } | Select-Object -First 30) -join "`n") }
}

# --- 10 Runtime smoke tests (passive unless -AllowActiveNetwork) ---------------------------
function Get-ProfileDefault {
    <# Current Outlook default profile, to prove D3 changed nothing during its refusal test. #>
    foreach ($v in '16.0', '15.0') {
        $p = Get-ItemProperty -LiteralPath ('HKCU:\Software\Microsoft\Office\{0}\Outlook' -f $v) -Name DefaultProfile -ErrorAction SilentlyContinue
        if ($p) { return [string]$p.DefaultProfile }
    }
    return ''
}

function Get-ActiveScope {
    <# One line naming the network the active cases would touch, printed before any of them run. #>
    if ($onWindows) {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
        $ip = if ($route) { Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 }
        return ('{0}/{1} (gateway {2})' -f $ip.IPAddress, $ip.PrefixLength, $route.NextHop)
    }
    # The same picker the bash scripts use (no traffic: reads the routing table and interfaces).
    $helper = ConvertTo-BashPath (Join-RepoPath 'endpoint-systems/utilities/msp-toolkit-common.sh')
    $r = Invoke-Bash -Command ('. {0}; msp_detect_platform; if msp_local_subnet; then echo "$MSP_NET_CIDR via $MSP_NET_IFACE (this computer $MSP_NET_IP, gateway $MSP_NET_GATEWAY)"; else echo "$MSP_NET_ERROR"; fi' -f (Format-BashQuote $helper))
    return $r.Output.Trim()
}

if ($SkipRuntime) { Add-Result 'Runtime smoke tests' 'NOT RUN' '-SkipRuntime' }
else {
    $diag = 'security-operations/diagnostics'
    $ep = 'security-operations/diagnostics/endpoint-posture'
    $net = 'core-infrastructure/networking/diagnostics'
    $si = 'endpoint-systems/diagnostics/system-info'
    $b2ps = 'endpoint-systems/diagnostics/networking/Get-NetworkConnectivityReport.ps1'
    $b2sh = 'endpoint-systems/diagnostics/networking/get-network-connectivity-report.sh'
    $b3ps = 'endpoint-systems/diagnostics/event-logs/Get-RecentCriticalErrors.ps1'
    $b3sh = 'endpoint-systems/diagnostics/event-logs/get-recent-critical-errors.sh'
    $b4sh = 'endpoint-systems/remediation/safe/restart-services/restart-common-services.sh'
    # Platform: where the case can run. Expect: allowed exit codes. Active: sends traffic beyond
    # this computer (gated by -AllowActiveNetwork). Bash cases get --output, PowerShell -OutputPath.
    $cases = @(
        @{ Platform = 'Windows'; Name = 'A1 endpoint security'; Script = "$ep/Get-EndpointSecurityStatus.ps1"; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'A3 Wi-Fi (netsh, local)'; Script = "$net/Get-WiFiSecurityAudit.ps1"; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'A4 listening ports (no -ScanLan)'; Script = "$ep/Get-OpenPortScan.ps1"; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'A2 -Passive (neighbor table only, nothing sent)'; Script = "$net/Get-HomeNetworkMap.ps1"; Args = @('-Passive'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'A5 browsers'; Script = "$si/Get-BrowserSecurityCheck.ps1"; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'A6 updates (last scan, no -Online)'; Script = "$si/Get-WindowsUpdateCompliance.ps1"; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'A8 inventory'; Script = 'endpoint-systems/audit/software-inventory/Get-HomeDeviceInventory.ps1'; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'Bundle without A2/A7 + A9 report'; Script = "$diag/Invoke-HomeAuditBundle.ps1"; Args = @('-Skip', 'Get-HomeNetworkMap,Get-RouterSecurityCheck', '-TechnicianName', 'Test'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'D1 -WhatIf'; Script = 'endpoint-systems/remediation/safe/clear-caches/Clear-WindowsUpdateCache.ps1'; Args = @('-WhatIf'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'D1 non-interactive, no -Force (must refuse)'; Script = 'endpoint-systems/remediation/safe/clear-caches/Clear-WindowsUpdateCache.ps1'; Args = @(); Expect = @(1) }
        @{ Platform = 'Windows'; Name = 'D2 -WhatIf -SkipConnectivityTest'; Script = 'endpoint-systems/remediation/elevated/network-resets/Reset-NetworkStack.ps1'; Args = @('-WhatIf', '-SkipConnectivityTest'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'D2 -BackupOnly -SkipConnectivityTest'; Script = 'endpoint-systems/remediation/elevated/network-resets/Reset-NetworkStack.ps1'; Args = @('-BackupOnly', '-SkipConnectivityTest'); Expect = @(0); CleanBackup = $true }
        @{ Platform = 'Windows'; Name = 'D2 non-interactive, no -Force (must refuse)'; Script = 'endpoint-systems/remediation/elevated/network-resets/Reset-NetworkStack.ps1'; Args = @('-SkipConnectivityTest'); Expect = @(1) }
        @{ Platform = 'Windows'; Name = 'D3 -WhatIf'; Script = 'cloud-services/m365/remediation/Reset-OutlookProfile.ps1'; Args = @('-WhatIf'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'D3 non-interactive, no -Force (must refuse)'; Script = 'cloud-services/m365/remediation/Reset-OutlookProfile.ps1'; Args = @(); Expect = @(0, 1); CheckOutlook = $true }
        @{ Platform = 'Windows'; Name = 'B4 -WhatIf'; Script = 'endpoint-systems/remediation/safe/restart-services/Restart-CommonServices.ps1'; Args = @('-WhatIf'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'B4 non-interactive, no -Force (must refuse)'; Script = 'endpoint-systems/remediation/safe/restart-services/Restart-CommonServices.ps1'; Args = @(); Expect = @(0, 1) }
        # macOS: run with /bin/bash, the bash 3.2 that ships with macOS.
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A1 endpoint security (macOS)'; Script = "$ep/get-endpoint-security-status-macos.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A2 --passive (neighbor table only, nothing sent)'; Script = "$net/get-home-network-map.sh"; Args = @('--passive'); Expect = @(0); MustContain = 'Passive: nothing is sent' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A3 Wi-Fi (macOS, local)'; Script = "$net/get-wifi-security-audit-macos.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A4 listening ports (no --scan-lan)'; Script = "$ep/get-open-port-scan.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A5 browsers (macOS)'; Script = "$si/get-browser-security-check.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A6 updates (macOS, last check, no --online)'; Script = "$si/get-update-compliance-macos.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A8 inventory (macOS)'; Script = 'endpoint-systems/audit/software-inventory/get-home-device-inventory.sh'; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'Bundle --passive (A7 not run) + A9 report'; Script = "$diag/run-home-audit-bundle.sh"; Args = @('--passive', '--technician', 'Test'); Expect = @(0); MustContain = 'Report written' }
        # Linux: the same, with the Linux scripts.
        @{ Platform = 'Linux'; Name = 'Bundle --passive (A7 not run) + A9 report if pwsh is installed'; Script = "$diag/run-home-audit-bundle.sh"; Args = @('--passive', '--technician', 'Test'); Expect = @(0); MustContain = 'Not run with --passive' }
        @{ Platform = 'Linux'; Name = 'A1 endpoint security (Linux)'; Script = "$ep/get-endpoint-security-status-linux.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'A2 --passive (neighbor table only, nothing sent)'; Script = "$net/get-home-network-map.sh"; Args = @('--passive'); Expect = @(0); MustContain = 'Passive: nothing is sent' }
        @{ Platform = 'Linux'; Name = 'A3 Wi-Fi (Linux, local)'; Script = "$net/get-wifi-security-audit-linux.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'A4 listening ports (no --scan-lan)'; Script = "$ep/get-open-port-scan.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'A5 browsers (Linux)'; Script = "$si/get-browser-security-check.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'A6 updates (Linux, local package lists, no --online)'; Script = "$si/get-update-compliance-linux.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'A8 inventory (Linux)'; Script = 'endpoint-systems/audit/software-inventory/get-home-device-inventory.sh'; Args = @(); Expect = @(0) }
        # Active network cases: never run without -AllowActiveNetwork.
        @{ Platform = 'Windows'; Name = 'A2 ping sweep of the local subnet'; Script = "$net/Get-HomeNetworkMap.ps1"; Args = @(); Expect = @(0); Active = 'ping sweep of the whole local subnet + reverse DNS' }
        @{ Platform = 'Windows'; Name = 'A2 -SkipPing'; Script = "$net/Get-HomeNetworkMap.ps1"; Args = @('-SkipPing'); Expect = @(0); Active = 'reverse DNS lookups of neighbors via the DNS server' }
        @{ Platform = 'Windows'; Name = 'A4 -ScanLan'; Script = "$ep/Get-OpenPortScan.ps1"; Args = @('-ScanLan'); Expect = @(0); Active = 'ping sweep + TCP probes of 11 ports on every device' }
        @{ Platform = 'Windows'; Name = 'A7 router check'; Script = "$net/Get-RouterSecurityCheck.ps1"; Args = @('-SkipChecklistPrompt'); Expect = @(0); Active = 'TCP/HTTP to the gateway + SSDP multicast' }
        @{ Platform = 'Windows'; Name = 'A6 -Online'; Script = "$si/Get-WindowsUpdateCompliance.ps1"; Args = @('-Online'); Expect = @(0); Active = 'Microsoft Update online search' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A2 ping sweep (macOS)'; Script = "$net/get-home-network-map.sh"; Args = @(); Expect = @(0); Active = 'ping sweep of the whole local subnet + hostname lookups' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A4 --scan-lan (macOS)'; Script = "$ep/get-open-port-scan.sh"; Args = @('--scan-lan'); Expect = @(0); Active = 'ping sweep + TCP probes of 11 ports on every device' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A7 router check (macOS)'; Script = "$net/get-router-security-check.sh"; Args = @('--skip-checklist-prompt'); Expect = @(0); Active = 'TCP/HTTP to the gateway + SSDP multicast' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'A6 --online (macOS)'; Script = "$si/get-update-compliance-macos.sh"; Args = @('--online'); Expect = @(0); Active = 'Apple software update servers' }
        @{ Platform = 'Linux'; Name = 'A7 router check (Linux)'; Script = "$net/get-router-security-check.sh"; Args = @('--skip-checklist-prompt'); Expect = @(0); Active = 'TCP/HTTP to the gateway + SSDP multicast' }
        @{ Platform = 'Linux'; Name = 'A6 --online (Linux)'; Script = "$si/get-update-compliance-linux.sh"; Args = @('--online'); Expect = @(0); Active = 'distribution package servers and the Snap Store' }
        @{ Platform = 'Linux'; Name = 'A2 ping sweep (Linux)'; Script = "$net/get-home-network-map.sh"; Args = @(); Expect = @(0); Active = 'ping sweep of the whole local subnet + hostname lookups' }
        @{ Platform = 'Linux'; Name = 'A4 --scan-lan (Linux)'; Script = "$ep/get-open-port-scan.sh"; Args = @('--scan-lan'); Expect = @(0); Active = 'ping sweep + TCP probes of 11 ports on every device' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'Bundle with A2 ping sweep and A7 (macOS)'; Script = "$diag/run-home-audit-bundle.sh"; Args = @(); Expect = @(0); Active = 'ping sweep + hostname lookups of the local subnet, TCP/HTTP to the gateway + SSDP multicast' }
        @{ Platform = 'Linux'; Name = 'Bundle with A2 ping sweep and A7 (Linux)'; Script = "$diag/run-home-audit-bundle.sh"; Args = @(); Expect = @(0); Active = 'ping sweep + hostname lookups of the local subnet, TCP/HTTP to the gateway + SSDP multicast' }
        # Batch B. B2 without -Passive / --passive sends traffic (gateway, DNS, internet, web).
        @{ Platform = 'Windows'; Name = 'B1 health snapshot'; Script = "$si/Get-ClientHealthSnapshot.ps1"; Args = @(); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'B2 -Passive (configuration only, nothing sent)'; Script = $b2ps; Args = @('-Passive'); Expect = @(0) }
        @{ Platform = 'Windows'; Name = 'B3 recent critical errors (48 h)'; Script = $b3ps; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'B1 health snapshot (macOS)'; Script = "$si/get-client-health-snapshot.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'B2 --passive (configuration only, nothing sent)'; Script = $b2sh; Args = @('--passive'); Expect = @(0); MustContain = 'Passive: nothing was sent' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'B3 recent critical errors (macOS)'; Script = $b3sh; Args = @(); Expect = @(0) }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'B4 --what-if (macOS)'; Script = $b4sh; Args = @('--what-if'); Expect = @(0); MustContain = 'nothing was changed' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'B4 non-interactive, no --force (must refuse)'; Script = $b4sh; Args = @(); Expect = @(1) }
        @{ Platform = 'Linux'; Name = 'B1 health snapshot (Linux)'; Script = "$si/get-client-health-snapshot.sh"; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'B2 --passive (configuration only, nothing sent)'; Script = $b2sh; Args = @('--passive'); Expect = @(0); MustContain = 'Passive: nothing was sent' }
        @{ Platform = 'Linux'; Name = 'B3 recent critical errors (Linux)'; Script = $b3sh; Args = @(); Expect = @(0) }
        @{ Platform = 'Linux'; Name = 'B4 --what-if (Linux)'; Script = $b4sh; Args = @('--what-if'); Expect = @(0); MustContain = 'nothing was changed' }
        @{ Platform = 'Linux'; Name = 'B4 non-interactive, no --force (must refuse)'; Script = $b4sh; Args = @(); Expect = @(1) }
        @{ Platform = 'Windows'; Name = 'B2 full connectivity test'; Script = $b2ps; Args = @(); Expect = @(0); Active = 'ping gateway, DNS lookup, TCP 443 to 1.1.1.1/8.8.8.8, HTTP(S) to www.msftconnecttest.com and 3 cloud endpoints' }
        @{ Platform = 'macOS'; Shell = '/bin/bash'; Name = 'B2 full connectivity test (macOS)'; Script = $b2sh; Args = @(); Expect = @(0); Active = 'ping gateway, DNS lookup, TCP 443 to 1.1.1.1/8.8.8.8, HTTP(S) to www.msftconnecttest.com and 3 cloud endpoints' }
        @{ Platform = 'Linux'; Name = 'B2 full connectivity test (Linux)'; Script = $b2sh; Args = @(); Expect = @(0); Active = 'ping gateway, DNS lookup, TCP 443 to 1.1.1.1/8.8.8.8, HTTP(S) to www.msftconnecttest.com and 3 cloud endpoints' }
        @{ Platform = 'Windows'; Name = 'D2 -WhatIf with connectivity test'; Script = 'endpoint-systems/remediation/elevated/network-resets/Reset-NetworkStack.ps1'; Args = @('-WhatIf'); Expect = @(0); Active = 'ping gateway, DNS lookup, TCP to www.msftconnecttest.com' }
    )
    if ($AllowActiveNetwork) {
        Write-Host ('-AllowActiveNetwork: active cases WILL send traffic on {0}.' -f (Get-ActiveScope)) -ForegroundColor Yellow
    }
    foreach ($case in $cases) {
        $label = 'Runtime ({0}): {1}' -f $case.Platform, $case.Name
        if ($case.Platform -ne $platform) {
            Add-Result $label 'NOT RUN' ('{0} only; this computer is {1}' -f $case.Platform, $platform)
            continue
        }
        if ($case.Active -and -not $AllowActiveNetwork) {
            Add-Result $label 'NOT RUN' ('active network ({0}); needs -AllowActiveNetwork and approval' -f $case.Active)
            continue
        }
        $script = Join-RepoPath $case.Script
        if (-not (Test-Path -LiteralPath $script)) { Add-Result $label FAIL ('script not found: {0}' -f $case.Script); continue }
        $out = Join-Path $work ('runtime-{0}' -f ($case.Name -replace '[^A-Za-z0-9]+', '-'))
        $null = New-Item -ItemType Directory -Path $out -Force
        $profileBefore = if ($case.CheckOutlook) { Get-ProfileDefault } else { '' }
        if ($script -like '*.sh') {
            # stdin from /dev/null: nothing may ever wait for keyboard input.
            $bashArgs = (@($case.Args) + @('--output', $out) | ForEach-Object { Format-BashQuote $_ }) -join ' '
            $shell = $(if ($case.Shell) { $case.Shell } else { 'bash' })
            $r = Invoke-Bash -Shell $shell -Command ('{0} {1} {2} </dev/null' -f $shell, (Format-BashQuote (ConvertTo-BashPath $script)), $bashArgs)
            $console = $r.Output
            $code = $r.Code
        }
        else {
            # -NonInteractive: nothing may ever wait for keyboard input, and confirmation must refuse.
            $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script) + $case.Args + @('-OutputPath', $out)
            $console = & $psExe @argList 2>&1
            $code = $LASTEXITCODE
        }
        ($console | Out-String) | Set-Content -LiteralPath (Join-Path $out 'console.txt') -Encoding UTF8
        $problems = @()
        if ($case.Expect -notcontains $code) { $problems += ('exit code {0}, expected {1}' -f $code, ($case.Expect -join ' or ')) }
        if ($case.CheckOutlook -and (Get-ProfileDefault) -ne $profileBefore) { $problems += 'Outlook default profile CHANGED during a refusal test' }
        foreach ($pattern in @($case.MustContain)) {
            if ($pattern -and ($console | Out-String) -notmatch $pattern) { $problems += ('console does not match "{0}"' -f $pattern) }
        }
        $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File -Recurse)
        if ($json.Count -eq 0) { $problems += 'no JSON result written' }
        else {
            $v = & $psExe -NoProfile -ExecutionPolicy Bypass -File $validator -Path $out 2>&1
            if ($LASTEXITCODE -ne 0) { $problems += ('schema: {0}' -f ((@($v) | Where-Object { "$_" -match 'error' } | Select-Object -First 3) -join '; ')) }
            foreach ($j in $json) {
                $result = Get-Content -LiteralPath $j.FullName -Raw | ConvertFrom-Json
                foreach ($e in @($result.Findings | Where-Object { $_.Status -eq 'ERROR' })) {
                    if ($case.AllowError -notcontains $e.Check) { $problems += ('ERROR finding: {0}: {1}' -f $e.Check, $e.Detail) }
                }
            }
        }
        if ($case.CleanBackup) {
            # Remove the backup folder this test created (its path is in the result's evidence).
            foreach ($j in $json) {
                $folder = ((Get-Content -LiteralPath $j.FullName -Raw | ConvertFrom-Json).Findings | Where-Object { $_.Check -eq 'Settings saved' -and $_.Status -eq 'PASS' }).Evidence.Folder
                if ($folder -and (Split-Path $folder -Leaf) -like 'NetworkStackBackup_*' -and (Test-Path -LiteralPath $folder)) { Remove-Item -LiteralPath $folder -Recurse -Force }
            }
        }
        if ($problems.Count -eq 0) { Add-Result $label PASS ('exit {0}; {1} result file(s) valid' -f $code, $json.Count) }
        else { Add-Result $label FAIL (($problems -join "`n") + "`nconsole: " + (Join-Path $out 'console.txt')) }
    }
}

# --- Summary -----------------------------------------------------------------------------
Write-Host ''
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
$notRun = @($results | Where-Object { $_.Result -eq 'NOT RUN' }).Count
Write-Host ('{0} step(s): {1} passed, {2} failed, {3} not run. Work folder: {4}' -f $results.Count, @($results | Where-Object { $_.Result -eq 'PASS' }).Count, $failed, $notRun, $work)
Write-Host 'The work folder holds this run''s logs and exported results; it is outside the repository and is not committed.' -ForegroundColor DarkGray
if ($failed -gt 0) { exit 1 }
exit 0
