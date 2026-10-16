<#
.SYNOPSIS
    Development-side verification for the toolkit: parsers, PSScriptAnalyzer, ShellCheck,
    bash 3.2 compatibility scan, embedded-helper check, bash helper unit tests and JSON schema
    validation. Never run on client machines.

.DESCRIPTION
    Steps (each reports PASS / FAIL / NOT RUN with the reason):
      1  PowerShell parser on every .ps1/.psm1 (Windows PowerShell 5.1, and PowerShell 7 if installed)
      2  PSScriptAnalyzer (PSAvoidUsingWriteHost excluded: console tools print to the screen on purpose)
      3  bash -n on every .sh (bash in WSL; also bash 3.2 at /opt/bash-3.2 in WSL if built)
      4  ShellCheck on every .sh
      5  bash 4+ / GNU-only construct scan (tests/bash/check-bash32-compat.sh)
      6  Sync-MSPEmbeddedHelper.ps1 -Check, plus a tamper test in a temporary copy
      7  bash helper unit tests in WSL (as a normal user and as root; bash 3.2 too if built),
         cross-checked from PowerShell: JSON escaping round-trip, ID parity, schema validation
      8  PowerShell helper unit tests (tests/Test-MSPToolkitCommon.ps1) on 5.1 and 7
      9  Runtime smoke tests of the Windows scripts on this PC, results validated against schema 2.0.
         PASSIVE BY DEFAULT: only cases that stay on this PC run (local diagnostics, remediation
         with -WhatIf, non-interactive refusal checks). Cases that send traffic beyond this PC
         (ping sweep, reverse DNS of neighbors, LAN port scan, router/SSDP checks, Microsoft
         Update online search, connectivity probes) are listed as NOT RUN unless
         -AllowActiveNetwork is given.
    _archive\ is never scanned.

.PARAMETER Path
    Limit steps 1-5 to these files or folders (relative to the repository root). Default: all.

.PARAMETER Distro
    WSL distribution used for bash steps. Default: Ubuntu.

.PARAMETER TestUser
    Non-root WSL account used to run tests as a normal user. Default: msptest.

.PARAMETER AllowActiveNetwork
    Also run the runtime cases that send network traffic beyond this PC (see step 9). The local
    subnet and the cases are printed first. Only use with approval for that network.

.PARAMETER SkipRuntime
    Skip step 9 (runtime smoke tests).

.EXAMPLE
    .\tests\Invoke-ToolkitTests.ps1

.EXAMPLE
    .\tests\Invoke-ToolkitTests.ps1 -Path endpoint-systems\utilities, tests

.NOTES
    Risk Level    : Safe -- reads repository files; writes only to a temporary folder
    Prerequisites : Windows PowerShell 5.1 | PSScriptAnalyzer (in a module path or
                    %LOCALAPPDATA%\PSModules) | ShellCheck | WSL with bash | PowerShell 7 optional
    Exit code     : 0 when every step that ran passed, 1 otherwise
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Add-Result (Step, Result, Detail) is called ~40 times; positional calls keep each step on one readable line.')]
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
    if ($Path.Count -gt 0) { $bases = @($Path | ForEach-Object { Join-Path -Path $root -ChildPath $_ }) }
    $files = foreach ($b in $bases) {
        if (Test-Path -LiteralPath $b -PathType Leaf) { Get-Item -LiteralPath $b }
        elseif (Test-Path -LiteralPath $b) { Get-ChildItem -LiteralPath $b -Recurse -File }
    }
    return @($files | Where-Object { $Extension -contains $_.Extension -and $_.FullName -notmatch '\\(_archive|\.git)\\' } | Sort-Object FullName -Unique)
}

function Get-Relative { param([string]$Full) return $Full.Substring($root.Length + 1) }

# --- Tool discovery ----------------------------------------------------------------------
$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $pwsh -and (Test-Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe")) { $pwsh = "$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe" }
$shellcheck = (Get-Command shellcheck -ErrorAction SilentlyContinue).Source
if (-not $shellcheck) {
    $shellcheck = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter shellcheck.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}
$pssa = Get-Module -ListAvailable PSScriptAnalyzer | Select-Object -First 1
if (-not $pssa -and (Test-Path "$env:LOCALAPPDATA\PSModules\PSScriptAnalyzer")) { $pssa = "$env:LOCALAPPDATA\PSModules\PSScriptAnalyzer" }

$wslOk = $false
try {
    $probe = (& wsl.exe -d $Distro -- bash -c 'echo ok' 2>$null) -join ''
    $wslOk = ($probe -replace "`0", '').Trim() -eq 'ok'
}
catch { $wslOk = $false }

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $drive = $WindowsPath.Substring(0, 1).ToLower()
    return ('/mnt/{0}{1}' -f $drive, ($WindowsPath.Substring(2) -replace '\\', '/'))
}

function Invoke-Wsl {
    <# Runs a bash command line in WSL; returns @{ Code; Output }. #>
    param([string]$Command, [string]$User = 'root')
    $out = & wsl.exe -d $Distro -u $User -- bash -c $Command 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Code = $code; Output = (($out | ForEach-Object { "$_" -replace "`0", '' }) -join "`n") }
}

function Format-BashQuote { param([string]$Text) return ("'{0}'" -f ($Text -replace "'", "'\''")) }

$rootWsl = ConvertTo-WslPath $root
$bash32 = $false
if ($wslOk) { $bash32 = ((Invoke-Wsl -Command 'test -x /opt/bash-3.2/bin/bash && echo yes').Output.Trim() -eq 'yes') }
$userOk = $false
if ($wslOk) { $userOk = ((Invoke-Wsl -Command ('id -u {0} >/dev/null 2>&1 && echo yes' -f $TestUser)).Output.Trim() -eq 'yes') }

$psFiles = Get-RepoFile -Extension @('.ps1', '.psm1')
$shFiles = Get-RepoFile -Extension @('.sh')

# --- 1 Parsers ---------------------------------------------------------------------------
$bad = foreach ($f in $psFiles) {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    foreach ($e in $errs) { '{0}:{1} {2}' -f (Get-Relative $f.FullName), $e.Extent.StartLineNumber, $e.Message }
}
if ($bad) { Add-Result 'Parse (Windows PowerShell 5.1)' FAIL (($bad | Select-Object -First 20) -join "`n") }
else { Add-Result 'Parse (Windows PowerShell 5.1)' PASS ('{0} file(s)' -f $psFiles.Count) }

if ($pwsh) {
    $list = Join-Path $work 'psfiles.txt'
    $psFiles.FullName | Set-Content -LiteralPath $list -Encoding UTF8
    $code = 'Get-Content -LiteralPath ''{0}'' | ForEach-Object {{ $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($_, [ref]$null, [ref]$e); foreach ($x in $e) {{ ''{{0}}:{{1}} {{2}}'' -f $_, $x.Extent.StartLineNumber, $x.Message }} }}' -f $list
    $out = & $pwsh -NoProfile -Command $code
    if ($out) { Add-Result 'Parse (PowerShell 7)' FAIL (($out | Select-Object -First 20) -join "`n") }
    else { Add-Result 'Parse (PowerShell 7)' PASS ('{0} file(s)' -f $psFiles.Count) }
}
else { Add-Result 'Parse (PowerShell 7)' 'NOT RUN' 'pwsh not installed' }

# --- 2 PSScriptAnalyzer ------------------------------------------------------------------
if ($pssa) {
    Import-Module $pssa -ErrorAction Stop
    $issues = foreach ($f in $psFiles) {
        Invoke-ScriptAnalyzer -Path $f.FullName -ExcludeRule PSAvoidUsingWriteHost |
            ForEach-Object { '{0}:{1} [{2}] {3}' -f (Get-Relative $f.FullName), $_.Line, $_.RuleName, ($_.Message -split "`n")[0] }
    }
    $issues = @($issues)
    if ($issues.Count -gt 0) {
        $byFile = $issues | ForEach-Object { ($_ -split ':')[0] } | Group-Object | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count }
        Add-Result 'PSScriptAnalyzer' FAIL ('{0} finding(s): {1}' -f $issues.Count, ($byFile -join '; '))
        $issues | Set-Content -LiteralPath (Join-Path $work 'pssa.txt') -Encoding UTF8
    }
    else { Add-Result 'PSScriptAnalyzer' PASS ('{0} file(s), PSAvoidUsingWriteHost excluded' -f $psFiles.Count) }
}
else { Add-Result 'PSScriptAnalyzer' 'NOT RUN' 'module not found' }

# --- 3 bash -n ---------------------------------------------------------------------------
if ($shFiles.Count -eq 0) { Add-Result 'bash -n' 'NOT RUN' 'no .sh files in scope' }
elseif (-not $wslOk) { Add-Result 'bash -n' 'NOT RUN' "WSL distro '$Distro' not available" }
else {
    $quoted = ($shFiles | ForEach-Object { Format-BashQuote (ConvertTo-WslPath $_.FullName) }) -join ' '
    $shells = @('bash')
    if ($bash32) { $shells += '/opt/bash-3.2/bin/bash' }
    foreach ($sh in $shells) {
        $r = Invoke-Wsl -Command ('rc=0; for f in {0}; do {1} -n "$f" || rc=1; done; exit $rc' -f $quoted, $sh)
        $label = 'bash -n ({0})' -f $(if ($sh -eq 'bash') { 'bash 5 in WSL' } else { 'bash 3.2.57' })
        if ($r.Code -eq 0) { Add-Result $label PASS ('{0} file(s)' -f $shFiles.Count) } else { Add-Result $label FAIL $r.Output }
    }
    if (-not $bash32) { Add-Result 'bash -n (bash 3.2.57)' 'NOT RUN' 'bash 3.2 not built at /opt/bash-3.2 in WSL' }
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
elseif (-not $wslOk) { Add-Result 'bash 3.2 construct scan' 'NOT RUN' 'WSL not available' }
else {
    # The scanner and the test file mention the constructs they look for, so skip both.
    $scan = @($shFiles | Where-Object { $_.Name -notin @('check-bash32-compat.sh') })
    $quoted = ($scan | ForEach-Object { Format-BashQuote (ConvertTo-WslPath $_.FullName) }) -join ' '
    $r = Invoke-Wsl -Command ('bash {0}/tests/bash/check-bash32-compat.sh {1}' -f (Format-BashQuote $rootWsl), $quoted)
    if ($r.Code -eq 0) { Add-Result 'bash 3.2 construct scan' PASS $r.Output } else { Add-Result 'bash 3.2 construct scan' FAIL $r.Output }
}

# --- 6 Embedded helpers ------------------------------------------------------------------
$sync = Join-Path $root 'endpoint-systems\utilities\Sync-MSPEmbeddedHelper.ps1'
$out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $sync -Check 2>&1
if ($LASTEXITCODE -eq 0) { Add-Result 'Embedded helpers (Sync -Check)' PASS ((@($out) | Select-Object -Last 1) -join '') }
else { Add-Result 'Embedded helpers (Sync -Check)' FAIL ((@($out) | Where-Object { $_ -match 'MISMATCH|PROBLEM' }) -join "`n") }

# Tamper test in a throwaway copy: generate, verify, hand-edit, verify again (must fail).
$fake = Join-Path $work 'synctest'
$util = Join-Path $fake 'endpoint-systems\utilities'
$null = New-Item -ItemType Directory -Path $util -Force
Copy-Item (Join-Path $root 'endpoint-systems\utilities\MSPToolkit.Common.psm1'), (Join-Path $root 'endpoint-systems\utilities\msp-toolkit-common.sh'), $sync -Destination $util
[System.IO.File]::WriteAllText((Join-Path $fake 'a.ps1'), "param()`r`n#region MSPToolkit (generated) Sections=Core`r`n#endregion MSPToolkit (generated)`r`n", (New-Object System.Text.UTF8Encoding($true)))
[System.IO.File]::WriteAllText((Join-Path $fake 'b.sh'), "#!/usr/bin/env bash`n#region MSPToolkit (generated) Sections=Core,Net`n#endregion MSPToolkit (generated)`n", (New-Object System.Text.UTF8Encoding($false)))
$fakeSync = Join-Path $util 'Sync-MSPEmbeddedHelper.ps1'
$null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fakeSync -Check; $c0 = $LASTEXITCODE
$null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fakeSync; $c1 = $LASTEXITCODE
$null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fakeSync -Check; $c2 = $LASTEXITCODE
$bBytes = [System.IO.File]::ReadAllBytes((Join-Path $fake 'b.sh'))
$hasCr = [array]::IndexOf($bBytes, [byte]13) -ge 0
$hasBom = $bBytes[0] -eq 0xEF
$bText = [System.IO.File]::ReadAllText((Join-Path $fake 'b.sh'))
[System.IO.File]::WriteAllText((Join-Path $fake 'b.sh'), ($bText -replace 'MSP_SCHEMA_VERSION=''2.0''', 'MSP_SCHEMA_VERSION=''9.9'''), (New-Object System.Text.UTF8Encoding($false)))
$null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fakeSync -Check; $c3 = $LASTEXITCODE
$ok = ($c0 -eq 1) -and ($c1 -eq 0) -and ($c2 -eq 0) -and (-not $hasCr) -and (-not $hasBom) -and ($c3 -eq 1) -and $bText.Contains('msp_json_escape')
$detail = 'empty region -Check={0} (want 1), generate={1}, -Check={2} (want 0), .sh LF-only={3}, no BOM={4}, hand-edited .sh -Check={5} (want 1)' -f $c0, $c1, $c2, (-not $hasCr), (-not $hasBom), $c3
if ($ok) { Add-Result 'Sync tamper test (.ps1 + .sh)' PASS $detail } else { Add-Result 'Sync tamper test (.ps1 + .sh)' FAIL $detail }

# --- 7 bash helper unit tests + PowerShell cross-checks -----------------------------------
if (-not $wslOk) { Add-Result 'bash helper unit tests' 'NOT RUN' 'WSL not available' }
else {
    $runs = @(@{ Label = 'bash 5, root'; Shell = 'bash'; User = 'root' })
    if ($userOk) { $runs += @{ Label = ('bash 5, normal user ({0})' -f $TestUser); Shell = 'bash'; User = $TestUser } }
    else { Add-Result 'bash helper unit tests (normal user)' 'NOT RUN' ("WSL account '$TestUser' does not exist") }
    if ($bash32) {
        $runs += @{ Label = 'bash 3.2.57, root'; Shell = '/opt/bash-3.2/bin/bash'; User = 'root' }
        if ($userOk) { $runs += @{ Label = ('bash 3.2.57, normal user ({0})' -f $TestUser); Shell = '/opt/bash-3.2/bin/bash'; User = $TestUser } }
    }
    else { Add-Result 'bash helper unit tests (bash 3.2.57)' 'NOT RUN' 'bash 3.2 not built at /opt/bash-3.2 in WSL' }

    $i = 0
    foreach ($run in $runs) {
        $i++
        # Emit into a Linux-side temp folder (writable by any user), then copy back for PowerShell.
        $emit = '/tmp/msp-emit-{0}-{1}' -f $PID, $i
        $cmd = 'rm -rf {0}; mkdir -p {0}; chmod 777 {0}; cd {1} && {2} tests/bash/test-msp-helper.sh --emit {0}' -f $emit, (Format-BashQuote $rootWsl), $run.Shell
        $r = Invoke-Wsl -Command $cmd -User $run.User
        $last = ($r.Output -split "`n" | Where-Object { $_ -match 'passed, .* failed' } | Select-Object -Last 1)
        if ($r.Code -eq 0) { Add-Result ('bash helper unit tests ({0})' -f $run.Label) PASS $last }
        else { Add-Result ('bash helper unit tests ({0})' -f $run.Label) FAIL (($r.Output -split "`n" | Where-Object { $_ -match 'FAIL|passed' }) -join "`n") }

        $local = Join-Path $work ('emit{0}' -f $i)
        $null = New-Item -ItemType Directory -Path $local -Force
        $null = Invoke-Wsl -Command ('cp -r {0}/. {1}/ && rm -rf {0}' -f $emit, (Format-BashQuote (ConvertTo-WslPath $local)))

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

        # ID parity: bash msp_id_part vs PowerShell ConvertTo-MSPIdPart.
        $idFile = Join-Path $local 'id-cases.txt'
        if ((Test-Path $idFile) -and $i -eq 1) {
            Import-Module (Join-Path $root 'endpoint-systems\utilities\MSPToolkit.Common.psm1') -Force
            $diff = foreach ($line in [System.IO.File]::ReadAllLines($idFile, [System.Text.Encoding]::UTF8)) {
                $parts = $line -split "`t", 2
                $ps = ConvertTo-MSPIdPart -Text $parts[0]
                if ($ps -ne $parts[1]) { '"{0}": bash {1}, PowerShell {2}' -f $parts[0], $parts[1], $ps }
            }
            if ($diff) { Add-Result 'Finding ID parity (bash vs PowerShell)' FAIL ($diff -join "`n") }
            else { Add-Result 'Finding ID parity (bash vs PowerShell)' PASS 'identical IDs for all cases' }
        }

        # Schema validation of the bash export.
        $export = Join-Path $local 'export'
        if (Test-Path $export) {
            $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'Test-MSPResultSchema.ps1') -Path $export 2>&1
            if ($LASTEXITCODE -eq 0) { Add-Result ('Schema 2.0 validation of bash export ({0})' -f $run.Label) PASS ((@($out) | Select-Object -Last 1) -join '') }
            else { Add-Result ('Schema 2.0 validation of bash export ({0})' -f $run.Label) FAIL ((@($out) | Where-Object { $_ -match 'error|FAIL' }) -join "`n") }
        }
    }
}

# --- 8 PowerShell helper unit tests ------------------------------------------------------
$unit = Join-Path $here 'Test-MSPToolkitCommon.ps1'
$out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $unit 2>&1
if ($LASTEXITCODE -eq 0) { Add-Result 'PowerShell helper unit tests (5.1)' PASS ((@($out) | Select-Object -Last 1) -join '') }
else { Add-Result 'PowerShell helper unit tests (5.1)' FAIL ((@($out) | Where-Object { "$_" -match 'FAIL|passed' }) -join "`n") }
if ($pwsh) {
    $out = & $pwsh -NoProfile -File $unit 2>&1
    if ($LASTEXITCODE -eq 0) { Add-Result 'PowerShell helper unit tests (7)' PASS ((@($out) | Select-Object -Last 1) -join '') }
    else { Add-Result 'PowerShell helper unit tests (7)' FAIL ((@($out) | Where-Object { "$_" -match 'FAIL|passed' }) -join "`n") }
}

# --- 9 Runtime smoke tests (passive unless -AllowActiveNetwork) ---------------------------
function Get-ProfileDefault {
    <# Current Outlook default profile, to prove D3 changed nothing during its refusal test. #>
    foreach ($v in '16.0', '15.0') {
        $p = Get-ItemProperty -LiteralPath ('HKCU:\Software\Microsoft\Office\{0}\Outlook' -f $v) -Name DefaultProfile -ErrorAction SilentlyContinue
        if ($p) { return [string]$p.DefaultProfile }
    }
    return ''
}

if ($SkipRuntime) { Add-Result 'Runtime smoke tests' 'NOT RUN' '-SkipRuntime' }
else {
    $r = 'security-operations\diagnostics'
    $ep = 'security-operations\diagnostics\endpoint-posture'
    $net = 'core-infrastructure\networking\diagnostics'
    $si = 'endpoint-systems\diagnostics\system-info'
    # Expect: allowed exit codes. Active: sends traffic beyond this PC (gated by -AllowActiveNetwork).
    $cases = @(
        @{ Name = 'A1 endpoint security'; Script = "$ep\Get-EndpointSecurityStatus.ps1"; Args = @(); Expect = @(0) }
        @{ Name = 'A3 Wi-Fi (netsh, local)'; Script = "$net\Get-WiFiSecurityAudit.ps1"; Args = @(); Expect = @(0) }
        @{ Name = 'A4 listening ports (no -ScanLan)'; Script = "$ep\Get-OpenPortScan.ps1"; Args = @(); Expect = @(0) }
        @{ Name = 'A5 browsers'; Script = "$si\Get-BrowserSecurityCheck.ps1"; Args = @(); Expect = @(0) }
        @{ Name = 'A6 updates (last scan, no -Online)'; Script = "$si\Get-WindowsUpdateCompliance.ps1"; Args = @(); Expect = @(0) }
        @{ Name = 'A8 inventory'; Script = 'endpoint-systems\audit\software-inventory\Get-HomeDeviceInventory.ps1'; Args = @(); Expect = @(0) }
        @{ Name = 'Bundle without A2/A7 + A9 report'; Script = "$r\Invoke-HomeAuditBundle.ps1"; Args = @('-Skip', 'Get-HomeNetworkMap,Get-RouterSecurityCheck', '-TechnicianName', 'Test'); Expect = @(0) }
        @{ Name = 'D1 -WhatIf'; Script = 'endpoint-systems\remediation\safe\clear-caches\Clear-WindowsUpdateCache.ps1'; Args = @('-WhatIf'); Expect = @(0) }
        @{ Name = 'D1 non-interactive, no -Force (must refuse)'; Script = 'endpoint-systems\remediation\safe\clear-caches\Clear-WindowsUpdateCache.ps1'; Args = @(); Expect = @(1) }
        @{ Name = 'D2 -WhatIf -SkipConnectivityTest'; Script = 'endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1'; Args = @('-WhatIf', '-SkipConnectivityTest'); Expect = @(0) }
        @{ Name = 'D2 -BackupOnly -SkipConnectivityTest'; Script = 'endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1'; Args = @('-BackupOnly', '-SkipConnectivityTest'); Expect = @(0); CleanBackup = $true }
        @{ Name = 'D2 non-interactive, no -Force (must refuse)'; Script = 'endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1'; Args = @('-SkipConnectivityTest'); Expect = @(1) }
        @{ Name = 'D3 -WhatIf'; Script = 'cloud-services\m365\remediation\Reset-OutlookProfile.ps1'; Args = @('-WhatIf'); Expect = @(0) }
        @{ Name = 'D3 non-interactive, no -Force (must refuse)'; Script = 'cloud-services\m365\remediation\Reset-OutlookProfile.ps1'; Args = @(); Expect = @(0, 1); CheckOutlook = $true }
        @{ Name = 'B4 -WhatIf'; Script = 'endpoint-systems\remediation\safe\restart-services\Restart-CommonServices.ps1'; Args = @('-WhatIf'); Expect = @(0) }
        @{ Name = 'B4 non-interactive, no -Force (must refuse)'; Script = 'endpoint-systems\remediation\safe\restart-services\Restart-CommonServices.ps1'; Args = @(); Expect = @(0, 1) }
        # Active network cases: never run without -AllowActiveNetwork.
        @{ Name = 'A2 ping sweep of the local subnet'; Script = "$net\Get-HomeNetworkMap.ps1"; Args = @(); Expect = @(0); Active = 'ping sweep of the whole local subnet' }
        @{ Name = 'A2 -SkipPing'; Script = "$net\Get-HomeNetworkMap.ps1"; Args = @('-SkipPing'); Expect = @(0); Active = 'reverse DNS lookups of neighbors via the DNS server' }
        @{ Name = 'A4 -ScanLan'; Script = "$ep\Get-OpenPortScan.ps1"; Args = @('-ScanLan'); Expect = @(0); Active = 'ping sweep + TCP probes of 11 ports on every device' }
        @{ Name = 'A7 router check'; Script = "$net\Get-RouterSecurityCheck.ps1"; Args = @('-SkipChecklistPrompt'); Expect = @(0); Active = 'TCP/HTTP to the gateway + SSDP multicast' }
        @{ Name = 'A6 -Online'; Script = "$si\Get-WindowsUpdateCompliance.ps1"; Args = @('-Online'); Expect = @(0); Active = 'Microsoft Update online search' }
        @{ Name = 'D2 -WhatIf with connectivity test'; Script = 'endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1'; Args = @('-WhatIf'); Expect = @(0); Active = 'ping gateway, DNS lookup, TCP to www.msftconnecttest.com' }
    )
    if ($AllowActiveNetwork) {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
        $ip = if ($route) { Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 }
        Write-Host ('-AllowActiveNetwork: active cases WILL send traffic on {0}/{1} (gateway {2}).' -f $ip.IPAddress, $ip.PrefixLength, $route.NextHop) -ForegroundColor Yellow
    }
    foreach ($case in $cases) {
        $label = 'Runtime: {0}' -f $case.Name
        if ($case.Active -and -not $AllowActiveNetwork) {
            Add-Result $label 'NOT RUN' ('active network ({0}); needs -AllowActiveNetwork and approval' -f $case.Active)
            continue
        }
        $script = Join-Path $root $case.Script
        $out = Join-Path $work ('runtime-{0}' -f ($case.Name -replace '[^A-Za-z0-9]+', '-'))
        $null = New-Item -ItemType Directory -Path $out -Force
        $profileBefore = if ($case.CheckOutlook) { Get-ProfileDefault } else { '' }
        # -NonInteractive: nothing may ever wait for keyboard input, and confirmation must refuse.
        $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script) + $case.Args + @('-OutputPath', $out)
        $console = & powershell.exe @argList 2>&1
        $code = $LASTEXITCODE
        ($console | Out-String) | Set-Content -LiteralPath (Join-Path $out 'console.txt') -Encoding UTF8
        $problems = @()
        if ($case.Expect -notcontains $code) { $problems += ('exit code {0}, expected {1}' -f $code, ($case.Expect -join ' or ')) }
        if ($case.CheckOutlook -and (Get-ProfileDefault) -ne $profileBefore) { $problems += 'Outlook default profile CHANGED during a refusal test' }
        $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File -Recurse)
        if ($json.Count -eq 0) { $problems += 'no JSON result written' }
        else {
            $v = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'Test-MSPResultSchema.ps1') -Path $out 2>&1
            if ($LASTEXITCODE -ne 0) { $problems += ('schema: {0}' -f ((@($v) | Where-Object { "$_" -match 'error' } | Select-Object -First 3) -join '; ')) }
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
if ($failed -gt 0) { exit 1 }
exit 0
