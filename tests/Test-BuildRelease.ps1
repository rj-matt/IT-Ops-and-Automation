#Requires -Version 7.0
<#
.SYNOPSIS
    Tests tools/Build-Release.ps1: package contents, checksums and refusals.

.DESCRIPTION
    Development-side check; never run on client machines. PowerShell 7 on any platform. Writes
    only to a temporary folder (the repository's dist/ is not touched).

      From this checkout   one top folder; README, START-HERE.txt, SHA256SUMS, both data files and
                           the scripts; nothing from _archive, tests, docs, .github, tools,
                           .playbooks, no Markdown but README, no results or logs; SHA256SUMS matches every
                           file; .sh entries executable; the .sha256 file matches the zip; a second
                           build of the same version is refused without -Force.
      From a copy (no git) the file list comes from the file system; stray result files and
                           logs are still left out.
      Hand-edited helper   an embedded helper copy changed in the copy: the build is refused and no
                           zip is written.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-BuildRelease.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
    Prerequisites : PowerShell 7
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-True (Name, Condition, Detail) is a one-line test assertion used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-buildtest-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
Add-Type -AssemblyName System.IO.Compression

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

function Invoke-Build {
    <# Runs the build script found under ROOT; returns @{ Code; Output }. #>
    param([string]$Root, [string[]]$BuildArgs)
    $ErrorActionPreference = 'Continue'
    $out = & $exe -NoProfile -NonInteractive -File (Join-Path $Root 'tools/Build-Release.ps1') @BuildArgs 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (@($out) -join "`n") }
}

function Get-ZipContent {
    <# Entry name -> bytes, plus each entry's external attributes. #>
    param([string]$Path)
    $result = @{ Files = @{}; Attributes = @{} }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($e in $zip.Entries) {
            $ms = New-Object System.IO.MemoryStream
            $s = $e.Open()
            try { $s.CopyTo($ms) } finally { $s.Dispose() }
            $result.Files[$e.FullName] = $ms.ToArray()
            $result.Attributes[$e.FullName] = $e.ExternalAttributes
        }
    }
    finally { $zip.Dispose() }
    return $result
}

function Get-Sha256 {
    param([byte[]]$Bytes)
    return ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($Bytes)) -replace '-', '').ToLowerInvariant()
}

try {
    # --- From this checkout ------------------------------------------------------------------
    $out1 = Join-Path $work 'out1'
    $r = Invoke-Build $repo @('-Version', 'v9.9.9-test', '-OutputPath', $out1)
    Assert-True 'build: exit 0' ($r.Code -eq 0) $r.Output
    $zipPath = Join-Path $out1 'MSP-Toolkit-9.9.9-test.zip'
    Assert-True 'build: leading v dropped from the version' (Test-Path -LiteralPath $zipPath) $r.Output
    if (Test-Path -LiteralPath $zipPath) {
        $z = Get-ZipContent $zipPath
        $names = @($z.Files.Keys)
        $prefix = 'MSP-Toolkit-9.9.9-test/'
        Assert-True 'zip: one top folder' (@($names | Where-Object { -not $_.StartsWith($prefix) }).Count -eq 0)
        $rel = @($names | ForEach-Object { $_.Substring($prefix.Length) })
        foreach ($must in 'README.md', 'START-HERE.txt', 'SHA256SUMS',
            'endpoint-systems/audit/software-inventory/approved-remote-tools.txt',
            'endpoint-systems/audit/software-inventory/software-watchlist.txt',
            'security-operations/diagnostics/run-home-audit-bundle.sh',
            'security-operations/diagnostics/Invoke-HomeAuditBundle.ps1',
            'endpoint-systems/utilities/MSPToolkit.Common.psm1') {
            Assert-True ('zip: contains {0}' -f $must) ($rel -contains $must)
        }
        $forbidden = @($rel | Where-Object { $_ -match '^(_archive|tests|docs|\.github|tools|\.playbooks)/' -or ($_ -like '*.md' -and $_ -ne 'README.md') -or $_ -match '\.(json|csv|log|gitkeep)$' -or $_ -match '(^|/)\.git' })
        Assert-True 'zip: nothing from _archive, tests, docs, .github, tools, .playbooks; no Markdown but README, no results or logs' ($forbidden.Count -eq 0) ($forbidden -join ', ')
        $other = @($rel | Where-Object { $_ -notmatch '\.(ps1|psm1|sh)$' -and $_ -notin @('README.md', 'START-HERE.txt', 'SHA256SUMS', 'endpoint-systems/audit/software-inventory/approved-remote-tools.txt', 'endpoint-systems/audit/software-inventory/software-watchlist.txt') })
        Assert-True 'zip: only scripts, the two data files, README, START-HERE.txt and SHA256SUMS' ($other.Count -eq 0) ($other -join ', ')
        $repoScripts = @(& git -C $repo ls-files '*.ps1' '*.psm1' '*.sh' | Where-Object { $_ -notmatch '^(_archive|tests|docs|\.github|tools|\.playbooks)/' })
        Assert-True 'zip: every tracked script outside the excluded folders' (@($repoScripts | Where-Object { $rel -notcontains $_ }).Count -eq 0) ((@($repoScripts | Where-Object { $rel -notcontains $_ })) -join ', ')

        $sumText = [System.Text.Encoding]::UTF8.GetString($z.Files[$prefix + 'SHA256SUMS'])
        $sumLines = @($sumText -split "`n" | Where-Object { $_ })
        $listed = @{}
        foreach ($l in $sumLines) { if ($l -match '^([0-9a-f]{64})  (.+)$') { $listed[$Matches[2]] = $Matches[1] } }
        Assert-True 'SHA256SUMS: one line per file except itself' ($listed.Count -eq ($rel.Count - 1) -and $sumLines.Count -eq $listed.Count) ('{0} lines, {1} files' -f $sumLines.Count, $rel.Count)
        $wrong = @($listed.Keys | Where-Object { -not $z.Files.ContainsKey($prefix + $_) -or (Get-Sha256 $z.Files[$prefix + $_]) -ne $listed[$_] })
        Assert-True 'SHA256SUMS: every hash matches' ($wrong.Count -eq 0) ($wrong -join ', ')
        Assert-True 'SHA256SUMS: LF line endings, sha256sum format' (-not $sumText.Contains("`r") -and $sumText.EndsWith("`n"))

        $shModes = @($rel | Where-Object { $_ -like '*.sh' } | ForEach-Object { ($z.Attributes[$prefix + $_] -shr 16) -band 0xFFFF } | Sort-Object -Unique)
        Assert-True 'zip: .sh entries are executable (0755)' ($shModes.Count -eq 1 -and $shModes[0] -eq 0x81ED) (($shModes | ForEach-Object { '{0:X}' -f $_ }) -join ', ')
        $crInSh = @($rel | Where-Object { $_ -like '*.sh' -and $z.Files[$prefix + $_] -contains [byte]13 })
        Assert-True 'zip: .sh files LF only' ($crInSh.Count -eq 0) ($crInSh -join ', ')
        $start = [System.Text.Encoding]::UTF8.GetString($z.Files[$prefix + 'START-HERE.txt'])
        Assert-True 'START-HERE: Windows unblock and run' ($start -match 'Unblock-File' -and $start -match 'Invoke-HomeAuditBundle\.ps1 -Passive')
        Assert-True 'START-HERE: macOS quarantine and run' ($start -match 'xattr -dr com\.apple\.quarantine' -and $start -match 'run-home-audit-bundle\.sh --passive')
        Assert-True 'START-HERE: checksum steps' ($start -match 'shasum -a 256 -c SHA256SUMS' -and $start -match 'sha256sum -c SHA256SUMS')

        $side = Join-Path $out1 'MSP-Toolkit-9.9.9-test.zip.sha256'
        $zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
        Assert-True 'zip .sha256: matches the zip' ((Test-Path -LiteralPath $side) -and ([System.IO.File]::ReadAllText($side)) -eq ('{0}  MSP-Toolkit-9.9.9-test.zip' -f $zipHash) + "`n")
    }
    $r = Invoke-Build $repo @('-Version', '9.9.9-test', '-OutputPath', $out1)
    Assert-True 'rebuild without -Force: refused (exit 1)' ($r.Code -eq 1 -and $r.Output -match 'already exists') $r.Output
    $r = Invoke-Build $repo @('-Version', 'bad/version', '-OutputPath', $out1)
    Assert-True 'bad version: refused (exit 1)' ($r.Code -eq 1) $r.Output

    # --- From a copy without git, with stray results -------------------------------------------
    $copy = Join-Path $work 'copy'
    $null = New-Item -ItemType Directory -Path $copy -Force
    foreach ($item in Get-ChildItem -LiteralPath $repo -Force | Where-Object { $_.Name -notin @('.git', '_archive', 'dist') }) {
        Copy-Item -LiteralPath $item.FullName -Destination $copy -Recurse -Force
    }
    $results = Join-Path $copy 'endpoint-systems/audit'
    [System.IO.File]::WriteAllText((Join-Path $results 'Get-LocalAdminReport_HOST_20260101-000000.json'), '{}')
    [System.IO.File]::WriteAllText((Join-Path $results 'run.log'), 'log')
    $out2 = Join-Path $work 'out2'
    $r = Invoke-Build $copy @('-Version', '1.0.0', '-OutputPath', $out2)
    Assert-True 'copy: exit 0' ($r.Code -eq 0) $r.Output
    Assert-True 'copy: file list from the file system' ($r.Output -match 'File list from file system') $r.Output
    $zip2 = Join-Path $out2 'MSP-Toolkit-1.0.0.zip'
    if (Test-Path -LiteralPath $zip2) {
        $n2 = @((Get-ZipContent $zip2).Files.Keys)
        Assert-True 'copy: stray result and log left out' (@($n2 | Where-Object { $_ -match '\.(json|log)$' }).Count -eq 0)
        Assert-True 'copy: no tests or docs' (@($n2 | Where-Object { $_ -match '^MSP-Toolkit-1\.0\.0/(tests|docs|tools|\.github)/' -or ($_ -like '*.md' -and $_ -notlike '*/README.md') }).Count -eq 0)
    }

    # --- Hand-edited embedded helper: refused --------------------------------------------------
    $victim = Join-Path $copy 'security-operations/diagnostics/run-home-audit-bundle.sh'
    $text = [System.IO.File]::ReadAllText($victim)
    Assert-True 'tamper: the embedded helper line exists' ($text.Contains("MSP_SCHEMA_VERSION='2.0'"))
    [System.IO.File]::WriteAllText($victim, $text.Replace("MSP_SCHEMA_VERSION='2.0'", "MSP_SCHEMA_VERSION='9.9'"), (New-Object System.Text.UTF8Encoding($false)))
    $out3 = Join-Path $work 'out3'
    $r = Invoke-Build $copy @('-Version', '1.0.1', '-OutputPath', $out3)
    Assert-True 'tamper: build refused (exit 1)' ($r.Code -eq 1 -and $r.Output -match 'Sync-MSPEmbeddedHelper\.ps1 -Check failed') $r.Output
    Assert-True 'tamper: no zip written' (-not (Test-Path -LiteralPath (Join-Path $out3 'MSP-Toolkit-1.0.1.zip')))
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
