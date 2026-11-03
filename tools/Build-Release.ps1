#Requires -Version 7.0
<#
.SYNOPSIS
    Builds the technician package dist/MSP-Toolkit-<version>.zip: the scripts, the shared data
    files and README.md, with SHA256SUMS and START-HERE.txt. Development side; runs on PowerShell 7
    on Windows, macOS or Linux.

.DESCRIPTION
    1. Runs endpoint-systems/utilities/Sync-MSPEmbeddedHelper.ps1 -Check and refuses to build if
       any embedded helper copy is hand-edited or out of date.
    2. Collects the files: every .ps1, .psm1 and .sh, plus approved-remote-tools.txt,
       software-watchlist.txt and README.md. Never included: _archive/, tests/, docs/, .github/,
       tools/, .playbooks/, any other Markdown file, and anything else (results, logs). In a git checkout the
       list comes from "git ls-files", so untracked files are never packaged.
    3. Refuses if a .sh file has CR line endings (bash cannot run it).
    4. Writes the zip with one top folder, MSP-Toolkit-<version>/, holding the files at their
       repository paths plus SHA256SUMS (sha256sum format, every file in the package) and
       START-HERE.txt. .sh entries are marked executable for unzip on macOS/Linux.
    5. Writes MSP-Toolkit-<version>.zip.sha256 next to the zip.

.PARAMETER Version
    Version in the file name (letters, digits, . _ -; a leading "v" before a digit is dropped, so
    tag v1.2.0 gives 1.2.0). Default: the git tag on HEAD, otherwise dev-<short commit>.

.PARAMETER OutputPath
    Folder for the zip. Default: dist/ in the repository (ignored by git).

.PARAMETER Force
    Overwrite an existing zip of the same version.

.EXAMPLE
    pwsh -NoProfile -File tools/Build-Release.ps1 -Version 1.0.0

.NOTES
    Risk Level    : Safe -- reads the repository; writes only the zip, its .sha256 and a temporary folder
    Exit code     : 0 built, 1 refused or failed
    Version       : 1.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$OutputPath = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$pwshExe = (Get-Process -Id $PID).Path
$excludedTop = @('_archive', 'tests', 'docs', '.github', 'tools', '.playbooks', 'dist', '.git')
$dataFiles = @(
    'endpoint-systems/audit/software-inventory/approved-remote-tools.txt',
    'endpoint-systems/audit/software-inventory/software-watchlist.txt',
    'README.md'
)

function Exit-Build {
    param([string]$Message)
    Write-Host ('Refused: {0}' -f $Message) -ForegroundColor Red
    exit 1
}

function Get-GitOutput {
    <# Output lines of a git command in the repository, or $null when git or the repository is missing. #>
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return $null }
    $out = & git -C $root @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return @($out)
}

# --- Version ------------------------------------------------------------------------------
if (-not $Version) {
    $tag = Get-GitOutput @('describe', '--tags', '--exact-match', 'HEAD')
    $sha = Get-GitOutput @('rev-parse', '--short', 'HEAD')
    if ($tag) { $Version = [string]$tag[0] } elseif ($sha) { $Version = 'dev-{0}' -f $sha[0] } else { $Version = 'dev' }
}
$Version = $Version.Trim() -replace '^refs/tags/', '' -replace '^v(?=\d)', ''
if ($Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { Exit-Build ('version "{0}" may only contain letters, digits, ".", "_" and "-".' -f $Version) }
$name = 'MSP-Toolkit-{0}' -f $Version
if (-not $OutputPath) { $OutputPath = Join-Path $root 'dist' }
$zipPath = Join-Path $OutputPath ('{0}.zip' -f $name)
if ((Test-Path -LiteralPath $zipPath) -and -not $Force) { Exit-Build ('{0} already exists (use -Force to replace it).' -f $zipPath) }

# --- 1 Embedded helpers -------------------------------------------------------------------
$sync = Join-Path $root 'endpoint-systems/utilities/Sync-MSPEmbeddedHelper.ps1'
if (-not (Test-Path -LiteralPath $sync)) { Exit-Build 'Sync-MSPEmbeddedHelper.ps1 not found.' }
$syncOut = & { $ErrorActionPreference = 'Continue'; & $pwshExe -NoProfile -NonInteractive -File $sync -Check 2>&1 }
if ($LASTEXITCODE -ne 0) {
    @($syncOut) | Where-Object { "$_" -match 'MISMATCH|PROBLEM|out of date|hand-edited' } | Select-Object -First 20 | ForEach-Object { Write-Host ('  {0}' -f $_) }
    Exit-Build 'Sync-MSPEmbeddedHelper.ps1 -Check failed: an embedded helper copy is hand-edited or out of date. Run the sync, review, commit, then build.'
}
Write-Host ('Embedded helpers: {0}' -f ((@($syncOut) | Select-Object -Last 1) -join ''))

# --- 2 File list --------------------------------------------------------------------------
$tracked = Get-GitOutput @('ls-files', '-z')
if ($null -ne $tracked) {
    $source = 'git ls-files'
    $all = @(($tracked -join '') -split "`0" | Where-Object { $_ })
}
else {
    $source = 'file system (no git checkout)'
    $all = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($root.Length + 1) -replace '\\', '/' })
}
$files = @($all | Where-Object {
        $top = ($_ -split '/')[0]
        ($excludedTop -notcontains $top) -and ($_ -match '\.(ps1|psm1|sh)$')
    }) + $dataFiles | Sort-Object -Unique
foreach ($d in $dataFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $d))) { Exit-Build ('{0} is missing.' -f $d) }
}
$bad = @($files | Where-Object { ($excludedTop -contains ($_ -split '/')[0]) -or ($_ -like '*.md' -and $_ -ne 'README.md') })
if ($bad) { Exit-Build ('excluded path in the file list: {0}' -f ($bad -join ', ')) }
$missing = @($files | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_)) })
if ($missing) { Exit-Build ('tracked but missing on disk: {0}' -f ($missing -join ', ')) }

# --- 3 Line endings -----------------------------------------------------------------------
$crlf = @($files | Where-Object { $_ -like '*.sh' } | Where-Object { [System.IO.File]::ReadAllBytes((Join-Path $root $_)) -contains [byte]13 })
if ($crlf) { Exit-Build ('.sh file(s) with CR line endings (bash cannot run them): {0}' -f ($crlf -join ', ')) }

# --- 4 Package ----------------------------------------------------------------------------
$startHere = @"
MSP Toolkit $Version
====================

Read README.md for the full runbook, what each script checks and how to read the results.
Results contain user, device and account names: keep them with the client's records.
Check the download first. In this folder:
  Windows : Get-FileHash -Algorithm SHA256 <file>, compare with SHA256SUMS
  macOS   : shasum -a 256 -c SHA256SUMS
  Linux   : sha256sum -c SHA256SUMS

WINDOWS (Windows PowerShell 5.1, as administrator for complete results)
  1. Unblock before extracting: right-click the zip > Properties > Unblock > OK.
     (Already extracted? In PowerShell, in this folder: Get-ChildItem -Recurse | Unblock-File)
  2. Run the home audit, sending nothing on the network:
       powershell.exe -ExecutionPolicy Bypass -File .\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -Passive -TechnicianName "Your Name"
     Any single script runs the same way: powershell.exe -ExecutionPolicy Bypass -File .\<path>\<Script>.ps1

MACOS (bash 3.2 or later; sudo recommended for complete results)
  1. Remove the download quarantine from this folder:
       xattr -dr com.apple.quarantine "$name"
  2. Run the home audit, sending nothing on the network:
       sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --technician "Your Name"
     The HTML report needs PowerShell 7 (pwsh); without it the results are still written.

LINUX (bash; sudo recommended for complete results)
  1. Nothing to unblock. Run the home audit, sending nothing on the network:
       sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --technician "Your Name"

Without -Passive / --passive the audit also scans the local network and the router: only on a
network the client owns and has asked you to check.
"@

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-release-{0}' -f [guid]::NewGuid().ToString('N'))
$pkg = Join-Path $stage $name
try {
    $null = New-Item -ItemType Directory -Path $pkg -Force
    foreach ($f in $files) {
        $dest = Join-Path $pkg $f
        $null = New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force
        Copy-Item -LiteralPath (Join-Path $root $f) -Destination $dest
    }
    [System.IO.File]::WriteAllText((Join-Path $pkg 'START-HERE.txt'), ($startHere -replace "`r`n", "`n" -replace "`n", "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    $entries = @($files + 'START-HERE.txt' | Sort-Object)
    $sums = foreach ($f in $entries) { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $pkg $f)).Hash.ToLowerInvariant(), $f }
    [System.IO.File]::WriteAllText((Join-Path $pkg 'SHA256SUMS'), (($sums -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    $entries = @($entries + 'SHA256SUMS' | Sort-Object)

    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression
    $stream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
    $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in $entries) {
            $entry = $zip.CreateEntry(('{0}/{1}' -f $name, $f), [System.IO.Compression.CompressionLevel]::Optimal)
            # Unix mode in the upper 16 bits: rwxr-xr-x for .sh, rw-r--r-- for everything else.
            $mode = 0x81A4
            if ($f -like '*.sh') { $mode = 0x81ED }
            $entry.ExternalAttributes = $mode -shl 16
            $entry.LastWriteTime = [System.IO.File]::GetLastWriteTime((Join-Path $pkg $f))
            $out = $entry.Open()
            try { $bytes = [System.IO.File]::ReadAllBytes((Join-Path $pkg $f)); $out.Write($bytes, 0, $bytes.Length) }
            finally { $out.Dispose() }
        }
    }
    finally { $zip.Dispose(); $stream.Dispose() }
}
finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}

# --- 5 Checksum of the zip ----------------------------------------------------------------
$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText(('{0}.sha256' -f $zipPath), ('{0}  {1}.zip' -f $zipHash, $name) + "`n", (New-Object System.Text.UTF8Encoding($false)))
$scriptCount = @($files | Where-Object { $_ -match '\.(ps1|psm1|sh)$' }).Count
Write-Host ('Built {0} ({1:N0} KB): {2} scripts, {3} data files + README, START-HERE.txt, SHA256SUMS. File list from {4}.' -f $zipPath, ((Get-Item -LiteralPath $zipPath).Length / 1KB), $scriptCount, ($dataFiles.Count - 1), $source)
Write-Host ('SHA256 {0}' -f $zipHash)
exit 0
