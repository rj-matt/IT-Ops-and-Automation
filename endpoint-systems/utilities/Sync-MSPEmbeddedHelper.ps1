<#
.SYNOPSIS
    Copies helper code into every toolkit script that embeds it (PowerShell scripts from
    MSPToolkit.Common.psm1, bash scripts from msp-toolkit-common.sh), or (-Check) verifies
    that every embedded copy matches its source exactly.

.DESCRIPTION
    Toolkit scripts must run standalone (for example, copied alone to a USB stick), so they
    carry their own copy of the helper functions they use. This tool keeps those copies
    identical to the two single sources in endpoint-systems\utilities\:

        *.ps1  <-  MSPToolkit.Common.psm1
        *.sh   <-  msp-toolkit-common.sh

    A script opts in by containing these two lines (PowerShell: after its param() block;
    bash: before the code that calls the helpers):

        #region MSPToolkit (generated) Sections=Core,Net
        #endregion MSPToolkit (generated)

    Everything between them is replaced with the named sections of the matching source (Core is
    always included first), a "DO NOT EDIT" notice and a SHA256 hash of the embedded code.
    PowerShell scripts are written as UTF-8 with BOM and CRLF line endings (Windows PowerShell
    5.1 needs the BOM); bash scripts as UTF-8 without BOM and LF line endings (a BOM or CR
    breaks bash and the #! line).

    -Check mode changes nothing. It exits with code 1 when any script:
      - was edited by hand inside the generated region (hash no longer matches its content),
      - is out of date with its source (content differs from what would be generated),
      - names a section that does not exist, or has a begin marker without an end marker,
      - is a bash script containing a CR character or a BOM.

    Files under _archive\ and .git\ are never touched or checked.

.PARAMETER Root
    Repository root to scan. Defaults to two folders above this script.

.PARAMETER Check
    Verify only. Exit 0 when everything matches, 1 on any mismatch.

.EXAMPLE
    .\Sync-MSPEmbeddedHelper.ps1
    Regenerates embedded helper regions in all scripts.

.EXAMPLE
    .\Sync-MSPEmbeddedHelper.ps1 -Check
    Verifies all embedded regions; exits 1 if any drifted. Use before committing.

.EXAMPLE
    .\Sync-MSPEmbeddedHelper.ps1 -WhatIf
    Shows which scripts would be rewritten without writing anything.

.NOTES
    Purpose       : Keep embedded helper code identical to its single source.
    Use Case      : Toolkit maintenance (developers/Tier 3). Not run on client machines.
    Scope         : Rewrites only the generated region of .ps1 and .sh files in this repository.
    Risk Level    : Safe -- edits repository files only; supports -WhatIf; -Check is read-only.
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No | Modules: none
    Version       : 2.0.0
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Root,
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty inside param() defaults on Windows PowerShell 5.1, so resolve here.
$scriptFolder = $PSScriptRoot
if (-not $scriptFolder) { $scriptFolder = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
if (-not $Root) { $Root = Split-Path -Path (Split-Path -Path $scriptFolder -Parent) -Parent }
$Root = (Resolve-Path -LiteralPath $Root).ProviderPath.TrimEnd([char]0x5C, [char]0x2F)
$beginPattern = '^#region MSPToolkit \(generated\) Sections=([A-Za-z,]+)\s*$'
$endLine = '#endregion MSPToolkit (generated)'
# Built from a char code so this file stays plain ASCII (Windows PowerShell 5.1 reads
# BOM-less files as ANSI and would mangle a literal em dash).
$doNotEdit = '# DO NOT EDIT {0} regenerate with Sync-MSPEmbeddedHelper.ps1' -f [char]0x2014

function Get-NormalizedText {
    param([string]$Text)
    return (($Text -replace "`r`n", "`n") -replace "`r", "`n")
}

function Get-TextHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-NormalizedText -Text $Text))
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Read-HelperSection {
    <# Splits a helper source file into its "#region MSPHelper:<Name>" sections. #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Helper source not found: $Path" }
    $sourceLines = (Get-NormalizedText -Text ([System.IO.File]::ReadAllText($Path))) -split "`n"
    $found = [ordered]@{}
    $current = $null
    $buffer = $null
    foreach ($line in $sourceLines) {
        if ($line -match '^#region MSPHelper:([A-Za-z]+)\s*$') {
            $current = $Matches[1]
            $buffer = New-Object System.Collections.Generic.List[string]
            $buffer.Add($line)
            continue
        }
        if ($current) {
            $buffer.Add($line)
            if ($line -match ('^#endregion MSPHelper:{0}\s*$' -f $current)) {
                $found[$current] = ($buffer -join "`n")
                $current = $null
            }
        }
    }
    if ($current) { throw "Section '$current' in $Path has no matching #endregion line." }
    if (-not $found.Contains('Core')) { throw "$Path has no Core section." }
    return $found
}

# One entry per script language: which files, which source, how to write them.
$languages = @(
    [pscustomobject]@{
        Extension = '.ps1'
        Source    = 'endpoint-systems/utilities/MSPToolkit.Common.psm1'
        Sections  = (Read-HelperSection -Path (Join-Path -Path $scriptFolder -ChildPath 'MSPToolkit.Common.psm1'))
        NewLine   = "`r`n"
        Encoding  = (New-Object System.Text.UTF8Encoding($true))
    },
    [pscustomobject]@{
        Extension = '.sh'
        Source    = 'endpoint-systems/utilities/msp-toolkit-common.sh'
        Sections  = (Read-HelperSection -Path (Join-Path -Path $scriptFolder -ChildPath 'msp-toolkit-common.sh'))
        NewLine   = "`n"
        Encoding  = (New-Object System.Text.UTF8Encoding($false))
    }
)

function Get-ExpectedRegion {
    <# Returns the full text that should sit between (and including) the begin/end markers. #>
    param([string[]]$Requested, [string]$BeginLine, $Language)
    $sections = $Language.Sections
    $names = New-Object System.Collections.Generic.List[string]
    $names.Add('Core')
    foreach ($n in $Requested) { if ($n -and -not $names.Contains($n)) { $names.Add($n) } }
    $missing = @($names | Where-Object { -not $sections.Contains($_) })
    if ($missing.Count -gt 0) { throw ("Unknown helper section(s): {0}. Available in {1}: {2}" -f ($missing -join ', '), $Language.Source, ($sections.Keys -join ', ')) }
    $code = ($names | ForEach-Object { $sections[$_] }) -join "`n`n"
    $hash = Get-TextHash -Text $code
    $lines = @(
        $BeginLine,
        $doNotEdit,
        ('# Source: {0} | Sections: {1} | SHA256: {2}' -f $Language.Source, ($names -join ','), $hash),
        $code,
        $endLine
    )
    return [pscustomobject]@{ Text = ($lines -join "`n"); Hash = $hash; Code = $code }
}

# --- Process scripts ---------------------------------------------------------------------
$helperSources = @($languages | ForEach-Object { (Join-Path -Path $Root -ChildPath $_.Source) -replace '/', '\' })
$scripts = Get-ChildItem -LiteralPath $Root -Recurse -File |
    Where-Object { $_.Extension -in @('.ps1', '.sh') } |
    Where-Object { $_.FullName -notmatch '[\\/](_archive|\.git)[\\/]' -and $_.FullName -ne $PSCommandPath -and ($helperSources -notcontains ($_.FullName -replace '/', '\')) }

$problems = 0
$updated = 0
$unchanged = 0

foreach ($file in $scripts) {
    $language = $languages | Where-Object { $_.Extension -eq $file.Extension } | Select-Object -First 1
    $relative = $file.FullName.Substring($Root.Length).TrimStart('\', '/')
    $raw = [System.IO.File]::ReadAllText($file.FullName)

    if ($file.Extension -eq '.sh') {
        # Checked for every bash script, generated region or not: either one breaks bash.
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            Write-Host ('[PROBLEM]  {0}: starts with a UTF-8 BOM (breaks the #! line).' -f $relative) -ForegroundColor Red
            $problems++
        }
        if ($raw.Contains("`r")) {
            Write-Host ('[PROBLEM]  {0}: has CR (Windows) line endings; bash needs LF. Check .gitattributes / editor settings.' -f $relative) -ForegroundColor Red
            $problems++
        }
    }

    $text = Get-NormalizedText -Text $raw
    $lines = $text -split "`n"
    $beginIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $beginPattern) { $beginIndex = $i; break }
    }
    if ($beginIndex -lt 0) { continue }
    $requested = $Matches[1].Split(',') | ForEach-Object { $_.Trim() }
    $endIndex = -1
    for ($j = $beginIndex + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j].TrimEnd() -eq $endLine) { $endIndex = $j; break }
    }
    if ($endIndex -lt 0) {
        Write-Host ("[PROBLEM]  {0}: begin marker without '{1}'." -f $relative, $endLine) -ForegroundColor Red
        $problems++
        continue
    }

    try {
        $expected = Get-ExpectedRegion -Requested $requested -BeginLine $lines[$beginIndex].TrimEnd() -Language $language
    }
    catch {
        Write-Host ('[PROBLEM]  {0}: {1}' -f $relative, $_.Exception.Message) -ForegroundColor Red
        $problems++
        continue
    }
    $actualRegion = ($lines[$beginIndex..$endIndex] -join "`n")

    if ($actualRegion -eq $expected.Text) {
        $unchanged++
        Write-Host ('[OK]       {0}' -f $relative) -ForegroundColor Green
        continue
    }

    if ($Check) {
        # Work out why it differs so the fix is obvious.
        $reason = 'out of date with its helper source (run Sync-MSPEmbeddedHelper.ps1)'
        if ($endIndex - $beginIndex -ge 3 -and $lines[$beginIndex + 2] -match 'SHA256: ([0-9a-f]{64})') {
            $recordedHash = $Matches[1]
            $embeddedCode = ($lines[($beginIndex + 3)..($endIndex - 1)] -join "`n")
            if ((Get-TextHash -Text $embeddedCode) -ne $recordedHash) {
                $reason = 'edited by hand inside the generated region (hash mismatch)'
            }
        }
        elseif ($endIndex -eq $beginIndex + 1) {
            $reason = 'region is empty (never generated)'
        }
        Write-Host ('[MISMATCH] {0}: {1}' -f $relative, $reason) -ForegroundColor Red
        $problems++
        continue
    }

    $before = if ($beginIndex -gt 0) { $lines[0..($beginIndex - 1)] } else { @() }
    $after = if ($endIndex -lt $lines.Count - 1) { $lines[($endIndex + 1)..($lines.Count - 1)] } else { @() }
    $newText = ((@($before) + $expected.Text + @($after)) -join "`n")
    if ($language.NewLine -ne "`n") { $newText = $newText -replace "`n", $language.NewLine }
    if ($PSCmdlet.ShouldProcess($relative, 'Regenerate embedded MSPToolkit helper region')) {
        [System.IO.File]::WriteAllText($file.FullName, $newText, $language.Encoding)
        Write-Host ('[UPDATED]  {0}' -f $relative) -ForegroundColor Yellow
        $updated++
    }
}

Write-Host ''
if ($Check) {
    Write-Host ('Checked: {0} matching, {1} problem(s).' -f $unchanged, $problems)
    if ($problems -gt 0) { exit 1 }
    exit 0
}
Write-Host ('Updated: {0}  Unchanged: {1}  Problems: {2}' -f $updated, $unchanged, $problems)
if ($problems -gt 0) { exit 1 }
