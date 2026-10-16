<#
.SYNOPSIS
    Validates toolkit result JSON files (PowerShell or bash output) against result schema 2.0.

.DESCRIPTION
    Development-side check; never run on client machines. For every .json file given (or found
    under a given folder) it checks:
      - all required top-level fields exist with the right type and allowed values
        (SchemaVersion 2.0, CheckId, ScriptName, Version, Platform, OSVersion, Shell, Host, User,
        IsAdmin, RiskLevel, Parameters, Timestamp, EndTime, Summary, Findings, Data)
      - Timestamp/EndTime are ISO 8601 with offset (2026-10-16T14:05:09+02:00)
      - every finding has Id, Category, Check, Status, Severity, Target, Detail, Recommendation,
        Evidence; Status/Severity are allowed values; Id starts with "<CheckId>."
      - Summary counts equal the counted finding statuses
      - Data is an object whose values are arrays of objects
    Unknown top-level fields are reported as warnings (not failures).

    Files with SchemaVersion 1.0 are reported as LEGACY (not failures): the HTML report still
    reads them, but new scripts must write 2.0.

.PARAMETER Path
    One or more .json files or folders (folders are searched recursively).

.EXAMPLE
    .\tests\Test-MSPResultSchema.ps1 -Path C:\Temp\HomeAudit_PC1_20261016-101010

.NOTES
    Risk Level    : Read-Only (reads files only)
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No | Modules: none
    Exit code     : 0 all valid, 1 any failure, 2 no files found
    Version       : 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Path
)

$statusSet = @('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED', 'ERROR')
$severitySet = @('Critical', 'High', 'Medium', 'Low', 'Info')
$platformSet = @('Windows', 'macOS', 'Linux')
$riskSet = @('Read-Only', 'Safe', 'Elevated', 'Destructive')
$topLevel = @('SchemaVersion', 'CheckId', 'ScriptName', 'Version', 'Platform', 'OSVersion', 'Shell', 'Host', 'User',
    'IsAdmin', 'RiskLevel', 'Parameters', 'Timestamp', 'EndTime', 'Summary', 'Findings', 'Data')
$findingFields = @('Id', 'Category', 'Check', 'Status', 'Severity', 'Target', 'Detail', 'Recommendation', 'Evidence')
$isoPattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$'

function Test-IsString { param($Value) return ($Value -is [string]) }
function Test-IsObject { param($Value) return ($Value -is [System.Management.Automation.PSCustomObject]) }

function Get-RawJsonString {
    <# PowerShell 7 turns ISO date strings into DateTime while parsing, so read the raw text. #>
    param([string]$Json, [string]$Name)
    $m = [regex]::Match($Json, ('"{0}"\s*:\s*"([^"]*)"' -f [regex]::Escape($Name)))
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Test-ResultFile {
    param([string]$File)
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $raw = [System.IO.File]::ReadAllText($File)
    try {
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ File = $File; Result = 'FAIL'; Errors = @('Not valid JSON: ' + $_.Exception.Message); Warnings = @() }
    }
    if (-not (Test-IsObject $data)) {
        return [pscustomobject]@{ File = $File; Result = 'FAIL'; Errors = @('Top level is not a JSON object.'); Warnings = @() }
    }
    $names = @($data.PSObject.Properties.Name)
    if ([string]$data.SchemaVersion -eq '1.0') {
        return [pscustomobject]@{ File = $File; Result = 'LEGACY'; Errors = @(); Warnings = @('SchemaVersion 1.0 (readable by the report; new output must be 2.0).') }
    }

    foreach ($field in $topLevel) {
        if ($names -notcontains $field) { $errors.Add(('Missing top-level field "{0}".' -f $field)) }
    }
    foreach ($field in $names) {
        if ($topLevel -notcontains $field) { $warnings.Add(('Unknown top-level field "{0}".' -f $field)) }
    }
    if ($errors.Count -gt 0) {
        return [pscustomobject]@{ File = $File; Result = 'FAIL'; Errors = $errors.ToArray(); Warnings = $warnings.ToArray() }
    }

    if ($data.SchemaVersion -ne '2.0') { $errors.Add(('SchemaVersion is "{0}", expected "2.0".' -f $data.SchemaVersion)) }
    if (-not (Test-IsString $data.CheckId) -or $data.CheckId -notmatch '^[A-Za-z][A-Za-z0-9-]*$') { $errors.Add('CheckId must be a catalog ID such as "A1".') }
    foreach ($field in @('ScriptName', 'OSVersion', 'Shell', 'Host', 'User')) {
        $v = $data.$field
        if (-not (Test-IsString $v) -or -not $v) { $errors.Add(('{0} must be a non-empty string.' -f $field)) }
    }
    if (-not (Test-IsString $data.Version) -or $data.Version -notmatch '^\d+\.\d+\.\d+$') { $errors.Add('Version must look like 1.2.3.') }
    if ($platformSet -notcontains $data.Platform) { $errors.Add(('Platform "{0}" is not one of {1}.' -f $data.Platform, ($platformSet -join ', '))) }
    if ($riskSet -notcontains $data.RiskLevel) { $errors.Add(('RiskLevel "{0}" is not one of {1}.' -f $data.RiskLevel, ($riskSet -join ', '))) }
    if ($data.IsAdmin -isnot [bool]) { $errors.Add('IsAdmin must be true or false (JSON boolean).') }
    if (-not (Test-IsObject $data.Parameters)) { $errors.Add('Parameters must be a JSON object.') }
    else {
        foreach ($p in $data.Parameters.PSObject.Properties) {
            if (-not (Test-IsString $p.Value)) { $errors.Add(('Parameter "{0}" must be a string.' -f $p.Name)) }
        }
    }
    foreach ($field in @('Timestamp', 'EndTime')) {
        $text = Get-RawJsonString -Json $raw -Name $field
        if (-not $text -or $text -notmatch $isoPattern) { $errors.Add(('{0} must be ISO 8601 with offset, e.g. 2026-10-16T14:05:09+02:00 (found "{1}").' -f $field, $text)) }
    }

    $findings = @($data.Findings)
    if ($data.Findings -isnot [array] -and $null -ne $data.Findings) { $errors.Add('Findings must be a JSON array.') }
    $counts = @{}
    foreach ($s in $statusSet) { $counts[$s] = 0 }
    $index = 0
    foreach ($f in $findings) {
        $where = 'Finding #{0}' -f $index
        if (-not (Test-IsObject $f)) { $errors.Add(('{0} is not an object.' -f $where)); $index++; continue }
        $fNames = @($f.PSObject.Properties.Name)
        foreach ($field in $findingFields) {
            if ($fNames -notcontains $field) { $errors.Add(('{0}: missing "{1}".' -f $where, $field)) }
        }
        foreach ($field in @('Id', 'Category', 'Check', 'Target')) {
            if ($fNames -contains $field -and (-not (Test-IsString $f.$field) -or -not $f.$field)) { $errors.Add(('{0}: "{1}" must be a non-empty string.' -f $where, $field)) }
        }
        foreach ($field in @('Detail', 'Recommendation')) {
            if ($fNames -contains $field -and -not (Test-IsString $f.$field)) { $errors.Add(('{0}: "{1}" must be a string (may be empty).' -f $where, $field)) }
        }
        if ($statusSet -notcontains $f.Status) { $errors.Add(('{0}: Status "{1}" not allowed.' -f $where, $f.Status)) }
        else { $counts[$f.Status]++ }
        if ($severitySet -notcontains $f.Severity) { $errors.Add(('{0}: Severity "{1}" not allowed.' -f $where, $f.Severity)) }
        if ((Test-IsString $f.Id) -and -not $f.Id.StartsWith(('{0}.' -f $data.CheckId))) { $errors.Add(('{0}: Id "{1}" does not start with "{2}.".' -f $where, $f.Id, $data.CheckId)) }
        if ($fNames -contains 'Evidence' -and $null -ne $f.Evidence -and -not (Test-IsObject $f.Evidence)) { $errors.Add(('{0}: Evidence must be an object or null.' -f $where)) }
        $index++
    }

    if (-not (Test-IsObject $data.Summary)) { $errors.Add('Summary must be a JSON object.') }
    else {
        foreach ($s in $statusSet) {
            $v = $data.Summary.$s
            if ($null -eq $v -or -not ($v -is [int] -or $v -is [long])) { $errors.Add(('Summary.{0} must be an integer.' -f $s)) }
            elseif ([int64]$v -ne $counts[$s]) { $errors.Add(('Summary.{0} is {1} but {2} finding(s) have that status.' -f $s, $v, $counts[$s])) }
        }
    }

    if (-not (Test-IsObject $data.Data)) { $errors.Add('Data must be a JSON object.') }
    else {
        foreach ($table in $data.Data.PSObject.Properties) {
            $rows = $table.Value
            if ($null -ne $rows -and $rows -isnot [array] -and -not (Test-IsObject $rows)) { $errors.Add(('Data.{0} must be an array of objects.' -f $table.Name)); continue }
            foreach ($row in @($rows)) {
                if ($null -ne $row -and -not (Test-IsObject $row)) { $errors.Add(('Data.{0} contains a row that is not an object.' -f $table.Name)); break }
            }
        }
    }

    $result = 'PASS'
    if ($errors.Count -gt 0) { $result = 'FAIL' }
    return [pscustomobject]@{ File = $File; Result = $result; Errors = $errors.ToArray(); Warnings = $warnings.ToArray() }
}

$files = foreach ($p in $Path) {
    if (Test-Path -LiteralPath $p -PathType Container) { Get-ChildItem -LiteralPath $p -Filter '*.json' -File -Recurse | ForEach-Object { $_.FullName } }
    elseif (Test-Path -LiteralPath $p -PathType Leaf) { (Resolve-Path -LiteralPath $p).ProviderPath }
    else { Write-Warning ('Not found: {0}' -f $p) }
}
$files = @($files)
if ($files.Count -eq 0) {
    Write-Host 'No JSON files found.' -ForegroundColor Yellow
    exit 2
}

$failed = 0
foreach ($file in $files) {
    $r = Test-ResultFile -File $file
    $color = 'Green'
    if ($r.Result -eq 'FAIL') { $color = 'Red'; $failed++ }
    elseif ($r.Result -eq 'LEGACY') { $color = 'Yellow' }
    Write-Host ('[{0}] {1}' -f $r.Result, $file) -ForegroundColor $color
    foreach ($e in $r.Errors) { Write-Host ('    error: {0}' -f $e) -ForegroundColor Red }
    foreach ($w in $r.Warnings) { Write-Host ('    note : {0}' -f $w) -ForegroundColor DarkGray }
}
Write-Host ''
Write-Host ('{0} file(s) checked, {1} failed.' -f $files.Count, $failed)
if ($failed -gt 0) { exit 1 }
exit 0
