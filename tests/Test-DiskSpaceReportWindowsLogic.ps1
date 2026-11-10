<#
.SYNOPSIS
    Runs B5 Get-DiskSpaceReport.ps1 against a fake Windows folder tree and mocked volume and
    health cmdlets, so its logic is tested on any platform.

.DESCRIPTION
    Development-side check; never run on client machines. The script's real folder walk runs on a
    fake C: drive built in a temporary folder (SystemDrive, windir, USERPROFILE, TEMP, LOCALAPPDATA
    and ProgramData point into it); the big files are sparse, so no real disk space is used.
    Get-CimInstance (volumes, reliability), Get-PhysicalDisk and Get-WinEvent are stand-ins.

      Volumes       C: 8 % free = WARN; D: 3 GB free = FAIL; a 0.5 GB EFI volume at 40 % = PASS
                    (judged on the percentage only).
      Folders       Largest folders of the profile and the system drive, with the biggest subfolder;
                    a symbolic link is not followed (counted once).
      Reclaimable   Windows.old, the Windows Update cache, the Recycle Bin, temp files, Delivery
                    Optimization, crash dumps: measured; nothing deleted (the tree is unchanged).
      Health        An unhealthy disk = FAIL Critical; reliability index 3.2 = WARN; disk errors in
                    the System log = WARN; then a healthy computer with no history (SKIPPED) and no errors.
      What to do    Biggest first, the Windows Update cache step points to D1, the backup step
                    comes first when a disk is unhealthy.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-DiskSpaceReportWindowsLogic.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-True (Name, Condition, Detail) is a one-line test assertion used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-b5-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$b5 = Join-Path $repo 'endpoint-systems/diagnostics/storage/Get-DiskSpaceReport.ps1'

$script:passed = 0
$script:failed = 0
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}
function Join-PathPart { param([string]$Base, [string[]]$Part) $p = $Base; foreach ($x in $Part) { $p = Join-Path $p $x }; return $p }
function Write-FakeFile {
    <# A sparse file of MB megabytes at PATH (parent folders created). #>
    param([string]$Path, [double]$MB)
    $null = New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
    try { $fs.SetLength([long]($MB * 1MB)) } finally { $fs.Dispose() }
}

# --- Fake C: drive ---------------------------------------------------------------------------
$c = Join-Path $work 'C'
$win = Join-Path $c 'Windows'
$profileDir = Join-PathPart $c 'Users', 'alice'
$local = Join-PathPart $profileDir 'AppData', 'Local'
$data = Join-Path $c 'ProgramData'
Write-FakeFile (Join-PathPart $profileDir 'Downloads', 'setup.iso') 500
Write-FakeFile (Join-PathPart $profileDir 'Documents', 'Projects', 'big.pst') 200
Write-FakeFile (Join-PathPart $local 'Temp', 'junk.tmp') 150
Write-FakeFile (Join-PathPart $local 'CrashDumps', 'app.dmp') 5
Write-FakeFile (Join-PathPart $win 'Temp', 'cab.tmp') 20
Write-FakeFile (Join-PathPart $win 'SoftwareDistribution', 'Download', 'kb.cab') 400
Write-FakeFile (Join-PathPart $win 'Minidump', 'mini.dmp') 2
Write-FakeFile (Join-PathPart $win 'MEMORY.DMP') 30
Write-FakeFile (Join-PathPart $win 'ServiceProfiles', 'NetworkService', 'AppData', 'Local', 'Microsoft', 'Windows', 'DeliveryOptimization', 'Cache', 'do.bin') 60
Write-FakeFile (Join-PathPart $c '$Recycle.Bin', 'S-1-5-21-1', '$RABC.zip') 250
Write-FakeFile (Join-PathPart $c 'Windows.old', 'Windows', 'old.wim') 700
Write-FakeFile (Join-PathPart $data 'Microsoft', 'Windows', 'WER', 'ReportArchive', 'r.wer') 1
# A symbolic link back to Downloads must not be counted twice (skipped where links need rights).
$linked = $false
try { $null = New-Item -ItemType SymbolicLink -Path (Join-PathPart $profileDir 'Desktop', 'DownloadsLink') -Target (Join-Path $profileDir 'Downloads') -ErrorAction Stop; $linked = $true } catch { $linked = $false }
$filesBefore = @(Get-ChildItem -LiteralPath $c -Recurse -Force -File | ForEach-Object { $_.FullName } | Sort-Object)

$envText = @"
`$env:SystemDrive = '$($c -replace "'", "''")'
`$env:windir = '$($win -replace "'", "''")'
`$env:USERPROFILE = '$($profileDir -replace "'", "''")'
`$env:TEMP = '$((Join-Path $local 'Temp') -replace "'", "''")'
`$env:LOCALAPPDATA = '$($local -replace "'", "''")'
`$env:ProgramData = '$($data -replace "'", "''")'
"@
$mocks = @'
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Filter)
    switch ($ClassName) {
        'Win32_LogicalDisk' { return $global:Volumes }
        'Win32_ReliabilityStabilityMetrics' { return $global:Reliability }
    }
    throw ('Unexpected class {0}' -f $ClassName)
}
function Get-PhysicalDisk { [CmdletBinding()] param() return $global:PhysicalDisks }
function Get-WinEvent {
    [CmdletBinding()] param([hashtable]$FilterHashtable)
    if (@($global:DiskEvents).Count -eq 0) { throw 'No events were found that match the specified selection criteria.' }
    return $global:DiskEvents
}
'@
$bad = @'
$global:Volumes = @(
    [pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'Windows'; FileSystem = 'NTFS'; Size = 500GB; FreeSpace = 40GB },
    [pscustomobject]@{ DeviceID = 'D:'; VolumeName = 'Data'; FileSystem = 'NTFS'; Size = 100GB; FreeSpace = 3GB },
    [pscustomobject]@{ DeviceID = 'E:'; VolumeName = 'EFI'; FileSystem = 'FAT32'; Size = 0.5GB; FreeSpace = 0.2GB }
)
$global:Reliability = @([pscustomobject]@{ TimeGenerated = (Get-Date).AddDays(-2); SystemStabilityIndex = 6.0 }, [pscustomobject]@{ TimeGenerated = (Get-Date).AddHours(-3); SystemStabilityIndex = 3.2 })
$global:PhysicalDisks = @([pscustomobject]@{ FriendlyName = 'Samsung SSD 980'; MediaType = 'SSD'; Size = 500GB; HealthStatus = 'Unhealthy'; OperationalStatus = @('Predictive Failure') })
$global:DiskEvents = @([pscustomobject]@{ ProviderName = 'disk'; Id = 7 }, [pscustomobject]@{ ProviderName = 'disk'; Id = 7 }, [pscustomobject]@{ ProviderName = 'Ntfs'; Id = 55 })
'@
$good = @'
$global:Volumes = @([pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'Windows'; FileSystem = 'NTFS'; Size = 500GB; FreeSpace = 300GB })
$global:Reliability = @()
$global:PhysicalDisks = @([pscustomobject]@{ FriendlyName = 'Samsung SSD 980'; MediaType = 'SSD'; Size = 500GB; HealthStatus = 'Healthy'; OperationalStatus = @('OK') })
$global:DiskEvents = @()
'@

function Invoke-Mocked {
    param([string]$Name, [string]$Scene, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work ('run-' + $Name)
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "{0}`n{1}`n{2}`n& '{3}' -OutputPath '{4}' {5}`nexit `$LASTEXITCODE`n" -f $envText, $mocks, $Scene, ($b5 -replace "'", "''"), ($out -replace "'", "''"), ($ScriptArgs -join ' ')
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & { $ErrorActionPreference = 'Continue'; & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 } | Out-String
    $code = $LASTEXITCODE
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    $result = $null
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json }
    return [pscustomobject]@{ Code = $code; Console = $console; Result = $result }
}
function Get-Finding { param($Run, [string]$Check) if ($Run.Result) { @($Run.Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1 } }
function Assert-Finding {
    param($Run, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '', [string]$Severity = '')
    $f = Get-Finding $Run $Check
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern) -and (-not $Severity -or $f.Severity -eq $Severity)
    $got = 'missing'
    if ($f) { $got = '[{0}/{1}] {2}' -f $f.Status, $f.Severity, $f.Detail }
    Assert-True $Label $ok $got
}

try {
    $r = Invoke-Mocked 'bad' $bad @('-TimeLimitSeconds', '30', '-TopFolders', '5')
    Assert-True 'bad: exit 0' ($r.Code -eq 0) $r.Console
    Assert-True 'bad: JSON written' ($null -ne $r.Result) $r.Console
    Assert-True 'bad: no ERROR findings' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) ((@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
    Assert-True 'bad: CheckId B5' ($r.Result.CheckId -eq 'B5')
    Assert-Finding $r 'C: 8 % free = WARN' 'Disk space C:' 'WARN' '40\.0 GB free of 500\.0 GB \(8 % free\)' 'Medium'
    Assert-Finding $r 'D: 3 GB free = FAIL' 'Disk space D:' 'FAIL' '3\.0 GB free of 100\.0 GB' 'High'
    Assert-Finding $r 'EFI 0.5 GB at 40 % = PASS (percentage only)' 'Disk space E:' 'PASS'
    Assert-Finding $r 'profile folders, biggest first' 'Largest folders: User profile' 'INFO' 'Downloads 500 MB; Documents 200 MB'
    Assert-Finding $r 'system drive folders listed' 'Largest folders: System drive' 'INFO' ': Users 855 MB; Windows\.old 700 MB; Windows 512 MB; \$Recycle\.Bin 250 MB; ProgramData 1 MB\.$'
    $dl = @($r.Result.Data.LargestFolders | Where-Object { $_.Place -eq 'User profile' -and $_.Folder -like '*Desktop' })
    if ($linked) { Assert-True 'symbolic link not followed (Desktop is empty)' ($dl.Count -eq 0 -or [double]$dl[0].SizeGB -lt 0.01) ($dl | Out-String) }
    $rec = Get-Finding $r 'Reclaimable space'
    Assert-True 'reclaimable total and items' ([string]$rec.Detail -match '^1\.6 GB in known cleanup locations: Previous Windows installation 700 MB; Windows Update cache 400 MB; Recycle Bin 250 MB; Temporary files \(yours\) 150 MB; Delivery Optimization cache 60 MB; Crash dumps and error reports 38 MB; Temporary files \(Windows\) 20 MB\. Nothing was deleted\.$') ([string]$rec.Detail)
    Assert-Finding $r 'unhealthy disk = FAIL Critical' 'Disk health' 'FAIL' 'Samsung SSD 980 \(SSD, 500 GB\): Unhealthy, Predictive Failure' 'Critical'
    Assert-Finding $r 'newest reliability index 3.2 = WARN' 'Reliability index' 'WARN' 'Reliability index 3\.2 of 10' 'Low'
    Assert-Finding $r 'disk errors = WARN' 'Disk errors' 'WARN' '^3 disk or file system.*disk, 7 x2' 'High'
    $steps = @($r.Result.Data.NextSteps | Sort-Object { [int]$_.Step } | ForEach-Object { [string]$_.Action })
    Assert-True 'what to do: the space needed first' ($steps[0] -match '^C: needs about \d+ GB more free space|^D: needs about \d+ GB more free space') $steps[0]
    Assert-True 'what to do: backup before any cleanup when a disk is unhealthy' ($steps[1] -match '^Back up the data now') ($steps -join ' | ')
    Assert-True 'what to do: cleanup biggest first' ($steps[2] -match '^Previous Windows installation \(700 MB\)' -and $steps[3] -match '^Windows Update cache \(400 MB\).*D1: Clear-WindowsUpdateCache\.ps1' -and $steps[4] -match '^Recycle Bin \(250 MB\)' -and $steps[5] -match '^Temporary files \(yours\) \(150 MB\)') ($steps -join ' | ')
    Assert-True 'what to do: items under 100 MB are not listed as steps' (@($steps | Where-Object { $_ -match '^Delivery Optimization|^Crash dumps' }).Count -eq 0) ($steps -join ' | ')
    Assert-True 'what to do: profile folders to review' (@($steps | Where-Object { $_ -match '^Go through the largest folders in the profile.*Downloads 500 MB' }).Count -eq 1) ($steps -join ' | ')
    $filesAfter = @(Get-ChildItem -LiteralPath $c -Recurse -Force -File | ForEach-Object { $_.FullName } | Sort-Object)
    Assert-True 'nothing deleted: the fake drive is unchanged' (($filesBefore -join '|') -eq ($filesAfter -join '|'))
    foreach ($t in 'Volumes', 'LargestFolders', 'Reclaimable', 'NextSteps') { Assert-True ('table {0}' -f $t) (@($r.Result.Data.$t).Count -gt 0) }

    $r = Invoke-Mocked 'good' $good
    Assert-True 'good: exit 0, no ERROR' ($r.Code -eq 0 -and @($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) $r.Console
    Assert-Finding $r 'good: C: PASS' 'Disk space C:' 'PASS' '300\.0 GB free'
    Assert-Finding $r 'good: healthy disk PASS' 'Disk health' 'PASS' 'Healthy'
    Assert-Finding $r 'good: no reliability history = SKIPPED' 'Reliability index' 'SKIPPED' 'no reliability history'
    Assert-Finding $r 'good: no disk errors = PASS' 'Disk errors' 'PASS'
    $steps = @($r.Result.Data.NextSteps | Sort-Object { [int]$_.Step } | ForEach-Object { [string]$_.Action })
    Assert-True 'good: no "needs more space" step' (@($steps | Where-Object { $_ -match 'needs about' -or $_ -match '^Back up' }).Count -eq 0) ($steps -join ' | ')

    $r = Invoke-Mocked 'range' $good @('-TimeLimitSeconds', '5')
    Assert-True '-TimeLimitSeconds 5: plain message, exit 1' ($r.Code -eq 1 -and $r.Console.Contains('-TimeLimitSeconds must be between 10 and 600 (you gave 5)')) $r.Console
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
