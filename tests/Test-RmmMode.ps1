<#
.SYNOPSIS
    Checks RMM mode (-Rmm) of the PowerShell scripts as an RMM agent would run them: as SYSTEM,
    with no prompts, a one-line summary, an exit code to alert on and the JSON result saved to the
    protected results folder.

.DESCRIPTION
    Development-side check; never run on client machines. Runs on Windows PowerShell 5.1 and on
    PowerShell 7 (Windows, macOS, Linux). Every run uses two development-only settings:
      MSP_TEST_SERVICE_ACCOUNT=1  the scripts behave as under SYSTEM (an RMM agent);
      MSP_TEST_RESULTS_ROOT       the results folder is moved into a temporary folder.

      Exit codes      B5 on a fake drive (as in Test-DiskSpaceReportWindowsLogic.ps1): a healthy
                      computer = 0, a nearly full C: = 1, a failing disk = 2, an out-of-range
                      -ScanSeconds = 3; MSP_TOOLKIT_RMM=1 works like -Rmm.
      Summary line    the last line on stdout is "B5 WARN=n FAIL=n ERROR=n" with the run's counts;
                      no colour codes anywhere in the output.
      Results folder  one JSON file per run, nothing else; the newest 10 per script are kept
                      (11 older ones pre-seeded), other scripts' files are left alone.
      Permissions     Windows: inheritance off, access only for Administrators, SYSTEM and the
                      running account; macOS/Linux: folder 700, file 600. A results folder that
                      is a link (planted in advance) is not used: exit 3, nothing written there.
      As SYSTEM       B5 skips the "User profile" folder scan and measures every user's temp
                      files; A5 covers every user profile and names them; D3 refuses even with
                      -Force (it needs the user's own profile; run with -WhatIf as well, so
                      nothing could change even if the refusal were missing).
      Remediation     Confirm-MSPChange refuses in RMM mode without -Force (SKIPPED) and goes
                      ahead with -Force.
      Network         B2 in RMM mode runs passive (its network cmdlets are stand-ins that fail
                      the run if called); A7 records SKIPPED and exits 3; A4 -ScanLan and A6
                      -Online record SKIPPED and the passive checks still run. -ActiveNetwork is
                      not run here (it would send traffic).
      D2              refuses in RMM mode even with -Force (run with -WhatIf as well).

.EXAMPLE
    pwsh -NoProfile -File tests/Test-RmmMode.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.1.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-True (Name, Condition, Detail) is a one-line test assertion used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$onWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-rmm-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
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
function Get-UnixMode {
    <# Permission bits of PATH as text, e.g. "700" (macOS and Linux stat differ). #>
    param([string]$Path)
    if ($IsMacOS) { return [string](& stat -f '%Lp' $Path) }
    return [string](& stat -c '%a' $Path)
}
function Get-Finding {
    param($Result, [string]$Check)
    if (-not $Result) { return $null }
    return @($Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1
}

# --- Fake C: drive with one user profile (as in Test-DiskSpaceReportWindowsLogic.ps1) ----------
$c = Join-Path $work 'C'
$win = Join-Path $c 'Windows'
$profileDir = Join-PathPart $c 'Users', 'alice'
$local = Join-PathPart $profileDir 'AppData', 'Local'
$data = Join-Path $c 'ProgramData'
$systemProfile = Join-PathPart $win 'System32', 'config', 'systemprofile'
Write-FakeFile (Join-PathPart $profileDir 'Downloads', 'setup.iso') 50
Write-FakeFile (Join-PathPart $local 'Temp', 'junk.tmp') 30
Write-FakeFile (Join-PathPart $local 'CrashDumps', 'app.dmp') 5
Write-FakeFile (Join-PathPart $win 'Temp', 'cab.tmp') 2
Write-FakeFile (Join-PathPart $systemProfile 'AppData', 'Local', 'Temp', 'system.tmp') 1
$null = New-Item -ItemType Directory -Path $data -Force

# SYSTEM's own folders, as an RMM agent sees them: no user profile of its own.
$envText = @"
`$env:SystemDrive = '$($c -replace "'", "''")'
`$env:windir = '$($win -replace "'", "''")'
`$env:USERPROFILE = '$($systemProfile -replace "'", "''")'
`$env:TEMP = '$((Join-PathPart $systemProfile 'AppData', 'Local', 'Temp') -replace "'", "''")'
`$env:LOCALAPPDATA = '$((Join-PathPart $systemProfile 'AppData', 'Local') -replace "'", "''")'
`$env:APPDATA = '$((Join-PathPart $systemProfile 'AppData', 'Roaming') -replace "'", "''")'
`$env:ProgramData = '$($data -replace "'", "''")'
`$env:MSP_TEST_SERVICE_ACCOUNT = '1'
"@
$mocks = @"
function Get-CimInstance {
    [CmdletBinding()] param([string]`$ClassName, [string]`$Filter)
    switch (`$ClassName) {
        'Win32_LogicalDisk' { return `$global:Volumes }
        'Win32_ReliabilityStabilityMetrics' { return @() }
        'Win32_UserProfile' { return @([pscustomobject]@{ LocalPath = '$($profileDir -replace "'", "''")'; SID = 'S-1-5-21-1000-2000-3000-1001'; Loaded = `$true; Special = `$false }) }
    }
    throw ('Unexpected class {0}' -f `$ClassName)
}
function Get-PhysicalDisk { [CmdletBinding()] param() return `$global:PhysicalDisks }
function Get-WinEvent { [CmdletBinding()] param([hashtable]`$FilterHashtable) throw 'No events were found that match the specified selection criteria.' }
"@
$scenes = @{
    good = '$global:Volumes = @([pscustomobject]@{ DeviceID = ''C:''; VolumeName = ''Windows''; FileSystem = ''NTFS''; Size = 500GB; FreeSpace = 300GB }); $global:PhysicalDisks = @([pscustomobject]@{ FriendlyName = ''SSD''; MediaType = ''SSD''; Size = 500GB; HealthStatus = ''Healthy''; OperationalStatus = @(''OK'') })'
    warn = '$global:Volumes = @([pscustomobject]@{ DeviceID = ''C:''; VolumeName = ''Windows''; FileSystem = ''NTFS''; Size = 500GB; FreeSpace = 40GB }); $global:PhysicalDisks = @([pscustomobject]@{ FriendlyName = ''SSD''; MediaType = ''SSD''; Size = 500GB; HealthStatus = ''Healthy''; OperationalStatus = @(''OK'') })'
    bad  = '$global:Volumes = @([pscustomobject]@{ DeviceID = ''C:''; VolumeName = ''Windows''; FileSystem = ''NTFS''; Size = 500GB; FreeSpace = 300GB }); $global:PhysicalDisks = @([pscustomobject]@{ FriendlyName = ''SSD''; MediaType = ''SSD''; Size = 500GB; HealthStatus = ''Unhealthy''; OperationalStatus = @(''Predictive Failure'') })'
}

function Invoke-Rmm {
    <#
        Runs SCRIPT with the mocks and SCENE defined first, as SYSTEM in RMM mode, the results
        folder under RESULTSROOT. Returns the exit code, stdout lines, the console text (stdout
        and stderr) and the JSON results in the results folder.
    #>
    param([string]$Name, [string]$Script = $b5, [string]$Scene = $scenes.good, [string[]]$ScriptArgs = @('-Rmm', '-ScanSeconds', '10'),
        [string]$ResultsRoot = (Join-Path $work ('rr-' + $Name)), [string]$Extra = '')
    $dir = Join-Path $work ('run-' + $Name)
    $null = New-Item -ItemType Directory -Path $dir -Force
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "{0}`n`$env:MSP_TEST_RESULTS_ROOT = '{1}'`n{2}`n{3}`n{4}`n& '{5}' {6}`nexit `$LASTEXITCODE`n" -f $envText, ($ResultsRoot -replace "'", "''"), $Extra, $mocks, $Scene, ($Script -replace "'", "''"), ($ScriptArgs -join ' ')
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $errFile = Join-Path $dir 'stderr.txt'
    $stdout = @(& { $ErrorActionPreference = 'Continue'; & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>$errFile })
    $code = $LASTEXITCODE
    $stderr = ''
    if (Test-Path -LiteralPath $errFile) { $stderr = [System.IO.File]::ReadAllText($errFile) }
    $folder = Join-Path $ResultsRoot 'results'
    $json = @()
    if (Test-Path -LiteralPath $folder) { $json = @(Get-ChildItem -LiteralPath $folder -Filter '*.json' -File | Sort-Object LastWriteTime) }
    $result = $null
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[-1].FullName -Raw | ConvertFrom-Json }
    $lines = @($stdout | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
    return [pscustomobject]@{ Code = $code; Lines = $lines; Last = $(if ($lines.Count) { $lines[-1] } else { '' }); Console = (($stdout -join "`n") + "`n" + $stderr); Folder = $folder; Json = $json; Result = $result }
}

try {
    # --- Exit codes and summary line -----------------------------------------------------------
    $r = Invoke-Rmm -Name 'good'
    Assert-True 'healthy computer: exit 0' ($r.Code -eq 0) ('exit {0}; console: {1}' -f $r.Code, $r.Console)
    Assert-True 'healthy computer: summary line last' ($r.Last -ceq 'B5 WARN=0 FAIL=0 ERROR=0') ('last line: [{0}]' -f $r.Last)
    Assert-True 'no colour codes in the output' ($r.Console -notmatch [char]27) ''
    Assert-True 'one JSON result in the results folder' ($r.Json.Count -eq 1) ('{0} file(s)' -f $r.Json.Count)
    Assert-True 'nothing but JSON in the results folder' (@(Get-ChildItem -LiteralPath $r.Folder -Force | Where-Object { $_.Extension -ne '.json' }).Count -eq 0) ''
    if ($r.Result) {
        Assert-True 'result names the check' ($r.Result.CheckId -eq 'B5') $r.Result.CheckId
        Assert-True 'summary line matches the result counts' ($r.Last -ceq ('B5 WARN={0} FAIL={1} ERROR={2}' -f $r.Result.Summary.WARN, $r.Result.Summary.FAIL, $r.Result.Summary.ERROR)) $r.Last
        $f = Get-Finding $r.Result 'Largest folders: User profile'
        Assert-True 'as SYSTEM: user profile scan SKIPPED with the reason' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail -match 'no user profile of its own') $(if ($f) { $f.Detail })
        $f = Get-Finding $r.Result 'Users covered'
        Assert-True 'as SYSTEM: users covered named' ($f -and $f.Detail -match '1 user profile') $(if ($f) { $f.Detail })
        $temp = @($r.Result.Data.Reclaimable | Where-Object { $_.Item -like 'Temporary files (all users)*' })
        Assert-True 'as SYSTEM: every user''s temp files measured' ($temp.Count -eq 1) (($r.Result.Data.Reclaimable | ForEach-Object { $_.Item }) -join ', ')
    }

    $r = Invoke-Rmm -Name 'warn' -Scene $scenes.warn
    Assert-True 'nearly full C: (WARN): exit 1' ($r.Code -eq 1) ('exit {0}' -f $r.Code)
    Assert-True 'WARN: summary line' ($r.Last -match '^B5 WARN=[1-9]\d* FAIL=0 ERROR=0$') $r.Last

    $r = Invoke-Rmm -Name 'bad' -Scene $scenes.bad
    Assert-True 'failing disk (FAIL): exit 2' ($r.Code -eq 2) ('exit {0}' -f $r.Code)
    Assert-True 'FAIL: summary line' ($r.Last -match '^B5 WARN=\d+ FAIL=[1-9]\d* ERROR=0$') $r.Last

    $r = Invoke-Rmm -Name 'range' -ScriptArgs @('-Rmm', '-ScanSeconds', '601')
    Assert-True 'out-of-range value (could not run): exit 3' ($r.Code -eq 3) ('exit {0}' -f $r.Code)
    Assert-True 'could not run: summary line still printed' ($r.Last -ceq 'B5 WARN=0 FAIL=0 ERROR=1') $r.Last
    Assert-True 'could not run: plain message' ($r.Console -match '-ScanSeconds must be between 10 and 600') ''
    Assert-True 'could not run: result saved' ($r.Json.Count -eq 1) ''

    $r = Invoke-Rmm -Name 'env' -ScriptArgs @('-ScanSeconds', '10') -Extra '$env:MSP_TOOLKIT_RMM = ''1'''
    Assert-True 'MSP_TOOLKIT_RMM=1 works like -Rmm' ($r.Code -eq 0 -and $r.Last -ceq 'B5 WARN=0 FAIL=0 ERROR=0' -and $r.Json.Count -eq 1) ('exit {0}, last [{1}]' -f $r.Code, $r.Last)

    # --- History: the newest 10 per script ------------------------------------------------------
    $root = Join-Path $work 'rr-prune'
    $pre = Join-Path $root 'results'
    $null = New-Item -ItemType Directory -Path $pre -Force
    for ($i = 1; $i -le 11; $i++) {
        $p = Join-Path $pre ('Get-DiskSpaceReport_OLDPC_202001{0:00}-000000.json' -f $i)
        [System.IO.File]::WriteAllText($p, '{}')
        (Get-Item -LiteralPath $p).LastWriteTime = (Get-Date).AddDays(-100 + $i)
    }
    $other = Join-Path $pre 'Get-PerformanceSnapshot_OLDPC_20200101-000000.json'
    [System.IO.File]::WriteAllText($other, '{}')
    (Get-Item -LiteralPath $other).LastWriteTime = (Get-Date).AddDays(-200)
    $r = Invoke-Rmm -Name 'prune' -ResultsRoot $root
    $left = @(Get-ChildItem -LiteralPath $pre -Filter 'Get-DiskSpaceReport_*.json' -File)
    Assert-True 'history: 10 results of the script kept' ($left.Count -eq 10) ('{0} left' -f $left.Count)
    Assert-True 'history: the new result is kept' (@($left | Where-Object { $_.Name -notlike '*OLDPC*' }).Count -eq 1) ''
    Assert-True 'history: the two oldest removed' (-not (Test-Path (Join-Path $pre 'Get-DiskSpaceReport_OLDPC_20200101-000000.json')) -and -not (Test-Path (Join-Path $pre 'Get-DiskSpaceReport_OLDPC_20200102-000000.json'))) ''
    Assert-True 'history: other scripts'' results left alone' (Test-Path -LiteralPath $other) ''

    # --- Permissions --------------------------------------------------------------------------
    if ($onWindows) {
        foreach ($f in @($r.Folder, (Split-Path $r.Folder -Parent))) {
            $acl = Get-Acl -LiteralPath $f
            $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Select-Object -Unique)
            $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            Assert-True ('permissions: inheritance off on {0}' -f (Split-Path $f -Leaf)) $acl.AreAccessRulesProtected ''
            Assert-True ('permissions: only Administrators, SYSTEM and this account on {0}' -f (Split-Path $f -Leaf)) (@($sids | Where-Object { $_ -notin @('S-1-5-32-544', 'S-1-5-18', $me) }).Count -eq 0 -and $sids -contains 'S-1-5-32-544' -and $sids -contains 'S-1-5-18') ($sids -join ', ')
        }
    }
    else {
        Assert-True 'permissions: results folder 700' ((Get-UnixMode $r.Folder) -eq '700') (Get-UnixMode $r.Folder)
        Assert-True 'permissions: parent folder 700' ((Get-UnixMode (Split-Path $r.Folder -Parent)) -eq '700') ''
        $new = @($left | Where-Object { $_.Name -notlike '*OLDPC*' })
        if ($new.Count -eq 1) { Assert-True 'permissions: result file 600' ((Get-UnixMode $new[0].FullName) -eq '600') (Get-UnixMode $new[0].FullName) }
    }

    # A results folder planted in advance as a link is never used.
    $root = Join-Path $work 'rr-link'
    $target = Join-Path $work 'elsewhere'
    $null = New-Item -ItemType Directory -Path $root, $target -Force
    $linkMade = $true
    try {
        if ($onWindows) { $null = New-Item -ItemType Junction -Path (Join-Path $root 'results') -Target $target -ErrorAction Stop }
        else { $null = New-Item -ItemType SymbolicLink -Path (Join-Path $root 'results') -Target $target -ErrorAction Stop }
    }
    catch { $linkMade = $false; Write-Host ('  (link not created here: {0})' -f $_.Exception.Message) }
    if ($linkMade) {
        $r = Invoke-Rmm -Name 'link' -ResultsRoot $root
        Assert-True 'planted link: exit 3' ($r.Code -eq 3) ('exit {0}' -f $r.Code)
        Assert-True 'planted link: nothing written through it' (@(Get-ChildItem -LiteralPath $target -Force).Count -eq 0) ''
        Assert-True 'planted link: summary line still printed' ($r.Last -match '^B5 WARN=\d+ FAIL=\d+ ERROR=\d+$') $r.Last
    }

    # A plain results folder another account created in advance (a standard user can create folders
    # in %ProgramData%) is refused, not taken over. A test cannot create a folder someone else owns,
    # so MSP_TEST_FOREIGN_OWNER marks it as such.
    $root = Join-Path $work 'rr-foreign'
    $planted = Join-Path $root 'results'
    # First a normal run, so the parent folder (MSP_TEST_RESULTS_ROOT) is created and locked down
    # before anything is planted; its permissions then cannot change during the planted run.
    $pre = Invoke-Rmm -Name 'foreign-pre' -ResultsRoot $root
    Assert-True 'planted foreign results folder: the parent is set up by a normal run first' ($pre.Code -eq 0 -and $pre.Json.Count -eq 1) ('exit {0}; {1} result(s)' -f $pre.Code, $pre.Json.Count)
    Remove-Item -LiteralPath $planted -Recurse -Force
    $null = New-Item -ItemType Directory -Path $planted
    if (-not $onWindows) { & chmod 777 $planted }
    $sddlBefore = ''
    $entriesBefore = ''
    if ($onWindows) {
        $acl = Get-Acl -LiteralPath $planted
        $sddlBefore = $acl.GetSecurityDescriptorSddlForm('Owner, Access')
        $entriesBefore = (@($acl.Access | ForEach-Object { '{0}:{1}:{2}' -f $_.IdentityReference, $_.FileSystemRights, $_.IsInherited })) -join ', '
    }
    $r = Invoke-Rmm -Name 'foreign' -ResultsRoot $root -Extra ('$env:MSP_TEST_FOREIGN_OWNER = ''{0}''' -f ($planted -replace "'", "''"))
    Assert-True 'planted foreign results folder: exit 3' ($r.Code -eq 3) ('exit {0}' -f $r.Code)
    Assert-True 'planted foreign results folder: nothing written' (@(Get-ChildItem -LiteralPath $planted -Force).Count -eq 0) ''
    Assert-True 'planted foreign results folder: says it was not used' ($r.Console -match 'belongs to another account; it was not used') ''
    if ($onWindows) {
        # The whole security descriptor (owner and every entry, own or inherited) must be unchanged.
        $acl = Get-Acl -LiteralPath $planted
        $sddlAfter = $acl.GetSecurityDescriptorSddlForm('Owner, Access')
        $entriesAfter = (@($acl.Access | ForEach-Object { '{0}:{1}:{2}' -f $_.IdentityReference, $_.FileSystemRights, $_.IsInherited })) -join ', '
        Write-Host ('  planted results folder SDDL before: {0}' -f $sddlBefore)
        Write-Host ('  planted results folder SDDL after:  {0}' -f $sddlAfter)
        Assert-True 'planted foreign results folder: permissions not taken over (full SDDL unchanged)' ($sddlAfter -ceq $sddlBefore) `
            ('before [{0}] after [{1}]; entries before: {2}; entries after: {3}' -f $sddlBefore, $sddlAfter, $entriesBefore, $entriesAfter)
    }
    else { Assert-True 'planted foreign results folder: permissions not taken over' ((Get-UnixMode $planted) -eq '777') (Get-UnixMode $planted) }
    Assert-True 'planted foreign results folder: summary line still printed' ($r.Last -match '^B5 WARN=\d+ FAIL=\d+ ERROR=\d+$') $r.Last

    # A log folder another account created in advance (C:\Windows\Temp is SYSTEM's TEMP; /tmp is
    # shared): a new private folder with a random name is used, nothing is written into it.
    if ($onWindows) {
        $logBase = Join-PathPart $systemProfile 'AppData', 'Local', 'Temp'
        $plantedLog = Join-Path $logBase 'MSP-Toolkit'
        $extra = ''
    }
    else {
        $logBase = Join-Path $work 'tmp-foreign'
        $plantedLog = Join-Path $logBase 'msp-toolkit'
        $extra = ('$env:TMPDIR = ''{0}''' -f ($logBase -replace "'", "''")) + "`n"
    }
    if (Test-Path -LiteralPath $plantedLog) { Remove-Item -LiteralPath $plantedLog -Recurse -Force }
    $null = New-Item -ItemType Directory -Path $plantedLog -Force
    if (-not $onWindows) { & chmod 777 $plantedLog }
    $extra += ('$env:MSP_TEST_FOREIGN_OWNER = ''{0}''' -f ($plantedLog -replace "'", "''"))
    $r = Invoke-Rmm -Name 'foreign-log' -Extra $extra
    Assert-True 'planted foreign log folder: run completes (exit 0)' ($r.Code -eq 0) ('exit {0}; console: {1}' -f $r.Code, $r.Console)
    Assert-True 'planted foreign log folder: nothing written into it' (@(Get-ChildItem -LiteralPath $plantedLog -Force).Count -eq 0) ''
    $logLine = @($r.Lines | Where-Object { $_ -like ' Log     : *' }) | Select-Object -First 1
    $logFile = ''
    if ($logLine) { $logFile = $logLine.Substring(' Log     : '.Length) }
    $logDir = ''
    if ($logFile) { $logDir = Split-Path $logFile -Parent }
    Assert-True 'planted foreign log folder: a new folder with a random name used instead' ($logDir -and (Split-Path $logDir -Parent) -eq $logBase -and (Split-Path $logDir -Leaf) -ne (Split-Path $plantedLog -Leaf) -and (Test-Path -LiteralPath $logFile)) ('log line: [{0}]' -f $logLine)
    if ($logDir -and (Test-Path -LiteralPath $logDir)) {
        if ($onWindows) {
            $acl = Get-Acl -LiteralPath $logDir
            $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Select-Object -Unique)
            Assert-True 'fallback log folder: inheritance off; only Administrators, SYSTEM and this account' ($acl.AreAccessRulesProtected -and @($sids | Where-Object { $_ -notin @('S-1-5-32-544', 'S-1-5-18', $me) }).Count -eq 0) ($sids -join ', ')
        }
        else {
            Assert-True 'fallback log folder: mode 700' ((Get-UnixMode $logDir) -eq '700') (Get-UnixMode $logDir)
            Assert-True 'fallback log file: mode 600' ((Get-UnixMode $logFile) -eq '600') (Get-UnixMode $logFile)
        }
    }

    # --- Per-user checks as SYSTEM ---------------------------------------------------------------
    $r = Invoke-Rmm -Name 'a5' -Script (Join-Path $repo 'endpoint-systems/diagnostics/system-info/Get-BrowserSecurityCheck.ps1') -ScriptArgs @('-Rmm')
    Assert-True 'A5: summary line' ($r.Last -match '^A5 WARN=\d+ FAIL=\d+ ERROR=\d+$') $r.Last
    $f = Get-Finding $r.Result 'Users covered'
    Assert-True 'A5 as SYSTEM: every user profile covered and named' ($f -and $f.Detail -match '1 user\(s\)' -and $f.Detail -match 'alice') $(if ($f) { $f.Detail } else { $r.Console })
    $f = Get-Finding $r.Result 'Other users'' browser profiles'
    Assert-True 'A5 as SYSTEM: SYSTEM''s own profile left out' ($f -and $f.Detail -match 'Checking 1 user profile') $(if ($f) { $f.Detail })

    $r = Invoke-Rmm -Name 'd3' -Script (Join-Path $repo 'cloud-services/m365/remediation/Reset-OutlookProfile.ps1') -ScriptArgs @('-Rmm', '-Force', '-WhatIf')
    Assert-True 'D3 as SYSTEM: refused even with -Force, exit 3' ($r.Code -eq 3) ('exit {0}' -f $r.Code)
    $f = Get-Finding $r.Result 'Running as the affected user'
    Assert-True 'D3 as SYSTEM: SKIPPED with the reason' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail -match 'runs as SYSTEM') $(if ($f) { $f.Detail })
    Assert-True 'D3 as SYSTEM: nothing else ran' (@($r.Result.Findings | Where-Object { $_.Check -ne 'Running as the affected user' }).Count -eq 0) ''

    # --- Remediation: no changes in RMM mode without -Force ---------------------------------------
    $module = Join-Path $repo 'endpoint-systems/utilities/MSPToolkit.Common.psm1'
    $confirmTest = @"
Import-Module '$($module -replace "'", "''")' -Force
Initialize-MSPRun -ScriptName 'Test-Confirm' -ScriptVersion '1.0.0' -CheckId 'T' -RiskLevel 'Safe' -Parameters @{ Rmm = `$true } -Description 'Confirmation test' | Out-Null
`$no = Confirm-MSPChange -Question 'Change it?'
`$yes = Confirm-MSPChange -Question 'Change it?' -Force
`$findings = & (Get-Module MSPToolkit.Common) { `$script:MSPRun.Findings }
[Console]::Out.WriteLine(('RESULT no={0} yes={1}' -f `$no, `$yes))
foreach (`$f in `$findings) { [Console]::Out.WriteLine(('FINDING {0}|{1}' -f `$f.Status, `$f.Detail)) }
"@
    [System.IO.File]::WriteAllText((Join-Path $work 'confirm.ps1'), $confirmTest, (New-Object System.Text.UTF8Encoding($true)))
    $r = Invoke-Rmm -Name 'confirm' -Script (Join-Path $work 'confirm.ps1') -ScriptArgs @() -Scene ''
    Assert-True 'RMM without -Force: no changes; with -Force: go ahead' (@($r.Lines) -contains 'RESULT no=False yes=True') ($r.Console)
    Assert-True 'RMM without -Force: SKIPPED with the reason' (@($r.Lines | Where-Object { $_ -like 'FINDING SKIPPED|No changes made: RMM mode never makes changes without -Force.*' }).Count -eq 1) ''

    # --- Network: passive in RMM mode unless -ActiveNetwork ---------------------------------------
    $b2Mocks = @'
function Get-NetAdapter { [CmdletBinding()] param() [pscustomobject]@{ Name = 'Wi-Fi'; InterfaceDescription = 'Mock Wireless 6E'; Status = 'Up'; Virtual = $false; ifIndex = 12; LinkSpeed = '866 Mbps'; MacAddress = '02-00-00-00-00-01' } }
function Get-NetIPAddress { [CmdletBinding()] param([string]$AddressFamily) [pscustomobject]@{ IPAddress = '198.51.100.23'; PrefixLength = 24; InterfaceIndex = 12; InterfaceAlias = 'Wi-Fi'; PrefixOrigin = 'Dhcp' } }
function Get-NetRoute { [CmdletBinding()] param([string]$DestinationPrefix) [pscustomobject]@{ NextHop = '198.51.100.1'; InterfaceIndex = 12; InterfaceAlias = 'Wi-Fi'; RouteMetric = 25 } }
function Get-DnsClientServerAddress { [CmdletBinding()] param([string]$AddressFamily) [pscustomobject]@{ InterfaceIndex = 12; ServerAddresses = @('198.51.100.1') } }
function Get-VpnConnection { [CmdletBinding()] param() }
function Get-ItemProperty { [CmdletBinding()] param([string]$LiteralPath, [string]$Path, [string]$Name) [pscustomobject]@{ ProxyEnable = 0; ProxyServer = ''; AutoConfigURL = '' } }
function netsh.exe { 'Current WinHTTP proxy settings:', '    Direct access (no proxy server).' }
function Test-Connection { throw 'Test-Connection must not be called in RMM mode without -ActiveNetwork' }
function Test-NetConnection { throw 'Test-NetConnection must not be called in RMM mode without -ActiveNetwork' }
function Resolve-DnsName { throw 'Resolve-DnsName must not be called in RMM mode without -ActiveNetwork' }
function Invoke-WebRequest { throw 'Invoke-WebRequest must not be called in RMM mode without -ActiveNetwork' }
'@
    $r = Invoke-Rmm -Name 'b2' -Script (Join-Path $repo 'endpoint-systems/diagnostics/networking/Get-NetworkConnectivityReport.ps1') -ScriptArgs @('-Rmm') -Scene $b2Mocks
    $f = Get-Finding $r.Result 'Network tests'
    Assert-True 'B2 in RMM mode: passive, says how to test' ($f -and $f.Detail -match 'Add -ActiveNetwork') $(if ($f) { $f.Detail } else { $r.Console })
    $f = Get-Finding $r.Result 'Connectivity tests'
    Assert-True 'B2 in RMM mode: nothing sent' ($f -and $f.Status -eq 'SKIPPED') $(if ($f) { $f.Detail })
    Assert-True 'B2 in RMM mode: no network cmdlet called' ($r.Console -notmatch 'must not be called') ''
    $f = Get-Finding $r.Result 'Proxy'
    Assert-True 'B2 as SYSTEM: per-user proxy SKIPPED' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail -match 'per-user setting') $(if ($f) { $f.Detail })

    $r = Invoke-Rmm -Name 'a7' -Script (Join-Path $repo 'core-infrastructure/networking/diagnostics/Get-RouterSecurityCheck.ps1') -ScriptArgs @('-Rmm') -Scene $b2Mocks
    Assert-True 'A7 in RMM mode without -ActiveNetwork: exit 3' ($r.Code -eq 3) ('exit {0}' -f $r.Code)
    $f = Get-Finding $r.Result 'Router checks'
    Assert-True 'A7 in RMM mode: SKIPPED with the reason' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail -match 'without -ActiveNetwork') $(if ($f) { $f.Detail })
    Assert-True 'A7 in RMM mode: summary line' ($r.Last -ceq 'A7 WARN=0 FAIL=0 ERROR=0') $r.Last

    # --- A4 -ScanLan and A6 -Online need -ActiveNetwork in RMM mode; D2 never runs ------------------
    $reason = 'RMM mode: add -ActiveNetwork to allow network traffic; this can reach many client networks at once.'
    $a4Mocks = @'
function Get-NetTCPConnection { [CmdletBinding()] param([string]$State) [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 23; OwningProcess = 4; State = 'Listen' } }
function Get-NetConnectionProfile { [CmdletBinding()] param() [pscustomobject]@{ Name = 'Home'; NetworkCategory = 'Private'; InterfaceAlias = 'Wi-Fi' } }
function Get-Process { [CmdletBinding()] param([int[]]$Id, [string]$Name, [Parameter(ValueFromRemainingArguments = $true)]$Rest) [pscustomobject]@{ Id = 4; ProcessName = 'System'; Path = '' } }
function Get-NetNeighbor { throw 'Get-NetNeighbor must not be called in RMM mode without -ActiveNetwork' }
function Test-Connection { throw 'Test-Connection must not be called in RMM mode without -ActiveNetwork' }
function Test-NetConnection { throw 'Test-NetConnection must not be called in RMM mode without -ActiveNetwork' }
function New-Object {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList, [string]$ComObject)
    if ($TypeName -match 'Ping|TcpClient|Socket') { throw ('{0} must not be created in RMM mode without -ActiveNetwork' -f $TypeName) }
    if ($ComObject) { throw ('COM object {0} not available (mocked).' -f $ComObject) }
    Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
'@
    $r = Invoke-Rmm -Name 'a4' -Script (Join-Path $repo 'security-operations/diagnostics/endpoint-posture/Get-OpenPortScan.ps1') -ScriptArgs @('-Rmm', '-ScanLan') -Scene $a4Mocks
    $f = Get-Finding $r.Result 'Local network port check'
    Assert-True 'A4 -Rmm -ScanLan without -ActiveNetwork: SKIPPED with the reason' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail.StartsWith($reason)) $(if ($f) { $f.Detail } else { $r.Console })
    Assert-True 'A4: nothing sent' ($r.Console -notmatch 'must not be (called|created)') ''
    Assert-True 'A4: passive checks still ran' (@($r.Result.Findings | Where-Object { $_.Category -eq 'LocalPorts' }).Count -gt 0) ''
    Assert-True 'A4: summary line' ($r.Last -match '^A4 WARN=\d+ FAIL=\d+ ERROR=\d+$') $r.Last

    $r = Invoke-Rmm -Name 'a6' -Script (Join-Path $repo 'endpoint-systems/diagnostics/system-info/Get-WindowsUpdateCompliance.ps1') -ScriptArgs @('-Rmm', '-Online') -Scene $a4Mocks
    $f = Get-Finding $r.Result 'Online update search'
    Assert-True 'A6 -Rmm -Online without -ActiveNetwork: SKIPPED with the reason' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail.StartsWith($reason)) $(if ($f) { $f.Detail } else { $r.Console })
    Assert-True 'A6: Microsoft Update not asked' ($r.Console -notmatch 'Asking Microsoft Update') ''
    Assert-True 'A6: passive checks still ran' (@($r.Result.Findings | Where-Object { $_.Check -ne 'Online update search' }).Count -gt 0) ''
    Assert-True 'A6: summary line' ($r.Last -match '^A6 WARN=\d+ FAIL=\d+ ERROR=\d+$') $r.Last

    # -WhatIf as well, so nothing could change even if the refusal were missing.
    $r = Invoke-Rmm -Name 'd2' -Script (Join-Path $repo 'endpoint-systems/remediation/elevated/network-resets/Reset-NetworkStack.ps1') -ScriptArgs @('-Rmm', '-Force', '-WhatIf') -Scene $a4Mocks
    Assert-True 'D2 in RMM mode: refused even with -Force, exit 3' ($r.Code -eq 3) ('exit {0}' -f $r.Code)
    $f = Get-Finding $r.Result 'RMM mode'
    Assert-True 'D2 in RMM mode: SKIPPED with the reason' ($f -and $f.Status -eq 'SKIPPED' -and $f.Detail -match 'cuts off the RMM agent''s connection and needs a restart' -and $f.Recommendation -match 'survives a restart') $(if ($f) { $f.Detail })
    Assert-True 'D2 in RMM mode: nothing else ran' (@($r.Result.Findings | Where-Object { $_.Check -ne 'RMM mode' }).Count -eq 0) (($r.Result.Findings | ForEach-Object { $_.Check }) -join ', ')

    # D2 outside RMM mode (-WhatIf, so nothing changes): Get-NetIPConfiguration throws on some
    # adapters ("Exception setting NetAdapter", seen on a CI runner); the IPv4 pre-flight must still
    # read the address and gateway instead of reporting ERROR.
    if ($onWindows) {
        $d2Mocks = @'
function Get-NetAdapter { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments = $true)]$Rest) [pscustomobject]@{ Name = 'Ethernet'; InterfaceDescription = 'Mock Ethernet'; Status = 'Up'; LinkSpeed = '1 Gbps'; ifIndex = 7; InterfaceGuid = '{00000000-0000-0000-0000-000000000007}' } }
function Get-NetIPConfiguration { throw 'Exception setting "NetAdapter": "Cannot convert the "System.Object[]" value of type "System.Object[]" to type "Microsoft.Management.Infrastructure.CimInstance"."' }
function Get-NetIPInterface { [CmdletBinding()] param([int]$InterfaceIndex, [string]$AddressFamily) [pscustomobject]@{ Dhcp = 'Enabled' } }
function Get-NetIPAddress { [CmdletBinding()] param([int]$InterfaceIndex, [string]$AddressFamily) [pscustomobject]@{ IPAddress = '198.51.100.23'; PrefixLength = 24 } }
function Get-NetRoute { [CmdletBinding()] param([int]$InterfaceIndex, [string]$DestinationPrefix) [pscustomobject]@{ NextHop = '198.51.100.1' } }
function Get-DnsClientServerAddress { [CmdletBinding()] param([int]$InterfaceIndex, [string]$AddressFamily) [pscustomobject]@{ ServerAddresses = @('198.51.100.1') } }
function Test-Connection { throw 'Test-Connection must not be called with -SkipConnectivityTest' }
function Test-NetConnection { throw 'Test-NetConnection must not be called with -SkipConnectivityTest' }
'@
        $r = Invoke-Rmm -Name 'd2-ipconfig' -Script (Join-Path $repo 'endpoint-systems/remediation/elevated/network-resets/Reset-NetworkStack.ps1') -ScriptArgs @('-WhatIf', '-SkipConnectivityTest') -Scene $d2Mocks
        Assert-True 'D2 pre-flight with Get-NetIPConfiguration throwing: address and gateway read' ($r.Console -match 'IPv4: Ethernet - Ethernet: 198\.51\.100\.23/24 gateway 198\.51\.100\.1') $r.Console
        Assert-True 'D2 pre-flight with Get-NetIPConfiguration throwing: no ERROR for IPv4 settings' ($r.Console -notmatch 'IPv4 settings - The check could not complete') ''
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
