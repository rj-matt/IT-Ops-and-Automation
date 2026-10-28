<#
.SYNOPSIS
    CI only (GitHub Actions Windows runners): blocks and counts outbound connections from
    PowerShell and the Windows network tools, so a job fails if any script tries to reach beyond
    the runner. Never run on a client computer.

.DESCRIPTION
    -Action Start   Windows Firewall outbound block rules (group "MSP CI guard") for
                    powershell.exe (64/32-bit), pwsh.exe and the network tools the scripts could
                    call (ping, tracert, pathping, nslookup, curl, netsh, arp, nbtstat, net, nltest,
                    w32tm, wsl, bash), plus a rule blocking ICMP echo requests from any program.
                    Turns on auditing of blocked connections (Security event 5157).
    -Action Canary  From powershell.exe and pwsh.exe, a TCP connection to 192.0.2.1 (TEST-NET-1,
                    never routed) and a ping; each must be blocked and appear as event 5157.
    -Action Check   Fails if any connection from those programs was blocked after the canary, if a
                    workflow file mentions the active-network switch, or if a harness summary in
                    -SummaryDirectory reports active cases run.

    Not covered: name lookups. Windows resolves names in the DNS Client service, so a lookup is not
    tied to the program that asked for it. The Linux job covers DNS for the shared bash code; the
    PowerShell scripts that resolve names (A2, B2) only do so in their active modes, which the
    harness never runs in CI.

.PARAMETER Action
    Start, Canary or Check.

.PARAMETER RepositoryPath
    Check: the repository whose .github/workflows is scanned.

.PARAMETER SummaryDirectory
    Check: folder holding harness-summary-*.md files.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\ci\Invoke-CINetworkGuard.ps1 -Action Start

.NOTES
    Risk Level    : Changes firewall and audit settings: GitHub Actions runners only (refuses elsewhere)
    Exit code     : 0 when the step passed, 1 otherwise
    Version       : 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Start', 'Canary', 'Check')][string]$Action,
    [string]$RepositoryPath = '',
    [string]$SummaryDirectory = ''
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { Write-Host 'CI only: GITHUB_ACTIONS is not true. Nothing changed.' -ForegroundColor Red; exit 1 }

$state = Join-Path -Path $env:ProgramData -ChildPath 'msp-ci-network-guard.json'
$group = 'MSP CI guard'
# "Filtering Platform Connection" audit subcategory (language-independent GUID).
$auditGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'

function Get-GuardProgram {
    <# Full paths of the programs whose outbound connections are blocked. #>
    $sys = Join-Path $env:SystemRoot 'System32'
    $list = @(
        (Join-Path $sys 'WindowsPowerShell\v1.0\powershell.exe'),
        (Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe')
    )
    foreach ($tool in 'PING.EXE', 'TRACERT.EXE', 'PATHPING.EXE', 'nslookup.exe', 'curl.exe', 'netsh.exe', 'ARP.EXE', 'NBTSTAT.EXE', 'net.exe', 'net1.exe', 'nltest.exe', 'w32tm.exe', 'wsl.exe', 'bash.exe') {
        $list += (Join-Path $sys $tool)
    }
    foreach ($cmd in 'pwsh.exe', 'bash.exe', 'curl.exe') {
        $list += @(Get-Command $cmd -All -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    }
    return @($list | Where-Object { Test-Path -LiteralPath $_ } | Sort-Object -Unique)
}

function Get-BlockedConnection {
    <# Event 5157 records since the given time from guarded programs, or ICMP from any program. #>
    param([datetime]$Since, [string[]]$Program)
    $names = @($Program | ForEach-Object { (Split-Path $_ -Leaf).ToLowerInvariant() })
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $Since } -ErrorAction SilentlyContinue)
    foreach ($e in $events) {
        $data = @{}
        foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $data[$d.Name] = [string]$d.'#text' }
        $app = (Split-Path $data['Application'] -Leaf).ToLowerInvariant()
        $dest = $data['DestAddress']
        if ($dest -match '^(127\.|::1$)') { continue }
        if ($names -contains $app -or $data['Protocol'] -in @('1', '58')) {
            [pscustomobject]@{ Time = $e.TimeCreated; Application = $data['Application']; Destination = $dest; Port = $data['DestPort']; Protocol = $data['Protocol'] }
        }
    }
}

switch ($Action) {
    'Start' {
        $before = Get-NetFirewallProfile | ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }
        Write-Host ('Firewall profiles before: {0}' -f ($before -join ', '))
        Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Allow
        $programs = Get-GuardProgram
        foreach ($p in $programs) {
            $null = New-NetFirewallRule -DisplayName ('{0}: {1}' -f $group, $p) -Group $group -Direction Outbound -Action Block -Program $p -Profile Any
        }
        $null = New-NetFirewallRule -DisplayName ('{0}: ICMPv4 echo' -f $group) -Group $group -Direction Outbound -Action Block -Protocol ICMPv4 -IcmpType 8 -Profile Any
        $null = New-NetFirewallRule -DisplayName ('{0}: ICMPv6 echo' -f $group) -Group $group -Direction Outbound -Action Block -Protocol ICMPv6 -IcmpType 128 -Profile Any
        $null = & auditpol.exe /set /subcategory:$auditGuid /failure:enable
        if ($LASTEXITCODE -ne 0) { Write-Host 'auditpol failed: blocked connections would not be logged.' -ForegroundColor Red; exit 1 }
        @{ Started = (Get-Date).ToString('o'); Programs = $programs } | ConvertTo-Json | Set-Content -LiteralPath $state -Encoding UTF8
        Write-Host ('Network guard on: {0} program(s) blocked outbound, ICMP echo blocked, event 5157 audited.' -f $programs.Count)
        $programs | ForEach-Object { Write-Host ('  {0}' -f $_) }
        exit 0
    }
    'Canary' {
        $s = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
        $since = Get-Date
        $probe = 'try { $c = New-Object System.Net.Sockets.TcpClient; $t = $c.ConnectAsync(''192.0.2.1'', 9); [void]$t.Wait(3000) } catch { }; $null = & ping.exe -n 1 -w 1000 192.0.2.1'
        $hosts = @((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')) + @(Get-Command pwsh.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
        foreach ($h in $hosts) { $null = & $h -NoProfile -NonInteractive -Command $probe 2>&1 }
        Start-Sleep -Seconds 3
        $seen = @(Get-BlockedConnection -Since $since -Program $s.Programs)
        $rc = 0
        foreach ($h in $hosts) {
            $leaf = (Split-Path $h -Leaf).ToLowerInvariant()
            $hit = @($seen | Where-Object { (Split-Path $_.Application -Leaf).ToLowerInvariant() -eq $leaf -and $_.Protocol -eq '6' })
            Write-Host ('canary TCP from {0,-16} {1}' -f $leaf, $(if ($hit) { 'blocked and logged' } else { 'NOT SEEN by the guard' }))
            if (-not $hit) { $rc = 1 }
        }
        $icmp = @($seen | Where-Object { $_.Protocol -eq '1' })
        Write-Host ('canary ping                   {0}' -f $(if ($icmp) { 'blocked and logged' } else { 'NOT SEEN by the guard' }))
        if (-not $icmp) { $rc = 1 }
        if ($rc -ne 0) { $seen | Format-Table -AutoSize | Out-String | Write-Host; Write-Host 'The guard did not see every canary attempt.' -ForegroundColor Red; exit 1 }
        $s | Add-Member -NotePropertyName Baseline -NotePropertyValue (Get-Date).ToString('o') -Force
        $s | ConvertTo-Json | Set-Content -LiteralPath $state -Encoding UTF8
        exit 0
    }
    'Check' {
        $s = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
        if (-not $s.Baseline) { Write-Host 'No baseline: Start and Canary did not run.' -ForegroundColor Red; exit 1 }
        $rc = 0
        $seen = @(Get-BlockedConnection -Since ([datetime]$s.Baseline) -Program $s.Programs)
        if ($seen.Count -gt 0) {
            Write-Host ('FAIL: {0} connection(s) were blocked: a script tried to reach beyond the runner.' -f $seen.Count) -ForegroundColor Red
            $seen | Select-Object -First 40 | Format-Table -AutoSize | Out-String | Write-Host
            $rc = 1
        }
        else { Write-Host 'PASS: no connection from the guarded programs was blocked after the canary.' }
        $wf = Join-Path $RepositoryPath '.github\workflows'
        $hits = @(Get-ChildItem -LiteralPath $wf -File -ErrorAction SilentlyContinue | Select-String -SimpleMatch 'AllowActiveNetwork')
        if ($hits) { Write-Host 'FAIL: a workflow file mentions the active-network switch.' -ForegroundColor Red; $hits | ForEach-Object { Write-Host ('  {0}' -f $_) }; $rc = 1 }
        $summaries = @(Get-ChildItem -LiteralPath $SummaryDirectory -Filter 'harness-summary-*.md' -File -ErrorAction SilentlyContinue)
        if ($summaries.Count -eq 0) { Write-Host 'FAIL: no harness summary to check.' -ForegroundColor Red; $rc = 1 }
        foreach ($f in $summaries) {
            $text = [System.IO.File]::ReadAllLines($f.FullName)
            if ($text -notcontains 'Active network cases run: 0' -or $text -notcontains '-AllowActiveNetwork: not given') {
                Write-Host ('FAIL: {0} reports active network cases.' -f $f.Name) -ForegroundColor Red
                $rc = 1
            }
        }
        exit $rc
    }
}
