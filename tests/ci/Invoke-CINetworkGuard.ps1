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
                    Turns on auditing of blocked connections (Security event 5157) and the DNS
                    Client operational log, and clears the DNS cache, so every name looked up
                    during the job is recorded with its addresses.
    -Action Canary  From powershell.exe and pwsh.exe, a TCP connection to 192.0.2.1 (TEST-NET-1,
                    never routed) and a ping; each must be blocked and appear as event 5157.
    -Action Check   Fails if any connection from those programs was blocked after the canary, if a
                    workflow file mentions the active-network switch, or if a harness summary in
                    -SummaryDirectory reports active cases run.

    Listed but not counted: TCP port 80 to an address that, during this job, was the answer to a
    lookup of one of Microsoft's certificate revocation hosts (list in $revocationHosts below).
    Windows downloads CRLs and OCSP answers inside whichever process touches a certificate; under
    PowerShell 7 that includes Get-WinEvent, Get-AuthenticodeSignature and the Cert: drive (shown on
    the runner, 2026-10-29), so no script can avoid it. The address-to-name map comes from the DNS
    Client log and cache.

    Also listed but not counted: ICMP echo (ping) sent by the System process to an address that,
    during this job, was the answer to a lookup of a Windows Update host (list in
    $windowsUpdateHosts below). Windows Update on the fresh runner pinged download.windowsupdate.com
    on its own (seen 2026-11-03, PR #1's first run, during a case that sends nothing); a toolkit
    script never pings those hosts.

    Everything else is counted and fails the job: port 80 to any other host, an address with no
    recorded name, every private/LAN address on any port, every other ping (including pings to
    Windows Update hosts from any program but System) and every other port.

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
    Version       : 1.3.0
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
$dnsLog = 'Microsoft-Windows-DNS-Client/Operational'
# Microsoft's certificate revocation hosts (HTTP, port 80). Source: "Azure Certificate Authority
# details", section "Certificate downloads and revocation lists" (learn.microsoft.com, checked
# 2026-11-02): CRL www.microsoft.com (/pkiops/crl), OCSP oneocsp.microsoft.com. The same page's
# change log (2024-10-08) dropped crl.microsoft.com, mscrl.microsoft.com and ocsp.msocsp.com from
# the Azure list, but Microsoft's older CAs, including the code-signing CAs that sign Windows and
# PowerShell 7, still name them in their certificates, so Windows still contacts them.
# Not here on purpose: caissuers.microsoft.com (issuer certificates, not revocation),
# ctldl.windowsupdate.com (trust lists) and every non-Microsoft CA: port 80 to those is counted.
$revocationHosts = @('www.microsoft.com', 'oneocsp.microsoft.com', 'crl.microsoft.com', 'mscrl.microsoft.com', 'ocsp.msocsp.com')
# Windows Update hosts, as name patterns. Source: "Windows Update issues troubleshooting", section
# "Device can't access update files" (learn.microsoft.com, checked 2026-11-06): the endpoints a
# firewall must allow for Windows Update and Delivery Optimization. Used only for pings sent by the
# System process (Windows Update's own reachability checks), never for any other traffic.
$windowsUpdateHosts = @('*.windowsupdate.com', '*.dl.delivery.mp.microsoft.com', '*.delivery.mp.microsoft.com', '*.update.microsoft.com',
    '*.prod.do.dsp.mp.microsoft.com', 'emdl.ws.microsoft.com', 'tsfe.trafficshaping.dsp.mp.microsoft.com')

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

function Get-ResolvedName {
    <# Address -> names it was the answer for since $Since: the DNS Client log, then the cache. #>
    param([datetime]$Since)
    $map = @{}
    $add = {
        param([string]$Name, [string]$Address)
        $Address = $Address -replace '^::ffff:', ''
        if (-not $Name -or -not $Address) { return }
        if (-not $map.ContainsKey($Address)) { $map[$Address] = New-Object System.Collections.Generic.HashSet[string] }
        [void]$map[$Address].Add($Name.TrimEnd('.').ToLowerInvariant())
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = $dnsLog; StartTime = $Since } -ErrorAction SilentlyContinue)) {
        $data = @{}
        foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $data[$d.Name] = [string]$d.'#text' }
        if (-not $data['QueryName'] -or -not $data['QueryResults']) { continue }
        foreach ($part in $data['QueryResults'].Split(';')) {
            $v = $part.Trim()
            if ($v -match '^(::ffff:)?\d{1,3}(\.\d{1,3}){3}$' -or ($v -match '^[0-9a-f:]+$' -and $v.Contains(':'))) { & $add $data['QueryName'] $v }
        }
    }
    foreach ($c in @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -in 1, 28 })) { & $add $c.Entry $c.Data }
    return $map
}

function Get-BlockedConnection {
    <# Event 5157 records since the given time from guarded programs, or ICMP from any program. #>
    param([datetime]$Since, [string[]]$Program, [hashtable]$Resolved = @{})
    $names = @($Program | ForEach-Object { (Split-Path $_ -Leaf).ToLowerInvariant() })
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = $Since } -ErrorAction SilentlyContinue)
    foreach ($e in $events) {
        $data = @{}
        foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $data[$d.Name] = [string]$d.'#text' }
        $app = (Split-Path $data['Application'] -Leaf).ToLowerInvariant()
        $dest = $data['DestAddress']
        if ($dest -match '^(127\.|::1$)') { continue }
        if ($names -contains $app -or $data['Protocol'] -in @('1', '58')) {
            $hostNames = @()
            if ($Resolved.ContainsKey($dest)) { $hostNames = @($Resolved[$dest]) }
            $revocation = ($data['Protocol'] -eq '6') -and ($data['DestPort'] -eq '80') -and @($hostNames | Where-Object { $revocationHosts -contains $_ }).Count -gt 0
            $updatePing = ($data['Protocol'] -in @('1', '58')) -and ($app -eq 'system') -and @($hostNames | Where-Object { $n = $_; @($windowsUpdateHosts | Where-Object { $n -like $_ }).Count -gt 0 }).Count -gt 0
            $exempt = ''
            if ($revocation) { $exempt = 'Revocation' } elseif ($updatePing) { $exempt = 'WindowsUpdate' }
            [pscustomobject]@{ Time = $e.TimeCreated; Application = $data['Application']; Destination = $dest; Port = $data['DestPort']; Protocol = $data['Protocol']; Names = ($hostNames -join ', '); Exempt = $exempt; Counted = -not $exempt }
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
        $null = & wevtutil.exe sl $dnsLog /e:true
        if ($LASTEXITCODE -ne 0) { Write-Host 'wevtutil failed: name lookups would not be recorded.' -ForegroundColor Red; exit 1 }
        Clear-DnsClientCache
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
        if ($rc -ne 0) { $seen | ForEach-Object { Write-Host ('  {0} -> {1}:{2} (protocol {3})' -f $_.Application, $_.Destination, $_.Port, $_.Protocol) }; Write-Host 'The guard did not see every canary attempt.' -ForegroundColor Red; exit 1 }
        $s | Add-Member -NotePropertyName Baseline -NotePropertyValue (Get-Date).ToString('o') -Force
        $s | ConvertTo-Json | Set-Content -LiteralPath $state -Encoding UTF8
        exit 0
    }
    'Check' {
        $s = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
        if (-not $s.Baseline) { Write-Host 'No baseline: Start and Canary did not run.' -ForegroundColor Red; exit 1 }
        $rc = 0
        $resolved = Get-ResolvedName -Since ([datetime]$s.Started)
        $all = @(Get-BlockedConnection -Since ([datetime]$s.Baseline) -Program $s.Programs -Resolved $resolved)
        $revocationOnly = @($all | Where-Object { $_.Exempt -eq 'Revocation' })
        if ($revocationOnly.Count -gt 0) {
            Write-Host ('Not counted: {0} TCP port 80 connection(s) to Microsoft certificate revocation hosts (Windows CRL/OCSP checks):' -f $revocationOnly.Count)
            $revocationOnly | Group-Object Application, Destination, Names | ForEach-Object { Write-Host ('  {0} x {1}' -f $_.Count, $_.Name) }
        }
        $updateOnly = @($all | Where-Object { $_.Exempt -eq 'WindowsUpdate' })
        if ($updateOnly.Count -gt 0) {
            Write-Host ('Not counted: {0} ping(s) from the System process to Windows Update hosts (Windows Update''s own checks):' -f $updateOnly.Count)
            $updateOnly | Group-Object Application, Destination, Names | ForEach-Object { Write-Host ('  {0} x {1}' -f $_.Count, $_.Name) }
        }
        $seen = @($all | Where-Object { $_.Counted })
        if ($seen.Count -gt 0) {
            Write-Host ('FAIL: {0} connection(s) were blocked: a script tried to reach beyond the runner.' -f $seen.Count) -ForegroundColor Red
            $seen | Select-Object -First 40 | ForEach-Object { Write-Host ('  {0:HH:mm:ss}  {1} -> {2}:{3} (protocol {4}; name: {5})' -f $_.Time, $_.Application, $_.Destination, $_.Port, $_.Protocol, $(if ($_.Names) { $_.Names } else { 'none recorded' })) }
            $rc = 1
        }
        else { Write-Host 'PASS: no counted connection from the guarded programs was blocked after the canary.' }
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
