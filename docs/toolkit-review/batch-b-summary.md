# Batch B summary (B1-B4)

Updated 2026-10-21. Commit `9523d99`. Development machine: macOS 26, PowerShell 7,
bash 3.2.57 and 5.3, ShellCheck, PSScriptAnalyzer.

Harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
86 steps, 34 passed, 0 failed, 52 not run (other platforms, sudo, active network).
Stubbed bash tests: 284 passed under bash 3.2 and 5.3. Mocked Windows logic test
(`tests/Test-BatchBWindowsLogic.ps1`): 54 passed on PowerShell 7.

## Status

- **run**: run for real on that platform (passive, without sudo).
- **mocked**: logic run on pwsh 7 against stand-in Windows cmdlets; not run on Windows.
- **stubbed only**: logic run against stub commands and a fake file system on macOS.
  No Linux machine has run any of it.

| ID | Windows | macOS | Linux |
|---|---|---|---|
| B1 health snapshot | not run on Windows; mocked | run | stubbed only |
| B2 connectivity | not run on Windows; `-Passive` mocked | run (`--passive` only) | stubbed only |
| B3 recent errors | not run on Windows; mocked | run | stubbed only |
| B4 restart services | not run on Windows (earlier fix) | run (`--what-if`, refusal) | stubbed only |

B4 on macOS has not changed anything for real: only `--what-if` and the "not root" refusal ran.
Its restart and cache-clearing paths ran against stub `launchctl`, `dscacheutil` and `killall`.

## What changed

| Script | Change |
|---|---|
| B1 `Get-ClientHealthSnapshot.ps1` 2.0.0 | Rewritten: statuses, JSON/CSV, log; free-space rule; cached update info (the old version searched Windows Update online) |
| B2 `Get-NetworkConnectivityReport.ps1` 2.0.0 | Rewritten: layers in order, one "First failing layer" answer, `-Passive`, prints every address before sending |
| B3 `Get-RecentCriticalErrors.ps1` 2.0.0 | Rewritten: 48 h default, no admin needed, crash/shutdown/disk/service/app checks, JSON/CSV |
| B1-B4 bash versions | New, same check names and IDs as Windows |
| `msp-toolkit-common.sh` 1.3.0 | New Change section; fix for data tables created inside a pipeline |

Design choices to review:

1. **B2 `--passive` / `-Passive`** was added (not in the catalog) so B2 can run on the
   development machine and in the harness without traffic.
2. **B4 Linux NetworkManager** is on the allow-list but not in the default set: a restart drops
   the network for a few seconds, which also drops a remote session. It runs only when named.
3. **B4 macOS mDNSResponder** is never restarted: its DNS cache is cleared with Apple's method
   (`dscacheutil -flushcache; killall -HUP mDNSResponder`), like Windows' DNS Client.
4. **B3 macOS** does not search the unified log by default: a 48-hour search took 77 s on this
   Mac. It reads panic and crash report names and dates, `last reboot shutdown`, and SMART
   status. `--include-system-log` (1.1.0, `d7eaef0`) adds a search of kernel I/O, media and
   disk errors in the window; it warns that this can take a minute or more (45 s for 48 hours
   on this Mac) and stops after 10 minutes.
5. **B3 Linux without journal access** reports the journal checks as SKIPPED (with the sudo
   command), never as "none found".

## Bug fixed in Batch A scripts

A bash data table first filled inside a pipeline (`... | while read`) ran in a subshell, so the
main script did not know it existed. The table was left out of the export, and the next new
table reused its file. Seen in A6 macOS: `PendingUpdates.csv` held the `RecentUpdates` rows and
`RecentUpdates.csv` was missing. Table names are now kept in the run folder. The fix is in every
bash script (regenerated helper) and has a helper unit test that fails without it.

## Open items

- Batch A step A-3 is done (see `batch-a-summary.md`).
- B1-B3 are not in the home-audit bundle or the A9 report's coverage table; they are ticket
  tools, run on their own.

## Outstanding hand tests

Batch A hand tests are in `batch-a-summary.md`. Batch B adds the following. Run from the
repository root.

### Windows (PowerShell 5.1)

The harness covers B1, B2 `-Passive`, B3 and B4 `-WhatIf` / refusal:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1
```

Then by hand:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\endpoint-systems\diagnostics\system-info\Get-ClientHealthSnapshot.ps1 -OutputPath $o
.\endpoint-systems\diagnostics\event-logs\Get-RecentCriticalErrors.ps1 -Hours 168 -IncludeWarnings -OutputPath $o
```

Check: B1 pending updates come from the cached scan (no long wait); B3 names services and
programs; nothing shows ERROR.

### macOS with sudo

```bash
o=/tmp/msp-hand; mkdir -p "$o"
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh </dev/null
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --output "$o"
```

The first must refuse (exit 1, "cannot answer a confirmation prompt"). The second asks you to
type YES, then clears the DNS cache and restarts cupsd only if it is running. Check the
before/after state and exit code 0. Delete `/tmp/msp-hand` afterwards.

### Real Linux runs (all Linux results so far are stubbed only)

On one apt system (Ubuntu or Debian) and one dnf system (Fedora):

```bash
o=/tmp/msp-hand; mkdir -p "$o"
bash endpoint-systems/diagnostics/system-info/get-client-health-snapshot.sh --output "$o"
bash endpoint-systems/diagnostics/networking/get-network-connectivity-report.sh --passive --output "$o"
bash endpoint-systems/diagnostics/event-logs/get-recent-critical-errors.sh --output "$o"
sudo bash endpoint-systems/diagnostics/event-logs/get-recent-critical-errors.sh --hours 168 --output "$o"
bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --what-if
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh </dev/null
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --services cups
```

Check: B1 lists every real disk and no snap/loop mounts; B3 as a normal user either reads the
journal (adm / systemd-journal group) or says SKIPPED, and with sudo shows journal counts; B4
`--what-if` shows the plan, the `</dev/null` run refuses (exit 1), and the last run asks for
YES and restarts CUPS. Run `--services NetworkManager` only at the computer, not over SSH.

### Active network (each run needs your approval; name the subnet first)

B2 without `--passive` / `-Passive` sends: 2 pings to the gateway, a DNS lookup of
www.msftconnecttest.com, TCP connections to 1.1.1.1:443 and 8.8.8.8:443, an HTTP GET of
http://www.msftconnecttest.com/connecttest.txt and HTTPS HEAD requests to
login.microsoftonline.com, outlook.office365.com and www.google.com. It prints the list before
sending.

| Platform | Command |
|---|---|
| macOS, Linux | `bash endpoint-systems/diagnostics/networking/get-network-connectivity-report.sh` |
| Windows | `.\endpoint-systems\diagnostics\networking\Get-NetworkConnectivityReport.ps1` |
| Any (harness) | `pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1 -AllowActiveNetwork` |

Check: on a working connection the diagnosis is PASS ("Every layer works"); with Wi-Fi off it
names the adapter layer.
