# Batch A summary (A1-A9)

Updated 2026-10-23 (Windows bundle `-Passive` added after the A-3 stop). Built in steps A-1 (A1-A4), A-2 (A5-A8) and A-3 (A9 for every platform,
device checklist, macOS/Linux bundle), plus the A9 finding-ID fix, the A6 support-date review
and the A8 `~/Applications` change. Development machine: macOS 26 (Apple silicon),
PowerShell 7, bash 3.2.57 and 5.3, ShellCheck, PSScriptAnalyzer.

Harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
91 steps, 36 passed, 0 failed, 55 not run (other platforms, sudo, active network).
Stubbed bash tests (`tests/bash/test-scripts-mocked.sh`): 310 passed under bash 3.2 and 5.3.
Mixed-platform A9 test (`tests/Test-ExportSecurityAuditReportMixed.ps1`): 32 passed on
PowerShell 7 (23 of the 32 fail against A9 1.2.0).

## Status

- **run**: run for real on that platform (passive, without sudo unless noted).
- **not run on Windows**: written to standard; parse, analyzer and (where noted) mocked logic
  checks on PowerShell 7 on macOS only. No Windows machine has run any Batch A change yet.
- **built**: the same for macOS/Linux: not run on that platform.
- **stubbed only**: logic run against stub commands and a fake file system on macOS.
  No Linux machine has run any of it.

| ID | Windows | macOS | Linux |
|---|---|---|---|
| A1 endpoint security | not run on Windows | run | stubbed only |
| A2 network map | not run on Windows | run (`--passive` only) | stubbed only |
| A3 Wi-Fi | not run on Windows | run | stubbed only |
| A4 open ports | not run on Windows | run (no `--scan-lan`) | stubbed only |
| A5 browsers | not run on Windows | run | stubbed only |
| A6 updates | not run on Windows | run (no `--online`) | stubbed only |
| A7 router | not run on Windows | stubbed only (active) | stubbed only |
| A8 inventory | not run on Windows | run | stubbed only |
| A9 report | not run on Windows (5.1 or 7); mixed-platform test mocked | run (pwsh 7, mixed set below) | not run |
| Bundle | not run on Windows; `-Passive` mocked | run (`--passive`, without sudo) | stubbed only |

## Done in step A-3

| Commit | Change |
|---|---|
| `d7eaef0` | B3 macOS 1.1.0: opt-in `--include-system-log` (see `batch-b-summary.md`) |
| `9034075` | A8 macOS/Linux 1.1.1: last login read by weekday, not fixed columns of `last` (local macOS logins have no host column, so LastLogon was blank and "unused account" could not fire). Found while building E1; run on this Mac |
| `a632f1c` | Windows bundle 1.2.0: `-Passive` (A2 `-Passive`, A7 not run, refused with `-ScanLan` / `-OnlineUpdateSearch`); mocked test (`tests/Test-HomeAuditBundleWindowsLogic.ps1`, 19 checks) and a Windows harness runtime case |
| `ca105d9` | A9 1.3.0: coverage, areas and bundle lines keyed on the check ID (A1-A8), so macOS/Linux results fill the same rows; router checklist from any A7; "Other devices checklist" section; OS version per device. `run-home-audit-bundle.sh` 1.0.0. Tests, harness cases, README |

A9 test with a mixed set (PowerShell 7 on this Mac,
`tests/Test-ExportSecurityAuditReportMixed.ps1 -ExtraInputPath <mac>,<linux>`):

| Source | Platform | How produced |
|---|---|---|
| Made-up results (in the test) | Windows | A1, A2 with devices, A7 checklist answers, a bundle result with one skipped and one failed script |
| `run-home-audit-bundle.sh --passive` on this Mac | macOS | Real run, no sudo, nothing sent: A1-A6 and A8 completed, A7 not run (passive) |
| `run-home-audit-bundle.sh --passive` under the stubs | Linux | `test-scripts-mocked.sh --keep`, stub commands only |

Result: every macOS and Linux script appears in the coverage table under its check name; A7
"Not run" shows the bundle's reason; Windows and bash A7 answers are both in the router
checklist; the devices found by the Mac's and the Linux A2 are listed once each, without the
router or the computers in the report. One bug was found and fixed before the commit:
Windows writes MAC addresses as `AA-BB-...` and macOS/Linux as `aa:bb:...`, so the same
device was listed twice. The report and result files stayed in the session's temporary folder
(they name this Mac and the devices on its network) and were not committed.

`run-home-audit-bundle.sh` decisions:

1. **`--passive`** (not in the Windows bundle): A2 reads the neighbor table only and A7 is not
   run, because every A7 check talks to the router. Refused together with `--scan-lan` or
   `--online`. Without it the bundle behaves like the Windows one (A2 ping sweep, A7 run).
2. **`--include-router-checklist`**: A7 then runs at the terminal with no time limit (the
   questions take as long as the client does). Without a terminal it falls back to
   "Not verified", as A7 does on its own.
3. **The A9 report** needs PowerShell 7. With `--technician` and no `pwsh`, the bundle prints
   the command to run on another computer.

## Open items in Batch A

1. **Windows bundle update**: `-Passive` added (`a632f1c`). Not run on Windows.
2. **A9 on Windows PowerShell 5.1** has not run since the A-3 changes; the harness on Windows
   runs both A9 tests on 5.1 and 7.
3. B1-B3 are not in the bundle or the coverage table (ticket tools, run on their own).

## Outstanding hand tests

Run from the repository root. Validate any result folder with
`pwsh -NoProfile -File tests/Test-MSPResultSchema.ps1 -Path <folder>`.

### Windows (no Windows run of any Batch A change yet)

PowerShell 5.1, once from a normal window and once from "Run as administrator":

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1
```

That runs A1-A8 passive, the bundle with A9, the bundle with `-Passive`, both A9 logic tests
(including the Windows/macOS/Linux mix) and the mocked bundle test on 5.1 and 7, and B4/D1/D2/D3 with `-WhatIf` / `-BackupOnly` / the
non-interactive refusal. Then, as administrator:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\endpoint-systems\diagnostics\system-info\Get-BrowserSecurityCheck.ps1 -AllUsers -OutputPath $o
.\endpoint-systems\audit\software-inventory\Get-HomeDeviceInventory.ps1 -IncludeOtherUsers -OutputPath $o
```

Check: A1 shows BitLocker, TPM and SMBv1 without SKIPPED; A6 resolves this PC's build.

Combined report on 5.1: put the PC's bundle folder and a Mac's `run-home-audit-bundle.sh`
folder (copied from the Mac) under one parent folder, then:

```powershell
.\security-operations\diagnostics\Export-SecurityAuditReport.ps1 -InputPath <parent> -Recurse -TechnicianName "Test"
```

Check: the Mac's rows in Coverage show dates (not "Not run"); "Other devices checklist" lists
the devices from both A2 runs once each; the report opens and prints (the checkboxes print).

### macOS with sudo

```bash
o=/tmp/msp-hand; mkdir -p "$o"
sudo /bin/bash tests/bash/test-msp-helper.sh
sudo bash security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-macos.sh --output "$o"
sudo bash core-infrastructure/networking/diagnostics/get-wifi-security-audit-macos.sh --output "$o"
sudo bash endpoint-systems/diagnostics/system-info/get-browser-security-check.sh --all-users --output "$o"
sudo bash endpoint-systems/audit/software-inventory/get-home-device-inventory.sh --all-users --output "$o"
sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --all-users --technician "Test" --output "$o"
```

Check: A1 FileVault recovery key check runs; A3 lists security types of saved networks;
A5 and A8 list other users (A8: "Also listing the apps in N other user(s)' ~/Applications",
`User: <name>` scopes in the Software CSV, and your own apps still under your name, not root).
The bundle shows "Elevated: Yes", runs A5 and A8 with `--all-users`, and writes
`SecurityAuditReport_*.html` into its `HomeAudit_*` folder.
Delete `/tmp/msp-hand` afterwards (it holds account and app names).

### Real Linux runs (all Linux results so far are stubbed only)

On one apt system (Ubuntu or Debian, NetworkManager) and one dnf system (Fedora):

```bash
bash tests/bash/test-msp-helper.sh
bash tests/bash/test-scripts-mocked.sh
pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1      # if PowerShell 7 is installed
o=/tmp/msp-hand; mkdir -p "$o"
bash security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-linux.sh --output "$o"
bash core-infrastructure/networking/diagnostics/get-home-network-map.sh --passive --output "$o"
bash core-infrastructure/networking/diagnostics/get-wifi-security-audit-linux.sh --output "$o"
bash security-operations/diagnostics/endpoint-posture/get-open-port-scan.sh --output "$o"
bash endpoint-systems/diagnostics/system-info/get-browser-security-check.sh --output "$o"
bash endpoint-systems/diagnostics/system-info/get-update-compliance-linux.sh --output "$o"
bash endpoint-systems/audit/software-inventory/get-home-device-inventory.sh --output "$o"
sudo bash security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-linux.sh --output "$o"
sudo bash security-operations/diagnostics/endpoint-posture/get-open-port-scan.sh --output "$o"
sudo bash endpoint-systems/diagnostics/system-info/get-browser-security-check.sh --all-users --output "$o"
sudo bash endpoint-systems/audit/software-inventory/get-home-device-inventory.sh --output "$o"
bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --output "$o"
sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --technician "Test" --output "$o"
```

Check: no ERROR findings; A6 finds the distribution in its table; A1 with sudo shows root
password status and the running SSH settings; A8 with sudo shows the serial number and the
empty-password check. The bundle runs the `-linux.sh` scripts, all "Completed" except A7
("Skipped (passive)"); the `--technician` run builds the report only if `pwsh` is installed,
otherwise it prints the command.

### Active network (each run needs your approval; name the subnet first)

Each script prints the subnet or gateway before it sends anything. Harness, all at once on the
current platform:

```bash
pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1 -AllowActiveNetwork
```

Or one at a time:

| Platform | Command | Sends |
|---|---|---|
| macOS, Linux | `bash core-infrastructure/networking/diagnostics/get-home-network-map.sh` | ping sweep + name lookups, local subnet |
| macOS, Linux | `bash security-operations/diagnostics/endpoint-posture/get-open-port-scan.sh --scan-lan` | ping + 11 TCP ports per device |
| macOS, Linux | `bash core-infrastructure/networking/diagnostics/get-router-security-check.sh` | HTTP/TCP to the gateway, SSDP |
| macOS, Linux | `bash security-operations/diagnostics/run-home-audit-bundle.sh --include-router-checklist --technician "Test"` | A2 ping sweep + name lookups, A7 (HTTP/TCP to the gateway, SSDP); asks the router checklist |
| macOS | `bash endpoint-systems/diagnostics/system-info/get-update-compliance-macos.sh --online` | Apple update servers |
| Linux | `bash endpoint-systems/diagnostics/system-info/get-update-compliance-linux.sh --online` | package servers, Snap Store |
| Windows | `.\core-infrastructure\networking\diagnostics\Get-HomeNetworkMap.ps1` | ping sweep + reverse DNS |
| Windows | `.\security-operations\diagnostics\endpoint-posture\Get-OpenPortScan.ps1 -ScanLan` | ping + 11 TCP ports per device |
| Windows | `.\core-infrastructure\networking\diagnostics\Get-RouterSecurityCheck.ps1` | HTTP/TCP to the gateway, SSDP |
| Windows | `.\endpoint-systems\diagnostics\system-info\Get-WindowsUpdateCompliance.ps1 -Online` | Microsoft Update |
| Windows | `.\endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1 -WhatIf` | ping gateway, DNS, TCP to Microsoft |

Run A7 from a terminal once so the guided checklist is asked (the harness skips the prompt).
