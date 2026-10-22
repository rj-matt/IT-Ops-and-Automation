# Batch A summary (A1-A9)

Updated 2026-10-21. Built in steps A-1 (A1-A4) and A-2 (A5-A8), plus the A9 finding-ID fix,
the A6 support-date review and the A8 `~/Applications` change. Development machine: macOS 26
(Apple silicon), PowerShell 7, bash 3.2.57 and 5.3, ShellCheck, PSScriptAnalyzer.

Harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
69 steps, 28 passed, 0 failed, 41 not run (other platforms, sudo, active network).
Stubbed bash tests (`tests/bash/test-scripts-mocked.sh`): 200 passed under bash 3.2 and 5.3.

## Status

- **run**: run for real on that platform (passive, without sudo unless noted).
- **built**: written to standard; parse, analyzer and logic checks only; not run there.
- **stubbed only**: logic run against stub commands and a fake file system on macOS.
  No Linux machine has run any of it.

| ID | Windows | macOS | Linux |
|---|---|---|---|
| A1 endpoint security | built | run | stubbed only |
| A2 network map | built | run (`--passive` only) | stubbed only |
| A3 Wi-Fi | built | run | stubbed only |
| A4 open ports | built | run (no `--scan-lan`) | stubbed only |
| A5 browsers | built | run | stubbed only |
| A6 updates | built | run (no `--online`) | stubbed only |
| A7 router | built | stubbed only (active) | stubbed only |
| A8 inventory | built | run | stubbed only |
| A9 report | built | run (pwsh 7), gaps below | not run |
| Bundle | built | missing | missing |

## Done since the A-2 stop

| Commit | Change |
|---|---|
| `57a43f7` | A6 macOS/Linux 1.1.0: every support-table row has its official source URL and a verified-on date; unconfirmed rows say so in the finding |
| `3c5d558` | A8 1.1.0: macOS `~/Applications` (one folder deep); `--all-users` (root) adds every user's `~/Applications` |

A6 dates not confirmed by an official source (marked `unverified` in the scripts):

| Row | Why |
|---|---|
| macOS 15 expected end (2027-09) | Apple publishes no end dates; estimate from past releases |
| Pop!_OS 22.04, 24.04 | System76 publishes no end dates |
| Fedora 43, 44, 45 | EOL is 4 weeks after release N+2; Fedora 45 had not shipped on 2026-10-21; the Fedora schedule pages block automated readers |
| RHEL 9, 10 | The Red Hat life-cycle page did not show its dates table |

Fedora 42 (2026-05-27) came from a search-index copy of the Fedora EOL page, because the page
itself blocks automated readers. Ubuntu 22.04 and 24.04 use the May dates from
ubuntu.com/about/release-cycle; Ubuntu's release-team list says June for the same releases.

## Open items in Batch A

Step A-3 from the plan is not done yet. Found while catching up:

1. **A9 coverage table ignores macOS/Linux results.** It looks results up by the Windows script
   names, so a Mac's A1-A8 results show as "Not run" (seen in a report built from this Mac's
   harness results). Fix: match on `CheckId`.
2. **A9 router checklist ignores the bash A7.** It filters on
   `ScriptName -eq 'Get-RouterSecurityCheck'`, so checklist answers from
   `get-router-security-check.sh` are left out. Fix: match on `CheckId` `A7`.
3. **Not built:** the A9 manual device checklist (phones, TVs, consoles, IoT),
   `run-home-audit-bundle.sh` for macOS/Linux, and the Windows bundle update.

## Outstanding hand tests

Run from the repository root. Validate any result folder with
`pwsh -NoProfile -File tests/Test-MSPResultSchema.ps1 -Path <folder>`.

### Windows (no Windows run of any Batch A change yet)

PowerShell 5.1, once from a normal window and once from "Run as administrator":

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1
```

That runs A1-A8 passive, the bundle with A9, and B4/D1/D2/D3 with `-WhatIf` / `-BackupOnly` /
the non-interactive refusal. Then, as administrator:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\endpoint-systems\diagnostics\system-info\Get-BrowserSecurityCheck.ps1 -AllUsers -OutputPath $o
.\endpoint-systems\audit\software-inventory\Get-HomeDeviceInventory.ps1 -IncludeOtherUsers -OutputPath $o
```

Check: A1 shows BitLocker, TPM and SMBv1 without SKIPPED; A6 resolves this PC's build.

### macOS with sudo

```bash
o=/tmp/msp-hand; mkdir -p "$o"
sudo /bin/bash tests/bash/test-msp-helper.sh
sudo bash security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-macos.sh --output "$o"
sudo bash core-infrastructure/networking/diagnostics/get-wifi-security-audit-macos.sh --output "$o"
sudo bash endpoint-systems/diagnostics/system-info/get-browser-security-check.sh --all-users --output "$o"
sudo bash endpoint-systems/audit/software-inventory/get-home-device-inventory.sh --all-users --output "$o"
```

Check: A1 FileVault recovery key check runs; A3 lists security types of saved networks;
A5 and A8 list other users (A8: "Also listing the apps in N other user(s)' ~/Applications",
`User: <name>` scopes in the Software CSV, and your own apps still under your name, not root).
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
```

Check: no ERROR findings; A6 finds the distribution in its table; A1 with sudo shows root
password status and the running SSH settings; A8 with sudo shows the serial number and the
empty-password check.

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
| macOS | `bash endpoint-systems/diagnostics/system-info/get-update-compliance-macos.sh --online` | Apple update servers |
| Linux | `bash endpoint-systems/diagnostics/system-info/get-update-compliance-linux.sh --online` | package servers, Snap Store |
| Windows | `.\core-infrastructure\networking\diagnostics\Get-HomeNetworkMap.ps1` | ping sweep + reverse DNS |
| Windows | `.\security-operations\diagnostics\endpoint-posture\Get-OpenPortScan.ps1 -ScanLan` | ping + 11 TCP ports per device |
| Windows | `.\core-infrastructure\networking\diagnostics\Get-RouterSecurityCheck.ps1` | HTTP/TCP to the gateway, SSDP |
| Windows | `.\endpoint-systems\diagnostics\system-info\Get-WindowsUpdateCompliance.ps1 -Online` | Microsoft Update |
| Windows | `.\endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1 -WhatIf` | ping gateway, DNS, TCP to Microsoft |

Run A7 from a terminal once so the guided checklist is asked (the harness skips the prompt).
