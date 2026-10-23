# Scripting & Automation

## Overview
This repository contains operational scripts used to support troubleshooting,
diagnostics, remediation, auditing, and repeatable administrative tasks across
client environments.

The intent is to provide a centralized, consistent, and reliable set of tools
that reduce manual effort, improve response time, and promote predictable outcomes
during support and incident workflows.

---

## Organization Philosophy
Scripts are organized to reflect how work is actually performed:

1. By environment or scope (endpoint-systems, cloud-services, core-infrastructure, security-operations)
2. By function (diagnostics, remediation, audit, automation)

This structure is designed to make it easy to:

- Locate the right tool quickly
- Understand what a script affects before running it
- Reduct accidental misuse across environments

## Usage Expectations
Scripts in this repository are intended to be

- Reviewed before execution
- Used in the appropriate context
- Applied deliberately, not indiscriminately

Diagnostic scripts are generally read-only
Remediation scripts may modify system or tenant state and should be treated accordingly.

When in doubt, pause and confirm before proceeding.

---

## Script Standards

Each script includes a header describing:

- Purpose and use case
- Scope and impact
- Requirements or prerequisites
- Risk considerations
- Last verification date

These headers exist to support safe reuse, faster decision-making, and easier handoff
between technicians.

---

## Client-Specific Logic
Client-specific scripts are intentionally separated from general-purpose tooling.
This reduces the risk of cross-client impact and helps maintain clarity around scope
and intent

General-purpose scripts should remain client-agnostic unless explicitly noted.

---

## Maintenance and Improvement
Scripts are exptected to evolve as platforms, tooling, and best practices change.
Updates should prioritize:

- Clarity over cleverness
- Predictability over speed
- Safety over convenience

Scheduled upkeep:

- **Windows end-of-support table (A6).** `Get-WindowsUpdateCompliance.ps1` has a built-in
  `$lifecycle` table (build -> version, consumer/business/LTSC end dates) plus the Windows 10
  ESU end dates, marked "Reviewed 2026-10". Review it **every October and April** (feature
  updates ship in the autumn; Microsoft sometimes adjusts dates) and whenever a run reports a
  build as "newer than (or not in) this script's lifecycle table". Take dates only from
  Microsoft Lifecycle / Windows release health, add a row per new build, update the
  "Reviewed" comment and the `.NOTES` Limitations date, bump the script version, and run the
  script once to confirm the current PC's build resolves. A stale table under-reports
  end-of-support: an unsupported Windows version looks supported.
- **Approved remote tools.** Update `approved-remote-tools.txt` (next to
  `Get-HomeDeviceInventory.ps1` and `get-home-device-inventory.sh`, which both read it) when the
  MSP adds or retires an RMM/remote-support product.
- **macOS and Linux support tables (A6).** `get-update-compliance-macos.sh` (`SUPPORT_TABLE`:
  macOS majors) and `get-update-compliance-linux.sh` (`SUPPORT_TABLE`: Ubuntu, Debian, Fedora,
  RHEL family, Mint, Pop!_OS end dates) were reviewed 2026-10-21. Every row carries the official
  page its date came from and the day it was checked there; a row no official page confirmed is
  marked `unverified`, and the script says "not confirmed" when it reports that date. Review them
  every April and October like the Windows table: add new releases, take dates only from the
  vendor's own pages (macOS: Apple security releases, support.apple.com/en-us/100100, since
  Apple publishes no end dates; Ubuntu release cycle; Debian LTS wiki; Fedora EOL page; Red Hat,
  Rocky, Alma, CentOS, Mint release pages), update the source and verified-on fields, and try
  again to confirm the `unverified` rows.

Deprecated or superseded scripts should be retained in designated locations rather
than removed outright to preserve context.

---

## Operating Principle
Automation is most effective when it:

- Encodes known-good practices
- Reduces unnecessary variability

This repository exists to support those outcomes

---

## Script Catalog

Scripts reviewed against the toolkit standards (Batches A-C: home network audit, client
diagnostics, Microsoft 365 and triage, plus the safety fixes for the live remediation scripts). Every Windows script below runs on **Windows PowerShell
5.1** with **built-in modules only**, works without admin (admin-only checks show `SKIPPED`), logs
to `%TEMP%\MSP-Toolkit\`, and supports `-OutputPath` for JSON/CSV results. The macOS and Linux
scripts are listed after them.

Scripts that change something (B4, D1, D2, D3) always: show the current state and a numbered
plan first; support `-WhatIf` (plan only, nothing changed, no admin needed); ask you to type
**YES**; refuse to change anything in a non-interactive session (RMM job, scheduled task) unless
`-Force` is given; record the state afterwards; and say plainly what cannot be undone.
Exit codes: `0` done, `1` nothing changed (not admin / not confirmed / non-interactive),
`2` a step failed. The bash version of B4 (`restart-common-services.sh`) follows the same rules
with `--what-if` and `--force`.

| Script | Folder | Purpose | Risk | Admin required | PS version | Modules |
|---|---|---|---|---|---|---|
| `Get-EndpointSecurityStatus.ps1` (A1) | `security-operations/diagnostics/endpoint-posture/` | Antivirus, firewall, BitLocker, updates, local admins, UAC, SMBv1, Secure Boot, RDP | Read-Only | No (admin adds TPM, authoritative BitLocker/SMBv1) | 5.1 | Built-in |
| `Get-HomeNetworkMap.ps1` (A2) | `core-infrastructure/networking/diagnostics/` | Devices on the local subnet: IP, MAC, vendor hint, hostname, device type; flags unidentified devices. `-Passive` sends nothing (neighbor table only) | Read-Only (ping + ARP) | No | 5.1 | Built-in |
| `Get-WiFiSecurityAudit.ps1` (A3) | `core-infrastructure/networking/diagnostics/` | Current Wi-Fi security, saved profiles (no keys), nearby networks | Read-Only | No | 5.1 | Built-in (netsh) |
| `Get-OpenPortScan.ps1` (A4) | `security-operations/diagnostics/endpoint-posture/` | Listening ports with owning process; optional `-ScanLan` check of 11 risky ports on local devices | Read-Only | No | 5.1 | Built-in |
| `Get-BrowserSecurityCheck.ps1` (A5) | `endpoint-systems/diagnostics/system-info/` | Chrome/Edge/Brave/Firefox versions, extensions, update-blocking policies; no credential access | Read-Only | No (Yes for `-AllUsers`) | 5.1 | Built-in |
| `Get-WindowsUpdateCompliance.ps1` (A6) | `endpoint-systems/diagnostics/system-info/` | Windows version end-of-support, last install, pending updates (COM), restart, update policies | Read-Only | No | 5.1 | Built-in |
| `Get-RouterSecurityCheck.ps1` (A7) | `core-infrastructure/networking/diagnostics/` | Gateway, DNS, admin page HTTP vs HTTPS, UPnP (SSDP) and its port forwards, guided router checklist | Read-Only (no logins) | No | 5.1 | Built-in |
| `Get-HomeDeviceInventory.ps1` (A8) | `endpoint-systems/audit/software-inventory/` | Hardware/OS, users and last logon, installed software; flags remote-access and P2P tools | Read-Only | No (Yes for `-IncludeOtherUsers`) | 5.1 | Built-in |
| `Export-SecurityAuditReport.ps1` (A9) | `security-operations/diagnostics/` | One self-contained HTML report from the JSON results of Windows, macOS and Linux computers (matched by check ID), with a printable checklist for phones, TVs, consoles and smart-home devices | Read-Only (writes the report file) | No | 5.1, or 7 on Windows/macOS/Linux | Built-in |
| `Invoke-HomeAuditBundle.ps1` | `security-operations/diagnostics/` | Runs A1-A8 in order into one timestamped folder; continues past failures; `-Passive` sends nothing (A2 neighbor table only, A7 not run); optional A9 | Read-Only | No (recommended: Yes) | 5.1 | Built-in |
| `Get-SuspiciousActivityReport.ps1` (C3) | `security-operations/diagnostics/endpoint-posture/` | **First-look triage, not an antivirus or EDR.** Startup items (Run keys, Startup folders, scheduled tasks, services) in unusual folders, running scripts, unsigned or new; programs and connections from unusual folders; Defender detections and exclusions; new accounts, additions to Administrators and failed sign-ins (Security log); hosts file; proxy | Read-Only | No (admin adds the Security log, Defender exclusions and other users' programs) | 5.1 | Built-in |
| `Get-ClientHealthSnapshot.ps1` (B1) | `endpoint-systems/diagnostics/system-info/` | System, uptime and pending restart, memory, CPU load, free space per drive, last update and updates waiting (cached) | Read-Only | No | 5.1 | Built-in |
| `Get-NetworkConnectivityReport.ps1` (B2) | `endpoint-systems/diagnostics/networking/` | Adapter, address, gateway, DNS, internet, web (captive portal) in order, proxy, VPN; names the first failing layer. `-Passive` sends nothing | Read-Only (ping, DNS, TCP 443, HTTP(S)) | No | 5.1 | Built-in |
| `Get-RecentCriticalErrors.ps1` (B3) | `endpoint-systems/diagnostics/event-logs/` | Last 48 h (`-Hours`): blue screens, unexpected shutdowns, disk errors, service failures, app crashes, error counts by source | Read-Only | No | 5.1 | Built-in |
| `Restart-CommonServices.ps1` (B4) | `endpoint-systems/remediation/safe/restart-services/` | Restarts allow-listed Spooler, wuauserv, BITS; clears the DNS Client cache (Windows does not allow restarting it); before/after state | Safe | Yes (No for `-WhatIf`) | 5.1 | Built-in |
| `Clear-WindowsUpdateCache.ps1` (D1) | `endpoint-systems/remediation/safe/clear-caches/` | Renames (never deletes) SoftwareDistribution and catroot2, restarts the update services, checks they rebuilt | Safe | Yes (No for `-WhatIf`) | 5.1 | Built-in |
| `Reset-NetworkStack.ps1` (D2) | `endpoint-systems/remediation/elevated/network-resets/` | Pre-flight, saved copy of settings, `netsh winsock reset` + `netsh int ip reset` (exit codes checked) + DNS flush; restart required; **not fully reversible** | Elevated | Yes (No for `-WhatIf` / `-BackupOnly`) | 5.1 | Built-in |
| `Reset-OutlookProfile.ps1` (D3) | `cloud-services/m365/remediation/` | Backs up Outlook profile settings, creates a new empty default profile, keeps the old one; never closes Outlook; account must be added by hand | Elevated | No (run as the affected user) | 5.1 | Built-in |
| `MSPToolkit.Common.psm1` | `endpoint-systems/utilities/` | Shared helper source (embedded into each script; not run directly) | Read-Only | - | 5.1 | - |
| `Sync-MSPEmbeddedHelper.ps1` | `endpoint-systems/utilities/` | Regenerates / verifies (`-Check`) the embedded helper copies | Safe (repo files only) | No | 5.1 | - |

**Microsoft 365 (C1, C2).** PowerShell 7 on Windows, macOS or Linux (`pwsh`), run from the
technician's computer. They only read: C1 loads only Exchange `Get-` cmdlets, C2 asks Microsoft
Graph for read-only scopes. Each reuses an existing connection, otherwise signs in (browser, or
`-DeviceCode`), and disconnects at the end unless `-KeepConnection`.

| Script | Folder | Purpose | Risk | Account | Modules |
|---|---|---|---|---|---|
| `Get-UserMailboxStatus.ps1` (C1) | `cloud-services/m365/diagnostics/` | One mailbox: size and quota, archive, holds, recoverable items, mailbox and inbox-rule forwarding (outside the organization = WARN High), rules that hide mail, auto-reply, mail apps, mobile devices, delegates | Read-Only | Global Reader or View-Only Organization Management | ExchangeOnlineManagement 3.x |
| `Get-UserLicenseReport.ps1` (C2) | `cloud-services/m365/diagnostics/` | Licenses, service plan problems, disabled accounts holding licenses, last sign-in (needs Entra ID P1/P2), subscriptions over-assigned or expired; one user, several, or `-All` | Read-Only | Global Reader; an admin consents once to `User.Read.All`, `Organization.Read.All`, `AuditLog.Read.All` | Microsoft.Graph (Authentication, Users, Identity.DirectoryManagement) |

**D1 backup folders.** `Clear-WindowsUpdateCache.ps1` renames the caches to
`C:\Windows\SoftwareDistribution.old-<yyyyMMdd-HHmmss>` and
`C:\Windows\System32\catroot2.old-<yyyyMMdd-HHmmss>` and never deletes them. Running it again is
safe: it picks a new name (adding `-2`, `-3` ... if needed) before any service is stopped, and
never reuses or overwrites an earlier `.old` or `.old-<timestamp>` folder. The `.old` folders
are only needed to undo the reset. **Once Windows Update has installed updates successfully
again, they can be deleted** (as administrator) to free disk space. The script lists any it
finds from earlier runs.

### macOS and Linux scripts

Same checks, same check names and finding IDs, same JSON/CSV (schema 2.0) as the Windows versions,
so one HTML report (A9) can combine every computer in the home. Written for **bash 3.2** (the
version macOS ships) with **only tools that come with the OS** (no Homebrew, jq or Python). They
work without root; checks that need it show `SKIPPED` with the sudo command. They never call sudo
themselves. Logs go to `${TMPDIR:-/tmp}/msp-toolkit/`; results to `--output <folder>`; `--help`
shows the options.

| Script | Folder | Platform | Purpose | Risk | Root (sudo) required |
|---|---|---|---|---|---|
| `get-endpoint-security-status-macos.sh` (A1) | `security-operations/diagnostics/endpoint-posture/` | macOS | XProtect/AV, firewall, FileVault, updates (from macOS's records, no online check), admins, guest/root/auto-login, screen lock, SIP, Gatekeeper, MDM, Remote Login, Screen Sharing | Read-Only | No (Yes adds the FileVault recovery key check) |
| `get-endpoint-security-status-linux.sh` (A1) | `security-operations/diagnostics/endpoint-posture/` | Linux | AV/EDR, ufw/firewalld/nftables, LUKS, apt/dnf pending updates from the local cache, automatic updates, sudo members, extra UID 0, guest/auto-login, Secure Boot, SELinux/AppArmor, SSH, VNC/RDP | Read-Only | No (Yes adds root password status and the running SSH settings) |
| `get-home-network-map.sh` (A2) | `core-infrastructure/networking/diagnostics/` | macOS, Linux | Devices on the local subnet; `--passive` sends nothing | Read-Only (ping + ARP) | No |
| `get-wifi-security-audit-macos.sh` (A3) | `core-infrastructure/networking/diagnostics/` | macOS | Current Wi-Fi security, saved networks, nearby networks; never reads passwords | Read-Only | No (Yes adds the security type of each saved network) |
| `get-wifi-security-audit-linux.sh` (A3) | `core-infrastructure/networking/diagnostics/` | Linux (NetworkManager) | Current Wi-Fi security, saved connections (no secrets), nearby networks from the last scan | Read-Only | No |
| `get-open-port-scan.sh` (A4) | `security-operations/diagnostics/endpoint-posture/` | macOS, Linux | Listening ports with owning process; optional `--scan-lan` check of 11 risky ports on local devices | Read-Only | No (on Linux, Yes shows other users' process names) |
| `get-browser-security-check.sh` (A5) | `endpoint-systems/diagnostics/system-info/` | macOS, Linux | Chrome/Edge/Brave/Chromium/Firefox versions (estimated current), extensions, force-install and update-blocking policies; Safari version and extensions on macOS; no credential or history access | Read-Only | No (Yes for `--all-users`) |
| `get-update-compliance-macos.sh` (A6) | `endpoint-systems/diagnostics/system-info/` | macOS | macOS version support (built-in table from Apple's security releases, verified 2026-10-21), last macOS update, pending updates from the last check (`--online` asks Apple), uptime, update settings and profiles | Read-Only | No |
| `get-update-compliance-linux.sh` (A6) | `endpoint-systems/diagnostics/system-info/` | Linux (apt, dnf) | Distribution support (built-in table, sources verified 2026-10-21), last package update, pending (security) updates from the local lists (`--online` refreshes into a temporary folder), restart needed, automatic updates, held packages/snaps | Read-Only | No |
| `get-router-security-check.sh` (A7) | `core-infrastructure/networking/diagnostics/` | macOS, Linux | Gateway, DNS, admin page HTTP vs HTTPS, management ports, UPnP (SSDP, needs perl) and its port forwards, guided router checklist | Read-Only (no logins) | No |
| `get-home-device-inventory.sh` (A8) | `endpoint-systems/audit/software-inventory/` | macOS, Linux | Hardware/OS, accounts and last login, home folders, installed apps/packages (macOS: `/Applications` and `~/Applications`; every user's with `--all-users`); flags remote-access and P2P tools (uses `approved-remote-tools.txt`) | Read-Only | No (Linux: Yes adds serial number and empty-password check; macOS: Yes for `--all-users`) |
| `run-home-audit-bundle.sh` | `security-operations/diagnostics/` | macOS, Linux | Runs A1-A8 in order into one timestamped folder; continues past failures; `--passive` sends nothing (A2 neighbor table only, A7 not run); optional A9 with `--technician` (needs `pwsh`) | Read-Only | No (recommended: Yes) |
| `get-suspicious-activity-report-macos.sh` (C3) | `security-operations/diagnostics/endpoint-posture/` | macOS | **First-look triage, not an antivirus or EDR.** Launch agents/daemons and cron in unusual folders, running scripts, unsigned or new; Background items; login shell files; programs and connections from unusual folders; SSH keys; hosts file; proxy | Read-Only | No (Yes adds other users and Background items) |
| `get-suspicious-activity-report-linux.sh` (C3) | `security-operations/diagnostics/endpoint-posture/` | Linux | **First-look triage, not an antivirus or EDR.** systemd units, autostart, cron and rc.local in unusual folders, running scripts or new; `ld.so.preload`; login shell files; programs from unusual folders or memory only, and their connections; SSH keys; failed SSH sign-ins; hosts file; proxy | Read-Only | No (Yes, or the adm / systemd-journal group, for the journal; Yes for other users and every process) |
| `get-client-health-snapshot.sh` (B1) | `endpoint-systems/diagnostics/system-info/` | macOS, Linux | System, uptime and pending restart, memory, load, free space per volume, last update and updates waiting (cached) | Read-Only | No (Linux: Yes adds serial number) |
| `get-network-connectivity-report.sh` (B2) | `endpoint-systems/diagnostics/networking/` | macOS, Linux | Same layers and diagnosis as the Windows version; `--passive` sends nothing | Read-Only (ping, DNS, TCP 443, HTTP(S) via curl) | No |
| `get-recent-critical-errors.sh` (B3) | `endpoint-systems/diagnostics/event-logs/` | macOS, Linux | macOS: panic and crash reports, restarts without shutdown, SMART (`--include-system-log` adds kernel disk errors; slow). Linux: journal (kernel crashes, disk errors, failed units, segfaults, error counts), `last -x`, apport | Read-Only | No (Linux: Yes, or the adm / systemd-journal group, for system messages) |
| `restart-common-services.sh` (B4) | `endpoint-systems/remediation/safe/restart-services/` | macOS, Linux | Allow-list only: macOS mDNSResponder (DNS cache cleared) and cupsd; Linux cups, systemd-resolved, NetworkManager (only when named). `--what-if`, type YES, `--force` for non-interactive runs; before/after state | Safe | Yes (No for `--what-if`) |

Run them with `bash <script>` (no need to make them executable, and macOS's quarantine flag on
downloaded files does not apply to a script passed to bash). On macOS, macOS hides Wi-Fi names
from Terminal unless it has Location Services permission; the A3 ratings still work and the
name-matching checks say so. None of these scripts need Full Disk Access.

Scripts not listed here have not yet been reviewed against the standards (Batch E).
Superseded scripts and unsigned binaries are in `_archive/` (see `_archive/README.md`).

---

## Home Network Audit Runbook

Run on each PC the client wants checked, with the client present (the router checklist needs
their router login, which **they** type).

### 1. Get the scripts onto the PC

Copy the toolkit **without `_archive`** (it holds superseded scripts and unsigned binaries that
must never reach a client machine):

```powershell
robocopy "<repo>" "E:\MSP-Toolkit" *.ps1 approved-remote-tools.txt /S /XD _archive .git
```

`git archive` and GitHub "Download ZIP" already leave `_archive` out (`.gitattributes`).
A flat folder (all `.ps1` files side by side) also works: the bundle looks next to itself first.
Keep `approved-remote-tools.txt` in the same folder as `Get-HomeDeviceInventory.ps1`; without
it, our own RMM agent is flagged like any other remote-access tool.

### 2. Allow the scripts to run (non-managed home PCs)

Do **not** change the PC's execution policy (`Set-ExecutionPolicy` is not part of this runbook).
Instead, for this session only:

```powershell
# a) Remove the "downloaded from the internet" mark from the copied files
Get-ChildItem -Path "E:\MSP-Toolkit" -Recurse -Filter *.ps1 | Unblock-File

# b) Run each script through powershell.exe with a one-time bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\MSP-Toolkit\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1"
```

`-ExecutionPolicy Bypass` on the `powershell.exe` command line applies to that one process
only; nothing persists after it closes. Open PowerShell with **Run as administrator** for
complete results (BitLocker, TPM, SMBv1, other users).

### 3. Run the audit

One command (A1-A8, results in one folder, HTML report at the end):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -ScanLan -IncludeRouterChecklist -TechnicianName "Your Name" -ClientName "Smith household"
```

Useful options: `-HomeSsid "<wifi name>"` (PC is wired), `-OnlineUpdateSearch` (live Windows
Update query), `-ApprovedRemoteTool Kaseya,ScreenConnect` (replaces the approved list for this run, see below),
`-AllUsers` (admin: other users' browsers/software), `-Skip Get-HomeNetworkMap`,
`-Passive` (nothing sent beyond the PC: A2 reads the ARP table only, A7 is not run),
`-OutputPath E:\Results` (default `%TEMP%\MSP-Toolkit`). The bundle prints the results folder at the end.

**Approved remote tools.** Remote-access tools the MSP deploys on purpose are listed in
`endpoint-systems/audit/software-inventory/approved-remote-tools.txt` (one name per line,
`#` comments; **Kaseya** by default). `Get-HomeDeviceInventory.ps1` reports matches as INFO
instead of WARN/High, and records which list it used in an `Approved remote tools` finding.
`-ApprovedRemoteTool` (on the bundle or the script) **replaces** the file for that run, so
include Kaseya again if it should stay approved, e.g. `-ApprovedRemoteTool Kaseya,ScreenConnect`
when the client's own IT uses ScreenConnect. Change the file only when the MSP's own tooling
changes; confirm a client's tool per audit with the parameter.

Or run scripts one at a time (prefix each with `powershell.exe -NoProfile -ExecutionPolicy Bypass -File`):

| # | Command | Expected runtime | Admin |
|---|---|---|---|
| 1 | `.\security-operations\diagnostics\endpoint-posture\Get-EndpointSecurityStatus.ps1 -OutputPath <folder>` | 5-30 s | Recommended |
| 2 | `.\core-infrastructure\networking\diagnostics\Get-HomeNetworkMap.ps1 -OutputPath <folder>` | 15-60 s (/24) | No |
| 3 | `.\core-infrastructure\networking\diagnostics\Get-WiFiSecurityAudit.ps1 -OutputPath <folder>` | < 5 s | No |
| 4 | `.\security-operations\diagnostics\endpoint-posture\Get-OpenPortScan.ps1 -ScanLan -OutputPath <folder>` | < 5 s; 30-90 s with `-ScanLan` | No |
| 5 | `.\endpoint-systems\diagnostics\system-info\Get-BrowserSecurityCheck.ps1 -OutputPath <folder>` | < 5 s | No (Yes for `-AllUsers`) |
| 6 | `.\endpoint-systems\diagnostics\system-info\Get-WindowsUpdateCompliance.ps1 -OutputPath <folder>` | 5-15 s; 1-5 min with `-Online` | No |
| 7 | `.\core-infrastructure\networking\diagnostics\Get-RouterSecurityCheck.ps1 -OutputPath <folder>` | ~15 s + checklist with the client | No |
| 8 | `.\endpoint-systems\audit\software-inventory\Get-HomeDeviceInventory.ps1 -OutputPath <folder>` | 5-10 s | No |
| 9 | `.\security-operations\diagnostics\Export-SecurityAuditReport.ps1 -InputPath <folder> -TechnicianName "Your Name"` | < 5 s | No |

To combine several PCs into one report, copy each PC's results folder under one parent folder
and run step 9 with `-InputPath <parent> -Recurse`. Results folders from Macs and Linux
computers (`run-home-audit-bundle.sh`, below) can go in the same parent folder.

**Macs and Linux computers.** Copy the toolkit the same way (the bash scripts and
`approved-remote-tools.txt`), then in Terminal:

```bash
sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --include-router-checklist --technician "Your Name" --client "Smith household"
```

Options match the Windows bundle: `--scan-lan`, `--home-ssid NAME`, `--online`,
`--approved-remote-tool LIST`, `--all-users`, `--skip A2,A7`, `--output DIR` (default
`${TMPDIR:-/tmp}/msp-toolkit`), and `--passive` (`-Passive` on Windows) to send nothing on the
network. Without
`sudo` it still runs; the root-only checks show SKIPPED. The HTML report needs PowerShell 7
(`pwsh`); without it, bring the results folder to a PC and run step 9 there.

**Other devices.** The report has a printable checklist for phones, tablets, TVs, consoles,
printers and smart-home devices, listing the devices the network map (A2) found. Go through it
with the client; the scripts cannot check those devices.

Network scans (2, 4 with `-ScanLan`, 7) print their scope before sending anything and never
leave the PC's own subnet. Only scan networks the client owns and has asked us to audit.

---

## How to Read the Output

Every script ends with a **SUMMARY** line and a **COPY FOR TICKET** block (plain text; paste it
into the ticket as-is).

| Status | Meaning | What to do |
|---|---|---|
| `PASS` | The check passed. | Nothing. |
| `WARN` | Not ideal, or needs confirming with the client (for example remote-access software). | Read the `->` line under it; confirm or fix. |
| `FAIL` | A real security problem was found. | Fix it or put it in the remediation plan. Severity says how urgent. |
| `INFO` | Facts for context (versions, counts, scope). | Nothing. |
| `SKIPPED` | Not checked, usually "requires administrator". | Re-run as administrator if that area matters. |
| `ERROR` | The **check itself** could not run (missing component, access denied). This is **not** a failure of the PC. | Note it; escalate with the log file if it matters for the ticket. |

Severity (`Critical`, `High`, `Medium`, `Low`) is how much a WARN/FAIL matters, and is what the
HTML report uses to order the remediation plan. Results never change a script's exit code:
exit 0 means the script ran; non-zero means the script itself could not run.

Normal and not a problem: ports 135/139/445 on a Windows PC (INFO), "Unknown" vendor for a
device (many vendors are not in the built-in table), "Private/randomized MAC" for phones, and
browser versions marked "estimated" (confirm in the browser's About page).

Each run writes a log to `%TEMP%\MSP-Toolkit\<Script>_<Computer>_<timestamp>.log`.

---

## Maintaining the Shared Helpers

Each script carries a generated copy of the helper code it needs (so it runs alone from a USB
stick), between `#region MSPToolkit (generated)` markers labelled
"DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1".

There are two helper sources, one per script language:

| Scripts | Helper source | Sections |
|---|---|---|
| `*.ps1` | `endpoint-systems/utilities/MSPToolkit.Common.psm1` | Core (also runs on PowerShell 7 for macOS/Linux), Net, Updates, LocalAdmin, Software |
| `*.sh` | `endpoint-systems/utilities/msp-toolkit-common.sh` (bash 3.2 compatible) | Core, Net, Change |

1. Edit the helper source only, never a generated region.
2. Run `.\endpoint-systems\utilities\Sync-MSPEmbeddedHelper.ps1` to regenerate every copy
   (`.ps1` as UTF-8 with BOM, keeping each file's line endings: CRLF on a Windows checkout, LF on
   macOS/Linux; `.sh` always as UTF-8 without BOM + LF). It runs on Windows PowerShell 5.1 and on
   pwsh 7 on macOS/Linux.
3. Before committing, run `.\endpoint-systems\utilities\Sync-MSPEmbeddedHelper.ps1 -Check`.
   It exits **1** if any embedded copy was hand-edited (hash mismatch) or is out of date, or if a
   `.sh` file has CR line endings or a BOM. `.gitattributes` keeps `*.sh` at LF on every checkout.

### Output schema (SchemaVersion 2.0)

PowerShell and bash scripts write the same JSON, so one report can merge Windows, macOS and Linux
results. The HTML report (A9) also still reads 1.0 files from before the change.

| Field | Example / meaning |
|---|---|
| `SchemaVersion` | `"2.0"` |
| `CheckId` | Catalog ID, identical on every platform: `"A1"` |
| `ScriptName`, `Version` | `"get-endpoint-security-status-macos"`, `"1.0.0"` |
| `Platform`, `OSVersion`, `Shell` | `"macOS"`, `"macOS 15.1"`, `"bash 3.2.57"` |
| `Host`, `User`, `IsAdmin`, `RiskLevel` | Short host name; account; elevated (admin/root) true/false; Read-Only/Safe/Elevated/Destructive |
| `Parameters` | Object of strings |
| `Timestamp`, `EndTime` | ISO 8601 local time with offset: `"2026-10-16T14:05:09+02:00"` |
| `Summary` | Counts for PASS, WARN, FAIL, INFO, SKIPPED, ERROR |
| `Findings[]` | `Id`, `Category`, `Check`, `Status`, `Severity`, `Target`, `Detail`, `Recommendation`, `Evidence` |
| `Data` | Named tables (arrays of objects), also exported as CSV |

Finding IDs are `<CheckId>.<Category>.<Check>` with every run of non-alphanumeric characters
replaced by `-` (`A8.Software.Remote-access-tool-Kaseya`). Equivalent checks use the same
Category/Check text on every platform so their IDs match. Export file names:
`<ScriptName>_<Host>_<yyyyMMdd-HHmmss>.json`, `..._findings.csv`, `..._<Table>.csv`.

### Development checks (not for client machines)

`tests/Invoke-ToolkitTests.ps1` runs everything: PowerShell parser (5.1 and 7), PSScriptAnalyzer
(Write-Host allowed), `bash -n`, ShellCheck, a bash 4+ / GNU-only construct scan, the embedded-helper
check plus a tamper test, the bash helper unit tests (under every bash it finds, including bash
3.2.57), a JSON escaping round-trip into PowerShell, finding-ID and MAC-vendor parity between bash
and PowerShell, schema validation, the PowerShell helper unit tests, logic tests with mocked paths
(D1 repeat runs; A9; the Windows bundle; B1-B3 and C3 Windows against mocked cmdlets; C1 and C2
against mocked Exchange Online and Microsoft Graph cmdlets, so no tenant is contacted), then
runtime smoke tests of the scripts for the platform it runs on.

| Run on | Command | Not available there (reported as NOT RUN, with the reason) |
|---|---|---|
| Windows | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1` | bash steps need WSL (`-Distro`, `-TestUser`); macOS/Linux runtime cases |
| macOS | `pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1` | Windows PowerShell 5.1 steps; Windows/Linux runtime cases; bash tests as root (never uses sudo) |
| Linux | `pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1` | Windows PowerShell 5.1 steps; Windows/macOS runtime cases; bash 3.2 unless built at `/opt/bash-3.2` |

PSScriptAnalyzer findings in scripts not yet brought to standard (Batches C-D) are listed in
`tests/pssa-known-issues.txt` and reported as known, so a clean run is all green and any new
finding fails. Remove a script's lines from that file when its batch is reworked.

On a Mac, `/bin/bash` is the real bash 3.2.57 that ships with macOS, so the bash scripts are run
under it for real, not only parse-checked. Limit the static checks with `-Path folder1,folder2`;
skip the runtime tests with `-SkipRuntime`. Validate any result folder with
`tests/Test-MSPResultSchema.ps1 -Path <folder>`.

**The harness is passive by default.** Runtime cases that would send traffic beyond the computer
(A2 ping sweep or hostname lookups, A4 `-ScanLan` / `--scan-lan`, A7 router/SSDP, A6 `-Online`, D2
connectivity probes) are reported as NOT RUN; A2 runs only with `-Passive` / `--passive`. The
stubbed bash tests (`tests/bash/test-scripts-mocked.sh`) also cover the sweep and port-check code
paths, against stub `ping`/`nc` commands and the documentation-only range 198.51.100.0/24. Pass `-AllowActiveNetwork` only with approval for that
network; the subnet is printed before anything is sent. Remediation scripts are only ever run
with `-WhatIf`, `-BackupOnly`, or in non-interactive mode without `-Force` (which must refuse).

