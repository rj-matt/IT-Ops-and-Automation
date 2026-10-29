# Scripting & Automation

[![CI](https://github.com/rj-matt/IT-Ops-and-Automation/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rj-matt/IT-Ops-and-Automation/actions/workflows/ci.yml)

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
- Reduce accidental misuse across environments

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
Scripts are expected to evolve as platforms, tooling, and best practices change.
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
- **Software watchlist (E2).** `software-watchlist.txt` end-of-support dates were checked at the
  vendors' pages on 2026-10-26 (two still `unverified`). Add new end-of-support products when
  vendors announce them, and re-check the `unverified` lines, in the same April/October review.
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

Every script below follows the toolkit standards: a header (purpose, scope, risk, prerequisites,
limitations), the six statuses, a log file, a plain-text ticket block, and JSON/CSV results
(schema 2.0) with `-OutputPath` (Windows) or `--output` (macOS/Linux). Diagnostics change
nothing. Test status per platform (run for real, mocked, or stubbed) is in
`docs/toolkit-review/final-summary.md`.

**Columns.** *Privileges*: what the script needs; most run without admin/root and report the
parts that need it as SKIPPED. *Dependencies*: beyond what ships with the OS. Windows scripts
run on Windows PowerShell 5.1 (built in); macOS/Linux scripts on bash 3.2+ with only tools that
come with the OS (no Homebrew, jq or Python). A blank platform cell means there is no version
for that platform.

| ID | Windows | macOS | Linux | Folder | Purpose | Risk | Privileges | Dependencies |
|---|---|---|---|---|---|---|---|---|
| A1 | `Get-EndpointSecurityStatus.ps1` | `get-endpoint-security-status-macos.sh` | `get-endpoint-security-status-linux.sh` | `security-operations/diagnostics/endpoint-posture/` | Antivirus, firewall, disk encryption, updates, administrators, sign-in settings, platform protections (Secure Boot, SIP, SELinux...), remote access | Read-Only | None; admin/sudo adds TPM, BitLocker/SMBv1 detail, FileVault key, root password, SSH settings | - |
| A2 | `Get-HomeNetworkMap.ps1` | `get-home-network-map.sh` | same | `core-infrastructure/networking/diagnostics/` | Devices on the local subnet: address, MAC, vendor hint, name, type; unidentified devices | Read-Only; **sends** a ping sweep and name lookups unless `-Passive` / `--passive` | None | - |
| A3 | `Get-WiFiSecurityAudit.ps1` | `get-wifi-security-audit-macos.sh` | `get-wifi-security-audit-linux.sh` | `core-infrastructure/networking/diagnostics/` | Security of the current, saved and nearby Wi-Fi networks; never reads passwords | Read-Only | None; sudo adds saved-network security on macOS | Linux: NetworkManager |
| A4 | `Get-OpenPortScan.ps1` | `get-open-port-scan.sh` | same | `security-operations/diagnostics/endpoint-posture/` | Listening ports and their programs; risky services reachable from the network; optional LAN check of 11 risky ports | Read-Only; **sends** TCP probes to local devices only with `-ScanLan` / `--scan-lan` | None; Linux sudo shows other users' programs | - |
| A5 | `Get-BrowserSecurityCheck.ps1` | `get-browser-security-check.sh` | same | `endpoint-systems/diagnostics/system-info/` | Browser versions, extensions, force-install and update-blocking policies; no password or history access | Read-Only | None; admin/sudo for other users (`-AllUsers` / `--all-users`) | - |
| A6 | `Get-WindowsUpdateCompliance.ps1` | `get-update-compliance-macos.sh` | `get-update-compliance-linux.sh` | `endpoint-systems/diagnostics/system-info/` | OS end of support (built-in, source-checked tables), last update, pending updates, restart, update settings | Read-Only; `-Online` / `--online` asks the update servers | None | Linux: apt or dnf |
| A7 | `Get-RouterSecurityCheck.ps1` | `get-router-security-check.sh` | same | `core-infrastructure/networking/diagnostics/` | Gateway, DNS, admin page HTTP vs HTTPS, management ports, UPnP and its port forwards, guided router checklist | Read-Only; **sends** HTTP/TCP to the router and one SSDP multicast (no logins) | None | macOS/Linux: curl; perl for UPnP |
| A8 | `Get-HomeDeviceInventory.ps1` | `get-home-device-inventory.sh` | same | `endpoint-systems/audit/software-inventory/` | Hardware/OS, accounts and last sign-in, software; remote-access and file-sharing tools flagged | Read-Only | None; admin/sudo for other users (and the Linux serial number) | `approved-remote-tools.txt` |
| A9 | `Export-SecurityAuditReport.ps1` | same `.ps1` with `pwsh` | same `.ps1` with `pwsh` | `security-operations/diagnostics/` | One HTML report from the results of every computer (any platform), with a printable checklist for other devices | Read-Only (writes the report file) | None | macOS/Linux: PowerShell 7 |
| Bundle | `Invoke-HomeAuditBundle.ps1` | `run-home-audit-bundle.sh` | same | `security-operations/diagnostics/` | Runs A1-A8 into one timestamped folder, continues past failures; `-Passive` / `--passive` sends nothing; optional A9 | Read-Only | None (admin/sudo recommended) | The A1-A8 scripts |
| B1 | `Get-ClientHealthSnapshot.ps1` | `get-client-health-snapshot.sh` | same | `endpoint-systems/diagnostics/system-info/` | System, uptime and pending restart, memory, CPU/load, free space, last update and updates waiting | Read-Only | None; Linux sudo adds the serial number | - |
| B2 | `Get-NetworkConnectivityReport.ps1` | `get-network-connectivity-report.sh` | same | `endpoint-systems/diagnostics/networking/` | Adapter, address, gateway, DNS, internet, web in order; names the first failing layer | Read-Only; **sends** ping, DNS, TCP 443 and HTTP(S) unless `-Passive` / `--passive` | None | - |
| B3 | `Get-RecentCriticalErrors.ps1` | `get-recent-critical-errors.sh` | same | `endpoint-systems/diagnostics/event-logs/` | Crashes, unexpected shutdowns, disk errors, service failures, app crashes (48 h by default) | Read-Only | None; Linux: sudo or the adm / systemd-journal group for the journal | - |
| B4 | `Restart-CommonServices.ps1` | `restart-common-services.sh` | same | `endpoint-systems/remediation/safe/restart-services/` | Restarts an allow-list of services (printing, Windows Update, DNS cache...) with before/after state | **Safe** (changes) | admin/sudo (not for `-WhatIf` / `--what-if`) | - |
| C1 | `Get-UserMailboxStatus.ps1` | same `.ps1` with `pwsh` | same `.ps1` with `pwsh` | `cloud-services/m365/diagnostics/` | One Exchange Online mailbox: size, archive, holds, forwarding and hiding rules, apps, devices, delegates | Read-Only | Exchange: Global Reader or View-Only Organization Management | ExchangeOnlineManagement 3.x |
| C2 | `Get-UserLicenseReport.ps1` | same `.ps1` with `pwsh` | same `.ps1` with `pwsh` | `cloud-services/m365/diagnostics/` | Licenses, service plan problems, disabled accounts holding licenses, last sign-in, subscriptions | Read-Only | Global Reader; one-time **tenant-wide** admin consent (see below) | Microsoft.Graph (Authentication, Users, Identity.DirectoryManagement) |
| C3 | `Get-SuspiciousActivityReport.ps1` | `get-suspicious-activity-report-macos.sh` | `get-suspicious-activity-report-linux.sh` | `security-operations/diagnostics/endpoint-posture/` | **First-look triage, not an antivirus or EDR**: startup items, programs and connections from unusual folders, platform-specific traces | Read-Only | None; admin/sudo adds the Security log, Defender exclusions, Background items, other users, the journal | - |
| D1 | `Clear-WindowsUpdateCache.ps1` | | | `endpoint-systems/remediation/safe/clear-caches/` | Renames (never deletes) the Windows Update caches and restarts the update services | **Safe** (changes) | admin (not for `-WhatIf`) | - |
| D2 | `Reset-NetworkStack.ps1` | | | `endpoint-systems/remediation/elevated/network-resets/` | Saves the network settings, resets Winsock and TCP/IP, flushes DNS; restart required; **not fully reversible** | **Elevated** (changes) | admin (not for `-WhatIf` / `-BackupOnly`) | - |
| D3 | `Reset-OutlookProfile.ps1` | | | `cloud-services/m365/remediation/` | Backs up the Outlook profile settings and creates a new empty default profile; keeps the old one | **Elevated** (changes) | The affected user (not admin) | - |
| E1 | `Get-LocalAdminReport.ps1` | `get-local-admin-report.sh` | same | `endpoint-systems/audit/local-admins/` | Who has admin rights; too many, built-in/root, unused, old or empty passwords, orphaned entries, LAPS, sudo rules | Read-Only | None; sudo adds sudo rules and Linux password checks | - |
| E2 | `Get-InstalledSoftwareReport.ps1` | `get-installed-software-report.sh` | same | `endpoint-systems/audit/software-inventory/` | Installed software; end-of-support and watchlist programs; recent installs | Read-Only | None; admin/sudo for other users | `software-watchlist.txt` |
| E3 | `Get-BackupRecency.ps1` | `get-backup-recency.sh` | same | `core-infrastructure/backups-dr/diagnostics/` | When the computer was last backed up and by what (File History, Windows Server Backup, OneDrive folders, Time Machine, Deja Dup, Timeshift, known products) | Read-Only | None; admin adds Windows Server Backup and System Restore | - |
| E4 | `Get-ServerHealthReport.ps1` | | `get-server-health-report.sh` | `core-infrastructure/servers/windows/diagnostics/`, `core-infrastructure/servers/linux/diagnostics/` | Server health: restarts, updates, disks, memory, services and roles, events, time sync, certificates (Linux: also RAID, ZFS, inodes, OOM kills) | Read-Only | None (admin/sudo recommended) | Windows Server: ServerManager |
| RC4 | `Get-KerberosRC4Usage.ps1` | | | `security-operations/audit/` | RC4 use in Kerberos on a **domain controller** (KB5073381): RC4 tickets, RC4-only accounts, KDC refusals and settings | Read-Only | admin, on a domain controller; Kerberos auditing on | - |
| IdleLock | `Set-InactivityTimeout.ps1` | | | `security-operations/hardening/server-hardening/` | Sets or removes the machine inactivity limit (automatic lock) with before/after state and undo command | **Elevated** (changes) | admin (not for `-WhatIf`) | - |
| - | `Sync-MSPEmbeddedHelper.ps1`, `MSPToolkit.Common.psm1` | `msp-toolkit-common.sh` | same | `endpoint-systems/utilities/` | Shared helper sources and the tool that embeds them (development only; see Maintaining the Shared Helpers) | Safe (repository files only) | None | - |

**Scripts that change something** (B4, D1, D2, D3, Set-InactivityTimeout) always: show the
current state and a numbered plan first; support `-WhatIf` / `--what-if` (plan only, nothing
changed, no admin needed); ask you to type **YES**; refuse to change anything in a
non-interactive session (RMM job, scheduled task) unless `-Force` / `--force` is given; record
the state afterwards; and say plainly what cannot be undone. Exit codes: `0` done, `1` nothing
changed (not admin / not confirmed / non-interactive), `2` a step failed.

**Microsoft 365 (C1, C2).** Run from the technician's computer: Windows PowerShell 5.1 or
PowerShell 7 on Windows, PowerShell 7 (`pwsh`) on macOS or Linux. They only read: C1 loads
only Exchange `Get-` cmdlets, C2 asks Microsoft Graph for `User.Read.All`,
`Organization.Read.All` and `AuditLog.Read.All`. Each reuses an existing connection, otherwise
signs in (browser, or `-DeviceCode`), and disconnects at the end unless `-KeepConnection`.

**C2's first sign-in grants tenant-wide admin consent.** The first time C2's scopes are used in
a tenant, an administrator consents "on behalf of your organization" to Microsoft's own
"Microsoft Graph Command Line Tools" app. That consent applies to the whole tenant and stays
until an admin removes it (Entra admin center > Enterprise applications > Microsoft Graph
Command Line Tools > Permissions). **In a client's tenant, get the client's approval first and
note it in the ticket** (who approved, when, which scopes).

**RC4 audit (domain controllers).** Run on each domain controller as administrator; elsewhere it
reports SKIPPED. Its tables hold account names: use `-OutputPath` only with a folder outside
the toolkit, a repository or a USB stick that moves between clients.

**D1 backup folders.** `Clear-WindowsUpdateCache.ps1` renames the caches to
`C:\Windows\SoftwareDistribution.old-<yyyyMMdd-HHmmss>` and
`C:\Windows\System32\catroot2.old-<yyyyMMdd-HHmmss>` and never deletes them. Running it again is
safe: it picks a new name before any service is stopped and never reuses or overwrites an
earlier folder. **Once Windows Update has installed updates successfully again, they can be
deleted** (as administrator) to free disk space. The script lists any it finds from earlier runs.

**Data files** (keep them next to the scripts that read them; edit them for the MSP's needs):

- `approved-remote-tools.txt` (A8): remote-access tools the MSP uses on purpose (**Kaseya** by
  default); matches are INFO instead of WARN. `-ApprovedRemoteTool` / `--approved-remote-tool`
  **replaces** the file for one run, so include Kaseya again when adding a client's own tool.
- `software-watchlist.txt` (E2): end-of-support and "flag this" software as wildcard patterns.
  Each end-of-support line records its source page and the date it was checked there
  (`unverified` when no official page confirmed it).

Superseded scripts and unsigned binaries are in `_archive/` (see `_archive/README.md`); never
copy that folder to a client machine.

### What is Windows-only, and what only a manual checklist covers

| Covered by | Items |
|---|---|
| Windows only | D1 Windows Update cache, D2 network stack reset, D3 Outlook profile, RC4 audit (domain controllers), Set-InactivityTimeout. Inside cross-platform scripts: BitLocker, TPM, SMBv1, UAC (A1); Defender detections and exclusions, Security log (C3); LAPS, orphaned SIDs (E1); File History, Windows Server Backup, OneDrive folders, System Restore (E3); server roles, w32tm, certificate store (E4) |
| macOS only | FileVault, SIP, Gatekeeper, XProtect (A1); Background items (C3, sudo); Time Machine (E3). E4 has no macOS version (not a server platform here) |
| Linux only | LUKS, SELinux/AppArmor (A1); `ld.so.preload`, programs running from memory only, failed SSH logins (C3); administrators with an empty password (E1, sudo); Deja Dup, Timeshift (E3); RAID, ZFS, inodes, OOM kills (E4) |
| Manual checklist only | **Phones, tablets, TVs, streaming boxes, game consoles, smart-home devices, printers and NAS**: the "Other devices checklist" in the A9 report (devices found by A2 are listed to tick off). **Router settings behind its login**: A7's guided checklist (admin password changed, remote management off, WPS off, firmware current, UPnP off, guest isolation), answered with the client, who types their own router password |
| Not checked (say so in the report) | Microsoft Store apps and portable programs (E2 Windows); Homebrew packages (E2 macOS); iCloud Drive (E3 macOS: hidden from Terminal by macOS privacy controls); hardware RAID controllers and SMART on servers (E4); Microsoft 365 MFA, transport rules and the audit log (C1/C2) |

---

## Home Network Audit Runbook

Run on each computer the client wants checked, with the client present (the router checklist
needs their router login, which **they** type). Only scan networks the client owns and has asked
us to audit; the network scans (A2, A4 with `-ScanLan`, A7) print their scope before sending
anything and never leave the computer's own subnet. `-Passive` / `--passive` on the bundle sends
nothing on the network (A2 reads the neighbor table only, A7 is not run).

### Windows PCs

1. **Copy the toolkit without `_archive`** (it holds superseded scripts and unsigned binaries):

   ```powershell
   robocopy "<repo>" "E:\MSP-Toolkit" *.ps1 *.txt /S /XD _archive .git tests
   ```

   `git archive` and GitHub "Download ZIP" already leave `_archive` out. A flat folder (all
   `.ps1` files side by side) also works: the bundle looks next to itself first. Keep
   `approved-remote-tools.txt` next to `Get-HomeDeviceInventory.ps1`.

2. **Allow the scripts to run for this session only.** Do **not** change the PC's execution
   policy (`Set-ExecutionPolicy` is not part of this runbook):

   ```powershell
   # a) Remove the "downloaded from the internet" mark from the copied files
   Get-ChildItem -Path "E:\MSP-Toolkit" -Recurse -Filter *.ps1 | Unblock-File
   # b) Run each script through powershell.exe with a one-time bypass
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\MSP-Toolkit\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1"
   ```

   `-ExecutionPolicy Bypass` on the command line applies to that one process only; nothing
   persists after it closes. Open PowerShell with **Run as administrator** for complete
   results (BitLocker, TPM, SMBv1, other users).

3. **Run the audit** (A1-A8, one results folder, HTML report at the end):

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -ScanLan -IncludeRouterChecklist -TechnicianName "Your Name" -ClientName "Smith household"
   ```

   Options: `-Passive` (send nothing beyond the PC), `-HomeSsid "<wifi name>"` (PC is wired),
   `-OnlineUpdateSearch`, `-ApprovedRemoteTool Kaseya,ScreenConnect`, `-AllUsers` (admin),
   `-Skip Get-HomeNetworkMap`, `-OutputPath E:\Results` (default `%TEMP%\MSP-Toolkit`). The
   bundle prints the results folder at the end.

   Or one script at a time (prefix each with `powershell.exe -NoProfile -ExecutionPolicy Bypass -File`):

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

### Macs

1. **Copy the toolkit without `_archive`** (USB stick, or `git archive`). Scripts are run with
   `bash <script>`, so they do not need to be executable and macOS's quarantine flag (set on
   downloaded files) does not stop them. Only if you want to run them as `./script.sh`:

   ```bash
   xattr -dr com.apple.quarantine ~/MSP-Toolkit     # remove the "downloaded" flag
   chmod +x ~/MSP-Toolkit/**/*.sh                   # zsh; or: find ~/MSP-Toolkit -name '*.sh' -exec chmod +x {} +
   ```

2. **Full Disk Access is not needed.** No toolkit script requires it; do not grant it to
   Terminal. If macOS asks whether Terminal may access a folder (Desktop, Documents, Downloads),
   you can deny it: the check that wanted it says what it could not see. macOS hides Wi-Fi names
   from Terminal unless it has Location Services permission; the A3 ratings still work.

3. **Run the audit** in Terminal, from the toolkit folder. `sudo` gives complete results (the
   scripts never call sudo themselves; without it the root-only checks show SKIPPED):

   ```bash
   sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --include-router-checklist --technician "Your Name" --client "Smith household"
   ```

   Options match the Windows bundle: `--passive`, `--scan-lan`, `--home-ssid NAME`, `--online`,
   `--approved-remote-tool LIST`, `--all-users`, `--skip A2,A7`, `--output DIR` (default
   `${TMPDIR:-/tmp}/msp-toolkit`). The HTML report needs PowerShell 7 (`pwsh`); without it,
   bring the results folder to a PC and run step 9 there. Each script also runs on its own:
   `bash <script> --help` shows its options.

### Linux computers

1. **Copy the toolkit without `_archive`.** Run scripts with `bash <script>` (no `chmod`
   needed); to run them as `./script.sh`, `chmod +x` them first:

   ```bash
   find ~/MSP-Toolkit -name '*.sh' -exec chmod +x {} +
   ```

2. **Run the audit**, with `sudo` for complete results (root password, SSH settings, other
   users' programs; the journal also opens to members of the adm / systemd-journal group):

   ```bash
   sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --include-router-checklist --technician "Your Name" --client "Smith household"
   ```

   Same options as on the Mac. A3 needs NetworkManager; A6 knows apt and dnf systems.

### Combining computers, and the other devices

Copy each computer's results folder (Windows, Mac or Linux) under one parent folder and build
one report:

```powershell
.\security-operations\diagnostics\Export-SecurityAuditReport.ps1 -InputPath <parent> -Recurse -TechnicianName "Your Name" -ClientName "Smith household"
```

The report's **Other devices checklist** lists the phones, tablets, TVs, consoles, printers and
smart-home devices the network map found, with what to check on each type. Go through it with
the client and tick it off on a printed copy; the scripts cannot check those devices.

---

## How to Read the Output

Every script prints one line per check, then a **SUMMARY** with the counts, the most important
items, and a **COPY FOR TICKET** block: plain text to paste into the ticket as it is. Each check
has one of six statuses:

| Status | What it means | What to do (Tier 1) |
|---|---|---|
| `PASS` | The check ran and found nothing wrong. | Nothing. |
| `WARN` | Not ideal, or something to confirm with the client (for example a remote-access tool, a new startup item). | Read the `->` line under it. Confirm with the client or fix it; escalate if unsure. |
| `FAIL` | A real problem was found (security gap, full disk, failing backup...). | Fix it now or put it in the remediation plan. The severity says how urgent. |
| `INFO` | Facts for context: versions, counts, what was checked. | Nothing; useful in the ticket. |
| `SKIPPED` | Not checked, and the line says why: usually "requires administrator" / "requires root (sudo)", or the feature is not present. | If that area matters for the ticket, re-run as administrator / with `sudo`. Otherwise note it. |
| `ERROR` | The **check itself** could not run (a missing component, access denied, a timeout). It is **not** a problem with the computer. | Note it in the ticket. If it matters, escalate with the log file named at the end of the output. |

**Severity** (`Critical`, `High`, `Medium`, `Low`) says how much a WARN or FAIL matters; the HTML
report orders its remediation plan by it. Rough guide: Critical = fix now; High = this week;
Medium = this month; Low = when convenient.

**ERROR is not FAIL.** "Could not check BitLocker (access denied)" says nothing about BitLocker;
"BitLocker is off" is a FAIL. Never report an ERROR or SKIPPED as a finding against the client.

**Exit code** (for RMM tools): `0` means the script ran, whatever it found. Diagnostics return
non-zero only when the script itself could not run. Scripts that change something use `0` done,
`1` nothing changed, `2` a step failed.

**Normal and not a problem:** ports 135/139/445 on a Windows PC (INFO), "Unknown" vendor for a
network device (the built-in table is small), "Private/randomized MAC" for phones, browser
versions marked "estimated" (confirm in the browser's About page), "date unverified" next to an
end-of-support date (the date is our best information but no official page confirmed it).

**Where things are saved:** logs in `%TEMP%\MSP-Toolkit\` (Windows) or
`${TMPDIR:-/tmp}/msp-toolkit/` (macOS/Linux), named `<Script>_<Computer>_<timestamp>.log`.
Results only where you asked (`-OutputPath` / `--output`): a JSON file, a findings CSV and one
CSV per table. Results can contain user, device and account names: keep them with the client's
records, not on a shared USB stick.

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
(D1 repeat runs; A9; the Windows bundle; B1-B3, C3, E1-E4, Set-InactivityTimeout and the RC4
audit against mocked Windows cmdlets; C1 and C2 against mocked Exchange Online and Microsoft
Graph cmdlets, so no tenant is contacted), then
runtime smoke tests of the scripts for the platform it runs on.

| Run on | Command | Not available there (reported as NOT RUN, with the reason) |
|---|---|---|
| Windows | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1` | bash steps need WSL (`-Distro`, `-TestUser`); macOS/Linux runtime cases |
| macOS | `pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1` | Windows PowerShell 5.1 steps; Windows/Linux runtime cases; bash tests as root (never uses sudo) |
| Linux | `pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1` | Windows PowerShell 5.1 steps; Windows/macOS runtime cases; bash 3.2 unless built at `/opt/bash-3.2` |

Every script is now to standard, so any PSScriptAnalyzer finding fails the run. (The harness
still accepts a `tests/pssa-known-issues.txt` baseline of `path|rule|count` lines for scripts
added later that are not yet reworked.)

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

### Continuous integration (GitHub Actions)

`.github/workflows/ci.yml` runs on every push and pull request to `main`, on GitHub-hosted
runners: Windows (the harness under Windows PowerShell 5.1, then under PowerShell 7), Linux
(PowerShell 7 harness plus the bash stub tests) and macOS (PowerShell 7 harness plus the bash
tests under `/bin/bash` 3.2). ShellCheck and PSScriptAnalyzer are pinned to the versions used on
the development machine.

- **Passive only.** The harness refuses `-AllowActiveNetwork` when `GITHUB_ACTIONS=true`, so the
  active cases (A2 sweeps, A4 LAN scan, A7, A6 online search, B2 full test) are never run in CI.
  On top of that, `tests/ci/` puts a network guard on each runner before the tests and checks it
  afterwards; any blocked attempt fails the job. Linux and macOS: the tests run as a separate
  account, `msptest`, and its traffic beyond loopback and its DNS queries are blocked and counted
  (iptables / pf); on macOS name lookups go through mDNSResponder and are not tied to the account.
  Windows: outbound connections from PowerShell and the Windows network tools, and every ping,
  are blocked and logged (Windows Firewall, Security event 5157). Two gaps on Windows: name
  lookups go through the DNS Client service and are not tied to a program; and TCP port 80 to a
  public address is listed but not counted, because Windows downloads certificate revocation
  data on port 80 inside any PowerShell process that touches a certificate (Get-WinEvent is
  enough). LAN addresses on any port stay counted. Each guard first proves it works with a blocked attempt to
  192.0.2.1 (a documentation-only address).
- **No secrets.** No tenant connections, no M365 sign-ins: C1/C2 are covered by their mocked tests.
- **Only the harness summary is uploaded** (step names and results). Script results and logs stay
  on the runner.
- **CI does not replace the hand tests.** A runner is a fresh VM with no Wi-Fi, no BitLocker, no
  real users, no domain and no client software, so most checks there return SKIPPED or INFO. CI
  proves the scripts start, refuse what they must and write valid results on a real Windows and
  Linux machine; the hand tests in `docs/toolkit-review/final-summary.md` are still needed.

