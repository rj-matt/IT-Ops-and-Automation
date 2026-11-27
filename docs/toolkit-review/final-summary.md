# Final summary: MSP toolkit review (Batches A-E, Phase 5)

Updated 2026-11-18 (RMM mode added; CI added 2026-10-29). Development machine: macOS 26 (Apple silicon), PowerShell 7, bash 3.2.57
and 5.3, ShellCheck, PSScriptAnalyzer. The per-batch details are in `batch-a-summary.md`,
`batch-b-summary.md`, `batch-c-summary.md` and `batch-e-summary.md`; this file is the overall
status and the one list of what still has to be run by hand.

Last full harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive,
2026-11-18, RMM mode and its follow-up included): 151 steps, 61 passed, 0 failed, 90 not run
(other platforms, sudo, active network). Stubbed bash tests: 590 passed under bash 3.2 and 5.3. PSScriptAnalyzer: no findings in any
script (the known-issues baseline is empty and was removed).

**GitHub Actions CI** (`.github/workflows/ci.yml`, details in the README) now runs the same
harness, passive only, on every push and pull request to `main`:

| Runner | Harness | Result (run 34, 2026-11-19, commit 786b689: the latest green run on `main` when this was written) |
|---|---|---|
| windows-latest (image windows-2025-vs2026), Windows PowerShell 5.1, administrator | 156 steps | 79 passed, 0 failed, 77 not run |
| windows-latest, PowerShell 7.6, administrator | 156 steps | 79 passed, 0 failed, 77 not run |
| ubuntu-latest (image ubuntu-26.04), PowerShell 7.6, bash 5.3, normal account `msptest` | 148 steps | 57 passed, 0 failed, 91 not run; stubbed bash tests 581 passed (some blocks run only on a macOS host) |
| macos-latest (image macos-26-arm64), PowerShell 7.6, `/bin/bash` 3.2, normal account `msptest` | 146 steps | 56 passed, 0 failed, 90 not run; stubbed bash tests 590 passed |

Network guard on every runner (run 34): canary attempts blocked and counted, then nothing counted
during the tests. On Windows, 56 TCP port 80 connections to Microsoft's certificate revocation
hosts (Windows CRL/OCSP checks inside PowerShell) were listed and not counted (see open items).
Only the four harness summaries were uploaded as artifacts.

NOT RUN in CI, by design: active network cases, other platforms' cases, root/sudo runs, bash 3.2
on Linux, and on Windows the bash steps (no WSL distribution) and ShellCheck (it runs on Linux
and macOS).

**CI does not replace the hand tests below.** A runner is a fresh VM: no Wi-Fi, no BitLocker,
no TPM checks worth reading, no real users or their browsers, no domain, no client software,
Windows Server rather than Windows 10/11. CI proves that each script starts on a real Windows
and Linux machine, writes schema-valid results without ERROR findings, refuses what it must
(non-interactive without `-Force`), changes nothing with `-WhatIf`, and in its passive modes
sends nothing the network guard counts (within the guard's limits listed under open items). It does not prove the findings are right on a client's computer.

## Status by script and platform

**Tested** = run for real on that platform (Y/N). The status says how far it got:

- **run**: run for real (passive and without admin/sudo unless noted).
- **CI only**: run for real on a GitHub-hosted runner (Windows Server 2025 under 5.1 and 7, or
  Ubuntu 24.04 as a normal account) in its passive/`-WhatIf`/refusal form, and nothing else.
  Not run on a client-like Windows 10/11 PC or Linux desktop: the hand tests still apply.
  Tested column: "CI".
- **mocked**: logic run against stand-in cmdlets (on the Mac, and in CI on Windows under 5.1 and 7).
- **stubbed**: logic run against stub commands and a fake file system (on the Mac, and in CI on
  Linux and macOS).
- **-**: no version for that platform.

| ID | Script(s) | Windows | Tested | macOS | Tested | Linux | Tested |
|---|---|---|---|---|---|---|---|
| A1 | Get-EndpointSecurityStatus / get-endpoint-security-status-{macos,linux} | CI only | CI | run | Y | CI only | CI |
| A2 | Get-HomeNetworkMap / get-home-network-map | CI only (`-Passive`) | CI | run (`--passive` only) | Y | CI only (`--passive`) | CI |
| A3 | Get-WiFiSecurityAudit / get-wifi-security-audit-{macos,linux} | CI only (runner has no Wi-Fi) | CI | run | Y | CI only (no Wi-Fi) | CI |
| A4 | Get-OpenPortScan / get-open-port-scan | CI only (no `-ScanLan`) | CI | run (no `--scan-lan`) | Y | CI only (no `--scan-lan`) | CI |
| A5 | Get-BrowserSecurityCheck / get-browser-security-check | CI only | CI | run | Y | CI only | CI |
| A6 | Get-WindowsUpdateCompliance / get-update-compliance-{macos,linux} | CI only (no `-Online`) | CI | run (no `--online`) | Y | CI only (no `--online`) | CI |
| A7 | Get-RouterSecurityCheck / get-router-security-check | not run on Windows (active network) | N | stubbed (active network) | N | stubbed | N |
| A8 | Get-HomeDeviceInventory / get-home-device-inventory | CI only | CI | run (1.1.1 last-login fix included) | Y | CI only | CI |
| A9 | Export-SecurityAuditReport | CI only (inside the bundle cases, 5.1 and 7); mixed-platform test mocked | CI | run (pwsh 7, mixed Windows/macOS/Linux results) | Y | CI only (inside the bundle, pwsh 7) | CI |
| Bundle | Invoke-HomeAuditBundle / run-home-audit-bundle | CI only (`-Passive`, and without A2/A7) | CI | run (`--passive`) | Y | CI only (`--passive`) | CI |
| B1 | Get-ClientHealthSnapshot / get-client-health-snapshot | CI only; mocked | CI | run | Y | CI only | CI |
| B2 | Get-NetworkConnectivityReport / get-network-connectivity-report | CI only (`-Passive`); mocked | CI | run (`--passive` only) | Y | CI only (`--passive`) | CI |
| B3 | Get-RecentCriticalErrors / get-recent-critical-errors | CI only; mocked | CI | run (also `--include-system-log`) | Y | CI only | CI |
| B4 | Restart-CommonServices / restart-common-services | CI only (`-WhatIf` and refusal) | CI | run (`--what-if` and refusal only; changes stubbed) | Y (partly) | CI only (`--what-if` and refusal) | CI |
| B5 | Get-DiskSpaceReport / get-disk-space-report (added 2026-11-09) | CI only (runtime, 20 s folder limit); mocked on a fake drive | CI | run (no sudo) | Y | CI only (runtime); stubbed | CI |
| B6 | Get-PerformanceSnapshot / get-performance-snapshot (added 2026-11-09) | CI only (runtime, 10 s); mocked | CI | run (no sudo) | Y | CI only (runtime); stubbed | CI |
| C1 | Get-UserMailboxStatus (5.1 / pwsh 7) | mocked (also in CI on 5.1 and 7), no tenant | N | mocked, no tenant | N | not run | N |
| C2 | Get-UserLicenseReport (5.1 / pwsh 7) | mocked (also in CI on 5.1 and 7), no tenant | N | mocked, no tenant | N | not run | N |
| C4 | Get-M365SecurityPosture (5.1 / pwsh 7; added 2026-11-02) | mocked (also in CI on 5.1 and 7), no tenant | N | mocked, no tenant | N | mocked (CI, pwsh 7), no tenant | N |
| C5 | Get-AccountCompromiseTriage (5.1 / pwsh 7; added 2026-11-09) | mocked (also in CI on 5.1 and 7), no tenant | N | mocked, no tenant | N | mocked (CI, pwsh 7), no tenant | N |
| C3 | Get-SuspiciousActivityReport / get-suspicious-activity-report-{macos,linux} | CI only; mocked | CI | run (no sudo) | Y | CI only (no sudo) | CI |
| D1 | Clear-WindowsUpdateCache | CI only (`-WhatIf` and refusal); repeat-run logic mocked | CI | - | - | - | - |
| D2 | Reset-NetworkStack | CI only (`-WhatIf`, `-BackupOnly`, refusal; no connectivity test) | CI | - | - | - | - |
| D3 | Reset-OutlookProfile | CI only (`-WhatIf` and refusal; no Outlook on the runner) | CI | - | - | - | - |
| E1 | Get-LocalAdminReport / get-local-admin-report | CI only; mocked | CI | run (no sudo) | Y | CI only (no sudo) | CI |
| E2 | Get-InstalledSoftwareReport / get-installed-software-report | CI only; mocked | CI | run | Y | CI only | CI |
| E3 | Get-BackupRecency / get-backup-recency | CI only; mocked | CI | run (no Time Machine on this Mac; Time Machine parsing stubbed) | Y | CI only | CI |
| E4 | Get-ServerHealthReport / get-server-health-report | CI only (Windows Server 2025, no roles); mocked | CI | - | - | CI only | CI |
| RC4 | Get-KerberosRC4Usage (needs a domain controller) | CI only (SKIPPED path: not a DC); mocked | CI | - | - | - | - |
| IdleLock | Set-InactivityTimeout | CI only (`-WhatIf` and refusal); mocked (no registry access) | CI | - | - | - | - |

Totals: on Windows, 26 of the 30 IDs now run in CI (all but A7, active network, and C1/C2/C4/C5,
no tenant; their mocked tests run there on 5.1 and 7). On Linux, 21 of the 25 IDs run in CI (all
but A7 and C1/C2/C4/C5). On macOS, 19 of the 24 IDs ran for real on the Mac (not A7: active
network; not C1/C2/C4/C5: no tenant), and the same cases also pass on the macOS runner. Nothing has run on a
Windows 10/11 PC, a Windows Server with roles, a domain controller, a Microsoft 365 tenant, a
Linux desktop or any computer with root/sudo: that is the hand-test list below.

## B5 Disk space report (added 2026-11-09)

`endpoint-systems/diagnostics/storage/Get-DiskSpaceReport.ps1` (Windows) and `get-disk-space-report.sh`
(macOS, Linux), read-only; deletes nothing.

- **Checks:** every fixed / local volume (WARN under 15 % or 20 GB free, FAIL under 5 % or 5 GB;
  volumes under 50 GB such as EFI and /boot are judged on the percentage only, otherwise a 1 GB
  boot partition would always warn); the largest folders one and two levels under the user
  profile / home folder and the system drive, time-limited (`-ScanSeconds` / `--scan-seconds`,
  10-600, default 60; the earlier names `-TimeLimitSeconds` / `--time-limit` still work: the folder
  walk stops on time, says what it could not finish and names the setting to raise); reclaimable space
  measured but never deleted (Windows: temp folders, Windows Update cache, Recycle Bin,
  Windows.old, Delivery Optimization, crash dumps and error reports; macOS: user caches, Trash,
  iPhone/iPad backups, Xcode data; Linux: package caches, systemd journal, Trash, ~/.cache, disabled
  snap revisions); disk health without extra tools (Windows: Get-PhysicalDisk, reliability index,
  disk errors in the System log; macOS: SMART via diskutil; Linux: SMART only if smartctl is
  installed and run with sudo, plus kernel I/O errors); "What to do": the space needed, then the
  cleanup steps biggest first (items of 100 MB or more), the Windows Update cache step pointing to
  D1, a backup step first when a disk is failing.
- **Tested:** macOS run for real on this Mac (no sudo: the Trash is reported as not readable
  without Full Disk Access; `~/Library` did not finish in 10-30 s, which the output names).
  Windows: `tests/Test-DiskSpaceReportWindowsLogic.ps1` (30 checks; in the harness on 5.1 and 7)
  runs the real folder walk on a fake drive with sparse files, mocked volumes and health, and checks
  nothing was deleted; plus a CI runtime case. Linux: stubbed cases in
  `tests/bash/test-scripts-mocked.sh` with real `du` on a fake root (volumes, folders, a symbolic
  link not followed, package cache, journal, Trash, snaps, kernel I/O errors, step order, nothing
  deleted, the range message); plus a CI runtime case.
- **Found while testing:** a stopped `du` loses its buffered output, so the first version reported
  no folders when the time limit hit; the bash version now measures one top-level folder at a time
  and names the unfinished ones. Empty fields collapsed in a tab-separated `read`, which shifted the
  cleanup text; the field that can be empty is now last.

Hand tests (record the run time and whether the folder sizes match the system's own storage view):

```powershell
# Windows PC, once normal and once as administrator
.\endpoint-systems\diagnostics\storage\Get-DiskSpaceReport.ps1 -OutputPath $o
.\endpoint-systems\diagnostics\storage\Get-DiskSpaceReport.ps1 -ScanSeconds 300
.\endpoint-systems\diagnostics\storage\Get-DiskSpaceReport.ps1 -ScanSeconds 601    # plain message, exit 1
```

```bash
# macOS (once without sudo, once with sudo and Full Disk Access for Terminal) and real Linux
bash endpoint-systems/diagnostics/storage/get-disk-space-report.sh --output "$o"
sudo bash endpoint-systems/diagnostics/storage/get-disk-space-report.sh --scan-seconds 300
```

Check: volumes match Settings > System > Storage / About This Mac > Storage / `df -h`; the largest
folders match Explorer / Finder (Get Info) / `du -sh`; reclaimable sizes match Disk Cleanup /
Storage Sense; nothing was deleted (sizes are the same on a second run); Linux with sudo and
smartmontools shows SMART; a nearly full volume gives the "needs about N GB" first step.

## B6 Performance snapshot (added 2026-11-09)

`endpoint-systems/diagnostics/performance/Get-PerformanceSnapshot.ps1` (Windows) and
`get-performance-snapshot.sh` (macOS, Linux), read-only; changes nothing.

- **Checks:** CPU, memory and disk sampled every 2 seconds over `-SampleSeconds` / `--seconds`
  (default 30, max 120), average and peak (CPU average 85 % or more, memory 90 % or more or under
  500 MB available, disk busy 95 % or more = WARN); top processes by CPU over the window and by
  memory; memory pressure (Windows paging 1000 pages/s or more and commit 90 % or more; Linux swap
  100 pages/s or more and PSI; macOS pressure level and swap-outs); startup programs (more than 15 =
  WARN) and the heaviest running; uptime (more than 30 days = WARN) and pending restart; throttling
  (Windows CPU speed against its maximum while busy; macOS pmset speed limit; Linux temperature 90 C
  or more and speed) and power (Windows power plan / power mode, macOS Low Power Mode, Linux power
  profile, battery); known causes by the CPU they used (antivirus scan, updates installing,
  indexing), the disk at 100 %, and a nearly full system disk using B5's thresholds. "What to do"
  names the next step for each problem, or says nothing stood out.
- **Tested:** macOS run for real on this Mac (no sudo; disk busy time is SKIPPED: macOS does not
  report it). Windows: `tests/Test-PerformanceSnapshotWindowsLogic.ps1` (38 checks; in the harness on
  5.1 and 7) samples for 5 real seconds against mocked counters, processes, startup items, power and
  registry, a slow and a healthy PC; plus a CI runtime case. Linux: stubbed cases in
  `tests/bash/test-scripts-mocked.sh` where the `sleep` stub advances fake `/proc` counters, so the
  real rate and per-process CPU code runs on known numbers; plus a CI runtime case.
- **Found while testing:** the macOS boot time was read from the wrong field (`usec`), giving an
  uptime of 20758 days; Windows startup-program names were taken with a path function that only
  works with Windows separators (startup items never matched running programs when tested on
  macOS); memory in use was truncated instead of rounded on Linux.

Hand tests (run while the computer is slow, then again when it is idle):

```powershell
.\endpoint-systems\diagnostics\performance\Get-PerformanceSnapshot.ps1 -OutputPath $o
.\endpoint-systems\diagnostics\performance\Get-PerformanceSnapshot.ps1 -SampleSeconds 120
```

```bash
bash endpoint-systems/diagnostics/performance/get-performance-snapshot.sh --output "$o"
sudo bash endpoint-systems/diagnostics/performance/get-performance-snapshot.sh --seconds 60
```

Check: CPU, memory and disk match Task Manager / Activity Monitor / `top` and `iostat -x` over the
same minute; the top processes match; start a full antivirus scan or a big file copy and confirm it
is named under Known causes; on a laptop on battery with power saving on, the power finding warns;
startup items match Task Manager > Startup apps / Login Items / Startup Applications.

## RMM mode (added 2026-11-18)

Every script except A9 takes `-Rmm` / `--rmm` (or `MSP_TOOLKIT_RMM=1`) for running from an RMM
agent such as a Kaseya agent procedure. The README section "Running from an RMM" is the
technician's reference; in short:

- **Output:** no colour, no prompts, nothing waits for input. The JSON result always goes to
  `%ProgramData%\MSP-Toolkit\results\` (Windows) or `/var/tmp/msp-toolkit/results/`
  (macOS/Linux), newest 10 per script kept. The last stdout line is `<ID> WARN=n FAIL=n ERROR=n`.
- **Exit codes:** 0 all PASS/INFO/SKIPPED, 1 WARN, 2 FAIL, 3 ERROR or could not run (FAIL
  outranks ERROR). No summary line = the script did not start (PowerShell rejects an unknown
  parameter before the script runs).
- **Results folder:** Windows: owner Administrators, access for Administrators and SYSTEM only,
  inheritance off. macOS/Linux: folder 700, files 600. A link, a non-folder or (macOS/Linux) a
  folder owned by another account is never used (exit 3); `/var/tmp` is writable by everyone and
  a standard user can create folders in `%ProgramData%`, so a planted folder would otherwise
  receive root's / SYSTEM's results.
- **SYSTEM / root with no signed-in user:** detected (SID S-1-5-18/19/20; uid 0 without
  `SUDO_USER`) and shown in the banner. Per-user checks cover every user and add a "Users
  covered" finding (A5, A8, E2, C3, B3 macOS, B5, B6); checks that need a signed-in user say
  SKIPPED with the reason (A1 daily account, B2/C3 proxy, E3 File History and OneDrive, B5 profile
  scan). B1 names who is signed in. D3 always refuses under SYSTEM, even with `-Force`.
- **Changes:** B4, D1, D3 and Set-InactivityTimeout refuse in RMM mode without `-Force`
  (SKIPPED, exit 3). D2 always refuses in RMM mode, even with `-Force` (follow-up, 2026-11-18):
  the reset cuts off the agent's connection and needs a restart.
- **Network:** off unless `-ActiveNetwork` / `--active-network`: A2 and B2 run passive, the
  bundles run A2 passive and leave out A7, A7 alone exits 3. A4 `-ScanLan` and A6 `-Online`
  (and the bundles' `-ScanLan` / `-OnlineUpdateSearch`) record SKIPPED with "RMM mode: add
  -ActiveNetwork to allow network traffic; this can reach many client networks at once" and the
  passive checks still run (follow-up, 2026-11-18; outside RMM mode unchanged). The bundles roll each script's worst result up into one
  WARN/FAIL per script, give one summary line, and do not build the HTML report in RMM mode.
- **Versions:** every changed script went up one minor version (B5 to 1.2.0); the follow-up
  raised A4, A6, D2 and both bundles one more (A4 2.3.0 / 1.2.0, A6 1.4.0 / 1.3.0, D2 2.2.0,
  bundles 1.4.0 / 1.2.0).

Tested on this Mac and added to the harness and CI:

| Test | What it covers | Result here |
|---|---|---|
| `tests/Test-RmmMode.ps1` (logic step, 5.1 and 7) | Mocked SYSTEM (`MSP_TEST_SERVICE_ACCOUNT=1`) on B5's fake drive: exit 0/1/2/3, `MSP_TOOLKIT_RMM=1`, summary line last, no colour codes, only JSON in the folder, history of 10 (11 pre-seeded), permissions (Windows ACL / Unix 700 and 600), a planted link refused; B5 and A5 user coverage; D3 refused with `-Force -WhatIf`; `Confirm-MSPChange` refuses without `-Force`; B2 passive with stand-in network cmdlets that fail if called; A7 exit 3; A4 `-ScanLan` and A6 `-Online` SKIPPED with the reason while the passive checks run (stand-ins fail if anything is sent); D2 refused with `-Force -WhatIf`, nothing else run | 55 passed (pwsh 7.6) |
| `tests/bash/test-scripts-mocked.sh` (RMM block) | Stubbed root with no `SUDO_USER` (detected, not simulated): B5 exit 0/1/2/3, usage error exit 3, `MSP_TOOLKIT_RMM=1`, under sudo the old behaviour, permissions, history, planted link; B4 refusal and `--force`; A2/B2 passive, A7 exit 3 with no router request; A5 users covered (service accounts left out); A1 daily account SKIPPED; bundle with one summary line and a WARN carried up; A4 `--scan-lan` and A6 `--online` SKIPPED with the reason, passive checks still run, no network stub called; bundle `--scan-lan` / `--online` SKIPPED and A4 started without `--scan-lan` | 590 passed in all (bash 3.2 and 5.3) |
| Harness runtime cases "RMM: ..." | Real runs, passive, with `MSP_TEST_SERVICE_ACCOUNT=1` and the results folder in the case folder: B5, A1 (Windows), A5, B2, A7 (exit 3), B4 (refusal, exit 3), D3 `-Rmm -WhatIf` (Windows, exit 3, Outlook profile unchanged), A4 `-ScanLan` and A6 `-Online` SKIPPED, D2 `-Rmm -WhatIf` (Windows, exit 3) | macOS: 7 of 7 passed; Windows and Linux: CI |
| `tests/Test-HomeAuditBundleWindowsLogic.ps1` (mocked Start-Process) | RMM: `-ScanLan` / `-OnlineUpdateSearch` SKIPPED without `-ActiveNetwork` and not passed to A4/A6; passed on with `-ActiveNetwork` | 27 passed |

Platform status: macOS **run** (as the normal account with the service-account switch; not as
real root). Windows and Linux: **CI only** for the runtime cases, mocked/stubbed otherwise. Not
run anywhere: under the real SYSTEM account, as real root with no sudo, or from Kaseya. Those are
hand test 8.

## C4 Microsoft 365 security posture (added 2026-11-02)

`cloud-services/m365/audit/Get-M365SecurityPosture.ps1`, read-only, tenant-wide: MFA
registration (admins without MFA = FAIL High), security defaults vs Conditional Access (neither
= FAIL High), legacy authentication blocked and recent legacy sign-ins, admin roles (more than 4
or fewer than 2 Global Admins, admins with a licensed mailbox), external forwarding (outbound
spam policy, mailbox forwarding, inbox rules), guests (count, inactive 90+ days), organization
mailbox auditing, Secure Score with the top improvement actions. Each check is SKIPPED with a
plain reason when the license or role does not allow it.

- **Graph scopes (the minimum read-only set):** `User.Read.All` (guests, admins' licenses),
  `AuditLog.Read.All` (MFA registration report, sign-in logs), `Policy.Read.All` (security
  defaults, Conditional Access), `RoleManagement.Read.Directory` (admin role members),
  `SecurityEvents.Read.All` (Secure Score). No `Organization.Read.All`: Entra ID P1 is detected
  from Graph's "needs a premium license" answer instead of reading subscriptions.
- **Exchange Online:** read cmdlets only (`Get-AcceptedDomain`, `Get-HostedOutboundSpamFilterPolicy`,
  `Get-InboxRule`, `Get-OrganizationConfig`, `Get-EXO*`); Global Reader.
- **Needs Entra ID P1/P2:** MFA registration, Conditional Access, legacy sign-ins, inactive guests.
  Without P1 they are SKIPPED with the reason, and the run says which ones in an "Entra ID P1/P2"
  line; security defaults, admin roles, forwarding, auditing and Secure Score still run.
- **Consent:** same as C2: the first sign-in grants tenant-wide admin consent to Microsoft Graph
  Command Line Tools for these five scopes; in a client tenant get the client's approval first and
  note it in the ticket (who, when, which scopes).
- **Tested:** `tests/Test-M365SecurityPostureLogic.ps1` (88 checks; in the harness on 5.1 and 7)
  against mocked Graph and Exchange cmdlets: a risky tenant, a tenant without P1, neither defaults
  nor CA, a too-narrow role, a missing scope, `-SkipExchange`, and no terminal. It also fails if a
  real Graph or Exchange module gets loaded. No tenant has been contacted. Hand test: group 4,
  first in the MSP's own internal tenant, then client tenants with approval.

## C5 Account compromise triage (added 2026-11-09)

`security-operations/diagnostics/Get-AccountCompromiseTriage.ps1 -UserPrincipalName <user> [-Days 1-30]`,
read-only first look at one user suspected of business email compromise. It gathers evidence and
changes nothing; its closing "What to do now" list (reset password, revoke sessions, remove the
rules and forwarding it found, review MFA methods and app consents, check sent items, tell the
client) names what it found and is for the technician to do by hand. Each step appears once: the
generic MFA, app-consent and Sent/Deleted Items steps only when no specific step covers them. If a
flagged sign-in succeeded in the last 24 hours, or there is a sent-mail spike today, step 1 is
"Block sign-in" (then revoke sessions, then reset the password, with the reason for that order);
otherwise the list starts with the password reset (1.1.0, 2026-11-09).

- **Checks:** sign-ins (new country in the last 3 days, failed MFA then success within an hour,
  successful legacy-protocol sign-ins, two countries within 4 hours), Entra ID risk level and
  detections, every inbox rule (forward/redirect, delete, RSS Feeds / Conversation History /
  Archive / Junk, mark as read, payment words), mailbox forwarding, delegates, MFA methods added in
  the window, app consents (recent grants, third-party mail/file scopes), sent mail per day
  (spikes), the unified audit log (rule, forwarding and permission changes; mass deletion).
- **Graph scopes (the minimum read-only set):** `User.Read.All` (account, last password change),
  `AuditLog.Read.All` (sign-in logs, directory audit for MFA registrations and consents),
  `UserAuthenticationMethod.Read.All` (the user's MFA methods), `DelegatedPermissionGrant.Read.All`
  (the user's OAuth grants), `Application.Read.All` (the granted apps' names and publishers),
  `IdentityRiskyUser.Read.All` and `IdentityRiskEvent.Read.All` (Entra ID Protection).
- **Exchange Online:** read cmdlets only (`Get-AcceptedDomain`, `Get-InboxRule`, `Get-MessageTraceV2`,
  `Get-AdminAuditLogConfig`, `Search-UnifiedAuditLog`, `Get-EXO*`); Global Reader, plus View-Only
  Audit Logs for the audit log search.
- **Licenses:** sign-ins need Entra ID P1, risk needs P2, the audit log needs auditing on; without
  them those checks are SKIPPED with the reason and the rest still runs.
- **Consent:** same as C2/C4: the first sign-in grants tenant-wide admin consent to Microsoft Graph
  Command Line Tools for these seven scopes.
- **Tested:** `tests/Test-AccountCompromiseTriageLogic.ps1` (162 checks, including no repeated step and the block-first order; in the harness on 5.1 and
  7) against mocked Graph and Exchange cmdlets: a compromised user, a clean user without P1/P2 and
  with auditing off, an unknown user, a too-narrow role, `-Days 31`, a missing scope, no terminal.
  Every change cmdlet (Set-Mailbox, Remove-InboxRule, Revoke-MgUserSignInSession, ...) is a
  stand-in that records the call; the test fails if one is ever called, or if a real Graph or
  Exchange module loads. No tenant has been contacted. Hand test: group 4.

## Release package (added 2026-11-02)

`tools/Build-Release.ps1` builds `dist/MSP-Toolkit-<version>.zip` (scripts, the two data files,
README, `SHA256SUMS`, `START-HERE.txt`) and refuses to build when the embedded-helper check fails.
`tests/Test-BuildRelease.ps1` (32 checks, in the harness on PowerShell 7) covers the contents,
checksums, executable `.sh` entries and the refusals. The CI release job runs only on a `v*` tag.
Tag `v0.9.0` (commit 0b06ee9) has been pushed: CI run #11 (2026-11-03) passed the three test jobs
and built the package, artifact `MSP-Toolkit-v0.9.0`. **v0.9.0 predates C4, C5, B5, B6 and RMM
mode**: it does not contain them. The next release (sends the tag to GitHub):
`git tag v1.0.0 && git push origin v1.0.0`, then download the `MSP-Toolkit-v1.0.0` artifact from
that run and check it with `shasum -a 256 -c` / `sha256sum -c` against the `.sha256` file.

## Found and fixed by testing (for the record)

- Out-of-range number parameters (2026-11-09): `-Days 31` on C5 (and every other `[ValidateRange]`
  parameter in 21 PowerShell scripts) stopped with PowerShell's red parameter-binding error ("Cannot
  validate argument on parameter 'Days'...", plus CategoryInfo / FullyQualifiedErrorId lines on 5.1),
  before the script started, so there was no log or result. Ranges are now checked in the script body
  by the Core helper `Test-MSPParameterRange`: "-Days must be between 1 and 30 (you gave 31). Nothing
  was checked or changed.", a Setup finding, and exit 1. `tests/Test-ParameterRangeMessages.ps1`
  (in the harness on 5.1 and 7) runs every such script above its maximum and below its minimum.
  The first version of the helper misread `$PSBoundParameters` (`.Contains` is the key/value
  overload there) and reported parameters that were not given; caught by that test, fixed.

- A8 macOS/Linux read the last login from fixed columns of `last`; local macOS logins have no
  host column, so LastLogon was blank (found by E1, fixed in both).
- A9 listed the same device twice when Windows and macOS/Linux wrote its MAC address differently.
- C3 macOS flagged signed iPhone-app wrappers and signed apps in hidden folders (now judged by
  signature).
- E2's first Office 2019 for Mac date was wrong (2025-10-14; correct: 2023-10-10), found when
  checking the watchlist against Microsoft's pages.
- The old RC4 audit's "RC4 disabled by end of Q2 2026" line did not match KB5073381; the new
  audit follows the KB (enforcement from April 2026, KDC events 201-209).

Found by the first CI runs (2026-10-28/29) and fixed:

- E3 1.0.1: System Restore used `Get-ComputerRestorePoint`, which exists only in Windows
  PowerShell 5.1, so under PowerShell 7 the check was an ERROR on every PC; and Windows Server has
  no System Restore at all. Now read through the `SystemRestore` WMI class and SKIPPED where the
  class is missing. File History also ERRORed for a profile without a LocalApplicationData folder.
- D2 2.0.1: on an adapter without IPv4, `Get-NetIPConfiguration` printed "No MSFT_NetIPInterface
  objects found" despite `-ErrorAction`; now silenced.
- Harness 2.4.0: under Windows PowerShell 5.1 a child process's stderr line ended the whole run.
- bash helper: the banner's OS version read the real `/etc/os-release` instead of the tests'
  fake root (tests only; no effect on clients).
- Test gaps that only showed on real Windows/Linux: the B1 test let the real Windows Update agent
  answer, the E3 test read the real System Restore when elevated, and the stubbed bash tests saw
  the runner's real `apt`, `snap` and `mokutil`, GNU `date`/`stat`, and `SUDO_USER`.
- The network guard caught PowerShell 7 itself contacting Microsoft at startup (usage telemetry,
  `dc.services.visualstudio.com`) and Windows downloading certificate revocation data inside
  PowerShell 7 (see open items).

## Open items

- Everything in the hand-test list below. CI covers only the passive runs on clean runners.
- **Windows guard exemption (decided 2026-11-02: keep, narrowed).** Windows checks certificate
  revocation (TCP port 80) inside any PowerShell 7 process that touches a certificate;
  `Get-WinEvent`, `Get-AuthenticodeSignature` and the `Cert:` drive all do. The guard now exempts
  port 80 only to Microsoft's CRL/OCSP hosts (`www.microsoft.com`, `oneocsp.microsoft.com`,
  `crl.microsoft.com`, `mscrl.microsoft.com`, `ocsp.msocsp.com`), matched by the name each address
  was looked up as. Port 80 to anything else fails the job.
- **PowerShell 7 telemetry (fixed 2026-11-02).** `run-home-audit-bundle.sh` 1.0.1 starts pwsh for
  the HTML report with `POWERSHELL_TELEMETRY_OPTOUT=1` for that process only; a stubbed test checks
  it. No Windows script starts pwsh (the Windows bundle starts Windows PowerShell 5.1, which has
  no telemetry).
- **Windows Update pings on the runner (decided 2026-11-06: exempt, narrowly).** On PR #1's first
  run (2026-11-03, run 41558479313) the Windows guard counted 3 ICMP echo requests from the System
  process to `download.windowsupdate.com`, during the D2 `-BackupOnly -SkipConnectivityTest` case,
  and failed the job; D2 has no ping on that path, no toolkit script refers to that host, and the
  re-run passed. Guard 1.3.0 lists but does not count only pings sent by the System process to an
  address looked up as a Windows Update host (`*.windowsupdate.com`, `*.update.microsoft.com`,
  `*.delivery.mp.microsoft.com`, `*.dl.delivery.mp.microsoft.com`, `*.prod.do.dsp.mp.microsoft.com`,
  `emdl.ws.microsoft.com`, `tsfe.trafficshaping.dsp.mp.microsoft.com`; Microsoft's "Windows Update
  issues troubleshooting" endpoint list). Pings from any other program, any other host or an
  address with no recorded name, and every other protocol still fail the job.
- **RMM exit code in Kaseya.** The README examples capture the output with "Execute Shell
  Command - Get Results to Variable". Whether that step exposes the exit code to the procedure
  has to be confirmed in hand test 8; the summary line carries the same information either way.
- **Guard gap: name lookups.** A DNS lookup is not tied to the program that made it on Windows
  (the DNS Client service does the lookup) or on macOS (mDNSResponder does), so a script whose
  only traffic was a name lookup would not fail the Windows or macOS job. On Linux the bash
  scripts' lookups are counted (iptables, port 53, by account). The PowerShell scripts that look
  up names (A2 reverse DNS, B2 DNS test) only do so in their active modes, which CI never runs;
  the macOS bash scripts share that code with Linux. To close it fully, the Windows guard could
  compare the DNS Client log against an allow-list of the runner's own hosts; not done.

## Outstanding hand tests

CI does not replace any of these: it runs on clean runner VMs, passively, without a client's
hardware, accounts, software or network.

Run from the repository root. Validate any result folder with
`pwsh -NoProfile -File tests/Test-MSPResultSchema.ps1 -Path <folder>`. Delete hand-test result
folders afterwards: they contain user, device and account names.

### 1. Windows PC (Windows 10/11)

**a) Harness**, Windows PowerShell 5.1, once from a normal window and once from "Run as
administrator" (it also runs every mocked logic test on 5.1 and on 7 if installed):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1
```

This covers, passively: A1-A8, the bundle with A9 and with `-Passive`, B1-B3, C3, E1-E4, the RC4
audit (SKIPPED on a non-DC), and B4, D1, D2, D3 and Set-InactivityTimeout with `-WhatIf` /
`-BackupOnly` and the non-interactive refusal. Check: 0 failed; every NOT RUN has a reason.

**b) By hand, as administrator:**

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\endpoint-systems\diagnostics\system-info\Get-BrowserSecurityCheck.ps1 -AllUsers -OutputPath $o
.\endpoint-systems\audit\software-inventory\Get-HomeDeviceInventory.ps1 -IncludeOtherUsers -OutputPath $o
.\endpoint-systems\diagnostics\system-info\Get-ClientHealthSnapshot.ps1 -OutputPath $o
.\endpoint-systems\diagnostics\event-logs\Get-RecentCriticalErrors.ps1 -Hours 168 -IncludeWarnings -OutputPath $o
.\security-operations\diagnostics\endpoint-posture\Get-SuspiciousActivityReport.ps1 -Days 30 -OutputPath $o
.\endpoint-systems\audit\local-admins\Get-LocalAdminReport.ps1 -OutputPath $o
.\endpoint-systems\audit\software-inventory\Get-InstalledSoftwareReport.ps1 -IncludeOtherUsers -OutputPath $o
.\core-infrastructure\backups-dr\diagnostics\Get-BackupRecency.ps1 -OutputPath $o
.\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -Passive -TechnicianName "Test"
.\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -Passive -ScanLan          # must stop with exit 2
.\security-operations\hardening\server-hardening\Set-InactivityTimeout.ps1 -Minutes 15 -WhatIf
```

Check:
- A1 shows BitLocker, TPM and SMBv1 without SKIPPED; A6 finds this PC's build in its table.
- B1 reads pending updates from the cached scan (no long wait); B3 names services and programs.
- C3 shows the Security log checks and Defender exclusions; nothing flagged you cannot explain.
- E1 matches `net localgroup Administrators`; E2's count is close to Settings > Apps (Store apps
  are not listed); E3 shows File History's date if it is on, and System Restore points.
- The `-Passive` bundle shows A7 "Skipped (passive)"; its report's Coverage says "Not run: Not run
  with -Passive".
- Set-InactivityTimeout `-WhatIf` shows the current value and the plan and changes nothing. Only
  on a test PC, also try `-Minutes 15` (type YES), then the printed undo command.

**c) Combined report on 5.1:** put this PC's bundle folder and a Mac's `run-home-audit-bundle.sh`
folder under one parent folder, then
`.\security-operations\diagnostics\Export-SecurityAuditReport.ps1 -InputPath <parent> -Recurse -TechnicianName "Test"`.
Check: the Mac's Coverage rows show dates; the Other devices checklist lists each device once;
the report prints.

**d) Microsoft 365 scripts on Windows PowerShell 5.1:** see group 4 (run them once in
`powershell.exe` as well as in `pwsh`).

### 2. Windows Server

On a test or client server you are allowed to check, as administrator:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\core-infrastructure\servers\windows\diagnostics\Get-ServerHealthReport.ps1 -OutputPath $o
.\core-infrastructure\backups-dr\diagnostics\Get-BackupRecency.ps1 -OutputPath $o
.\security-operations\hardening\server-hardening\Set-InactivityTimeout.ps1 -Minutes 15 -WhatIf
```

Check: roles match Server Manager; "Stopped automatic services" lists nothing that is meant to be
stopped (note any for the ignore list); the time source matches `w32tm /query /status`;
certificates match `certlm.msc` > Personal; E3 shows Windows Server Backup's last success if it
is used.

### 3. Domain controller

On each domain controller (or a lab DC), as administrator:

```powershell
$o = "D:\Reports\RC4"      # not the toolkit folder: the tables hold account names
.\security-operations\audit\Get-KerberosRC4Usage.ps1 -Days 30 -OutputPath $o
.\core-infrastructure\servers\windows\diagnostics\Get-ServerHealthReport.ps1 -OutputPath $o
```

Check:
- "Domain controller" says so (not SKIPPED). If "Kerberos events" warns that auditing is off,
  turn on Success for "Kerberos Authentication Service" and "Kerberos Service Ticket Operations"
  and run again after a few days.
- RC4-only accounts and RC4 use by account look plausible against
  `Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes,PasswordLastSet` (old
  passwords). "KDC RC4 events" matches Event Viewer > System, source Kdcsvc, events 201-209;
  "KDC encryption settings" matches `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`.
- E4 says "primary/backup domain controller" and checks NTDS, Netlogon, DFSR and DNS.

### 4. Microsoft 365 tenant (C1, C2, C4, C5) - sends traffic to Microsoft 365

Use a test tenant or a client tenant you may review. **C2's first sign-in grants tenant-wide
admin consent** to Microsoft's "Microsoft Graph Command Line Tools" app; in a client tenant get
the client's approval first and note it in the ticket. Run the steps once in PowerShell 7 and
once in Windows PowerShell 5.1 (`powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`).

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
$o = "$HOME/m365-hand"
pwsh -File ./cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1 -UserPrincipalName <you@tenant> -OutputPath $o
pwsh -File ./cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1 -All -IncludeServicePlans -OutputPath $o
pwsh -File ./cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1 -UserPrincipalName <user> -DeviceCode
pwsh -File ./cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1 -UserPrincipalName <user@tenant> -OutputPath $o
pwsh -File ./cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1 -UserPrincipalName <shared-mailbox@tenant> -DeviceCode
pwsh -File ./cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1 -UserPrincipalName nobody-here@<tenant domain>
```

C4: run first in the MSP's own internal tenant, signed in as a Global Administrator for the
first consent; record the consent screen's scopes. Client tenants come after that, with the
client's approval and a ticket note (who approved, when, which scopes; in the ticket, not in this
repository).

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser    # C4 uses Reports, Identity.SignIns, Security as well
pwsh -File ./cloud-services/m365/audit/Get-M365SecurityPosture.ps1 -OutputPath $o
pwsh -File ./cloud-services/m365/audit/Get-M365SecurityPosture.ps1 -DeviceCode -SkipInboxRules
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\cloud-services\m365\audit\Get-M365SecurityPosture.ps1 -SkipExchange
```

Check for C4:
- First run (internal tenant, Global Administrator): the consent screen lists exactly
  `User.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`,
  `SecurityEvents.Read.All` plus the standard sign-in permissions; record the scopes it showed.
  Later runs can use a Global Reader account (the consent is already in place).
- MFA gaps match Entra admin center > Protection > Authentication methods > User registration
  details; Global Administrators match Roles and admins; security defaults / CA match the Entra
  pages; outbound forwarding matches Defender > Anti-spam > Outbound; mailbox auditing matches
  `Get-OrganizationConfig | Select AuditDisabled`; Secure Score matches the Defender portal
  (it is a daily snapshot).
- In a tenant without Entra ID P1, MFA, legacy sign-ins and inactive guests are SKIPPED with the
  P1 reason and the "Entra ID P1/P2" line names them; nothing is ERROR.
- With a Global Reader account nothing is SKIPPED for a role reason; run once with a narrower
  account (for example Exchange Administrator only) and note which checks become SKIPPED.
- Time the run with and without `-SkipInboxRules` and note the mailbox count.
- Delete the result folder afterwards: it holds user, admin and guest names.

C5: run first in the MSP's own internal tenant against a test user you control (Global
Administrator for the first consent; record the consent screen's scopes). Set the test user up
beforehand so there is something to find: an inbox rule that moves mail with "invoice" in the
subject to RSS Feeds and marks it read, a forwarding rule to an outside test address, and a
second Authenticator registration. Client tenants come after that, with the client's approval and
a ticket note.

```powershell
pwsh -File ./security-operations/diagnostics/Get-AccountCompromiseTriage.ps1 -UserPrincipalName <test-user@internal tenant> -OutputPath $o
pwsh -File ./security-operations/diagnostics/Get-AccountCompromiseTriage.ps1 -UserPrincipalName <test-user@internal tenant> -Days 30 -DeviceCode
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\security-operations\diagnostics\Get-AccountCompromiseTriage.ps1 -UserPrincipalName <test-user@internal tenant> -SkipExchange
pwsh -File ./security-operations/diagnostics/Get-AccountCompromiseTriage.ps1 -UserPrincipalName nobody-here@<internal tenant domain>
```

Check for C5:
- The consent screen lists exactly `User.Read.All`, `AuditLog.Read.All`,
  `UserAuthenticationMethod.Read.All`, `DelegatedPermissionGrant.Read.All`, `Application.Read.All`,
  `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` plus the standard sign-in permissions.
- The planted rules, forwarding and the new Authenticator are flagged, and "What to do now" names
  each of them. Afterwards the test user's rules, forwarding, sessions and methods are exactly as
  before the run (the script changed nothing); remove the planted items by hand.
- Sign-ins match Entra admin center > Users > the user > Sign-in logs; without P1 they are SKIPPED
  with the P1 reason; without P2 risk is SKIPPED with the P2 reason; nothing is ERROR.
- Sent mail per day matches the message trace in the Exchange admin center; audit events match a
  Purview audit search for the user (allow up to a day of delay).
- Run once with Global Reader only (no View-Only Audit Logs): the audit log is SKIPPED naming that
  role. The unknown address gives FAIL for the account and the mailbox.
- Delete the result folder afterwards: it holds the user's sign-in IPs and correspondents.

Check:
- The C2 consent page lists `User.Read.All`, `Organization.Read.All`, `AuditLog.Read.All` plus
  the standard sign-in permissions; record exactly what it showed. Afterwards the "Graph
  connection" finding lists only those scopes. C1 shows a consent page only in some tenants;
  record it if it appears.
- C2: subscriptions match the admin center (Billing > Your products); last sign-in matches the
  Entra sign-in log, or is SKIPPED with the "no Microsoft Entra ID P1 or P2 license" reason in a
  tenant without P1; nothing is ERROR.
- C1: size and quota match the Exchange admin center; rules and forwarding match Outlook on the
  web; delegates match the mailbox's delegation page; the unknown address gives FAIL "No mailbox".
- Both disconnect at the end (`Get-MgContext` / `Get-ConnectionInformation` empty). Run each once
  with an account without a reader role and note which checks become SKIPPED.

### 5. macOS with sudo

```bash
o=/tmp/msp-hand; mkdir -p "$o"
sudo /bin/bash tests/bash/test-msp-helper.sh
sudo bash security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-macos.sh --output "$o"
sudo bash core-infrastructure/networking/diagnostics/get-wifi-security-audit-macos.sh --output "$o"
sudo bash endpoint-systems/diagnostics/system-info/get-browser-security-check.sh --all-users --output "$o"
sudo bash endpoint-systems/audit/software-inventory/get-home-device-inventory.sh --all-users --output "$o"
sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --all-users --technician "Test" --output "$o"
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh </dev/null   # must refuse
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --output "$o"
sudo bash security-operations/diagnostics/endpoint-posture/get-suspicious-activity-report-macos.sh --days 30 --output "$o"
sudo bash endpoint-systems/audit/local-admins/get-local-admin-report.sh --output "$o"
sudo bash endpoint-systems/audit/software-inventory/get-installed-software-report.sh --all-users --output "$o"
bash core-infrastructure/backups-dr/diagnostics/get-backup-recency.sh --output "$o"    # on a Mac WITH Time Machine
```

Check: A1 runs the FileVault recovery key check; A3 lists saved networks' security; A5/A8/E2
include other users; the bundle shows "Elevated: Yes" and writes the HTML report; B4 refuses
under `</dev/null` and, after YES, clears the DNS cache; C3 runs "Background items" (compare
with System Settings > General > Login Items & Extensions); E1 runs "Sudo rules"; on a Mac with
Time Machine, E3's date matches "Latest backup" in System Settings (if it says no backup is
recorded, note the macOS version: the settings-file key may have changed).

### 6. Real Linux

On one apt desktop (Ubuntu or Debian with NetworkManager), one dnf system (Fedora), and one
Linux server:

```bash
o=/tmp/msp-hand; mkdir -p "$o"
bash tests/bash/test-msp-helper.sh && bash tests/bash/test-scripts-mocked.sh
pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1          # if PowerShell 7 is installed
for s in security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-linux.sh \
         core-infrastructure/networking/diagnostics/get-wifi-security-audit-linux.sh \
         security-operations/diagnostics/endpoint-posture/get-open-port-scan.sh \
         endpoint-systems/diagnostics/system-info/get-browser-security-check.sh \
         endpoint-systems/diagnostics/system-info/get-update-compliance-linux.sh \
         endpoint-systems/audit/software-inventory/get-home-device-inventory.sh \
         endpoint-systems/diagnostics/system-info/get-client-health-snapshot.sh \
         endpoint-systems/diagnostics/event-logs/get-recent-critical-errors.sh \
         security-operations/diagnostics/endpoint-posture/get-suspicious-activity-report-linux.sh \
         endpoint-systems/audit/local-admins/get-local-admin-report.sh \
         endpoint-systems/audit/software-inventory/get-installed-software-report.sh \
         core-infrastructure/backups-dr/diagnostics/get-backup-recency.sh \
         core-infrastructure/servers/linux/diagnostics/get-server-health-report.sh; do
    bash "$s" --output "$o"; sudo bash "$s" --output "$o"
done
bash core-infrastructure/networking/diagnostics/get-home-network-map.sh --passive --output "$o"
bash endpoint-systems/diagnostics/networking/get-network-connectivity-report.sh --passive --output "$o"
sudo bash security-operations/diagnostics/run-home-audit-bundle.sh --passive --technician "Test" --output "$o"
bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --what-if
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh </dev/null   # must refuse
sudo bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --services cups
```

Check: no ERROR findings; A6 finds the distribution in its table; with sudo, A1 shows root
password status and SSH settings, A8 the serial number, B3/C3/E4 read the journal, E1 runs the
password and sudo-rule checks, E4 the certificates; B1/E4 disk numbers match `df -h`; E2's
count matches `dpkg -l | grep -c ^ii` (or `rpm -qa | wc -l`) plus snaps/Flatpaks; E3 finds Deja
Dup or Timeshift if used (else SKIPPED); C3 does not flag snaps, Flatpaks or desktop autostart
entries (note any false positive with its path). Run `--services NetworkManager` only at the
computer, never over SSH.

### 7. Active network on your home network

Each run needs your approval; name the subnet first. Every script prints the subnet or gateway
before it sends anything. All at once on the current platform:

```bash
pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1 -AllowActiveNetwork
```

Or one at a time:

| Platform | Command | Sends |
|---|---|---|
| macOS, Linux | `bash core-infrastructure/networking/diagnostics/get-home-network-map.sh` | Ping sweep + name lookups, local subnet |
| macOS, Linux | `bash security-operations/diagnostics/endpoint-posture/get-open-port-scan.sh --scan-lan` | Ping + 11 TCP ports per device |
| macOS, Linux | `bash core-infrastructure/networking/diagnostics/get-router-security-check.sh` | HTTP/TCP to the gateway, SSDP multicast; asks the guided checklist in a terminal |
| macOS, Linux | `bash security-operations/diagnostics/run-home-audit-bundle.sh --include-router-checklist --technician "Test"` | A2 sweep + A7; asks the router checklist |
| macOS, Linux | `bash endpoint-systems/diagnostics/networking/get-network-connectivity-report.sh` | Ping gateway, DNS lookup, TCP 443 to 1.1.1.1/8.8.8.8, HTTP(S) to 4 sites |
| macOS | `bash endpoint-systems/diagnostics/system-info/get-update-compliance-macos.sh --online` | Apple update servers |
| Linux | `bash endpoint-systems/diagnostics/system-info/get-update-compliance-linux.sh --online` | Package servers, Snap Store |
| Windows | `.\core-infrastructure\networking\diagnostics\Get-HomeNetworkMap.ps1` | Ping sweep + reverse DNS |
| Windows | `.\security-operations\diagnostics\endpoint-posture\Get-OpenPortScan.ps1 -ScanLan` | Ping + 11 TCP ports per device |
| Windows | `.\core-infrastructure\networking\diagnostics\Get-RouterSecurityCheck.ps1` | HTTP/TCP to the gateway, SSDP; asks the guided checklist |
| Windows | `.\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -ScanLan -IncludeRouterChecklist -TechnicianName "Test"` | Full audit: A2 sweep, A4 LAN ports, A7 |
| Windows | `.\endpoint-systems\diagnostics\networking\Get-NetworkConnectivityReport.ps1` | Same as the bash version |
| Windows | `.\endpoint-systems\diagnostics\system-info\Get-WindowsUpdateCompliance.ps1 -Online` | Microsoft Update |
| Windows | `.\endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1 -WhatIf` | Ping gateway, DNS, TCP to Microsoft (pre-flight only; changes nothing) |

Check: A2 finds the devices you know of; A4 finds no risky open ports you do not expect; A7's
admin-page and UPnP results match the router's own pages, and the checklist answers appear in
the A9 report; B2 says "Every layer works" on a good connection and names the adapter layer
with Wi-Fi off.

### 8. RMM mode for real (SYSTEM, root, and one run from Kaseya)

Passive throughout: nothing here sends traffic beyond the computer (no `-ActiveNetwork`).
Delete the results folders afterwards: they hold device and user names.

**Windows as SYSTEM** (Sysinternals PsExec on a test PC, elevated prompt):

```powershell
psexec -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\endpoint-systems\diagnostics\storage\Get-DiskSpaceReport.ps1" -Rmm
echo $LASTEXITCODE
psexec -s powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\endpoint-systems\diagnostics\system-info\Get-BrowserSecurityCheck.ps1" -Rmm
psexec -s powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\endpoint-systems\remediation\safe\restart-services\Restart-CommonServices.ps1" -Rmm
psexec -s powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\cloud-services\m365\remediation\Reset-OutlookProfile.ps1" -Rmm -WhatIf
psexec -s powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\endpoint-systems\remediation\elevated\network-resets\Reset-NetworkStack.ps1" -Rmm -WhatIf
psexec -s powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\security-operations\diagnostics\endpoint-posture\Get-OpenPortScan.ps1" -Rmm -ScanLan
icacls C:\ProgramData\MSP-Toolkit\results
```

Check: the banner says "Account : SYSTEM"; the last line is `B5 WARN=.. FAIL=.. ERROR=..` and
matches the exit code; A5 "Users covered" names every user profile on the PC; B4, D2 and D3
exit 3 and change nothing; A4 records the LAN check as SKIPPED ("this can reach many client
networks at once") and still lists this PC's ports; `icacls` lists only BUILTIN\Administrators and NT AUTHORITY\SYSTEM, no
inherited entries; after 11 B5 runs there are 10 B5 files.

**macOS and Linux as root with no technician** (`env -u SUDO_USER` makes sudo look like an
agent):

```bash
sudo env -u SUDO_USER bash endpoint-systems/diagnostics/storage/get-disk-space-report.sh --rmm; echo "EXIT=$?"
sudo env -u SUDO_USER bash endpoint-systems/diagnostics/system-info/get-browser-security-check.sh --rmm; echo "EXIT=$?"
sudo env -u SUDO_USER bash endpoint-systems/remediation/safe/restart-services/restart-common-services.sh --rmm; echo "EXIT=$?"
sudo ls -la /var/tmp/msp-toolkit /var/tmp/msp-toolkit/results
```

Check: "Account : root with no signed-in user"; B5 skips the home folder and names every user
under "Users covered"; A5 lists every user's browsers and not root's; B4 exits 3; the folders are
`drwx------ root` and the files `-rw------- root`.

**One real run from Kaseya on a test machine** (a test device in the MSP's own VSA, not a
client's):

1. Copy the toolkit to the device (`C:\MSP-Toolkit`, `/opt/msp-toolkit`).
2. New agent procedure with one step "Execute Shell Command - Get Results to Variable", run as
   System (Windows) / root (macOS), with the README's command for that platform, followed by a
   "Write Procedure Log Entry" of `#global:cmdresults#`.
3. Run it on the test device, then a second procedure with `Restart-CommonServices.ps1 -Rmm`
   (must refuse).

Check: the procedure log ends with the summary line; how VSA shows the exit code (success or
failure of the step for exit 1-3; note it in the README if the step fails on any non-zero code,
so alerts can be built on that); the JSON file is in the results folder and can be fetched with a
"Get File" step; the B4 procedure changed no service. Record the VSA version and the step names
used.
