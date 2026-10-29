# Final summary: MSP toolkit review (Batches A-E, Phase 5)

Updated 2026-10-29 (CI added). Development machine: macOS 26 (Apple silicon), PowerShell 7, bash 3.2.57
and 5.3, ShellCheck, PSScriptAnalyzer. The per-batch details are in `batch-a-summary.md`,
`batch-b-summary.md`, `batch-c-summary.md` and `batch-e-summary.md`; this file is the overall
status and the one list of what still has to be run by hand.

Last full harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
114 steps, 45 passed, 0 failed, 69 not run (other platforms, sudo, active network).
Stubbed bash tests: 459 passed under bash 3.2 and 5.3. PSScriptAnalyzer: no findings in any
script (the known-issues baseline is empty and was removed).

**GitHub Actions CI** (`.github/workflows/ci.yml`, details in the README) now runs the same
harness, passive only, on every push and pull request to `main`:

| Runner | Harness | Result (run 7, 2026-10-29, commit fab9f51) |
|---|---|---|
| windows-latest (Windows Server 2025), Windows PowerShell 5.1, administrator | 113 steps | 54 passed, 0 failed, 59 not run |
| windows-latest, PowerShell 7.6, administrator | 113 steps | 54 passed, 0 failed, 59 not run |
| ubuntu-latest (Ubuntu 24.04), PowerShell 7.6, bash 5.2, normal account `msptest` | 111 steps | 41 passed, 0 failed, 70 not run; stubbed bash tests 450 passed (one B3 block runs only on a macOS host) |
| macos-latest (macOS 26, arm64), PowerShell 7.6, `/bin/bash` 3.2, normal account `msptest` | 109 steps | 40 passed, 0 failed, 69 not run; stubbed bash tests 459 passed |

Network guard on every runner: canary attempts to 192.0.2.1 blocked and counted, then nothing
counted during the tests. On Windows, 27 TCP port 80 connections to Microsoft/CDN addresses
(Windows certificate downloads inside PowerShell, 25 of them from pwsh 7) were listed and not
counted (see open items). Only the four harness summaries were uploaded as artifacts.

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
| C1 | Get-UserMailboxStatus (5.1 / pwsh 7) | mocked (also in CI on 5.1 and 7), no tenant | N | mocked, no tenant | N | not run | N |
| C2 | Get-UserLicenseReport (5.1 / pwsh 7) | mocked (also in CI on 5.1 and 7), no tenant | N | mocked, no tenant | N | not run | N |
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

Totals: on Windows, 24 of the 26 IDs now run in CI (all but A7, active network, and C1/C2, no
tenant; C1/C2's mocked tests run there on 5.1 and 7). On Linux, 19 of the 21 IDs run in CI (all
but A7 and C1/C2). On macOS, 17 of the 20 IDs ran for real on the Mac (not A7: active network;
not C1/C2: no tenant), and the same cases also pass on the macOS runner. Nothing has run on a
Windows 10/11 PC, a Windows Server with roles, a domain controller, a Microsoft 365 tenant, a
Linux desktop or any computer with root/sudo: that is the hand-test list below.

## Found and fixed by testing (for the record)

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
- **Decide: Windows guard exemption.** On Windows, PowerShell 7 downloads certificate
  revocation data and issuer certificates (TCP port 80 to Microsoft/CDN servers) whenever a script
  touches a certificate; `Get-WinEvent`, `Get-AuthenticodeSignature` and the `Cert:` drive all do,
  and turning off Windows' root-list updates did not stop it. The Windows guard therefore lists
  but does not count TCP port 80 to public addresses. LAN addresses on any port, pings and every
  other port stay counted; the only active-mode traffic it would miss on its own is B2's
  plain-HTTP test. Keep, or treat it as a failure?
- **PowerShell 7 telemetry on client computers.** pwsh 7 sends usage telemetry to Microsoft at
  startup unless `POWERSHELL_TELEMETRY_OPTOUT=1` is set. CI sets it. On a client, the bash
  bundle's A9 step and any script run under pwsh would send it, so "`--passive`: nothing is sent"
  is not strictly true there. Suggested fix (not done): set the variable in
  `run-home-audit-bundle.sh` before it starts pwsh, and say so in the README.
- **Guard gaps:** name lookups are not tied to a program on Windows or macOS (Linux covers them
  for the bash scripts), so a script that only resolved names would not be caught there.
- `software-watchlist.txt`: QuickTime for Windows and Java SE 6/7 dates are still `unverified`
  (Apple gives no date; Oracle's pages refuse automated readers). Confirm them in a browser.
- E4 "Stopped automatic services" ignore list and C3 "unusual folders" rules will need tuning
  after the first real Windows/Linux runs (note any false positive with its path).

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

### 4. Microsoft 365 tenant (C1, C2) - sends traffic to Microsoft 365

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
