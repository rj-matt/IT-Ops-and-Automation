# Final summary: MSP toolkit review (Batches A-E, Phase 5)

Updated 2026-10-26. Development machine: macOS 26 (Apple silicon), PowerShell 7, bash 3.2.57
and 5.3, ShellCheck, PSScriptAnalyzer. The per-batch details are in `batch-a-summary.md`,
`batch-b-summary.md`, `batch-c-summary.md` and `batch-e-summary.md`; this file is the overall
status and the one list of what still has to be run by hand.

Last full harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
114 steps, 45 passed, 0 failed, 69 not run (other platforms, sudo, active network).
Stubbed bash tests: 459 passed under bash 3.2 and 5.3. PSScriptAnalyzer: no findings in any
script (the known-issues baseline is empty and was removed).

## Status by script and platform

**Tested** = run for real on that platform (Y/N). The status says how far it got:

- **run**: run for real (passive and without admin/sudo unless noted).
- **mocked**: logic run on PowerShell 7 on the Mac against stand-in cmdlets. **Not run on
  Windows**: no Windows machine has run any script in this review.
- **stubbed**: logic run against stub commands and a fake file system on the Mac. No Linux
  machine has run any of it.
- **runtime only**: covered by the Windows harness runtime cases, which have not been run yet.
- **-**: no version for that platform.

| ID | Script(s) | Windows | Tested | macOS | Tested | Linux | Tested |
|---|---|---|---|---|---|---|---|
| A1 | Get-EndpointSecurityStatus / get-endpoint-security-status-{macos,linux} | not run on Windows | N | run | Y | stubbed | N |
| A2 | Get-HomeNetworkMap / get-home-network-map | not run on Windows | N | run (`--passive` only) | Y | stubbed | N |
| A3 | Get-WiFiSecurityAudit / get-wifi-security-audit-{macos,linux} | not run on Windows | N | run | Y | stubbed | N |
| A4 | Get-OpenPortScan / get-open-port-scan | not run on Windows | N | run (no `--scan-lan`) | Y | stubbed | N |
| A5 | Get-BrowserSecurityCheck / get-browser-security-check | not run on Windows | N | run | Y | stubbed | N |
| A6 | Get-WindowsUpdateCompliance / get-update-compliance-{macos,linux} | not run on Windows | N | run (no `--online`) | Y | stubbed | N |
| A7 | Get-RouterSecurityCheck / get-router-security-check | not run on Windows | N | stubbed (active network) | N | stubbed | N |
| A8 | Get-HomeDeviceInventory / get-home-device-inventory | not run on Windows | N | run (1.1.1 last-login fix included) | Y | stubbed | N |
| A9 | Export-SecurityAuditReport | not run on Windows (5.1 or 7); mixed-platform test mocked | N | run (pwsh 7, mixed Windows/macOS/Linux results) | Y | not run | N |
| Bundle | Invoke-HomeAuditBundle / run-home-audit-bundle | not run on Windows; `-Passive` mocked | N | run (`--passive`) | Y | stubbed | N |
| B1 | Get-ClientHealthSnapshot / get-client-health-snapshot | not run on Windows; mocked | N | run | Y | stubbed | N |
| B2 | Get-NetworkConnectivityReport / get-network-connectivity-report | not run on Windows; `-Passive` mocked | N | run (`--passive` only) | Y | stubbed | N |
| B3 | Get-RecentCriticalErrors / get-recent-critical-errors | not run on Windows; mocked | N | run (also `--include-system-log`) | Y | stubbed | N |
| B4 | Restart-CommonServices / restart-common-services | not run on Windows; runtime only | N | run (`--what-if` and refusal only; changes stubbed) | Y (partly) | stubbed | N |
| C1 | Get-UserMailboxStatus (5.1 / pwsh 7) | not run on Windows; mocked, no tenant | N | mocked, no tenant | N | not run | N |
| C2 | Get-UserLicenseReport (5.1 / pwsh 7) | not run on Windows; mocked, no tenant | N | mocked, no tenant | N | not run | N |
| C3 | Get-SuspiciousActivityReport / get-suspicious-activity-report-{macos,linux} | not run on Windows; mocked | N | run (no sudo) | Y | stubbed | N |
| D1 | Clear-WindowsUpdateCache | not run on Windows; repeat-run logic mocked | N | - | - | - | - |
| D2 | Reset-NetworkStack | not run on Windows; runtime only | N | - | - | - | - |
| D3 | Reset-OutlookProfile | not run on Windows; runtime only | N | - | - | - | - |
| E1 | Get-LocalAdminReport / get-local-admin-report | not run on Windows; mocked | N | run (no sudo) | Y | stubbed (user and root) | N |
| E2 | Get-InstalledSoftwareReport / get-installed-software-report | not run on Windows; mocked | N | run | Y | stubbed | N |
| E3 | Get-BackupRecency / get-backup-recency | not run on Windows; mocked | N | run (no Time Machine on this Mac; Time Machine parsing stubbed) | Y | stubbed | N |
| E4 | Get-ServerHealthReport / get-server-health-report | not run on Windows Server; mocked | N | - | - | stubbed | N |
| RC4 | Get-KerberosRC4Usage (needs a domain controller) | not run on Windows; mocked | N | - | - | - | - |
| IdleLock | Set-InactivityTimeout | not run on Windows; mocked (no registry access) | N | - | - | - | - |

Totals: on Windows, mocked logic tests exist for A9, the bundle, B1-B3, C1-C3, D1, E1-E4, RC4
and Set-InactivityTimeout; A1-A8, B4, D2 and D3 are parse- and analyzer-checked only, with
Windows harness runtime cases waiting to be run. Every bash script has stubbed tests. On macOS, 17 of the 20 IDs with a macOS
version ran for real (not A7: active network; not C1/C2: no tenant). No Windows script (26 IDs)
and no Linux script (21 IDs, counting A9 and C1/C2 under pwsh) has run on its own platform.

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

## Open items

- Everything in the hand-test list below. Nothing on Windows, Windows Server, a domain
  controller, a Microsoft 365 tenant or real Linux has run.
- `software-watchlist.txt`: QuickTime for Windows and Java SE 6/7 dates are still `unverified`
  (Apple gives no date; Oracle's pages refuse automated readers). Confirm them in a browser.
- E4 "Stopped automatic services" ignore list and C3 "unusual folders" rules will need tuning
  after the first real Windows/Linux runs (note any false positive with its path).

## Outstanding hand tests

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
