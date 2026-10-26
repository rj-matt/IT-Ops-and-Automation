# Batch E summary (E1-E4)

Updated 2026-10-26. Commit `9034075` (Batch E, A8 last-login fix); C1/C2 follow-up `82ba739`
is in `batch-c-summary.md`. Development machine: macOS 26, PowerShell 7, bash 3.2.57 and 5.3,
ShellCheck, PSScriptAnalyzer.

Harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
110 steps, 44 passed, 0 failed, 66 not run (other platforms, sudo, active network).

| Test | Result |
|---|---|
| `tests/Test-BatchEWindowsLogic.ps1` (E1-E4 Windows, mocked cmdlets) | 63 passed, PowerShell 7 |
| `tests/bash/test-scripts-mocked.sh` (now with E1-E4 Linux and E1-E3 macOS scenarios) | 459 passed, bash 3.2 and 5.3 |
| PSScriptAnalyzer `PSUseCompatibleSyntax` (5.1 and 7) on the four Windows scripts and their test | no findings |
| E1 macOS, real run (no sudo) | 4 PASS, 1 INFO, 1 SKIPPED (sudo rules), 0 WARN/FAIL/ERROR; 0.2 s |
| E2 macOS, real run | 25 apps; 2 PASS (nothing end-of-support or on the watchlist), 3 INFO; 0.5 s |
| E3 macOS, real run | Time Machine not set up, no known backup app: "Backup recency" WARN High (correct for this Mac); 0.1 s |

All result files validated against schema 2.0. The real results stayed in the session's
temporary folder (they name this Mac's account and apps) and were not committed.

## Status

- **run**: run for real on that platform (passive, without sudo).
- **not run on Windows**: logic run on PowerShell 7 on macOS against stand-in cmdlets only.
- **stubbed only**: logic run against stub commands and a fake file system on macOS.
  No Linux machine has run any of it.

| ID | Windows | macOS | Linux |
|---|---|---|---|
| E1 local admins | not run on Windows; mocked | run (no sudo); sudo paths stubbed | stubbed only (normal user and root) |
| E2 installed software | not run on Windows; mocked | run; watchlist matches stubbed | stubbed only |
| E3 backup recency | not run on Windows; mocked | run (Time Machine not set up here); Time Machine parsing stubbed | stubbed only |
| E4 server health | not run on Windows (Server); mocked | N/A (plan) | stubbed only |

## What was built

The plan named E1-E4 with folders and platforms only; the checks below are my reading of
"local admin report", "installed software report", "backup recency" and "server health".
Check names are the same on every platform where the check is the same, so A9-style
reports can line them up.

| Script | Checks |
|---|---|
| E1 `Get-LocalAdminReport.ps1`, `get-local-admin-report.sh` (`endpoint-systems/audit/local-admins/`) | Administrators (table); Number of administrators (more than `-MaxAdmins`, default 2 = WARN Low); Built-in Administrator account (Windows) / Root account (macOS enabled = WARN; Linux extra UID 0 = FAIL High); Unused administrator accounts (90 days); Administrator password age (over a year = WARN Low); Administrators without a password (Windows; Linux with sudo = FAIL High); Orphaned administrator entries and Domain and cloud administrators (Windows); Local admin password management (Windows LAPS / legacy LAPS); Sudo rules (macOS/Linux, sudo: `NOPASSWD: ALL` = WARN Medium) |
| E2 `Get-InstalledSoftwareReport.ps1`, `get-installed-software-report.sh` + `software-watchlist.txt` (`endpoint-systems/audit/software-inventory/`) | Installed software (table); End-of-support software (WARN High); Watchlist software (WARN Medium); Recently installed software (INFO, 30 days) |
| E3 `Get-BackupRecency.ps1`, `get-backup-recency.sh` (`core-infrastructure/backups-dr/diagnostics/`) | Windows: File History, Windows Server Backup (admin), OneDrive folder backup, System Restore (admin; "not a backup"); macOS: Time Machine; Linux: Deja Dup, Timeshift; all: Other backup software (detected only); Backup recency (newest dated backup: up to 7 days PASS, up to 30 WARN, older FAIL) |
| E4 `Get-ServerHealthReport.ps1` (`core-infrastructure/servers/windows/diagnostics/`), `get-server-health-report.sh` (`core-infrastructure/servers/linux/diagnostics/`) | Server, Uptime (60 days), Restart pending, disk space (B1 rule), Memory; Windows: Last update installed, Stopped automatic services, Server roles (main service of AD DS, DNS, DHCP, IIS, Hyper-V, File, Print), Critical events, Time synchronization (w32tm), Certificates (computer store, 30 days); Linux: Load, Swap usage, Inode usage, Failed services, RAID arrays, ZFS pools, Time synchronization, Out-of-memory kills, Certificates (Let's Encrypt, sudo), Listening services |

Also fixed: **A8 `get-home-device-inventory.sh` 1.1.1**. It read the last login from fixed
columns of `last`, which shift when the host column is empty (local logins on macOS), so the
Users table's LastLogon was blank and "unused account" warnings could not fire. Found when
E1 (same code) reported this Mac's own account as never signed in; both now find the date by
its weekday. Batch A's A8 status is unchanged (run on macOS); the fix itself ran on this Mac.

### Design choices to review

1. **No `tmutil` in E3.** `tmutil latestbackup` tries to mount the backup destination (it did
   so here and failed), which for a network disk means traffic. E3 reads
   `/Library/Preferences/com.apple.TimeMachine.plist` (`Destinations[].SnapshotDates`)
   instead. That key was not checked on a Mac with Time Machine set up: hand test below.
2. **E3 on Linux reports SKIPPED** when no known tool is found (plan), and WARN High on
   Windows/macOS ("no backup this script knows about"), which always asks the technician to
   confirm with the client rather than claiming there is no backup.
3. **E3 detects third-party products but does not read them** (Veeam, Macrium, Acronis,
   Backblaze, Carbonite, CrashPlan, Datto, IDrive, Synology, Cove, Arq; macOS and Linux
   equivalents). With only such a product, "Backup recency" is WARN Medium "check its console".
4. **E2 watchlist format**: wildcard patterns (`*`, `?`, comma-separated), not regular
   expressions: `|` is the field separator and wildcards are easier for technicians to edit.
   Fifteen starter entries: 12 end-of-support (Flash, Silverlight, QuickTime for Windows,
   Windows Essentials, Office 2010/2013/2016/2019, Office 2019 for Mac builds, Python 2,
   Java 6/7) and 3 "watch" groups (cleaners / driver updaters, peer-to-peer, adware toolbars).
5. **E2 end-of-support dates are all marked `unverified`.** I wrote them from the vendors'
   announcements but did not open the source pages (no network approval for this run). The
   report says "date unverified" next to each such hit. Hand test below.
6. **E1 Windows "Number of administrators"** counts enabled local admins and domain/Entra ID
   *users*, not groups (a group's size is unknown locally); default limit 2 (`-MaxAdmins`).
7. **E4 stopped automatic services** ignores a fixed list of services that stop by design
   (update services, triggered services). Expect to tune the list after real servers.
8. **E4 w32tm** output is parsed in English; other display languages give SKIPPED with the
   command to run by hand.

## Open items

- Nothing in Batch E has run on Windows, Windows Server or a real Linux machine.
- **RC4 audit** (`security-operations/audit/Invoke-RC4AuditReport-SelfContained-v2.ps1`):
  the plan puts "RC4 audit to standard" in Batch E (rename to `Get-KerberosRC4Usage.ps1`,
  stop writing account names next to the script, add the MIT notice for the Microsoft code it
  includes). Not done: you asked for E1-E4. Say if it should be next; it can only be tested on
  a domain controller.
- E2 end-of-support dates need confirming at their sources (design choice 5).
- E3 Time Machine and macOS sudo paths of E1 were stubbed, not run.

## Outstanding hand tests

Run from the repository root. Validate any result folder with
`pwsh -NoProfile -File tests/Test-MSPResultSchema.ps1 -Path <folder>`.

### Windows 10/11 (nothing in Batch E has run on Windows)

PowerShell 5.1, once from a normal window and once from "Run as administrator":

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1
```

That adds the E1-E4 mocked test on 5.1 and 7 and runtime cases for E1-E4. Then, as administrator:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\endpoint-systems\audit\local-admins\Get-LocalAdminReport.ps1 -OutputPath $o
.\endpoint-systems\audit\software-inventory\Get-InstalledSoftwareReport.ps1 -IncludeOtherUsers -OutputPath $o
.\core-infrastructure\backups-dr\diagnostics\Get-BackupRecency.ps1 -OutputPath $o
```

Check: E1 lists the same members as `net localgroup Administrators`, with correct last
sign-in dates; E2's count is close to Settings > Apps (Store apps are not included) and
flags nothing you cannot explain; E3 shows File History's date if File History is on
(compare with Control Panel > File History) and System Restore points.

### Windows Server (E4, and E3's Windows Server Backup)

On a test or client server you are allowed to check, as administrator:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\core-infrastructure\servers\windows\diagnostics\Get-ServerHealthReport.ps1 -OutputPath $o
.\core-infrastructure\backups-dr\diagnostics\Get-BackupRecency.ps1 -OutputPath $o
```

Check: roles match Server Manager; "Stopped automatic services" lists nothing that is meant to
be stopped (note any for the ignore list); time source matches `w32tm /query /status`;
certificates match `certlm.msc` > Personal; E3 shows Windows Server Backup's last success if
it is used. On a domain controller, "Server" says domain controller.

### macOS with sudo, and Time Machine

```bash
o=/tmp/msp-hand; mkdir -p "$o"
sudo bash endpoint-systems/audit/local-admins/get-local-admin-report.sh --output "$o"
sudo bash endpoint-systems/audit/software-inventory/get-installed-software-report.sh --all-users --output "$o"
bash core-infrastructure/backups-dr/diagnostics/get-backup-recency.sh --output "$o"   # on a Mac WITH Time Machine
```

Check: E1 "Sudo rules" runs and lists nothing unexpected; E2 includes other users' apps; on a
Mac that uses Time Machine, E3's "Time Machine" date matches the "Latest backup" in System
Settings > General > Time Machine. If it says "no completed backup is recorded" while Time
Machine shows backups, the settings-file key has changed in that macOS version: tell me the
macOS version. Delete `/tmp/msp-hand` afterwards.

### Real Linux runs (all Batch E Linux results are stubbed only)

On one apt desktop (Ubuntu or Debian) and one Linux server (any distribution with systemd):

```bash
o=/tmp/msp-hand; mkdir -p "$o"
bash tests/bash/test-scripts-mocked.sh
bash endpoint-systems/audit/local-admins/get-local-admin-report.sh --output "$o"
sudo bash endpoint-systems/audit/local-admins/get-local-admin-report.sh --output "$o"
bash endpoint-systems/audit/software-inventory/get-installed-software-report.sh --output "$o"
bash core-infrastructure/backups-dr/diagnostics/get-backup-recency.sh --output "$o"
bash core-infrastructure/servers/linux/diagnostics/get-server-health-report.sh --output "$o"
sudo bash core-infrastructure/servers/linux/diagnostics/get-server-health-report.sh --output "$o"
```

Check: E1 members match `getent group sudo` (or wheel); with sudo, password checks and sudo
rules run; E2's package count matches `dpkg -l | grep -c ^ii` (or `rpm -qa | wc -l`) plus
snaps/Flatpaks; E3 finds Deja Dup or Timeshift if used (else SKIPPED); E4 disk numbers match
`df -h`, and with sudo the journal and certificate checks run. Note any false positive.

### E2 watchlist dates (needs web access; your approval)

Open each `Source` URL in `endpoint-systems/audit/software-inventory/software-watchlist.txt`,
confirm the date, and replace `unverified` with the date you checked (`YYYY-MM-DD`), or correct
the line. Nothing in the scripts needs changing.

### Active network

Nothing in Batch E sends network traffic.
