# Batch C summary (C1-C3)

Updated 2026-10-26 (C1/C2 on Windows PowerShell 5.1, C2 P1 test, consent note). Commits `a632f1c` (Windows bundle `-Passive`, finishing Batch A) and
`55fcb93` (Batch C). Development machine: macOS 26, PowerShell 7, bash 3.2.57 and 5.3,
ShellCheck, PSScriptAnalyzer. No Microsoft 365 tenant was contacted.

Harness on macOS (`pwsh -NoProfile -File tests/Invoke-ToolkitTests.ps1`, passive):
98 steps, 40 passed, 0 failed, 58 not run (other platforms, sudo, active network).

| Test | Result |
|---|---|
| `tests/Test-BatchCCloudLogic.ps1` (C1, C2, mocked Exchange Online / Graph) | 73 passed, PowerShell 7 |
| `tests/Test-SuspiciousActivityWindowsLogic.ps1` (C3 Windows, mocked cmdlets) | 31 passed, PowerShell 7 |
| `tests/Test-HomeAuditBundleWindowsLogic.ps1` (Windows bundle `-Passive`) | 19 passed, PowerShell 7 |
| `tests/bash/test-scripts-mocked.sh` (now with C3 Linux and macOS scenarios) | 363 passed, bash 3.2 and 5.3 |
| C3 macOS, real run on this Mac (passive, no sudo) | 10 PASS, 0 WARN/FAIL/ERROR, 2 INFO, 1 SKIPPED (Background items: sudo); 2.6 s; schema valid |

## Status

- **run**: run for real on that platform.
- **not run on Windows**: logic run on PowerShell 7 on macOS against stand-in cmdlets only.
- **mocked, no tenant**: C1/C2 logic run against stand-in Exchange Online / Graph cmdlets;
  never signed in to Microsoft 365.
- **stubbed only**: logic run against stub commands and a fake file system on macOS.
  No Linux machine has run any of it.

| ID | Windows | macOS | Linux |
|---|---|---|---|
| C1 mailbox status (5.1 / pwsh 7) | not run on Windows (5.1 or 7); mocked, no tenant | mocked, no tenant | not run |
| C2 license report (5.1 / pwsh 7) | not run on Windows (5.1 or 7); mocked, no tenant | mocked, no tenant | not run |
| C3 suspicious activity | not run on Windows; mocked | run (no sudo) | stubbed only |
| Bundle `-Passive` (Batch A) | not run on Windows; mocked | (bash: run, Batch A) | (bash: stubbed, Batch A) |

The C1/C2 mocked test runs the same scenarios on Windows PowerShell 5.1 and PowerShell 7 (the
harness on Windows runs it under both); here it ran on PowerShell 7 only, plus a
PSScriptAnalyzer check that C1, C2 and the test use no syntax newer than 5.1 (verified to flag
`??` and the ternary operator).

## What changed

| Script | Change |
|---|---|
| C1 `Get-UserMailboxStatus.ps1` 2.0.0 | Rewritten to standard (helper, statuses, JSON/CSV, log). Added holds, archive, recoverable items, inbox-rule forwarding, rules that hide mail, auto-reply, mail apps, delegates; forwarding outside the tenant's accepted domains is WARN High. No `Read-Host`: the mailbox is a mandatory parameter |
| C2 `Get-UserLicenseReport.ps1` 2.0.0 | Moved to `cloud-services/m365/diagnostics/` (was in `endpoint-systems/diagnostics/system-info/`) and rewritten; the old file did not parse. Adds subscription state, service-plan problems, the Entra ID P1 note, `-All` |
| C3 `Get-SuspiciousActivityReport.ps1`, `get-suspicious-activity-report-macos.sh`, `-linux.sh` 1.0.0 | New. Same check names (and IDs) on every platform |
| `Invoke-HomeAuditBundle.ps1` 1.2.0 | `-Passive` (Batch A follow-up) |

### Read-only by design

| Script | How it stays read-only |
|---|---|
| C1 | Only `Get-` cmdlets. A connection the script opens loads only `Get-InboxRule`, `Get-MailboxAutoReplyConfiguration`, `Get-AcceptedDomain` (`Connect-ExchangeOnline -CommandName`), plus the module's own `Get-EXO*` cmdlets. Exchange Online has no read-only sign-in scope: the account's role decides what it may do, so use **Global Reader** or **View-Only Organization Management** |
| C2 | Only `Get-Mg*` cmdlets. A connection the script opens asks for exactly `User.Read.All`, `Organization.Read.All`, `AuditLog.Read.All`, with `-ContextScope Process` (the token is not cached to disk). An existing connection with write scopes is used as it is and the report says so |
| C3 | Reads files, the registry, process and connection lists, Defender status and logs; no network traffic, no file contents except the hosts file, shell start-up files and (names, dates, counts of) authorized_keys |

### Design choices to review

1. **C3 is labelled triage, not EDR** in the help text, the banner ("not an antivirus or EDR")
   and a `Scope` INFO finding at the top of every result: "A clean result does not prove the
   computer is clean".
2. **C3 "unusual folders"**: temporary folders, Public / Shared, Downloads, the Recycle Bin and
   hidden folders. Programs elsewhere in a user profile are flagged only when unsigned
   (Windows Authenticode, macOS `codesign`; ad-hoc counts as unsigned). Linux has no signature
   check, so a hidden folder is always flagged, except common developer tool folders (`.local`,
   `.cargo`, `.nvm`, ...).
3. **False positives found on this Mac and fixed before the commit**: iPhone/iPad apps on Apple
   silicon run from `/var/folders/.../X/...` with an older Apple signature format that
   `codesign -v` rejects ("resource envelope is obsolete"); and two signed apps run from a
   hidden folder in the home folder. Both are now judged by their signature; `$TMPDIR`
   (`/var/folders/.../T/`) and `/tmp` stay unusual whatever the signature.
4. **C3 "New startup items"** is WARN Low (ask the user), not a sign of compromise by itself.
   Linux leaves out `/etc/xdg/autostart` and `/etc/crontab`, which package updates rewrite.
5. **C3 macOS does not search the unified log or XProtect history** (slow, as in B3); failed
   sign-ins are Windows (Security log) and Linux (journal) only.
6. **C2 SKU names**: the old map called `O365_BUSINESS_PREMIUM` "Business Premium"; in
   Microsoft's list it is Microsoft 365 Business Standard (`SPB` is Business Premium). The part
   number is now always shown next to the name.
7. **C1/C2 run on Windows PowerShell 5.1 or PowerShell 7 on Windows, and PowerShell 7 on
   macOS/Linux** (2.1.0, approved change). PowerShell 6 is refused with a plain message.
8. **SKIPPED/ERROR findings in C1/C2 carry the user or mailbox as Target**, so an `-All` report
   says whose check could not run.
9. **No Entra ID P1/P2 in the tenant**: C2's "Last sign-in" is SKIPPED for each user with
   "This tenant has no Microsoft Entra ID P1 or P2 license, and Microsoft only shows last
   sign-in dates to tenants that do (P1 is included in Microsoft 365 Business Premium, E3 and
   E5)"; never ERROR, and the other checks still run (mocked test, named users and `-All`).
10. **C2's first sign-in grants tenant-wide admin consent** to Microsoft's "Microsoft Graph
    Command Line Tools" app; it stays until an admin removes it. In a client tenant this needs
    the client's approval and a ticket note (C2 help text, README).

## Open items

- Nothing in Batch C has run on Windows, against a real tenant, or on a real Linux machine.
- C3 Windows administrator paths (Defender exclusions, Security log events) ran against mocks
  only as SKIPPED (not elevated on the Mac); with the harness elevated on Windows the test
  asserts them against the mocks.
- C3 `Background items` (macOS, sudo) parses `sfltool dumpbtm` output that was not available
  here; its parsing has not been checked against real output.
- `Get-InboxRule` may not list rules hidden through MAPI; the C1 help text says so.

## Outstanding hand tests

Run from the repository root. Validate any result folder with
`pwsh -NoProfile -File tests/Test-MSPResultSchema.ps1 -Path <folder>`.

### Windows (nothing in Batch C has run on Windows)

PowerShell 5.1, once from a normal window and once from "Run as administrator":

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-ToolkitTests.ps1
```

That adds, for Batch C: the C1/C2 mocked test on 5.1 and on 7 (if installed), the C3 mocked test on 5.1 and 7, the C3 runtime case, and the bundle `-Passive`
runtime and mocked cases. Then by hand, as administrator:

```powershell
$o = "$env:TEMP\MSP-Toolkit\hand"
.\security-operations\diagnostics\endpoint-posture\Get-SuspiciousActivityReport.ps1 -Days 30 -OutputPath $o
.\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -Passive -TechnicianName "Test"
.\security-operations\diagnostics\Invoke-HomeAuditBundle.ps1 -Passive -ScanLan
```

Check: C3 shows the Security log checks and Defender exclusions without SKIPPED, lists the
StartupItems table, and flags nothing you cannot explain (note any false positive with its
path). The `-Passive` bundle shows A7 "Skipped (passive)" and A9's Coverage row says
"Not run: Not run with -Passive"; the `-Passive -ScanLan` run stops with exit code 2 and
starts nothing.

### Microsoft 365 tenant (C1, C2) - sends traffic to Microsoft; your approval per run

Use a test tenant or a client tenant you are allowed to review. Run the steps below once in
PowerShell 7 (any platform) and once on Windows in **Windows PowerShell 5.1**
(`powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...` instead of `pwsh -File ...`;
install the modules in that shell too).

1. Install the modules once (from the PowerShell Gallery; no admin rights):

   ```powershell
   Install-Module ExchangeOnlineManagement -Scope CurrentUser
   Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
   ```

2. **C2 first sign-in (consent).** **This grants tenant-wide admin consent** to Microsoft's
   "Microsoft Graph Command Line Tools" app, which stays until an admin removes it (Entra admin
   center > Enterprise applications > Microsoft Graph Command Line Tools > Permissions). In a
   client's tenant, get the client's approval first and note it in the ticket (who approved,
   when, which scopes). Prefer a test tenant for this hand test. The script asks Microsoft Graph for exactly these
   delegated scopes; the sign-in page of the "Microsoft Graph Command Line Tools" app lists them:

   | Scope | Shown as (approximately) | Used for |
   |---|---|---|
   | `User.Read.All` | Read all users' full profiles | users, assigned licenses, license details |
   | `Organization.Read.All` | Read organization information | subscriptions (`subscribedSkus`) |
   | `AuditLog.Read.All` | Read all audit log data | last sign-in (`signInActivity`) |

   The page also lists the standard sign-in permissions Graph adds (`openid`, `profile`,
   `offline_access`, shown as "Sign you in", "View your basic profile", "Maintain access to
   data you have given it access to"). All three `*.Read.All` scopes need **admin consent**:
   the first sign-in must be by an account that can consent for the organization (Global
   Administrator, or Privileged Role / Cloud Application Administrator), ticking "Consent on
   behalf of your organization". After that, run it as a **Global Reader**. Record exactly what
   the consent page listed; I could not check it without a tenant.

3. **C1 sign-in.** Exchange Online asks for no per-script scopes; the module signs in through
   Microsoft's own Exchange Online PowerShell app. In most tenants no consent page appears; if
   one does, record what it lists. Sign in as Global Reader or View-Only Organization
   Management.

4. Run:

   ```powershell
   $o = "$HOME/m365-hand"
   pwsh -File ./cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1 -UserPrincipalName <you@tenant> -OutputPath $o
   pwsh -File ./cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1 -All -IncludeServicePlans -OutputPath $o
   pwsh -File ./cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1 -UserPrincipalName <user> -DeviceCode
   pwsh -File ./cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1 -UserPrincipalName <user@tenant> -OutputPath $o
   pwsh -File ./cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1 -UserPrincipalName <shared-mailbox@tenant> -DeviceCode
   pwsh -File ./cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1 -UserPrincipalName nobody-here@<tenant domain>
   ```

   Check:
   - C2: the "Graph connection" finding lists only the three scopes; subscriptions match the
     admin center (Billing > Your products); last sign-in matches the Entra sign-in log, or is
     SKIPPED with the P1/P2 reason in a tenant without it; nothing is ERROR.
   - C1: mailbox size and quota match the Exchange admin center; inbox rules and forwarding
     match Outlook on the web (Settings > Mail > Rules / Forwarding); delegates match the
     mailbox's delegation page; the unknown address gives FAIL "No mailbox ...".
   - On 5.1: the same results as on 7 (compare the two JSON files); browser sign-in and
     `-DeviceCode` both work.
   - Both: after the run, `Get-MgContext` / `Get-ConnectionInformation` show no connection
     (the script disconnected), unless `-KeepConnection` was given.
   - Optional: run each once as an account **without** a reader role and note which checks
     become SKIPPED (and whether any shows ERROR instead; that wording would need tuning).

   Delete `$HOME/m365-hand` afterwards (it names users and mailboxes).

### macOS with sudo

```bash
o=/tmp/msp-hand; mkdir -p "$o"
sudo bash security-operations/diagnostics/endpoint-posture/get-suspicious-activity-report-macos.sh --days 30 --output "$o"
```

Check: "Background items" runs (not SKIPPED) and its count looks like System Settings >
General > Login Items & Extensions; other users' launch agents and SSH keys are included;
"Connections from flagged programs" no longer says only this user's are visible. Delete
`/tmp/msp-hand` afterwards.

### Real Linux runs (C3 is stubbed only)

On one apt system (Ubuntu or Debian) and one dnf system (Fedora):

```bash
o=/tmp/msp-hand; mkdir -p "$o"
bash tests/bash/test-scripts-mocked.sh
bash security-operations/diagnostics/endpoint-posture/get-suspicious-activity-report-linux.sh --output "$o"
sudo bash security-operations/diagnostics/endpoint-posture/get-suspicious-activity-report-linux.sh --days 30 --output "$o"
pwsh -NoProfile -File tests/Test-BatchCCloudLogic.ps1          # if PowerShell 7 is installed
```

Check: no ERROR findings; as a normal user "Failed sign-ins" is SKIPPED unless the account is
in adm / systemd-journal, and with sudo it shows a count; with sudo "Programs running from
unusual folders" no longer reports processes it could not check; snaps, Flatpaks and desktop
autostart entries are not flagged (note any false positive with its path).

### Active network

Nothing new in Batch C sends traffic on the local network. C1/C2 send traffic to Microsoft
365 (`login.microsoftonline.com`, `graph.microsoft.com`, `outlook.office365.com`) and the module
installs go to the PowerShell Gallery; both are listed above and need your approval per run.
The Windows bundle without `-Passive` is listed in `batch-a-summary.md`.
