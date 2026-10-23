# Phase 2 - Status matrix and plan (2026-10-16)

Based on `phase1-inventory-audit.md`. **Awaiting approval before any Phase 3 work.**

## 1. Status matrix

Cells: **good** / **needs fixes** / **missing** / **N/A**. "needs fixes (minor)" = standards met apart from
the schema and shared-helper changes in sections 2 and 5, which every Batch A script picks up on regeneration.

| ID | Script (PowerShell / bash) | Folder | Risk | Windows | macOS | Linux |
|---|---|---|---|---|---|---|
| A1 | Get-EndpointSecurityStatus / get-endpoint-security-status-{macos,linux}.sh | security-operations/diagnostics/endpoint-posture/ | Read-Only | built (A-1; Windows run pending) | good (A-1; run on macOS 26) | built (A-1; stub-tested only) |
| A2 | Get-HomeNetworkMap / get-home-network-map.sh | core-infrastructure/networking/diagnostics/ | Read-Only | built (A-1; `-Passive` added; Windows run pending) | good (A-1; passive run on macOS 26) | built (A-1; stub-tested only) |
| A3 | Get-WiFiSecurityAudit / get-wifi-security-audit-{macos,linux}.sh | core-infrastructure/networking/diagnostics/ | Read-Only | built (A-1; Windows run pending) | good (A-1; run on macOS 26) | built (A-1; stub-tested only) |
| A4 | Get-OpenPortScan / get-open-port-scan.sh | security-operations/diagnostics/endpoint-posture/ | Read-Only | built (A-1; Windows run pending) | good (A-1; local part run on macOS 26) | built (A-1; stub-tested only) |
| A5 | Get-BrowserSecurityCheck / get-browser-security-check.sh | endpoint-systems/diagnostics/system-info/ | Read-Only | built (A-2; help text/names; Windows run pending) | good (A-2; run on macOS 26) | built (A-2; stub-tested only) |
| A6 | Get-WindowsUpdateCompliance / get-update-compliance-{macos,linux}.sh | endpoint-systems/diagnostics/system-info/ | Read-Only | built (A-2; help text/names; Windows run pending) | good (A-2; run on macOS 26) | built (A-2; stub-tested only) |
| A7 | Get-RouterSecurityCheck / get-router-security-check.sh | core-infrastructure/networking/diagnostics/ | Read-Only | built (A-2; help text/names; Windows run pending) | built (A-2; active only: stub-tested, not run) | built (A-2; stub-tested only) |
| A8 | Get-HomeDeviceInventory / get-home-device-inventory.sh | endpoint-systems/audit/software-inventory/ | Read-Only | built (A-2; help text/names; Windows run pending) | good (A-2; run on macOS 26) | built (A-2; stub-tested only) |
| A9 | Export-SecurityAuditReport (PS 7 on all; also 5.1) | security-operations/diagnostics/ | Read-Only | built (A-3; Platform-aware, device checklist; 5.1 run pending) | good (A-3; run on pwsh 7, macOS 26, mixed Windows/macOS/Linux results) | built (A-3; not run on Linux) |
| Bundle | Invoke-HomeAuditBundle / run-home-audit-bundle.sh | security-operations/diagnostics/ | Read-Only | built (unchanged in A-3; Windows run pending) | good (A-3; `--passive` run on macOS 26) | built (A-3; stub-tested only) |
| B1 | Get-ClientHealthSnapshot / get-client-health-snapshot.sh | endpoint-systems/diagnostics/system-info/ | Read-Only | built (B; mocked-cmdlet tests; Windows run pending) | good (B; run on macOS 26) | built (B; stub-tested only) |
| B2 | Get-NetworkConnectivityReport / get-network-connectivity-report.sh | endpoint-systems/diagnostics/networking/ | Read-Only | built (B; `-Passive` mocked; Windows run pending) | good (B; `--passive` run on macOS 26; active: stub-tested, not run) | built (B; stub-tested only) |
| B3 | Get-RecentCriticalErrors / get-recent-critical-errors.sh | endpoint-systems/diagnostics/event-logs/ | Read-Only | built (B; mocked-cmdlet tests; Windows run pending) | good (B; run on macOS 26) | built (B; stub-tested only) |
| B4 | Restart-CommonServices / restart-common-services.sh | endpoint-systems/remediation/safe/restart-services/ | Safe | built (safety fixes; Windows run pending) | built (B; `--what-if` and refusal run on macOS 26; changes stub-tested only, sudo not used) | built (B; stub-tested only) |
| C1 | Get-UserMailboxStatus (PS 7) | cloud-services/m365/diagnostics/ | Read-Only | built (C; mocked cmdlets; not run on Windows; no tenant) | built (C; mocked cmdlets on pwsh 7; no tenant) | built (C; not run on Linux) |
| C2 | Get-UserLicenseReport (PS 7) | cloud-services/m365/diagnostics/ (moved) | Read-Only | built (C; mocked cmdlets; not run on Windows; no tenant) | built (C; mocked cmdlets on pwsh 7; no tenant) | built (C; not run on Linux) |
| C3 | Get-SuspiciousActivityReport / get-suspicious-activity-report-{macos,linux}.sh | security-operations/diagnostics/endpoint-posture/ | Read-Only | built (C; mocked cmdlets; not run on Windows) | good (C; run on macOS 26, no sudo) | built (C; stub-tested only) |
| D1 | Clear-WindowsUpdateCache | endpoint-systems/remediation/safe/clear-caches/ | Safe | needs fixes (rename not delete, dry run) | N/A | N/A |
| D2 | Reset-NetworkStack | endpoint-systems/remediation/elevated/network-resets/ (rename) | Elevated | needs fixes (exit codes, overclaim, dry run) | N/A | N/A |
| D3 | Reset-OutlookProfile | cloud-services/m365/remediation/ | Elevated | needs fixes (keep old profile, overclaim) | N/A | N/A |
| E1 | Get-LocalAdminReport / get-local-admin-report.sh | endpoint-systems/audit/local-admins/ | Read-Only | missing | missing | missing |
| E2 | Get-InstalledSoftwareReport / get-installed-software-report.sh | endpoint-systems/audit/software-inventory/ | Read-Only | missing | missing | missing |
| E3 | Get-BackupRecency / get-backup-recency.sh | core-infrastructure/backups-dr/diagnostics/ | Read-Only | missing | missing | missing (SKIPPED unless a known tool is found) |
| E4 | Get-ServerHealthReport / get-server-health-report.sh | core-infrastructure/servers/{windows,linux}/diagnostics/ | Read-Only | missing | N/A | missing |

Nothing was rated **good** at Phase 2: the schema change (section 2) reaches every Batch A script.
Updated after steps A-1 (A1-A4) and A-2 (A5-A8): "good" = built to standard and run on that platform; "built" =
built to standard, logic tested with stubbed commands, not yet run on a real machine of that
platform. The A-1 Windows changes were parse- and analyzer-checked on pwsh 7 only.
Current status, open items and hand tests for each batch: `batch-a-summary.md`, `batch-b-summary.md`,
`batch-c-summary.md`.

**Planned macOS/Linux splits** (single shared `.sh` otherwise): A1, A3, A6, C3. In each, the two
platforms share almost no commands (FileVault/SIP/Gatekeeper vs LUKS/ufw/firewalld; `system_profiler`/`wdutil`
vs `nmcli`; `softwareupdate` vs apt/dnf; launchd vs systemd). One file would be mostly `if macOS ... else ...`.
A2, A4, A5, A7, A8, B1-B4, E1-E3 stay one `.sh` with small `uname` branches.

## 2. JSON schema across platforms

Today (`SchemaVersion` 1.0): `ScriptName, ScriptVersion, RiskLevel, Computer, User, IsAdmin, PSVersion,
StartTime, EndTime, Parameters, Summary, Findings[] (Id, Category, Check, Status, Severity, Target, Detail,
Recommendation, Evidence), Data`.

Gaps for mixed devices:
- No `Platform`. A9 cannot tell a Mac from a PC.
- No catalog `CheckId`. Finding IDs come from the script name (`Get-EndpointSecurityStatus:...`), so a bash
  sibling (`get-endpoint-security-status-macos`) would produce different IDs for the same check.
- `PSVersion` makes no sense for bash.

**Proposal: `SchemaVersion` 2.0** (A9 will still read 1.0 files):

```text
SchemaVersion   "2.0"
CheckId         "A1"                       catalog ID, same on every platform
ScriptName      "Get-EndpointSecurityStatus" | "get-endpoint-security-status-macos"
Version         "1.2.0"                    (was ScriptVersion)
Platform        "Windows" | "macOS" | "Linux"
OSVersion       "Windows 11 Pro 26200" | "macOS 15.1" | "Ubuntu 24.04"
Shell           "Windows PowerShell 5.1" | "bash 3.2.57"   (replaces PSVersion)
Host            "PC-01"                     (was Computer)
User, IsAdmin, RiskLevel, Parameters
Timestamp       ISO 8601 start time         (was StartTime)
EndTime         ISO 8601
Summary         { PASS, WARN, FAIL, INFO, SKIPPED, ERROR }
Findings[]      { Id, Category, Check, Status, Severity, Target, Detail, Recommendation, Evidence }
Data            { <table name>: [ {..}, .. ] }
```

Finding `Id` becomes `<CheckId>.<Area>.<Key>` (e.g. `A1.DiskEncryption.Enabled`), and the equivalent checks share
one ID on every platform (BitLocker / FileVault / LUKS all report `A1.DiskEncryption.Enabled`). A9 can then group
"disk encryption" across a household's devices. Platform-only checks get their own key (`A1.SIP.Enabled`).
A dev-side `Test-MSPResultSchema.ps1` checks every script's JSON (never run on client machines).

Alternative if you prefer no renames: keep the 1.0 names and add only `CheckId`, `Platform`, `OSVersion`,
`Shell` (schema 1.1). That is less churn but keeps `Computer`/`StartTime` instead of the `Host`/`Timestamp` names you listed.

## 3. Not on the catalog

| Item | Recommendation | Why |
|---|---|---|
| `security-operations/audit/Invoke-RC4AuditReport-SelfContained-v2.ps1` | **Keep**, rename `Get-KerberosRC4Usage.ps1`, bring to standard in Batch E | Real need: Microsoft is phasing out RC4 in Kerberos. Must stop writing account-name CSVs to its own folder and must carry the MIT notice for the Microsoft code it includes. Runs on DCs only, so it is not a home-audit script. |
| `security-operations/hardening/server-hardening/Set-InactivityTimeout.ps1` | **Keep**, bring to standard in Batch D | Small, useful, already has ShouldProcess. Needs before/after, log, risk level (Elevated), and `-Force` renamed (it means "rewrite even if equal"). `_archive/README.md` names it as the reviewed source for the archived `.exe`. |
| `.playbooks/README.md` | **Archive** | Describes a `playbooks/` folder and five playbooks that do not exist; the folder name starts with a dot, so it is hidden on macOS/Linux. The bundle runners cover the only real playbook today. |
| `docs/toolkit-review/` | Keep | This review. |

## 4. Build order

Default order, with Batch A split into three stops because it is about 20 new or changed files:

| Step | Contents | Stop |
|---|---|---|
| **F - Foundation** | `msp-toolkit-common.sh` (logging, statuses, color/plain output, ticket block, JSON escaping + export, privilege/FDA checks, subnet detection, 32-probe limiter); schema 2.0 in `MSPToolkit.Common.psm1`; module fixes (probe cap 32, never scan a VPN/virtual adapter: SKIPPED instead; Core runs on pwsh 7 for macOS/Linux for A9/C1/C2); `Sync-MSPEmbeddedHelper.ps1` handles `.sh` (same markers and hash, `-Check` still exits 1); unit tests for JSON escaping; `Test-MSPResultSchema.ps1`. Regenerate all embedded copies. | Yes |
| **A-1** | A1-A4: fix Windows, then macOS and Linux ports | Yes |
| **A-2** | A5-A8: fix Windows, then ports | Yes |
| **A-3** | A9 on pwsh 7 (all platforms) + 5.1, Platform-aware, manual device checklist (iOS, Android, TVs, consoles, IoT); `run-home-audit-bundle.sh`; Windows bundle update | Yes |
| **B** | B1-B4 (Windows rewritten to standard, then ports). B4 allow-lists, justified in the header: macOS `mDNSResponder` (DNS cache) and `cupsd` (printing); Linux `cups` and `systemd-resolved` / `NetworkManager` when present. | Yes |
| **C** | C2 parse fix + move + PS7 + P1 note; C1 holds/archive/inbox-rule forwarding + export; C3 on all three platforms | Yes |
| **E** | E1-E4; RC4 audit to standard | Yes |
| **D** | D1 rename-not-delete; D2 rework, honest about rollback; D3 keep old profile, ask to close Outlook, honest about account setup; Set-InactivityTimeout to standard | Yes |
| **Docs** | README catalog, per-platform runbooks, how to read output (Phase 5). The catalog table is also updated as each batch lands. | Final summary |

## 5. Decisions needed

1. Schema 2.0 (renames) or 1.1 (additive)? Recommended: 2.0.
2. Dev tooling, needed for Phase 4's "PSScriptAnalyzer and ShellCheck clean": may I install **PSScriptAnalyzer**
   (`Install-Module -Scope CurrentUser`), **ShellCheck** (winget or a portable zip in the scratchpad) and **PowerShell 7**
   (winget) on this machine? Otherwise those checks stay "not run".
3. Linux testing: may I install a WSL Ubuntu distro to run the Linux scripts? No macOS host and no bash 3.2 are
   available, so macOS will be covered by `bash -n`, a bash-4+ construct grep, and your testing.
4. Approve `git mv` for C2 (to `cloud-services/m365/diagnostics/`) and D2 (folder `network-resets/`), and archiving `.playbooks/`.
5. Split A1/A3/A6/C3 into `-macos.sh` / `-linux.sh` as described above?
