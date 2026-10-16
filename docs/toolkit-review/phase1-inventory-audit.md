# Phase 1 - Inventory and audit (2026-10-16)

Baseline: tag `pre-crossplatform` plus the approved-tools / A6 maintenance commit.
No script was assumed complete; Batch A was graded like everything else.

## Tooling used

| Check | Result |
|---|---|
| PowerShell parser (Windows PowerShell 5.1) on every `.ps1` / `.psm1` | Run. 1 failure (C2, see below). |
| Pattern scan (headers, risk level, ShouldProcess, Read-Host, Remove-Item, hardcoded paths/GUIDs/passwords, PS7-only syntax, logging, export) | Run on all scripts. |
| Manual read of every non-Batch-A script; targeted read of Batch A shared code (logging, output, schema, subnet selection, runspaces) | Done. |
| PSScriptAnalyzer | **Not run - not installed** on this machine (no PSGallery install was made). |
| ShellCheck | **Not run - not installed; there are no bash scripts yet.** |
| pwsh 7 | Not installed, so PS7-target scripts (C1, C2, A9 cross-platform) were only parsed under 5.1. |

## 1. Inventory

### Graded (outside `_archive/`)

| Path | Type | Catalog ID |
|---|---|---|
| `security-operations/diagnostics/endpoint-posture/Get-EndpointSecurityStatus.ps1` | Diagnostic | A1 |
| `core-infrastructure/networking/diagnostics/Get-HomeNetworkMap.ps1` | Diagnostic (ping/ARP) | A2 |
| `core-infrastructure/networking/diagnostics/Get-WiFiSecurityAudit.ps1` | Diagnostic | A3 |
| `security-operations/diagnostics/endpoint-posture/Get-OpenPortScan.ps1` | Diagnostic (opt-in LAN scan) | A4 |
| `endpoint-systems/diagnostics/system-info/Get-BrowserSecurityCheck.ps1` | Diagnostic | A5 |
| `endpoint-systems/diagnostics/system-info/Get-WindowsUpdateCompliance.ps1` | Diagnostic | A6 (name differs from catalog "UpdateCompliance", see section 4) |
| `core-infrastructure/networking/diagnostics/Get-RouterSecurityCheck.ps1` | Diagnostic | A7 |
| `endpoint-systems/audit/software-inventory/Get-HomeDeviceInventory.ps1` (+ `approved-remote-tools.txt`) | Diagnostic | A8 |
| `security-operations/diagnostics/Export-SecurityAuditReport.ps1` | Report builder | A9 |
| `security-operations/diagnostics/Invoke-HomeAuditBundle.ps1` | Runner | Bundle |
| `endpoint-systems/diagnostics/system-info/Get-ClientHealthSnapshot.ps1` | Diagnostic | B1 |
| `endpoint-systems/diagnostics/networking/Get-NetworkConnectivityReport.ps1` | Diagnostic | B2 |
| `endpoint-systems/diagnostics/event-logs/Get-RecentCriticalErrors.ps1` | Diagnostic | B3 |
| `endpoint-systems/remediation/safe/restart-services/Restart-CommonServices.ps1` | Remediation | B4 |
| `cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1` | Cloud diagnostic | C1 |
| `endpoint-systems/diagnostics/system-info/Get-UserLicenseReport.ps1` | Cloud diagnostic | C2 (**wrong folder**) |
| `endpoint-systems/remediation/safe/clear-caches/Clear-WindowsUpdateCache.ps1` | Remediation | D1 |
| `endpoint-systems/remediation/elevated/network-reset/Reset-NetworkStack.ps1` | Remediation | D2 (**folder `network-reset` vs catalog `network-resets`**) |
| `cloud-services/m365/remediation/Reset-OutlookProfile.ps1` | Remediation | D3 |
| `endpoint-systems/utilities/MSPToolkit.Common.psm1` | Shared helper source | - |
| `endpoint-systems/utilities/Sync-MSPEmbeddedHelper.ps1` | Dev tool | - |
| `security-operations/audit/Invoke-RC4AuditReport-SelfContained-v2.ps1` | AD audit | Not in catalog |
| `security-operations/hardening/server-hardening/Set-InactivityTimeout.ps1` | Hardening (changes registry) | Not in catalog |
| `.playbooks/README.md` | Docs only | Not in catalog |

No `.sh`, `.bat`, `.cmd`, `.py` or other executables exist outside `_archive/`.
Missing entirely: C3, E1-E4, every macOS/Linux script, `msp-toolkit-common.sh`.

### `_archive/` (listed, not graded)

| Path | Note |
|---|---|
| `_archive/core-infrastructure/networking/diagnostics/gateway-security/Check-GatewaySecurity.ps1` | Superseded by A7 |
| `_archive/core-infrastructure/networking/diagnostics/subnet-mapping/Get-SubnetMap.ps1` | Superseded by A2 |
| `_archive/core-infrastructure/networking/diagnostics/wifi-security/Check-WifiSecurity.ps1` | Superseded by A3 (read Wi-Fi keys) |
| `_archive/endpoint-systems/audit/inventory/Get-DeviceInventory.ps1` | Superseded by A8 / future E2 |
| `_archive/endpoint-systems/diagnostics/system-info/Check-BrowserSecurity.ps1` | Superseded by A5 (opened credential stores) |
| `_archive/core-infrastructure/servers/audit/Audit-ServerSecurity2.0.exe` | Unsigned .NET PE32, no source |
| `_archive/security-operations/hardening/server-hardening/Set-InactivityTimeout2.0.exe` | Unsigned .NET PE32 console app |

## 2. Grades against standards 1-12

Legend: **P** pass, **~** partial, **F** fail, **-** not applicable.
Standards: 1 header, 2 diagnostics change nothing, 3 state-change safety (dry run, before/after, confirm, -Force for non-interactive), 4 missing privileges -> SKIPPED with reason, 5 error handling, 6 status set, 7 console + ticket + JSON/CSV, 8 log file, 9 no secrets, 10 network-scan limits, 11 no overclaiming, 12 runs standalone.

| ID | Script | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1 | Get-EndpointSecurityStatus | P | P | - | P | P | P | ~ | P | P | - | P | P | 7: JSON lacks `Platform`/`CheckId` (schema, section 3). Admin path untested. |
| A2 | Get-HomeNetworkMap | P | P | - | P | P | P | ~ | P | P | ~ | P | P | 10: `-ThrottleLimit` accepts up to 64 (max allowed 32); adapter picker falls back to a VPN/virtual adapter when it is the only one with a gateway (it warns, but the standard says skip). /22 cap and scope print are correct. Active sweep untested. |
| A3 | Get-WiFiSecurityAudit | P | P | - | P | P | P | ~ | P | P | - | P | P | 9: `key=clear` deliberately never used (verified). |
| A4 | Get-OpenPortScan | P | P | - | P | P | P | ~ | P | P | ~ | P | P | 10: same 64-probe ceiling and virtual-adapter fallback as A2. `-ScanLan` untested. |
| A5 | Get-BrowserSecurityCheck | P | P | - | P | P | P | ~ | P | P | - | P | P | 9: credential files listed as never opened (verified). `-AllUsers` untested. |
| A6 | Get-WindowsUpdateCompliance | P | P | - | P | P | P | ~ | P | P | - | P | P | Lifecycle table reviewed 2026-10; maintenance note now in README. `-Online` untested. |
| A7 | Get-RouterSecurityCheck | P | P | - | P | P | P | ~ | P | P | ~ | P | P | Correctly suppresses prompts when non-interactive. 10: inherits the shared 64 ceiling (it uses 1 probe at a time in practice). Interactive checklist untested. |
| A8 | Get-HomeDeviceInventory | P | P | - | P | P | P | ~ | P | P | - | P | P | Approved-tools file added this session and tested (file / override / missing). `-IncludeOtherUsers` untested. |
| A9 | Export-SecurityAuditReport | P | P | - | P | P | P | ~ | P | P | - | P | P | **Will not run on pwsh 7 on macOS/Linux**: embedded Core uses `$env:TEMP`, `$env:COMPUTERNAME`, `WindowsIdentity`. Does not show `Platform`; manual checklist covers router only, not iOS/Android/TV/console/IoT devices. |
| Bundle | Invoke-HomeAuditBundle | P | P | - | P | P | P | P | P | P | - | P | P | Windows only (no bash runner yet). |
| - | MSPToolkit.Common.psm1 | P | P | - | P | P | P | ~ | P | P | ~ | P | - | Source of the A1-A9 gaps above (schema, 64 ceiling, virtual fallback, Windows-only Core). |
| - | Sync-MSPEmbeddedHelper | P | - | P | - | P | - | - | - | P | - | P | - | `-Check` exits 1 on mismatch (verified: 10 matching). PowerShell targets only. |
| B1 | Get-ClientHealthSnapshot | ~ | P | - | ~ | ~ | F | F | F | P | - | P | P | Old style: no risk value, claims PS 3.0, no statuses, text only, no log, no export. Errors become strings in the report. |
| B2 | Get-NetworkConnectivityReport | ~ | P | - | ~ | P | ~ | F | F | P | - | P | P | Own PASS/FAIL/WARN, no SKIPPED/ERROR split; no export (prints "copy this command to export"); does not name the first failing layer as one answer. Risk "SAFE" should be Read-Only. |
| B3 | Get-RecentCriticalErrors | ~ | P | - | ~ | P | F | ~ | F | P | - | ~ | P | Default 24 h (catalog: 48 h). Header says admin required; System/Application logs are readable without it. CSV only, no JSON, no log. |
| B4 | Restart-CommonServices | ~ | - | F | ~ | P | F | F | F | P | - | ~ | P | 3: no `-WhatIf`, no confirmation, no `-Force` for non-interactive runs. Before/after state captured (good). Dnscache absent (catalog lists it). Help says "four services", code has three. `#Requires -RunAsAdministrator` gives a generic error, not a plain reason. Also *starts* stopped services, which is more than a restart. |
| C1 | Get-UserMailboxStatus | ~ | P | - | ~ | P | F | F | F | P | - | P | P | No holds, no archive, no inbox-rule forwarding check (mailbox-level forwarding only). Prompts with `Read-Host` when no address is given. No export/log. Not checked on pwsh 7. |
| C2 | Get-UserLicenseReport | ~ | P | - | ~ | ~ | F | ~ | F | P | - | ~ | P | **Fails to parse**: a stray `Connect-MgGraph` at line 71 sits above `[CmdletBinding()] param(...)` (it would also connect before parameters are read). Wrong folder. `#Requires -Version 5.1` (target: PS7). Does not say last sign-in needs Entra ID P1. |
| D1 | Clear-WindowsUpdateCache | ~ | - | F | ~ | ~ | F | F | ~ | P | - | F | P | **Deletes** SoftwareDistribution/catroot2 contents (`Remove-Item -Recurse -Force`); catalog requires rename. No `-WhatIf`, no confirmation, no `-Force`. Logs to `C:\MSP\Logs` (persists on client). "Safe / no data loss" overstates a delete with no undo (update history is lost). |
| D2 | Reset-NetworkStack | ~ | - | ~ | ~ | F | F | F | ~ | P | - | F | P | 11: synopsis claims "rollback capability"; the Clixml export is a record, not a restore. 5: `netsh`/`ipconfig` exit codes ignored, so failures are reported as SUCCESS. 3: confirms with `Read-Host` (hangs or fails non-interactively), no `-WhatIf`, no `-Force`. Refers to `Get-NetworkDiagnostics.ps1`, which does not exist (should be B2). Log written only at the end. |
| D3 | Reset-OutlookProfile | ~ | - | ~ | ~ | P | F | F | ~ | P | - | F | P | 3: `-WhatIf` and backup present, but it **deletes** the old profile (catalog: keep it) and force-kills Outlook instead of asking for it to be closed. 11: "recreate a clean default profile via registry" only creates empty MAPI keys; Outlook still needs the account set up, which the script does not say. `C:\MSP\Backups` hardcoded. Risk "MEDIUM" is not in the risk scale (should be Elevated). |
| - | Invoke-RC4AuditReport-SelfContained-v2 | ~ | P | - | ~ | ~ | F | ~ | F | P | - | P | P | Not in catalog. Writes CSVs (account names) **to the script's own folder by default**, which can be the repo or a USB stick. Includes Microsoft open-source code without its license notice. No risk level. |
| - | Set-InactivityTimeout | ~ | - | ~ | ~ | P | F | F | F | P | - | ~ | P | Not in catalog. Has ShouldProcess, but `-Force` means "rewrite even if equal" (clashes with the toolkit meaning); no before/after output, no log, no risk level. |

## 3. Risky patterns

| Severity | Where | Pattern |
|---|---|---|
| High | D1 | Deletion where rename would do; no dry run or confirmation. |
| High | D2 | Reports success when `netsh` fails; claims rollback it cannot do; offers `Restart-Computer -Force`. |
| High | D3 | Deletes the existing Outlook profile; kills Outlook processes. |
| High | C2 | Does not parse; network call (`Connect-MgGraph`) placed before the param block. |
| Medium | B4 | State change without `-WhatIf` / confirmation. |
| Medium | RC4 audit | Default output folder = script folder; client account names could be committed or left on a USB stick. |
| Medium | Shared module (A2/A4/A7) | Probe ceiling 64 > 32; scans a VPN/virtual subnet when no physical adapter has a gateway. |
| Low | D1, D3, B3 example | Hardcoded `C:\MSP\...` paths (D1 log, D3 backup root). B3's `C:\Temp` is only in an example. |
| Low | Repo | `.gitignore` did not cover run outputs (JSON/CSV/HTML/backup folders). **Fixed in this commit.** |
| None found | All | Hardcoded credentials, tenant IDs, or GUIDs (0 matches); PS7-only syntax in 5.1 scripts. |

## 4. Mapping, naming and folder mismatches

| Catalog | Repo today | Mismatch |
|---|---|---|
| A6 UpdateCompliance | `Get-WindowsUpdateCompliance.ps1` | Fine on Windows; bash siblings would be `get-update-compliance.sh` (the PowerShell name says "Windows"). Proposal: keep the PS name, use `get-update-compliance.sh` for bash, and give all three the same CheckId prefix `A6`. |
| C2 | `endpoint-systems/diagnostics/system-info/` | Move to `cloud-services/m365/diagnostics/`. |
| D2 | `endpoint-systems/remediation/elevated/network-reset/` | Rename folder to `network-resets/`. |
| E1 LocalAdminReport | none (logic in module `LocalAdmin` section, used by A1) | New script; reuse helper. |
| E2 InstalledSoftwareReport | none (logic in module `Software` section, used by A8) | New script; reuse helper; add EOL/watchlist data file. |
| E4 ServerHealthReport | `core-infrastructure/servers/audit/` exists, `{windows,linux}/diagnostics/` does not | Create catalog folders. |
| Risk vocabulary | B/C/D scripts use SAFE, LOW, MEDIUM, Minimal | Normalize to Read-Only / Safe / Elevated / Destructive. |
