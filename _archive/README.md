# _archive

Superseded or untrusted files kept for reference only. **Nothing in this folder is to be run
on a client machine, copied to a USB stick, or included in any bundle.**

- `Invoke-HomeAuditBundle.ps1` refuses to run any script whose path is under `_archive\`.
- `Sync-MSPEmbeddedHelper.ps1` skips this folder.
- `.gitattributes` marks `_archive/` as `export-ignore`, so `git archive` and "Download ZIP"
  packages leave it out.

Paths below mirror where each file used to live.

| File | Archived | Reason | Replaced by |
|---|---|---|---|
| `core-infrastructure/networking/diagnostics/wifi-security/Check-WifiSecurity.ps1` | 2026-10-14 | Read every saved Wi-Fi password (`netsh ... key=clear`); unapproved verb; garbled catch block | `core-infrastructure/networking/diagnostics/Get-WiFiSecurityAudit.ps1` |
| `core-infrastructure/networking/diagnostics/gateway-security/Check-GatewaySecurity.ps1` | 2026-10-14 | Flagged legitimate DNS resolvers (Quad9, Comodo) as malicious; `http://$IP:8080` expansion bug; no real UPnP detection | `core-infrastructure/networking/diagnostics/Get-RouterSecurityCheck.ps1` |
| `core-infrastructure/networking/diagnostics/subnet-mapping/Get-SubnetMap.ps1` | 2026-10-14 | Ping sweep broken on PowerShell 5.1 (`-TimeoutSeconds`); sent MAC prefixes to an internet API; no subnet-size limit | `core-infrastructure/networking/diagnostics/Get-HomeNetworkMap.ps1` |
| `endpoint-systems/diagnostics/system-info/Check-BrowserSecurity.ps1` | 2026-10-14 | Opened browser credential stores (`logins.json`, `Login Data`); stale hardcoded version baselines | `endpoint-systems/diagnostics/system-info/Get-BrowserSecurityCheck.ps1` |
| `endpoint-systems/audit/inventory/Get-DeviceInventory.ps1` | 2026-10-14 | Required admin; probed other machines over WinRM/DCOM without showing scope; broken parallel path | `endpoint-systems/audit/software-inventory/Get-HomeDeviceInventory.ps1` (local) and, later, `Get-InstalledSoftwareReport.ps1` |
| `core-infrastructure/servers/audit/Audit-ServerSecurity2.0.exe` | 2026-10-14 | **Unsigned binary with no source code in the repository.** Cannot be reviewed; do not run. | None yet (server audit is Batch E: `Get-ServerHealthReport.ps1`) |
| `security-operations/hardening/server-hardening/Set-InactivityTimeout2.0.exe` | 2026-10-14 | **Unsigned binary**; may not match `Set-InactivityTimeout.ps1`, which remains the reviewed source. | `security-operations/hardening/server-hardening/Set-InactivityTimeout.ps1` |
