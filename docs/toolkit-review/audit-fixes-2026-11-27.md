# Audit fixes (audit of 2026-11-27, commit 786b689)

Four pull requests, one per group. Development machine: macOS 26 (Apple silicon), PowerShell 7.6,
bash 3.2.57 and 5.3. Everything was run passive only: no harness run with `-AllowActiveNetwork`,
no tenant, no Microsoft Graph or Exchange Online connection, and no client network.

## Summary

| PR | Backlog | Scripts and versions | Tests added |
|---|---|---|---|
| #11 Log folder hardening | P0-01, P1-01 | Shared helpers: PowerShell 2.1.0, bash 1.4.0. Every script that embeds them goes up one patch version (54 scripts). The bundles' default results folder follows the log folder. | bash helper tests (planted foreign folder, folder link, log-name link and hard link, log swapped mid-run, no writable temp, modes 700/600); stubbed RMM case (planted results and log folders); PowerShell helper tests; `Test-RmmMode.ps1` (planted plain results folder: exit 3, nothing written; planted log folder: fallback used) |
| #12 C5 audit-log cap | P0-02 | `Get-AccountCompromiseTriage.ps1` 1.2.1 | Busy mailbox with the rule outside the first 5,000 records; every search capped; 6,000 deletions |
| #13 Reliability and test fixes | P1-02, P1-03, P2-01, P2-07 | C3 Linux 1.1.1, E4 Linux 1.1.1, A2 bash 1.1.1, B4 bash 1.1.1 | Stub cases with `ss`, `timedatectl`, `journalctl` and `ip` missing (C3, E4, A2, bundle); E4 `timedatectl` present but failing stays ERROR; B4 with no matching service (normal and RMM); proxy variables unset for every case; real mail domains replaced in the M365 fixtures |
| #14 Documentation refresh | P1-04, P2-04 | none (documentation only) | none |

The CI result for each PR is in its pull request.

## Not done, and why

- **P2-04:** all 10 `unverified` rows stay `unverified`. No official page confirmed a date:
  - QuickTime 7 (support.apple.com/en-us/106375): the page says "no longer supported" but gives no date.
  - Java SE 6/7 (oracle.com Java SE support roadmap): HTTP 403 to automated readers.
  - Fedora 43, 44, 45 (docs.fedoraproject.org EOL page): the page is behind a bot block.
  - RHEL 9, 10 (access.redhat.com errata policy): the dates table does not come with the page text, which says only that the dates are approximations.
  - Pop!_OS 22.04, 24.04: no source page (System76 publishes no end date).
  - macOS Sequoia (support.apple.com/en-us/100100): Apple publishes no end dates; the newest Sequoia entry is 15.8.3 of 2026-11-09.
- **Real public domains in tests:** `contoso.com` and `fabrikam.com` were left in place. They are Microsoft's standard example names for documentation, used in about 100 places.

## Outstanding hand tests

Windows, as SYSTEM, on a test PC (Sysinternals PsExec, elevated prompt). Real foreign ownership
is only simulated in CI and here.

```powershell
# 1. As a standard user (not admin), plant the folders:
New-Item -ItemType Directory C:\Windows\Temp\MSP-Toolkit
New-Item -ItemType Directory C:\ProgramData\MSP-Toolkit\results -Force
# 2. Then, from an elevated prompt:
psexec -s powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\MSP-Toolkit\endpoint-systems\diagnostics\storage\Get-DiskSpaceReport.ps1" -Rmm
echo $LASTEXITCODE        # 3: the results folder is not used
Get-ChildItem C:\Windows\Temp\MSP-Toolkit, C:\ProgramData\MSP-Toolkit\results   # both empty
Get-ChildItem C:\Windows\Temp -Filter 'MSP-Toolkit-*'                            # the private fallback with the log
icacls (Get-ChildItem C:\Windows\Temp -Filter 'MSP-Toolkit-*' | Select-Object -First 1).FullName
```

Check: exit 3 with "belongs to another account; it was not used"; nothing written into either
planted folder; the planted folders' ACLs are unchanged; the fallback's `icacls` lists only
Administrators and SYSTEM, with no inherited entries. Afterwards, delete the planted folders and
the fallback (as administrator).

macOS / Linux as root, with folders planted by a second, normal account:

```bash
sudo -u <other-user> mkdir -m 777 /tmp/msp-toolkit /var/tmp/msp-toolkit
sudo env -u SUDO_USER TMPDIR=/tmp bash endpoint-systems/diagnostics/storage/get-disk-space-report.sh --rmm; echo "EXIT=$?"
ls -la /tmp/msp-toolkit /var/tmp/msp-toolkit; ls -ld /tmp/msp-toolkit.*
```

Check: exit 3 ("Not used", owned by another account); both planted folders are empty; the log is
in `/tmp/msp-toolkit.XXXXXX` (`drwx------ root`, file `-rw------- root`). Afterwards, remove the
folders with sudo.

C5 (group 4 in `final-summary.md`): on a test user with a busy mailbox, check that a planted
inbox rule appears under "Mailbox changes" with its name. If a search hits 5,000 records, the
output says "minimum".

Linux without iproute2 (for example a minimal container), not as root:

```bash
bash core-infrastructure/networking/diagnostics/get-home-network-map.sh --passive
bash core-infrastructure/servers/linux/diagnostics/get-server-health-report.sh
```

Check: "ip / ss is not installed on this computer" as SKIPPED, with no ERROR.

## Active-network commands

None. Nothing in these changes needs network traffic beyond this machine to be tested.
