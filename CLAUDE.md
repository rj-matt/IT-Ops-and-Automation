# Working rules for this repository

These rules apply to every working session on every machine (Windows, macOS, Linux).
Read README.md and docs/toolkit-review/ for the toolkit standards and the current plan.

## Network traffic

- No active network traffic beyond this machine without the owner's explicit approval for that
  specific run. That includes ping sweeps, port probes, SSDP/UPnP discovery, requests to the
  router's admin page, and reverse-DNS lookups of LAN addresses.
- Use passive modes, fake/mocked network data, or stop and ask. When asking, name the subnet
  and the exact scripts and parameters that would send traffic.
- The test harness (`tests/Invoke-ToolkitTests.ps1`) stays passive unless `-AllowActiveNetwork`
  is passed, and that switch is only used with approval for that run.

## Attribution

- No references to AI assistants or their vendors in commits, branch names, tags, pull requests,
  code comments, script headers or documentation. No `Co-Authored-By` or "Generated with" lines.
- Use the existing git identity. Never change git config.

## Commits

- Commit after each task or batch, with a clear message. Do not push.
- Never commit logs, exported results, or anything that identifies a client (host names, user
  names, MAC/IP addresses from real networks, account names). `.gitignore` covers the standard
  output names; check `git status` before every commit anyway.

## Testing

- Diagnostics may be run for real on the development machine in passive mode only.
- Remediation scripts are only run with `-WhatIf`, `-BackupOnly`, or non-interactively without
  `-Force` (which must refuse).
- Anything that could not be tested on the current machine is listed for the owner to run by
  hand, with exact commands.

## Reporting at each stop

- Write the stop's summary table, outstanding hand tests (with exact commands) and any
  active-network commands to `docs/toolkit-review/` (e.g. `batch-a-summary.md`), and commit it.
  Keep the chat summary to a few lines and point to the file; wide tables wrap in the terminal.
- Keep platform status honest: "run" only for a real run on that platform; Linux stays
  "stubbed only" until it has been run on a real Linux machine.
