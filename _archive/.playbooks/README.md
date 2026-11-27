# Playbooks

## What Is a Playbook?

A playbook is a multi-step, opinionated workflow that orchestrates scripts from across the toolkit to accomplish a complete operational task — from start to finished output.

Playbooks are different from domain scripts:

| Domain Scripts | Playbooks |
|---|---|
| Do one thing well | Run a full procedure |
| Live in `endpoint-systems/`, `core-infrastructure/`, etc. | Live here in `playbooks/` |
| Named after actions: `Get-`, `Test-`, `Repair-` | Named after tasks: `Invoke-` |
| Reusable building blocks | Orchestrate those building blocks |
| Scoped to a single function | Scoped to a complete technician workflow |

---

## Who Should Use Playbooks?

Playbooks are designed to be run by any technician, Tier 1 through Tier 3. They are written to be safe to execute without modification. Read the README inside each playbook folder before running — it will tell you exactly what the script does, what it needs, and what output to expect.

---

## Structure

Each playbook is a self-contained folder:

```
playbooks/
├── network-discovery/
│   ├── Invoke-NetworkDiscovery.ps1     # The script
│   ├── README.md                       # How to run it, what to expect
│   └── outputs/                        # Reports drop here at runtime
│
├── endpoint-triage/
├── new-client-onboarding/
├── incident-response-triage/
├── server-health-audit/
│
└── _shared/                            # Shared utilities called by playbooks
```

### `_shared/`

Utility scripts used by multiple playbooks. These are not meant to be run directly — they are called internally by playbook scripts. Do not run scripts from `_shared/` standalone unless you know what you are doing.

---

## Current Playbooks

| Playbook | Purpose | Risk Level |
|---|---|---|
| `network-discovery` | Scan and map a network — live hosts, hostnames, open ports, MAC addresses | Read-only |
| `endpoint-triage` | First-look diagnostics for a problem endpoint — performance, disk, network, events | Read-only |
| `new-client-onboarding` | Baseline setup and documentation capture for a new client environment | Low |
| `incident-response-triage` | Initial triage for a suspected security incident — isolation, evidence capture, account review | Elevated |
| `server-health-audit` | Full health and configuration audit of a Windows server | Read-only |

---

## How to Run a Playbook

1. Open PowerShell as Administrator
2. Navigate to the playbook folder
3. Read the `README.md` in that folder first
4. Run the script:

```powershell
.\Invoke-NetworkDiscovery.ps1
```

Or with parameters if required:

```powershell
.\Invoke-NetworkDiscovery.ps1 -Subnet "192.168.1.0/24" -OutputPath ".\outputs\"
```

Each playbook will tell you exactly what parameters it accepts.

---

## Output

Every playbook produces a plain-text or CSV report saved to its `outputs/` folder. Output is formatted to be copied directly into a support ticket or attached as documentation. The report will include a timestamp, the technician's machine name, and a summary of findings.

Output files are excluded from source control. Do not commit anything from an `outputs/` folder.

---

## Adding a New Playbook

1. Create a new folder under `playbooks/` using kebab-case: `my-new-playbook/`
2. Name the script `Invoke-MyNewPlaybook.ps1`
3. Include a `README.md` using the standard template (see `_shared/PLAYBOOK-TEMPLATE.md`)
4. Create an empty `outputs/` folder with a `.gitkeep` file inside
5. If the playbook shares utility logic with others, place that logic in `_shared/` rather than copying it

Follow the script standards defined in the root `README.md` of this repository.

---

## A Note on Risk

Playbooks are categorized by risk level. Before running any playbook, confirm the risk level in its `README.md`:

- **Read-only** — collects information only, makes no changes
- **Low** — makes minor, reversible changes (writing files, starting services)
- **Elevated** — makes meaningful changes to system state; confirm scope before running
- **Destructive** — irreversible actions; requires explicit sign-off before use

When in doubt, run diagnostics first and escalate before proceeding to anything elevated or above.
