# Check Point Audit — Data Collection Instructions

This script exports firewall configuration from **your** Check Point **Management Server** (SmartCenter) using the official Management API. It is **read-only** — it does not change policies or install anything.

**Important:** Use the management IP, username, password, and port for **this** environment only. Do not reuse values from another site or from examples in this document unless they match your server.

## Before you start

Ask your Check Point administrator to confirm:

1. **Management API** is enabled on the management server.
2. You have a **read-only API user** (username and password).
3. Your PC can reach the management IP on the API port (often **4434**, sometimes **443**).
4. **Python 3.8+** is installed on your PC.  
   → Windows: [INSTALL_PYTHON_WINDOWS.md](INSTALL_PYTHON_WINDOWS.md)  
   → Linux: [INSTALL_PYTHON_LINUX.md](INSTALL_PYTHON_LINUX.md)

## Step 1 — Install dependencies

Open **Command Prompt** or a terminal, go to this folder, and run:

```bash
cd path/to/netconverter-tools/checkpoint/smartconsole
pip install -r requirements.txt
```

On Linux, use `pip3` and see [INSTALL_PYTHON_LINUX.md](INSTALL_PYTHON_LINUX.md) for venv setup.

## Step 2 — Run the collector

Replace the values with your environment:

```bat
python checkpoint_collect_data.py --mgmt-ip YOUR_MGMT_IP --username YOUR_API_USER --password "YOUR_PASSWORD" --port 4434 --full-objects --where-used --verify-export
```

| Option | Meaning |
|--------|---------|
| `--mgmt-ip` | Management server IP or hostname |
| `--username` | API username |
| `--password` | API password |
| `--port` | API port (default **4434**; use `443` if your admin says so) |
| `--output` | Optional folder for output (default: current folder) |
| `--full-objects` | Host/network/range objects at **full** detail (object-level NAT + group membership) |
| `--where-used` | Native Check Point `where-used` per object (ground-truth references; slower) |
| `--verify-export` | Run export quality audit after collection; warn on critical gaps |

**Windows shortcut:** double-click `run_collect.bat` and answer the prompts.

## Step 3 — What you should see

- A new folder: `run-YYYYMMDD-HHMMSS\` (JSON files)
- A zip file: `checkpoint_audit_YYYYMMDD-HHMMSS.zip`

## Step 3b — Local HTML browser (optional, read-only)

Browse the export in your browser with the same Check Point theme as NetConverter.local:

```bat
python build_html.py --input run-YYYYMMDD-HHMMSS
start run-YYYYMMDD-HHMMSS\html_view\index.html
```

Includes dashboard, export coverage audit, policies (access/NAT/threat/HTTPS),
**Threat Profiles** (IPS/Anti-Bot/AV/TE), objects, relationships, VPN communities,
and **Global Properties & Implied Rules** — read-only browse (no optimization/
compliance/CVE).

**v1.5.6:** threat exceptions omit `layer-uid` on R81 (that parameter is
rejected); HTTPS dict layers remain from 1.5.5.

**v1.5.5:** collects HTTPS layers when the package uses an
`https-inspection-layers` dict; sends `layer-name`/`layer-uid` on threat
exception fetches; fills VPN community membership via per-UID show.
If you already sent a 1.5.4 (or older) zip, re-run — see
[CUSTOMER_RECOLLECT.md](CUSTOMER_RECOLLECT.md).

**v1.5.3:** recovers threat profiles when `show-threat-profiles` returns empty
(`show-threat-profile` per UID), exports threat exception rulebases, and adds
the Threat Profiles HTML page. App/URL Filtering = Access Service column;
Identity Awareness = Access Roles in Source.

**v1.4.0:** new **Global Properties & Implied Rules** page surfaces
`global-properties.json` — the implied ("hidden") rulebase, global NAT,
stateful-inspection timeouts, VPN/remote-access posture, hit-count, and logging.
Enabled implied rules permit traffic outside the explicit rulebase and must be
reproduced explicitly when migrating to Palo Alto / Fortinet.

**v1.3.1:** analysis pages (Optimization, Simplify & Merge, Compliance, CVE) removed
from the customer bundle; use `--analysis` only in NetConverter.local engagements.

**v1.3.0 highlights:** VSX platform stacks on **Physical Appliances**; **Firewall
View** top-down hierarchy (cluster → physical → VSX0 → virtual) with applicable
rule counts; gateway pages filter rules to what installs on that object first.

**v1.2.0 highlights:** readable threat/NAT/action names (fewer raw UIDs), fixed
interfaces table, access-role and time-object formatting, enriched security zones,
and a redesigned VPN page (summary + searchable peer list).

## Step 3c — Audit export completeness (optional)

```bat
python export_quality_audit.py run-YYYYMMDD-HHMMSS --output run-YYYYMMDD-HHMMSS\audit
```

Checks rulebase truncation, hit counts, HTTPS rulebases, object NAT settings, and native where-used. The HTML browser also surfaces these flags on **Export Coverage**.

## Step 4 — Send to ValeronLabs

Email or upload **only the zip file** (`checkpoint_audit_*.zip`).  
Do not send SmartConsole credentials separately unless ValeronLabs asks.

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| `Login failed` | Wrong IP, port, username, or password |
| `python` not recognized | Install Python; see [INSTALL_PYTHON_WINDOWS.md](INSTALL_PYTHON_WINDOWS.md) or [INSTALL_PYTHON_LINUX.md](INSTALL_PYTHON_LINUX.md); on Windows try `py -3` instead of `python` |
| Connection timeout | Firewall blocking port 4434/443 from your PC to management |
| SSL/certificate errors | Script disables certificate verify for self-signed certs (expected) |
| Corporate PC locked down | Run from a jump host/VM that has Python and network access to management |

## What this does NOT collect

Management API cannot see live Gaia state. If ValeronLabs asks for routing / HA /
IPsec, use [checkpoint_collect_routing.py](checkpoint_collect_routing.py) or
the clish mop in [CUSTOMER_RECOLLECT.md](CUSTOMER_RECOLLECT.md):

- Live routing (`show route`, `show route static`, `show ipv6 route`)
- Cluster state, interfaces, `show configuration`
- Optional: ARP, IPsec tunnel table (`show vpn tunnels` if the version has it)
