# Fortinet FortiManager — read-only collect

Read-only collector + local HTML browser for a **FortiManager** (manages FortiGate
firewalls). Uses the documented FortiManager **JSON-RPC API** (`POST /jsonrpc`). It
only issues `get` calls (plus login/logout) — it never writes to the FortiManager
database. Pre-shared keys are redacted from the output.

## What it collects

For every ADOM (auto-detected; falls back to implicit `root` when ADOMs are
disabled) and every managed device / VDOM:

- **Devices** — managed FortiGates: serial, mgmt IP, platform, OS, HA, VDOMs
- **Interfaces** — per-device interfaces with IP/mask, status, admin access, VLANs
- **Static routes** — per-device, per-VDOM
- **Policy packages** + **firewall policies** (per package)
- **Objects** — addresses, address groups, services, service groups
- **NAT** — VIPs (DNAT), IP pools (SNAT)
- **VPN** — IPsec phase 1 / phase 2 interfaces, SSL VPN portals

### Live-only state (perishable — captured by default)

Collected via a read-only proxy (`/sys/proxy/json`) to each **online** device.
None of this exists in a config backup; it can only be captured while the
devices are reachable. Opt out with `--no-live-state`.

- **Policy hit counters** (`policy_hits`) — per-device, per-VDOM bytes / packets
  / active sessions / **first_used** / **last_used** per policyid. This is the
  FortiGate equivalent of Check Point retained hit data and is what powers the
  behavior-preserving rule review (proving a rule is *never matched in the
  window*). **Grab this while on-site — it cannot be recovered later.**
- **HA / cluster sync state** (`ha_status`) — live cluster members + checksum
  sync; config backups do not reliably show live HA health.
- **Resource usage** (`sessions`) — session load / CPU / memory snapshot.
- **Effective routing table / FIB** (`routes_live`) — the routes actually
  installed, per device+VDOM.

Raw payloads are also saved under `live-state/<device>/*.json`. The HTML browser
surfaces them under **Live State** (Policy Hit Counters, HA / Cluster Sync,
Resource Usage, Live Routes).

## Local (device) firewall policies

Many FortiManager deployments manage FortiGates **without** a central policy
package — the firewall **policies** (and many objects) live *locally on each
device*. In that case the JSON-RPC pull legitimately returns `policies: 0`
because there is nothing central to read.

To see those device-local rules, NetConverter reads each FortiGate's full
config backup (the FortiOS `.conf` you can export from FortiManager's per-device
**revision history**, or pull automatically — see below) and merges the
device-local data into the same snapshot. This fills in:

- **Firewall policies** per device (the central-pull gap)
- Device-local **addresses / groups / services / VIPs / IP pools** referenced
  by those policies (deduplicated across devices, with every device they appear
  on listed under *Device(s)*)
- Routes / interfaces / VPN for any device the central pull did **not** cover

### Option A — pull the configs automatically (recommended)

Add `--pull-device-configs` to the collector. FortiManager proxies a read-only
GET to each managed FortiGate's own monitor API
(`/api/v2/monitor/system/config/backup` via `/sys/proxy/json`) and saves the
result under `<run>/Local Configs/`:

```bash
python fortimanager_collect.py --host fortimanager.example.com --user api_ro \
    --pull-device-configs --output .
```

The target devices must be **online / reachable** from the FortiManager for the
proxy backup to succeed (offline devices are skipped and noted).

### Option B — export configs manually

In FortiManager: *Device Manager ▸ \<device\> ▸ Config ▸ Revision History ▸
Download*. Drop the resulting `.conf` files into a folder named
`Local Configs` inside the run bundle. `build_html.py` auto-detects it.

Either way, the merge happens automatically at build time. Override or disable
with `--local-configs <dir>` / `--no-local-configs`.

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`
- A FortiManager API/admin user with read access, reachable on TCP **443** (the
  JSON-RPC endpoint).

## Usage

```bash
pip install -r requirements.txt

# Collect (auto-detects ADOMs; use --adom NAME to limit to one)
python fortimanager_collect.py --host fortimanager.example.com --user api_ro --output .

# Build the local HTML browser from the resulting bundle
python build_html.py --input run-YYYYMMDD-HHMMSS
```

| Option | Meaning |
|--------|---------|
| `--host` | FortiManager hostname or IP |
| `--user` | API username |
| `--password` | Password (prompted if omitted) |
| `--adom` | ADOM to collect (default: auto-detect / all) |
| `--output` | Output parent directory (default: current) |
| `--verify-tls` | Verify the TLS cert (default: off for self-signed mgmt certs) |
| `--pull-device-configs` | Also pull each FortiGate's full running config (device-local policies/objects) into `<run>/Local Configs/` |
| `--zip` | Package the run bundle into a single `fortinet_audit_<timestamp>.zip` next to the run folder |
| `--no-extract` | With `--zip`, delete the extracted run folder afterwards so only the `.zip` remains |

### `build_html.py` options

| Option | Meaning |
|--------|---------|
| `--input` | Run bundle folder produced by the collector |
| `--output` | HTML output folder (default: `<run>/html_view`) |
| `--local-configs` | Folder of per-device `.conf` backups (default: auto-detect `Local Configs/`) |
| `--no-local-configs` | Skip merging any device `.conf` backups |
| `--offline` | Skip live CISA KEV / NVD lookups (use cache/curated data) |

## Output

```
run-YYYYMMDD-HHMMSS/
  manifest.json                 # vendor, host, ADOMs, per-dataset counts
  fortimanager_snapshot.json    # full read-only export
  Local Configs/                # per-device .conf backups (if pulled/added)
  html_view/index.html          # local browser (after build_html.py)
```

## HTML browser

```bash
python build_html.py --input run-YYYYMMDD-HHMMSS
```

Self-contained static site using the shared NetConverter chrome with the
**Fortinet red + navy** accent. Pages: dashboard (inventory / objects / VPN /
health KPIs + IPsec-tunnels-per-device), **VPN Map** (interactive IPsec topology
— FortiGates, remote gateways, tunnels, and toggleable local/remote networks
with drag/zoom/pan), managed devices, interfaces, static routes, policy
packages, firewall policies, address & service objects/groups, VIPs, IP pools,
IPsec phase 1/2, SSL VPN, and raw JSON.
