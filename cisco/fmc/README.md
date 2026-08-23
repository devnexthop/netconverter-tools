# Cisco Secure Firewall (FMC) — read-only collector

Pulls a **complete, read-only snapshot** of your Cisco Secure Firewall Management
Center (FMC) configuration over the REST API, renders a browsable HTML view, and
packages a single `fmc_audit_*.zip` you upload to **NetConverter** for audit,
optimization, and migration to Palo Alto / Fortinet.

Read-only: the collector only issues `GET` requests (plus the auth token call).
It never modifies your FMC.

## Requirements

- Python 3.8+
- Network reach to the FMC on HTTPS/TCP 443
- An FMC API user (a **read-only** user is recommended and sufficient)

```bash
pip install -r requirements.txt   # just: requests
```

## Quick start

```bash
# 1. Confirm connectivity + credentials
python fmc_test_auth.py --host FMC_HOST --user API_USER

# 2. Collect (prompts for password, or set FMC_PASSWORD)
python fmc_collect_data.py --host FMC_HOST --user API_USER --output .

# 3. Build the HTML view
python build_html.py --input run-YYYYMMDD-HHMMSS
open run-YYYYMMDD-HHMMSS/html_view/index.html

# 4. Package the single deliverable
python package_run.py --input run-YYYYMMDD-HHMMSS   # -> fmc_audit_YYYYMMDD-HHMMSS.zip
```

**One step (Linux/macOS)** — collect + HTML + zip:

```bash
./run_collect.sh --host FMC_HOST --user API_USER full
```

Windows: `run_collect.bat` (same flags). Lab / self-signed FMC: add `--insecure`.

## What you get

A timestamped `run-*/` folder containing the raw JSON snapshot, a `manifest.json`
(vendor, version, counts, duration), `completeness.csv`, `collection.log`, and a
self-contained `html_view/` site:

- **Dashboard** — inventory / policy / object KPIs (Cisco FMC theme)
- **Completeness** — live FMC totals vs what was captured, per object & rule type
  (see below)
- **Managed Devices** — per-device interfaces and static routes
- **Policies** — access, NAT, prefilter, intrusion, file, DNS (containers + rules,
  with colored action badges)
- **Objects** — applications, hosts, networks, network-groups, FQDNs, URLs,
  protocol-ports, port-groups, security-zones
- **Apps & URLs In Use** — the L7 applications/URLs/categories *actually referenced
  by access rules*, cross-referenced to those rules with catalog risk/type — the
  migration-relevant set for Palo App-ID / Fortinet application-control mapping
- **Export Excel / CSV** — every table has a one-click button that downloads the
  table as CSV (opens directly in Excel). No extra software.

### Multi-domain (MDS / multitenancy)

Add `--all-domains` to collect every authorized domain into `domains/<name>/`
subfolders; the HTML view merges them and the completeness audit runs per domain.

## Resilient authentication

The FMC token endpoint can return transient `401`/`429`/timeouts under load
(common on shared sandbox/lab systems) — a later attempt with the same
credentials succeeds. Both `fmc_test_auth.py` and `fmc_collect_data.py`
**automatically retry** the token call (up to 6 attempts, exponential backoff)
on 401/429/5xx and network errors. If you see `Auth 401 … retry in Ns`, that is
expected; let it run. A `FAIL` only after all attempts means a real credential
or access-policy problem.

## Completeness audit (proof you captured everything)

After every collect, the tool re-queries each endpoint's live `paging.count` and
compares it to what it saved, writing `completeness.csv` and a **Completeness**
HTML page:

| Status | Meaning |
|--------|---------|
| `complete` | Captured count matches the live FMC total — nothing missing. |
| `api_blocked` | The FMC REST API does not expose this on your version (e.g. **DNS rule bodies return 404**, SSL/health may 403/404). A documented platform limit, not a collection defect. |
| `PARTIAL` | Captured fewer than the live total — investigate / re-run. |

Counts also clarify nuances such as NAT: e.g. *81 NAT policy containers, 22 rules*
— most ASA-migration NAT containers are empty shells, which is normal and not a
loss.

### Known FMC API limitation
DNS **policies** are captured, but DNS **rule bodies** are not exposed by the FMC
REST API on current versions (`/dnspolicies/{id}/dnsrules` → HTTP 404). They will
show as `api_blocked` in the audit. NAT and access rules — the core of any
migration — are captured in full.

## Delivery

Send the single **`fmc_audit_*.zip`** (not the loose folder). It contains the
`run-*/` directory with JSON, `html_view/`, `completeness.csv`, and
`manifest.json`.

| Format | When |
|--------|------|
| **zip** (default) | Client handoff — opens natively on Windows/macOS/Linux |
| **tar.gz** (`--format tgz`) | Slightly smaller; Linux-only paths |

## Options (`fmc_collect_data.py`)

| Option | Meaning |
|--------|---------|
| `--host` | FMC IP or hostname, no `https://` (**required**) |
| `--user` | API username (**required**) |
| `--password` | Password (or `FMC_PASSWORD` env, else prompt) |
| `--domain-uuid` | Specific domain UUID (default: token domain) |
| `--all-domains` | Collect every authorized domain into `domains/<name>/` |
| `--output` | Output parent directory (default `.`) |
| `--insecure` | Skip TLS verification (lab / self-signed only) |
| `--quick` | Smoke test: subset of objects + access/NAT only |

Re-pull only per-device interfaces/routes into an existing run:

```bash
python backfill_device_details.py --input run-YYYYMMDD-HHMMSS \
  --host FMC_HOST --user API_USER --insecure
python build_html.py --input run-YYYYMMDD-HHMMSS
```

## License

MIT — ValeronLabs LLC / NetConverter
