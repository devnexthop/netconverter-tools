# Cisco Secure Firewall (FMC) — read-only collector

Pulls a **read-only snapshot with explicit capture coverage** of your Cisco Secure Firewall Management
Center (FMC) configuration over the REST API, renders a browsable HTML view, and
packages a single `fmc_audit_*.zip` you upload to **NetConverter** for audit,
optimization, and migration to Palo Alto / Fortinet.

Read-only: the collector only issues `GET` requests (plus the auth token call).
It never modifies your FMC.

## Requirements

- Python 3.8+
- Network reach to the FMC on HTTPS/TCP 443
- An FMC API user with read access to the requested domains and endpoints

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

Windows: `run_collect.bat` (same flags). The `.bat` helper forces UTF-8 so a
default Windows console cannot drop `collection.log` / `manifest.json` after a
successful pull. Lab / self-signed FMC: add `--insecure`.

## What you get

A timestamped `run-*/` folder containing the raw JSON snapshot, a `manifest.json`
(vendor, version, counts, duration), `collection-evidence.json`, `policy-assignments.json`,
`completeness.csv`, `collection.log`, and a
self-contained `html_view/` site:

- **Dashboard** — inventory / policy / object KPIs (Cisco FMC theme)
- **Completeness** — recorded FMC totals vs retained rows, per endpoint and policy
  (see below)
- **Managed Devices** — per-device interfaces and static routes
- **Policies** — access, NAT, prefilter, intrusion, file, DNS (containers + rules,
  with colored action badges)
- **Objects** — applications, hosts, networks, network-groups, FQDNs, URLs,
  protocol-ports, port-groups, security-zones
- **Apps & URLs In Use** — the L7 applications/URLs/categories *actually referenced
  by access rules*, cross-referenced to those rules with catalog risk/type — the
  migration-relevant set for Palo App-ID / Fortinet application-control mapping
- **Export CSV** — supported tables have a button that downloads the currently
  filtered rows as CSV (opens directly in Excel). No extra software.

FMC 2.3.3 requires shared core 1.1.2 for HTML CSV controls; distribute the matching
collector/core bundle. A builder error may leave a partial dashboard on disk and
must not be reported as a successful HTML build.

`policy-assignments.json` retains the native expanded policy/target array from
`/assignment/policyassignments`. It is authoritative assignment evidence; device
records are not rewritten to insert ACP/NAT references.

Each domain's `collection-evidence.json` has schema version 1, collector/version,
domain ID, and an `endpoints` map keyed by the exact config-relative API path.
Entries record `status` (`complete`, `partial`, `error`), `items_captured`,
`reported_total` (null if FMC supplied none), timestamps and individual page
offsets/counts/errors. Interface and IPv4/IPv6 fallback endpoints remain separate.
The same evidence is embedded in the domain snapshot. Native JSON is not annotated.
An empty rule array is saved only after successful complete collection; absent or
failed capture must not be interpreted as an empty policy.

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

## Completeness audit and limits

After every collect, the tool compares saved endpoint evidence and actual reported
`paging.count` with retained rows, writing `completeness.csv` and a **Completeness**
HTML page. Rule endpoints are audited per policy; a captured count is never used
as an independent live total. A later successful probe cannot erase an earlier
pagination failure.

| Status | Meaning |
|--------|---------|
| `complete` | Recorded pagination reached the FMC-reported total. |
| `captured` | Successful capture, but FMC supplied no independent total. |
| `api_error` | Request failed; review the recorded HTTP status, permissions, version and endpoint. |
| `PARTIAL` | Pagination failed, repeated/skipped rows, changed totals, or exceeded bounds. |
| `not_collected` | Endpoint was not attempted, for example in quick mode. |

Counts also clarify nuances such as NAT: e.g. *81 NAT policy containers, 22 rules*
— most ASA-migration NAT containers are empty shells, which is normal and not a
loss.

Requests returning 403/404 do not establish that the platform lacks a feature.
Historical captures used the label `api_blocked`; inspect their underlying evidence.
NAT ordered/auto/manual endpoints overlap and their row counts are not additive.
Counts do not prove atomic capture, deployment state, inheritance, HA, live routing,
hit counters or migration equivalence. Those remain separate evidence requirements.

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
