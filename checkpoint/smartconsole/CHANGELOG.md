# Changelog — Check Point SmartConsole (`checkpoint/smartconsole/`)

All notable changes to the Check Point collector bundle. Collect and HTML share
one `__version__` (entry script + `build_html.py`).

## [1.5.6] — 2026-08-19

### Fixed

- **Threat exception fetch still empty on R81 CMA** — v1.5.5 sent `layer-uid`
  with `layer-name`. This Management API returns
  `generic_err_invalid_parameter_name: Unrecognized parameter [layer-uid]`.
  Payload now sends `layer-name` / `name` first and retries with `layer-uid`
  only if the API reports a missing layer parameter.

## [1.5.5] — 2026-08-18

### Fixed

- **HTTPS rulebases skipped on R81 CMA** — `show-package` often returns
  `https-inspection-policy: true` plus a sibling `https-inspection-layers`
  dict (`inbound-https-layer` / `outbound-https-layer`). The collector only
  looked at `https-layers` (list), `https-inspection-layer` (singular), or a
  **dict** `https-inspection-policy`. It never called `show-https-rulebase`.
  All three shapes plus the inbound/outbound map are now collected.
- **Threat exception rulebases failed** — `show-threat-rule-exception-rulebase`
  requires `layer-name` or `layer-uid`. The collector sent `rule-uid` and
  omitted the layer, so the API returned
  `generic_err_missing_required_parameters`. Payload now always includes
  `layer-name`, `layer-uid` (from `exceptions-layer`), and `rule-uid`.
- **VPN community `gateways: []`** — list calls (`show-vpn-communities-*`
  details-level full) often return empty membership. Collector now re-fetches
  each community with `show-vpn-community-meshed|star|remote-access` (UID)
  and falls back to `show-object`.

### Added

- `collect_helpers.py` + `test_collect_helpers.py` (no Management API required).
- Customer re-collect note: [CUSTOMER_RECOLLECT.md](CUSTOMER_RECOLLECT.md).
- Gaia routing companion: `show ipv6 route` (optional `show arp` /
  `show vpn tunnels` in the printed mop).

## [1.5.4] — 2026-08-15

### Changed

- **Non-VSX HA hierarchy copy** — L1/L2 notes no longer claim VSX0 / Virtual
  Systems on physical ClusterXL pairs (e.g. Spark 1570/1590).
- **Gateway detail interfaces** — zone, anti-spoof, network CIDR, and topology
  including `not defined` (was Internet / blank only).

## [1.5.3] — 2026-08-06

### Fixed

- **Threat profiles empty export** — `show-threat-profiles` often returns
  `total > 0` with an empty `objects[]` list. Collector now recovers via
  `show-objects type=threat-profile` and per-UID `show-threat-profile`
  (`details-level full`) for every profile referenced by Threat Prevention
  rules, so IPS / Anti-Bot / Anti-Virus / Threat Emulation settings land in
  `objects-threat-profiles.json`.
- **Threat exception rulebases** — parent TP rules that declare exceptions now
  trigger `show-threat-rule-exception-rulebase`; results saved as
  `policy-by-package/<pkg>/threat-exceptions-*.json`.

### Added

- **Threat Profiles** HTML page (`threat-profiles.html`) — IPS / Anti-Bot /
  Anti-Virus / TE columns, where-applied, and warnboxes when only name stubs
  exist (pre-1.5.3 pulls).
- **Threat Prevention** page — Exceptions column + exception detail tables;
  profile deep-links; notes clarifying empty standalone IPS layers vs merged TP.
- **Applications** page note — App Control / URL Filtering lives in Access
  **Service**; Identity Awareness via Access Roles in **Source**.
- Export coverage flags: `missing-threat-profile-detail`,
  `missing-threat-exceptions`.

## [1.5.2] — 2026-07-22

### Changed

- **Packages page layout** — per-package dossier now uses the same HTML primitives
  as the rest of the viewer (`cards` summary, `section-title`, `table-wrap` tables)
  instead of custom card CSS. Data unchanged (Access / NAT / Threat / HTTPS /
  gateways / object-type counts).

## [1.5.1] — 2026-07-22

### Added

- **Per-package dossier** on Packages page — Access / NAT / Threat / HTTPS layers,
  gateways installing the package, and UID-deduped object-type counts from the
  package rulebase dictionaries (competitor-parity package summary, denser cards).

## [1.5.0] — 2026-07-22

### Added

- **DNS Domains (FQDN)** inventory page (`dns-domains.html`) — surfaces
  collected `objects-dns-domains.json` (previously collected, not rendered).
  Nav: Inventory → DNS Domains.

### Notes

- Assessment finding `name_too_long_for_palo` (PAN-OS 63-char limit) lives in
  NetConverter.local / deliverable_v2, not in this standalone HTML builder.

## [1.4.0] — 2026-07-07

### Added

- **Global Properties & Implied Rules** page in `build_html.py` — surfaces
  `global-properties.json`, which was collected but never rendered. Includes:
  - **Implied rules** table (the hidden rulebase): each `accept-*` rule with
    ENABLED/disabled status, position (first / before last / last), and a
    migration note. Enabled implied rules permit traffic that never appears in
    the explicit rulebase and must be reproduced as explicit rules on
    Palo Alto / Fortinet.
  - **Global NAT** (bi-directional NAT, automatic ARP, IP Pool NAT).
  - **Stateful Inspection** (TCP/UDP/ICMP/SCTP timeouts, drop-out-of-state).
  - **VPN / Remote Access** global posture, **Hit Count**, **Log & Alert**.
  - Per-package **HTTPS Inspection layer** wiring read from each
    `policy-by-package/<pkg>/package.json` (not present in top-level
    `packages.json`).
- New nav entry **Policy → Global Properties & Implied Rules** (shown in both
  browse-only and `--analysis` modes — it is core config, not heuristic analysis).
- Linux Python install guide: `INSTALL_PYTHON_LINUX.md` (Windows guide unchanged).

### Fixed

- Closes the data-surfacing gap where `global-properties.json`, per-package
  `package.json`, and `access-layers-shared/_inventory.json` were collected but
  invisible in the HTML view.
- CVE intel prefetch now resolves repo root correctly (`parents[2]`) so
  `core.cve_intel` imports during collection (was silently skipped).
- Collect `__version__` aligned with HTML at **1.4.0** (was stuck at 1.2.0 while
  CHANGELOG/HTML advertised 1.3.x–1.4.0).

## [1.3.4] — 2026-06-24

### Added

- **Export Coverage** page: per-flag remediation with **Collector (Python)** commands,
  **Manual / Gaia / SmartConsole** steps, and **safe to ignore** badges.
- `collection_remediation.py` — shared guidance for audit flags (used by
  `export_quality_audit.py` and `build_html.py`).
- Dynamic re-collect command on Coverage page (only adds `--full-objects` /
  `--where-used` when those flags are active).
- Routing companion command block when `routing/` is missing (Gaia SSH, not API).
- `administrators.json` MDS-domain error documented as expected on single-domain SMS.

## [1.3.3] — 2026-06-24

### Added

- All **Inventory** pages (Hosts through Dynamic Objects) now use the same Excel-style
  filter bar, click-to-sort headers, and Export CSV as Gateways and Interfaces.

## [1.3.2] — 2026-06-24

### Added

- **Gateways & Servers** and **Interfaces / IPs**: Excel-style filter bar (text search,
  column filters, checkboxes), click-to-sort column headers with ▲▼ indicators, and
  Export CSV (visible rows only).

## [1.3.1] — 2026-06-24

### Changed

- `build_html.py`: customer HTML browser is **browse-only** by default — Optimization,
  Simplify & Merge, Compliance (NIST/CIS), and Versions/CVE pages are omitted from nav
  and not generated (faster build, no heuristic findings in the collector bundle).
  Use `--analysis` for the NetConverter.local engagement workflow.

## [1.3.0] — 2026-06-23

### Added

- `build_html.py`: **Physical Appliances** page — platform stacks (VSX HA cluster →
  physical members → virtual systems) with policy package, role hints, and L2
  Switch VS callouts.
- `build_html.py`: **Firewall View** platform hierarchy — expandable L1 Cluster →
  L2 Physical → L3 VSX0 → L4 Virtual tree per VSX platform; interface and
  applicable/total rule counts at each level; breadcrumb back to platform from
  gateway detail.
- `build_html.py`: gateway detail pages show **applicable rules first** (Install On,
  cluster parent, or Policy Targets) with full shared package in a collapsible
  “other install targets” section.
- `core/html_theme.py`: styles for platform stacks (`.plat-stack`) and firewall
  hierarchy (`.fw-platform`, `.fw-level`); `filterBlocks()` for platform search.
- `build_html.py`: fixed **vX.Y.Z** badge (top-right) on every page from `__version__`.

### Changed

- `build_html.py`: **Firewall View** — hierarchy is the primary navigation; legacy
  flat SMS inventory table moved to a collapsed section at the bottom.
- `build_html.py`: dashboard gateway topology links to Physical Appliances and
  hierarchy-aware Firewall View.

## [1.2.0] — 2026-06-23

### Added

- `build_html.py`: **VPN Communities** page redesign — community summary table plus a
  flat, searchable peer list (hub/spoke/member/RA gateway, VPN IP, device type, VSX
  parent); topology explainer; empty communities flagged.
- `build_html.py`: expanded built-in UID resolution and embedded/stub object harvest so
  threat, NAT, and track/action columns show readable names instead of raw UIDs.
- `build_html.py`: **Security zones** page — gateway interface assignments, role/domain
  columns, rule-reference hints.
- `build_html.py`: **Time objects** — human-readable active window, recurrence, daily
  schedule, and inferred rule usage column.
- `build_html.py`: NAT viewer — summary column, translated IPs, clickable object links.
- `build_html.py`: `--version` flag on collector and HTML builder CLIs.

### Fixed

- `build_html.py`: **Interfaces** page — IPv4 column used invalid markup (`span` instead
  of `td`), breaking the table layout.
- `build_html.py`: **Access roles** — `users: "all identified"` and `networks: "any"`
  no longer render as character-by-character garbage.
- `checkpoint_collect_data.py`: threat rulebase export requests
  `use-object-dictionary: true` and merges `objects-dictionary` for resolved
  action/track names on future collects.

### Changed

- `build_html.py`: VPN page no longer duplicates each community in a long scroll section
  or dumps every hub interface — one summary row + one peer row per gateway.

## [1.1.0] — 2026-06-23

### Added

- `export_quality_audit.py` — read-only export completeness auditor (access rulebase
  truncation, per-rule hit counts, HTTPS rulebases, object NAT settings, native
  where-used, orphan packages). Invoked automatically when collecting with
  `--verify-export`, or standalone via `python export_quality_audit.py run-*`.
- `build_html.py`: **Export Coverage** page (audit flags, re-collect command, API
  capability matrix); **Threat Prevention** rule viewer (IPS / Threat layers);
  inventory pages for access roles, users, time objects, security zones, and
  dynamic objects; merge of native `--where-used` data into Relationships; object
  NAT column on hosts/networks/ranges when `--full-objects` was used.
- README: documented `--full-objects`, `--where-used`, `--verify-export`; audit and
  HTML browser workflow (Step 3b / 3c).

### Fixed

- Access rulebase pagination uses the Management API `to` field as the next offset,
  avoiding premature exit at `access-section` boundaries on large layers.

### Changed

- `--verify-export` post-collection hook now ships with the audit script it invokes
  (previously referenced but missing from the repo).

## [1.0.0] — 2026-06-23

### Added

- First versioned release. Read-only Management API collector: paginated pull of
  packages, layers, objects, NAT, gateways, VPN; optional `--where-used`
  reverse-references; per-rule hit-count capture (`show-hits: true`).
