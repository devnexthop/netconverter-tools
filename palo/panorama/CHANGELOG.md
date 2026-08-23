# Changelog — Palo Alto (`palo/`)

All notable changes to the Palo Alto Panorama export bundle (`panorama_export.py`,
HTML browsers, and shared models). Collect (`panorama_export.py`) and HTML
(`palo/common/html_version.py`) share version **1.6.1**.

## [1.6.1] — 2026-08-22

### Fixed

- **`show devices all` now retries with backoff (4 attempts, 1s / 2s / 4s).** This
  single request is the only source of every hostname, model and HA state in a
  snapshot — lose it and a complete config still renders a table of blank device
  names. It was one-shot while the config branch fetches around it already
  retried, which was backwards. Found live on a degraded customer link where it
  timed out once and succeeded on the very next attempt.

  A well-formed response containing zero devices is treated as a real answer, not
  a transport failure, so it does not burn retries. On total failure the collector
  states plainly that the snapshot will have no hostnames and to re-run.

  Verified both paths: against an unreachable host, 4 attempts over 7.1s then a
  clear warning; against a live Panorama, 12 devices / 12 hostnames / 5 HA states
  in 0.5s. Forced-error output contains **0** occurrences of the API key.

## [1.6.0] — 2026-08-22

### Added

- **`--running-config`: pull the entire running config in one request.** PAN-OS
  answers `type=export&category=configuration` with the whole tree. Measured on a
  real 12-firewall estate: **1.5 MB in 2.1 seconds**, against roughly **50**
  separate per-entry fetches for the same content.

  On a degraded link this is not an optimisation, it is correctness. Observed
  live during a customer site network upgrade: the per-entry path averaged one
  connection failure per two device groups — **5 OK / 3 FAIL after six minutes**,
  still only partway through device groups — and was heading for a partial
  snapshot. The single call succeeded first time; the whole export finished in
  **72 seconds**. One request has one chance to fail; fifty have fifty.

  Completeness in this mode is **by construction** rather than by audit: you
  cannot miss a branch you never had to enumerate.

  Verified identical to a per-entry capture of the same estate on every object
  type — 21 device-groups, 27 templates, 12 template-stacks, 628 addresses, 54
  address-groups, 65 services, 7 profile-groups, 15 application-filters, 16 tags,
  24 certificates, 12 managed devices.

### Changed

- Two branches are stripped before writing in `--running-config` mode:
  - **`readonly`** — PAN-OS mirrors the entire `devices/entry` subtree here, so a
    consumer that does not dedupe sees **42** device-groups, **54** templates and
    **24** template-stacks instead of 21/27/12.
  - **`mgt-config`** — administrator accounts and password hashes. Kept only with
    `--include-mgt-config`.
- The per-entry path remains the default because it is the only one that supports
  `--device-group` / `--template` selection. For a whole-estate engagement
  collection, prefer `--running-config`.

### Known limitation

- Operational device facts (hostname, model, HA state) come from a `show devices
  all` op command, not from the config, so they need their own request in either
  mode. That call **timed out on the first attempt** during the same network
  degradation — a snapshot can therefore carry a complete config and no
  hostnames. The failure is reported, not assumed, and the call retries cleanly.

## [1.5.1] — 2026-08-22

### Fixed

- **Credential disclosure in error output.** `requests` puts the full request URL
  into its exception text and our URLs carry `key=<api key>`, so an ordinary
  connection timeout printed the customer's Panorama API key in clear — into
  output that gets pasted into engagement notes and tickets. Every path where an
  exception or response body reaches `print()` now passes through a redactor
  (8 sites), covering `key=`, `password=` and `<key>`. Verified: forcing a
  failure with a known key yields **0** occurrences of it in the output.
- **A partial collection could report COMPLETE.** The completeness audit answered
  "did we ask for every branch?" but not "did everything we enumerated actually
  arrive?". On a flaky link individual device-group fetches fail while every
  branch is still present, so the snapshot silently loses policy. The collector
  now compares enumerated names against written names, names anything missing,
  declares the snapshot **PARTIAL**, and **exits 3** — non-zero because a
  silently partial collection is how an engagement ships wrong data.

### Added

- HTML viewer: **certificates**, **certificate profiles**, **decryption
  exclusions** and **Panorama admin** pages. An audit matching every named
  `<entry>` in a real export against the text of every generated page found these
  collected since 1.5.0 and rendered nowhere. Render coverage 76% → 83% of
  distinct named entries.
- Certificates are scoped by **template**, not device group — a real Panorama
  keeps **0** certificates in `/config/shared` and **98** across its templates,
  because a certificate reaches a firewall via a template push rather than
  device-group inheritance.

## [1.5.0] — 2026-08-22

**Completeness release — found by pointing the collector at a real production
Panorama for the first time** (2026-08-22: 12 firewalls, 21 device groups, 27
templates, 12 template stacks, PAN-OS 11.2.10-h13). Through 1.4.0 the exporter
asked only for `device-group` and `template` — 2 of the 8 branches that exist
under `/config/devices/entry` — and for none of the 5 top-level `/config`
branches. Measured against that estate, a 1.4.0 snapshot held:

- address objects — **156 of 637 (24%)**
- address-groups — **16 of 54 (29%)**
- services — **36 of 65 (55%)**
- applications — **6 of 17 (35%)**
- profile-groups — **0 of 7 (0%)**
- application-filters — **0 of 15 (0%)**

Downstream on the same estate: **48 rule references resolved to nothing** (27
address, 14 service, 7 of 7 profile-group); `template-stacks.html` shipped a
header row and **zero data rows** for a customer with 12 stacks; **all 12
`HOSTNAME` cells** on Managed Firewalls rendered as an em dash even though
`show devices all` returns every hostname; and the dashboard's "133 unused
objects" was largely an artifact of the missing namespace rather than real dead
config.

### Added

- **`/config/shared`** — the single biggest gap. On a real Panorama most objects
  live in shared and every device group inherits from it; without it the object
  namespace is a fraction of the truth and rule references dangle.
- **`template-stack`** under `/config/devices/entry`, fetched as **one whole
  branch, not entry-by-entry**: per-entry config queries measured **~23s each**
  on that Panorama, so 12 stacks fetched that way would have added **~4.5
  minutes for 11 KB** of data.
- **`deviceconfig`, `log-collector`, `log-collector-group`, `plugins`,
  `platform`** under `/config/devices/entry`.
- **`/config/panorama`** at top level.
- **`<nc-managed-devices>`** — operational facts per managed firewall (hostname,
  model, sw-version, HA state, connected, uptime) pulled with a `show devices
  all` op command. Hostname and HA state live nowhere in the config, which is
  why every Managed Firewalls hostname cell was an em dash. Deliberately
  namespaced with an `nc-` prefix so no importer mistakes it for a config
  branch; `panorama_import.py` addresses config by xpath and never walks unknown
  siblings, so it is inert on the round trip.
- **Completeness audit** — after the snapshot is written, the collector pulls the
  real `/config` tree and reports every branch present on the Panorama but
  absent from our snapshot. This is the guard that makes the collector safe to
  point at a customer we have never seen: before it, an unfetched branch was
  invisible and nobody could distinguish "the customer has none" from "we never
  asked". Skippable with `--no-audit` because it pulls tens of MB.
- New flags: `--no-shared`, `--no-template-stacks`, `--no-managed-devices`,
  `--no-audit`, `--include-predefined`, `--include-mgt-config`.

### Changed

- **Bounded per-branch fetches** — `BRANCH_TIMEOUT_S = 25`, no retry. Found live:
  `log-collector-group` returns 0 bytes and hangs to the timeout ceiling on a
  Panorama with no dedicated log collectors; under the old retry logic that one
  branch cost **120s+**.
- **The snapshot is written to disk before the completeness audit runs**, so a
  slow or failed audit can never cost a collection already in hand.
- `predefined` and `mgt-config` are **opt-in, never default**. `predefined` is
  vendor-static apps/services/threats — tens of MB, identical on every box of the
  same PAN-OS version; useful for App-ID mapping work, useless in a per-customer
  snapshot. `mgt-config` carries administrator accounts, role assignments and
  **password hashes**: a policy snapshot has no need for it and a customer
  handoff must not carry it, so the collector prints a warning whenever
  `--include-mgt-config` is used.
- HTML viewer `html_version.py` / collector aligned at **1.5.0**.

### Fixed

- `template-stacks.html` rendered a header row and no data rows — template
  stacks were never fetched (12 present on the pilot estate).
- Managed Firewalls `HOSTNAME` was an em dash for all 12 devices — hostname is
  operational data, not config, and was never collected.
- Dangling rule references (27 address, 14 service, 7 of 7 profile-group on the
  pilot estate) — the targets existed in `/config/shared`, which was not being
  fetched.
- Dashboard "unused objects" was inflated (133 on the pilot estate) largely
  because the shared namespace was missing from the snapshot.

## [1.4.0] — 2026-08-21

### Added

- Panorama HTML: **GlobalProtect** portals/gateways, **IPsec/IKE** crypto +
  tunnels, **security profiles** / profile-groups, **application-override**,
  **HA stack variables**, and **log forwarding** (DG profiles + collector-group
  match lists).

## [1.3.0] — 2026-08-21

### Added

- Panorama HTML: **Decryption** rules, **External Dynamic Lists**, and template
  **Interfaces** (ethernet / AE / VLAN / loopback / tunnel + subinterfaces).
- Shared Panorama objects (`<shared>`) now appear as device-group **Shared**.
- Managed Firewalls show **hostname** from the site template in the stack.

### Fixed

- Template stacks were doubled (full stack + Panorama id-only stub). Merge like
  templates/device-groups; template-vsys enrichment no longer shows "—".
- Device-group vsys assignment reads `<vsys><entry name=` as well as `<member>`.
- Panorama hostname is taken from `deviceconfig/system/hostname`, not the first
  `<hostname>` anywhere in the file.

## [1.2.1] — 2026-08-19

### Changed

- HTML viewer `html_version.py` / collector aligned at **1.2.1**.

## [1.2.0] — 2026-06-24

### Added

- Panorama HTML: **template-scoped network** pages — Templates, Template stacks,
  Virtual systems, Virtual routers, BGP, OSPF; static routes scoped by
  template + virtual router (no misleading global dedupe).
- Per-template detail pages (`templates/<name>.html`) with vsys and VR summary.
- Device-group pages link to **template stacks** and member templates; Managed
  Firewalls shows **assigned vsys** vs **template vsys** (multi-vsys from stack).
- `palo_model.py`: `_load_template_network()` parses template vsys, VRs, BGP
  peers/groups, OSPF areas.
- Offline engagement runbook: `HIT-COUNT-COLLECTION.md` (manual
  `show rule-hit-count` collection; not part of the XML export).

### Changed

- Dashboard adds **Network & routing (templates)** card row.
- HTML viewer `html_version.py` → **1.2.0** (aligned with collector).
- Palo Alto tree split: `palo/common/` (shared models), `palo/firewall/` (standalone
  HTML), `palo/panorama/` (export + Panorama HTML). SCM stays at `palo/scm/`.
- Panorama HTML entry renamed to `build_html.py` (was `build_panorama_html.py`).
- `requirements.txt` added under `palo/panorama/`.

## [1.1.0] — 2026-06-24

### Added

- **`build_panorama_html.py`** — Panorama read-only HTML browser: device-group
  hierarchy (**Panorama View**), per–device-group drill-down pages, **Managed
  Firewalls**, **Relationships** (where-used), scoped policy/object tables.
- **`build_html.py`** — dedicated **standalone firewall** HTML browser (vsys /
  `rulebase` layout); auto-rejects Panorama XML unless `--force`.
- **`html_common.py`** — shared table/page rendering for both browsers.
- **`core/palo_model.py`**: `PaloStandaloneModel`, `PaloPanoramaModel`,
  `detect_export_kind()`, `load_palo_model()`.
- Panorama parser merges duplicate device-group XML entries (content block vs
  `parent-dg` hierarchy block) and reads **`pre-rulebase` / `post-rulebase`**
  security and NAT rules.
- Per–device-group unused-object analysis; NAT source/destination translation
  columns; disabled-rule and application columns on security rules.
- **`palo/html_version.py`** — HTML viewer semver (`v1.0.0` badge on every page).

### Changed

- **`build_html.py`** no longer attempts to render Panorama exports (use
  `build_panorama_html.py` instead).
- **`README.md`** documents which script to use for each export type.

## [1.0.0] — 2026-06-23

### Added

- First versioned release. `panorama_export.py` exports Panorama device-groups /
  templates via the PAN-OS XML API to standalone XML for audit, diff, and
  migration.
