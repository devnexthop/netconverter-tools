# Changelog — FortiManager (`fortinet/fortimanager/`)

Collect and HTML share one `__version__` (`fortimanager_collect.py` +
`build_html.py`).

## [1.3.0] — 2026-07-02
### Added
- **Live policy hit counters** (parity-critical): per-device, per-VDOM policy
  usage pulled via the proxied monitor API (`/api/v2/monitor/firewall/policy`
  + `/policy6`) — exported as `policy_hits`
  (policyid/name/bytes/packets/active_sessions/first_used/last_used). This is
  the FortiGate equivalent of Check Point retained hit data and is what lets
  the behavior-preserving rule review prove a rule is "never matched in the
  window". **Perishable — only available while devices are online.**
- **Live HA / cluster sync state** per device (`system/ha-peer`,
  `ha-checksum/cluster`, `ha-statistics`) — exported as `ha_status` and raw
  under `live-state/<device>/ha_status.json`.
- **Live resource usage** (session load / CPU / memory) per device
  (`system/resource/usage`) — `sessions` dataset + raw file. The full session
  table is intentionally NOT dumped (size / PII).
- **Live effective routing table / FIB** per device+VDOM
  (`router/ipv4`) — `routes_live` dataset + raw file (the installed routes,
  not just configured statics).
- New `live-state/<device>/*.json` output folder for raw payloads, and a
  `live_state` row in `collection-summary.csv` that explains an empty result
  (skipped vs. offline) so missing hit data is never mistaken for "clean".
- **HTML Live State pages** (`build_html.py`): Policy Hit Counters, HA / Cluster
  Sync, Resource Usage, Live Routes (FIB), plus dashboard KPI cards. Collect and
  HTML both at **1.3.0**.
- `requirements.txt` for the FortiManager folder.

### Changed
- Live-only state is collected **by default** (via `/sys/proxy/json` to each
  online device). Opt out with `--no-live-state`. Still 100% read-only
  (`get`/`exec get` only); no writes to FortiManager or devices.

## [1.2.0] — 2026-07-02
### Added
- **DHCP leases**: active leases pulled per device via the proxied monitor API
  (`/api/v2/monitor/system/dhcp`) — exported as `dhcp_leases`
  (ip/mac/hostname/interface/expiry/reserved/VCI) with a new DHCP Leases page.
- **Physical Appliances** page (`build_html.py` v1.2.0, Check Point parity):
  hardware/OS/HA/connection detail per FortiGate with click-through to the
  unit's **actual running config** — rendered viewer page plus downloadable
  raw `.conf` copied into `html_view/configs/`.

## [1.1.0] — 2026-07-02
### Added
- **Revision tracking**: ADOM database revisions (`/dvmdb/adom/<adom>/revision`)
  and per-device config revision history (proxied
  `/api/v2/monitor/system/config-revision`) exported as `adom_revisions` /
  `device_revisions`.
- New ADOM datasets: central SNAT rules, schedules (recurring/onetime/group),
  wildcard-FQDN + IPv6 addresses/groups, security (UTM) profiles across 9
  profile types, local users, user groups, auth servers
  (RADIUS/LDAP/TACACS+/SAML).
- New per-device datasets: security zones, DHCP servers, system DNS, local
  admin accounts (with trusted-host / two-factor detail); FortiManager admin
  accounts (`fmg_admins`).
- `collection-summary.csv` (dataset/rows/status/note) and
  `collection-progress.log` written into every run for coverage auditing.
- Local `.conf` parser (`fortigate_config.py`) now also extracts schedules,
  zones, admin accounts and DHCP servers from device backups.
- HTML view (`build_html.py` v1.1.0): new Revisions & Changes, Collection
  Coverage, Zones, DHCP Servers, Administrators, Users & Groups, Security
  Profiles, Schedules and Central SNAT pages; Change Tracking dashboard
  cards; device table shows revision history; viewer version badge.

### Changed
- Device config backups (`Local Configs/*.conf`) are now pulled **by default**;
  use `--no-device-configs` to skip. `--pull-device-configs` kept as a
  deprecated no-op.
- HTML view is now **browse-only by default** (matches Check Point): the
  Compliance (NIST/CIS) and Versions & CVE pages are omitted unless
  `--analysis` is passed; CVE intel lookups are skipped in browse-only builds.

## [1.0.0] — 2026-06-23
### Added
- First versioned release. Read-only JSON-RPC pull of devices, interfaces,
  routes, objects, policies, IPsec/SSL VPN; auto-detects ADOMs.
