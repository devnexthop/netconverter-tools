# Changelog — Cisco FMC (`cisco/fmc/`)

All notable changes to the FMC collector and its HTML builder. Collect and HTML
share one `__version__`. Versions are independent of other collectors and of
the NetConverter.local appliance.

## [2.3.0] — 2026-06-22
### Added
- Per-run completeness self-audit (`completeness.csv`) + a Completeness page
  reconciling captured vs live FMC totals; API-blocked endpoints labelled so a
  `0` is never mistaken for data loss.
- One-click Excel / CSV export on every browse/rule table.
- Applications & URLs "in use" L7 view: L7 objects referenced by access rules,
  cross-referenced to those rules + catalog risk/type.
- HTML viewer **v2.3.0** badge (`viewer_version`) on every generated page.
### Fixed
- Token auth now auto-retries transient `401`/`429`/timeout/`5xx` with backoff
  (sandbox/lab FMC resilience).
### Known limitations
- DNS rule bodies are not exposed by the FMC REST API on current versions
  (`/dnspolicies/{id}/dnsrules` -> `404`); shown as `api_blocked` in the audit.
  NAT, access, and L7 app/URL references are captured in full.
