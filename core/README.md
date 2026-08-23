# core

Shared utilities for NetConverter collection bundles and HTML reports.

| Module | Purpose |
|--------|---------|
| `manifest.py` | `run-*` folders + `manifest.json` |
| `bundle_zip.py` | Package `run-*` folders into zip/tar.gz deliverables |
| `html_theme.py` | Shared CSS/JS + vendor theme tokens (CP, PA, FMC, Forti, SCM) |
| `html_site.py` | `SiteBuilder` — static page shell, nav, tables, cards |
| `snapshot_html.py` | JSON snapshot → HTML (FMC / SCM / Forti scaffolds) |
| `cve_intel.py` | CISA KEV / NVD / EPSS lookups for HTML reports |

Vendor-specific parsers (e.g. Palo `palo_model.py`) live under their technology folder, not here.

Every technology folder has a `build_html.py` that writes `html_view/` — read-only, open `index.html` in a browser.
