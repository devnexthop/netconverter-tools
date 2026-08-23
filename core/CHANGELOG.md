# Changelog — shared collector core (`core/`)

## [1.1.1] — 2026-08-21

### Added

- `DESIGN-TOKENS.md` — the canonical token list, and the source of truth when a
  collector and the appliance disagree on a colour or radius.
- Long-name token aliases in `html_theme.py` (`--bg-surface`, `--text`,
  `--success`, …) mapping onto the existing values. Additive only — no visual
  change to any collector's output.

### Notes

- Decision #9: blue is the product accent, purple is engineering.
- Shipped in `3eb48ce` but left undocumented here; backfilled 2026-08-23 when
  the appliance's collector-consistency check flagged the gap. `manifest.py`
  and `collectors.lock.json` were already at 1.1.1.

## [1.1.0] — 2026-06-24

### Added

- Shared HTML site framework (`html_site.py`, `html_theme.py`) used by all
  vendor browsers.
- Bundle helpers: `make_run_dir` + `write_manifest` (metadata stamped with each
  collector's `__version__`).
- CVE intel helpers (`cve_intel.py`) for offline-friendly KEV/NVD/EPSS prefetch.
- Zip packaging helpers (`bundle_zip.py`, `snapshot_html.py`).

### Changed

- **`html_site.SiteBuilder`**: optional `viewer_version` renders the
  **vX.Y.Z** badge (top-right) on every generated page.

### Notes

- Palo Alto XML models live in `palo/common/palo_model.py` (not in `core/`).

## [1.0.0] — 2026-06-23

### Added

- First versioned release. `make_run_dir` + `write_manifest` (bundle metadata,
  now stamping each collector's real `__version__`).
