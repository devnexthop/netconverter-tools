#!/usr/bin/env python3
"""Build nc-collector-<vendor>.zip — the self-contained bundle the portal serves.

A collector is not shippable as loose files: build_html.py resolves its imports
by walking up to the repo root (palo_model, html_common) and html_common reaches
back for core.html_site. Only the folder layout makes it importable, so the unit
we hand a customer is a zip that preserves it.

Contents are driven by collectors.lock.json, and the build refuses to run if the
tree does not match it -- the zip therefore always contains the exact bytes the
lockfile describes.

Zips are byte-reproducible: fixed timestamps and fixed permissions, so rebuilding
an unchanged collector produces an identical file and a diff means a real change.

Usage:
    python3 scripts/build_collector_bundle.py palo --out ../aws-netconverter.ai/tool/downloads
    python3 scripts/build_collector_bundle.py --list
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_collectors_lock import COLLECTORS, check  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# Fixed epoch for reproducibility (1980-01-01, the ZIP format floor).
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

EXCLUDE_DIRS = frozenset({"__pycache__", ".pytest_cache"})
EXCLUDE_NAMES = frozenset({".DS_Store"})
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".zip")

# Vendor bundles always carry core/ — html_common imports core.html_site.
ALWAYS = ("core",)


def collector_row(key: str):
    for row in COLLECTORS:
        if row[0] == key:
            return row
    raise SystemExit(f"unknown collector: {key} (try --list)")


def folders_for(key: str) -> list[str]:
    _k, srcs, _e, _s = collector_row(key)
    extra = [f for a in ALWAYS for f in folders_for_raw(a)]
    return sorted(set(srcs) | set(extra))


def folders_for_raw(key: str) -> list[str]:
    return collector_row(key)[1]


def keep(p: Path) -> bool:
    if p.name in EXCLUDE_NAMES or p.name.endswith(EXCLUDE_SUFFIXES):
        return False
    return not any(part in EXCLUDE_DIRS for part in p.parts)


def gather(folders: list[str]) -> list[tuple[Path, str]]:
    """(absolute path, archive name) pairs, sorted for deterministic output."""
    out: list[tuple[Path, str]] = []
    for folder_rel in folders:
        folder = REPO_ROOT / folder_rel
        if not folder.is_dir():
            raise SystemExit(f"missing folder: {folder}")
        for p in sorted(folder.rglob("*")):
            if p.is_file() and keep(p):
                out.append((p, f"{folder_rel}/{p.relative_to(folder)}"))
        parent_readme = folder.parent / "README.md"
        if folder.parent != REPO_ROOT and parent_readme.is_file():
            out.append((parent_readme, str(parent_readme.relative_to(REPO_ROOT))))
    return sorted(set(out), key=lambda t: t[1])


def render_readme(key: str, lock: dict, folders: list[str]) -> str:
    meta = lock["collectors"][key]
    entry = meta["entry"]
    tree = "\n".join(f"  {f}/" for f in folders)
    return f"""# NetConverter — {key} collector bundle

NetConverter — by ValeronLabs LLC · https://netconverter.ai

Version **{meta['version']}** · folder sha256 `{meta['sha256'][:12]}`

Read-only. This bundle collects configuration from a management plane and builds
a local HTML view. It never writes to the device.

## Layout

```
{tree}
```

Keep the layout intact — the HTML builder resolves imports through it.

## Run

```bash
pip install -r {Path(entry).parent}/requirements.txt
python3 {entry} --help
```

Source, changelog, and hash verification:
https://github.com/netconverter-ai/netconverter-tools
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("collector", nargs="?", help="collector key, e.g. palo")
    ap.add_argument("--out", help="directory to write the zip into")
    ap.add_argument("--list", action="store_true", help="list collector keys")
    args = ap.parse_args()

    if args.list:
        for k, srcs, _e, status in COLLECTORS:
            print(f"  {k:12} {status:9} {' '.join(srcs)}")
        return 0
    if not args.collector or not args.out:
        ap.error("collector and --out are required")

    if check(REPO_ROOT) != 0:
        print("\nRefusing to build a bundle from a tree that does not match the lockfile.")
        return 2

    key = args.collector
    lock = json.loads((REPO_ROOT / "collectors.lock.json").read_text())
    if key not in lock["collectors"]:
        raise SystemExit(f"{key} is not in collectors.lock.json")

    folders = folders_for(key)
    files = gather(folders)
    readme = render_readme(key, lock, folders)

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"nc-collector-{key}.zip"

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        info = zipfile.ZipInfo("README.md", date_time=ZIP_EPOCH)
        info.external_attr = 0o644 << 16
        zf.writestr(info, readme)
        for full, arc in files:
            info = zipfile.ZipInfo(arc, date_time=ZIP_EPOCH)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, full.read_bytes())

    size = dest.stat().st_size
    print(f"wrote {dest}")
    print(f"  {key} {lock['collectors'][key]['version']} · {len(files) + 1} files · {size:,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
