#!/usr/bin/env python3
"""
NetConverter — Palo Alto **Panorama** read-only HTML browser.

Reads a Panorama PAN-OS XML export (from panorama_export.py or optimizer output)
and writes <html_dir>/ with device-group hierarchy, per-DG drill-down, and
relationship pages.

Usage:
    python build_html.py --input panorama_snapshot.xml
    python build_html.py --input input_config.xml --output ./html_view

License: MIT
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_TECH = Path(__file__).resolve().parent
_COMMON = _TECH.parent / "common"
_ROOT = _TECH.parents[1]
for _p in (_ROOT, _COMMON, _TECH):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from palo_model import PaloPanoramaModel, detect_export_kind  # noqa: E402
from html_common import build_panorama_site  # noqa: E402
from html_version import __version__  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Build Panorama HTML browser from XML export")
    p.add_argument("--input", required=True, help="Panorama PAN-OS XML file")
    p.add_argument("--output", default=None, help="Output dir (default: <input_dir>/html_view)")
    p.add_argument(
        "--force",
        action="store_true",
        help="Build even if the file looks like a standalone firewall export",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args()

    src = Path(args.input)
    if not src.is_file():
        print(f"Error: file not found: {src}")
        return 1

    import xml.etree.ElementTree as ET

    kind = detect_export_kind(ET.parse(src).getroot())
    if kind == "standalone" and not args.force:
        print(
            "Error: this XML looks like a standalone firewall export (vsys / rulebase).\n"
            "Use palo/firewall/build_html.py instead:\n"
            f"  python build_html.py --input {src}"
        )
        return 2

    out = Path(args.output) if args.output else src.parent / "html_view"
    model = PaloPanoramaModel(src)
    model.load()
    print(
        f"Loaded {src.name} [panorama]: {model.stats['device_groups']} device groups, "
        f"{model.stats['security_rules']} rules, {model.stats['addresses']} addresses, "
        f"{model.stats.get('managed_devices', 0)} firewalls, "
        f"{model.stats['unused_objects']} unused"
    )
    build_panorama_site(model, out, viewer_version=__version__)
    print(f"Done. Open:\n  {(out / 'index.html').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
