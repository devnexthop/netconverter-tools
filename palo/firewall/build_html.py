#!/usr/bin/env python3
"""
NetConverter — Palo Alto **standalone firewall** read-only HTML browser.

Reads a single-firewall PAN-OS XML export (backup or device config) and writes
<html_dir>/ with vendor-themed static pages.

For Panorama device-group exports use palo/panorama/build_html.py instead.

Usage:
    python build_html.py --input firewall.xml
    python build_html.py --input firewall.xml --output ./html_view

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

from palo_model import PaloStandaloneModel, detect_export_kind  # noqa: E402
from html_common import build_standalone_site  # noqa: E402
from html_version import __version__  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Build standalone Palo Alto HTML browser from XML export")
    p.add_argument("--input", required=True, help="PAN-OS XML file (standalone firewall)")
    p.add_argument("--output", default=None, help="Output dir (default: <input_dir>/html_view)")
    p.add_argument(
        "--force",
        action="store_true",
        help="Build even if the file looks like a Panorama export (not recommended)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args()

    src = Path(args.input)
    if not src.is_file():
        print(f"Error: file not found: {src}")
        return 1

    import xml.etree.ElementTree as ET

    kind = detect_export_kind(ET.parse(src).getroot())
    if kind == "panorama" and not args.force:
        print(
            "Error: this XML looks like a Panorama export (device-groups / pre-rulebase).\n"
            "Use palo/panorama/build_html.py instead:\n"
            f"  python build_html.py --input {src}"
        )
        return 2

    out = Path(args.output) if args.output else src.parent / "html_view"
    model = PaloStandaloneModel(src)
    model.load()
    print(
        f"Loaded {src.name} [standalone]: {model.stats['security_rules']} rules, "
        f"{model.stats['addresses']} addresses, {model.stats['routes']} routes, "
        f"{model.stats['unused_objects']} unused"
    )
    build_standalone_site(model, out, viewer_version=__version__)
    print(f"Done. Open:\n  {(out / 'index.html').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
