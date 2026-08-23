#!/usr/bin/env python3
"""
Package a run-* FMC collection folder into a single zip or tar.gz for delivery.

Usage:
    python package_run.py --input run-20260622-234939
    python package_run.py --input run-... --format tgz

License: MIT
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.bundle_zip import package_run  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Zip/tar.gz an FMC run-* bundle")
    p.add_argument("--input", required=True, help="run-* folder path")
    p.add_argument(
        "--format",
        choices=("zip", "tgz"),
        default="zip",
        help="zip = universal (default); tgz = smaller, Unix-native",
    )
    p.add_argument("--output-dir", default=None, help="Where to write archive (default: parent of run-*)")
    p.add_argument("--prefix", default="fmc_audit", help="Archive filename prefix")
    args = p.parse_args()

    run = Path(args.input)
    if not run.is_dir():
        print(f"Error: not a directory: {run}", file=sys.stderr)
        return 1

    archive = package_run(
        run,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        prefix=args.prefix,
        fmt=args.format,
    )
    size_mb = archive.stat().st_size / (1024 * 1024)
    print(f"Created: {archive.resolve()} ({size_mb:.1f} MB)")

    manifest = run / "manifest.json"
    if manifest.is_file():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["archive"] = {
            "path": archive.name,
            "format": args.format,
            "size_bytes": archive.stat().st_size,
        }
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
