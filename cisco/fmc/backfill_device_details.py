#!/usr/bin/env python3
"""Fetch per-device interfaces/routes for an existing run-* folder (no full re-collect)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from fmc_collect_data import FMCClient, collect_device_details, _safe_json_write  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Backfill device interfaces/routes into an existing run folder")
    p.add_argument("--input", required=True, help="run-* folder")
    p.add_argument("--host", help="FMC hostname (default: from fmc_snapshot.json)")
    p.add_argument("--user", help="FMC username (default: from manifest)")
    p.add_argument("--password", default=None)
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--domain-uuid", default=None)
    args = p.parse_args()

    run = Path(args.input)
    snap_path = run / "fmc_snapshot.json"
    if not snap_path.is_file():
        print(f"Missing {snap_path}")
        return 1

    snap = json.loads(snap_path.read_text(encoding="utf-8"))
    manifest = {}
    if (run / "manifest.json").is_file():
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))

    host = args.host or snap.get("host") or manifest.get("host")
    user = args.user or manifest.get("user")
    if not host or not user:
        print("Need --host and --user (or values in snapshot/manifest)")
        return 1

    devices_raw = json.loads((run / "devices.json").read_text(encoding="utf-8"))
    client = FMCClient(
        host=host,
        user=user,
        password=args.password,
        insecure=args.insecure,
        domain_uuid=args.domain_uuid or snap.get("domain_uuid"),
    )
    try:
        client.authenticate()
    except RuntimeError as exc:
        print(exc)
        return 1

    def log(msg: str) -> None:
        print(msg)

    collect_device_details(client, run, devices_raw, snap, log)
    _safe_json_write(run / "fmc_snapshot.json", snap)
    print("Updated fmc_snapshot.json, interfaces.json, routes.json, device-details/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
