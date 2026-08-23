#!/usr/bin/env python3
"""Generate collectors.lock.json — the canonical per-collector version record.

Reads each collector entry script's __version__ plus a content hash of its
folder, and writes <repo-root>/collectors.lock.json. Run after bumping any
collector's __version__. Pure stdlib.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 1

# key, hash folder(s), entry script, status
COLLECTORS = [
    ("checkpoint", ["checkpoint/smartconsole"], "checkpoint/smartconsole/checkpoint_collect_data.py", "ready"),
    ("palo",       ["palo/panorama", "palo/common", "palo/firewall"], "palo/panorama/panorama_export.py", "ready"),
    ("fmc",        ["cisco/fmc"],               "cisco/fmc/fmc_collect_data.py",                      "ready"),
    ("fortinet",   ["fortinet/fortimanager"],   "fortinet/fortimanager/fortimanager_collect.py",      "ready"),
    ("scm",        ["palo/scm"],                "palo/scm/scm_config_pull.py",                        "scaffold"),
    ("core",       ["core"],                    "core/manifest.py",                                   "library"),
]

_VER_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)


def read_version(path: Path) -> str:
    """Extract __version__ from a Python file without importing it."""
    m = _VER_RE.search(path.read_text(encoding="utf-8"))
    if not m:
        raise ValueError(f"no __version__ found in {path}")
    return m.group(1)


def folder_sha256(folder: Path) -> str:
    """Deterministic hash of all *.py under folder (sorted by relative path)."""
    if not folder.is_dir():
        raise ValueError(f"collector folder not found: {folder}")
    h = hashlib.sha256()
    for p in sorted(folder.rglob("*.py"), key=lambda x: str(x.relative_to(folder))):
        if "__pycache__" in p.parts:
            continue
        h.update(str(p.relative_to(folder)).encode())
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()


def folders_sha256(repo_root: Path, folders: list[str]) -> str:
    """Hash of *.py across multiple folders (paths prefixed in the hash)."""
    h = hashlib.sha256()
    for folder_rel in sorted(folders):
        folder = repo_root / folder_rel
        if not folder.is_dir():
            raise ValueError(f"collector folder not found: {folder}")
        for p in sorted(folder.rglob("*.py"), key=lambda x: str(x.relative_to(folder))):
            if "__pycache__" in p.parts:
                continue
            rel = f"{folder_rel}/{p.relative_to(folder)}"
            h.update(rel.encode())
            h.update(b"\0")
            h.update(p.read_bytes())
    return h.hexdigest()


def build_lock(repo_root: Path) -> dict:
    """Build the deterministic lock body (no timestamp — added by main()).

    A collector whose folders are absent is skipped with a notice rather than
    raising. The published subset in netconverter-tools ships only the "ready"
    and "library" collectors, and this script travels with it so a reader can
    regenerate the lockfile and verify the tree they downloaded.
    """
    collectors = {}
    for key, folders, entry, status in COLLECTORS:
        if not all((repo_root / f).is_dir() for f in folders):
            print(f"  {key:12} skipped — not present in this tree")
            continue
        collectors[key] = {
            "version": read_version(repo_root / entry),
            "entry": entry,
            "status": status,
            "sha256": folders_sha256(repo_root, folders),
        }
    return {"schema": SCHEMA, "collectors": collectors}


def check(repo_root: Path) -> int:
    """Compare the on-disk tree against collectors.lock.json. Non-zero on drift.

    Ignores generated_at — a timestamp is not drift. This is the gate: it fails
    when the bytes in this tree are not the bytes the lockfile describes.
    """
    lock_path = repo_root / "collectors.lock.json"
    if not lock_path.is_file():
        print(f"FAIL: {lock_path} not found")
        return 1
    recorded = json.loads(lock_path.read_text(encoding="utf-8"))["collectors"]
    actual = build_lock(repo_root)["collectors"]

    problems = []
    for key in sorted(set(recorded) | set(actual)):
        if key not in actual:
            problems.append(f"{key}: in lockfile but not in this tree")
        elif key not in recorded:
            problems.append(f"{key}: in this tree but not in the lockfile")
        elif recorded[key] != actual[key]:
            r, a = recorded[key], actual[key]
            if r["version"] != a["version"]:
                problems.append(f"{key}: lockfile {r['version']} != tree {a['version']}")
            if r["sha256"] != a["sha256"]:
                problems.append(
                    f"{key}: lockfile {r['sha256'][:12]} != tree {a['sha256'][:12]}"
                )
    if problems:
        print("FAIL: tree does not match collectors.lock.json")
        for x in problems:
            print(f"  - {x}")
        print("\nRun: python3 scripts/gen_collectors_lock.py")
        return 1
    print(f"OK: {len(actual)} collectors match collectors.lock.json")
    return 0


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    if "--check" in sys.argv[1:]:
        return check(repo_root)
    lock = build_lock(repo_root)
    lock["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = repo_root / "collectors.lock.json"
    out.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    for key, meta in sorted(lock["collectors"].items()):
        print(f"  {key:12} {meta['version']:8} {meta['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
