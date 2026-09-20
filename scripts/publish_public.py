#!/usr/bin/env python3
"""Publish the public-safe subset of this tree to netconverter-ai/netconverter-tools.

This repo is PRIVATE. The repo customers are pointed at is
https://github.com/netconverter-ai/netconverter-tools (public). Publishing is
one-way: private dev tree -> public tools repo. Never sync the other direction;
this tree holds scaffolds and work-in-progress that must not ship.

What gets published is driven by collectors.lock.json: every collector whose
status is "ready" or "library". Scaffolds are excluded. The folder mapping is
imported from gen_collectors_lock so the two cannot drift.

Before copying, each collector's folder hash is recomputed and compared against
the lockfile. A mismatch means the lockfile is stale and publishing aborts --
otherwise we would publish bytes the lockfile does not describe, which is the
exact failure this script exists to prevent.

Paths not managed by this script (e.g. fmc-import/, the ungoverned push tools)
are left untouched in the target, and README.md is rendered rather than copied
so publishing cannot silently drop them from the index.

Usage:
    python3 scripts/publish_public.py --target ../netconverter-tools --dry-run
    python3 scripts/publish_public.py --target ../netconverter-tools
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_collectors_lock import COLLECTORS, folders_sha256, read_version  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# Collector statuses that are safe to publish. "scaffold" is deliberately absent.
PUBLISH_STATUS = frozenset({"ready", "library"})

# Root-level files this script owns in the target.
ROOT_FILES = ("LICENSE", "VERSIONING.md")

# Extra managed folders that are not collectors. scripts/ ships so a reader can
# regenerate the lockfile and verify the published tree themselves.
EXTRA_FOLDERS = ("scripts",)

EXCLUDE_DIRS = frozenset({"__pycache__", ".pytest_cache", ".git", ".venv", "venv"})
EXCLUDE_NAMES = frozenset({".DS_Store"})
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".zip", ".tar.gz", ".log")


def publishable() -> list[tuple[str, list[str], str, str]]:
    """Collector rows from gen_collectors_lock filtered to publishable statuses."""
    return [row for row in COLLECTORS if row[3] in PUBLISH_STATUS]


def managed_folders() -> list[str]:
    """Every folder this script owns in the target, deduped and sorted."""
    folders: set[str] = set(EXTRA_FOLDERS)
    for _key, srcs, _entry, _status in publishable():
        folders.update(srcs)
    return sorted(folders)


def verify_against_lockfile(lock: dict) -> list[str]:
    """Recompute each publishable collector's hash. Returns a list of problems."""
    problems: list[str] = []
    for key, srcs, entry, _status in publishable():
        recorded = lock["collectors"].get(key)
        if recorded is None:
            problems.append(f"{key}: absent from collectors.lock.json")
            continue
        actual_sha = folders_sha256(REPO_ROOT, srcs)
        if actual_sha != recorded["sha256"]:
            problems.append(
                f"{key}: folder hash {actual_sha[:12]} != lockfile {recorded['sha256'][:12]} "
                f"-- run scripts/gen_collectors_lock.py"
            )
        actual_ver = read_version(REPO_ROOT / entry)
        if actual_ver != recorded["version"]:
            problems.append(
                f"{key}: {entry} is {actual_ver} but lockfile says {recorded['version']}"
            )
    return problems


def skip(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES:
        return True
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return True
    return path.name.endswith(EXCLUDE_SUFFIXES)


def iter_source_files(folders: list[str]) -> list[Path]:
    """Repo-relative paths of everything to publish, sorted for determinism."""
    out: list[Path] = []
    for name in ROOT_FILES:
        p = REPO_ROOT / name
        if p.is_file():
            out.append(Path(name))
    for folder_rel in folders:
        folder = REPO_ROOT / folder_rel
        if not folder.is_dir():
            continue
        for p in folder.rglob("*"):
            if p.is_file() and not skip(p):
                out.append(p.relative_to(REPO_ROOT))
        # A vendor-level README (e.g. palo/README.md) sits above the collector folder.
        parent_readme = folder.parent / "README.md"
        if folder.parent != REPO_ROOT and parent_readme.is_file():
            out.append(parent_readme.relative_to(REPO_ROOT))
    return sorted(set(out))


def filtered_lock(lock: dict) -> str:
    """The lockfile with only the collectors this publish actually ships.

    Copying the dev lockfile verbatim would advertise the scm scaffold, which is
    not published -- and would make `gen_collectors_lock.py` in the published
    tree produce a different file, breaking the verification PUBLISHED.md tells
    readers to run.
    """
    keys = {row[0] for row in publishable()}
    out = {
        "schema": lock["schema"],
        "collectors": {k: v for k, v in lock["collectors"].items() if k in keys},
        "generated_at": lock["generated_at"],
    }
    return json.dumps(out, indent=2, sort_keys=True) + "\n"


def unmanaged_top_level(target: Path, folders: list[str]) -> list[str]:
    """Top-level dirs in the target this script does not own (e.g. push tools)."""
    owned = {f.split("/")[0] for f in folders} | {".git"}
    return sorted(
        p.name for p in target.iterdir()
        if p.is_dir() and p.name not in owned and not p.name.startswith(".")
    )


def render_readme(target: Path, folders: list[str]) -> str:
    """Dev README plus a generated index of unmanaged folders in the target.

    Copying the dev README verbatim would delete the entry for anything that
    lives only in the public repo, so that part is generated from what is
    actually there.
    """
    body = (REPO_ROOT / "README.md").read_text(encoding="utf-8").rstrip("\n")
    extras = unmanaged_top_level(target, folders)
    if not extras:
        return body + "\n"
    rows = "\n".join(f"- [`{name}/`]({name}/)" for name in extras)
    return (
        f"{body}\n\n"
        "## Push tools\n\n"
        "Scripts that write converted output back to a management platform. These are\n"
        "maintained separately and are not covered by `collectors.lock.json`.\n\n"
        f"{rows}\n"
    )


def stale_targets(target: Path, folders: list[str], wanted: set[Path]) -> list[Path]:
    """Files inside managed folders in the target that the source no longer has."""
    out: list[Path] = []
    for folder_rel in folders:
        tdir = target / folder_rel
        if not tdir.is_dir():
            continue
        for p in tdir.rglob("*"):
            if p.is_file() and ".git" not in p.parts:
                rel = p.relative_to(target)
                if rel not in wanted:
                    out.append(rel)
    return sorted(out)


def source_commit() -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def render_stamp(lock: dict, commit: str) -> str:
    rows = "\n".join(
        f"| `{key}` | {lock['collectors'][key]['version']} | `{lock['collectors'][key]['sha256'][:12]}` |"
        for key, _s, _e, _st in publishable()
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        "# Published state\n\n"
        "Generated by `scripts/publish_public.py`. Do not edit by hand.\n\n"
        f"- Published: {now}\n"
        f"- Source commit: `{commit}`\n\n"
        "| Collector | Version | Folder sha256 |\n"
        "|---|---|---|\n"
        f"{rows}\n\n"
        "Verify the tree you downloaded matches these hashes:\n\n"
        "```bash\n"
        "python3 scripts/gen_collectors_lock.py --check\n"
        "```\n\n"
        "It recomputes every collector's folder hash and exits non-zero on any\n"
        "mismatch. Requires only the standard library.\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True, help="path to the netconverter-tools checkout")
    ap.add_argument("--dry-run", action="store_true", help="report actions, write nothing")
    args = ap.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not (target / ".git").is_dir():
        print(f"Error: {target} is not a git checkout")
        return 1

    lock = json.loads((REPO_ROOT / "collectors.lock.json").read_text())

    problems = verify_against_lockfile(lock)
    if problems:
        print("Refusing to publish -- lockfile does not describe this tree:")
        for p in problems:
            print(f"  - {p}")
        return 2

    folders = managed_folders()
    files = iter_source_files(folders)
    wanted = set(files) | {Path("PUBLISHED.md"), Path("README.md"), Path("collectors.lock.json")}
    stale = stale_targets(target, folders, wanted)

    excluded = [row[0] for row in COLLECTORS if row[3] not in PUBLISH_STATUS]
    print(f"Publishing {len(files)} files across {len(folders)} folders -> {target}")
    print(f"  collectors: {', '.join(row[0] for row in publishable())}")
    print(f"  excluded  : {', '.join(excluded) or '(none)'}")

    changed = added = 0
    for rel in files:
        src, dst = REPO_ROOT / rel, target / rel
        if not dst.exists():
            added += 1
            verb = "add"
        elif src.read_bytes() != dst.read_bytes():
            changed += 1
            verb = "update"
        else:
            continue
        print(f"  {verb:<7} {rel}")
        if not args.dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    for rel in stale:
        print(f"  delete  {rel}")
        if not args.dry_run:
            (target / rel).unlink()

    lock_text = filtered_lock(lock)
    lock_path = target / "collectors.lock.json"
    if not lock_path.exists() or lock_path.read_text() != lock_text:
        print("  render  collectors.lock.json")
        changed += 1
    if not args.dry_run:
        lock_path.write_text(lock_text, encoding="utf-8")

    readme = render_readme(target, folders)
    if (target / "README.md").read_text(encoding="utf-8") != readme:
        print("  render  README.md")
        changed += 1
    if not args.dry_run:
        (target / "README.md").write_text(readme, encoding="utf-8")
        (target / "PUBLISHED.md").write_text(render_stamp(lock, source_commit()), encoding="utf-8")

    print(f"\n{added} added, {changed} updated, {len(stale)} deleted"
          + (" (dry run -- nothing written)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
