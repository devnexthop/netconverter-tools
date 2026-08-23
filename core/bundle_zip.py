"""Package a run-* collection folder into a single deliverable archive."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


def archive_basename(run_dir: Path, prefix: str = "fmc_audit") -> str:
    """run-20260622-234939 → fmc_audit_20260622-234939"""
    name = run_dir.name
    stamp = name[4:] if name.startswith("run-") else name
    return f"{prefix}_{stamp}"


_SKIP_PARTS = frozenset({".DS_Store", "__MACOSX"})


def _iter_files(run_dir: Path) -> list[tuple[Path, Path]]:
    """Return (absolute path, arcname relative to run_dir parent) pairs."""
    run_dir = run_dir.resolve()
    root_name = run_dir.name
    out: list[tuple[Path, Path]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in _SKIP_PARTS or "__MACOSX" in path.parts:
            continue
        arc = Path(root_name) / path.relative_to(run_dir)
        out.append((path, arc))
    return out


def create_zip(run_dir: Path, dest: Path) -> Path:
    files = _iter_files(run_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for full, arc in files:
            zf.write(full, arc.as_posix())
    return dest


def create_tgz(run_dir: Path, dest: Path) -> Path:
    files = _iter_files(run_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w:gz") as tf:
        for full, arc in files:
            tf.add(full, arcname=arc.as_posix(), recursive=False)
    return dest


def package_run(
    run_dir: Path,
    *,
    output_dir: Path | None = None,
    prefix: str = "fmc_audit",
    fmt: str = "zip",
) -> Path:
    """
    Create one archive containing the entire run-* folder (json + html_view).

    fmt: 'zip' (default, Windows-friendly) or 'tgz' (smaller, Unix-native).
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Run folder not found: {run_dir}")

    out_dir = Path(output_dir) if output_dir else run_dir.parent
    base = archive_basename(run_dir, prefix=prefix)
    if fmt == "tgz":
        dest = out_dir / f"{base}.tar.gz"
        return create_tgz(run_dir, dest)
    if fmt == "zip":
        dest = out_dir / f"{base}.zip"
        return create_zip(run_dir, dest)
    raise ValueError(f"Unsupported format: {fmt}")
