"""Bundle manifest helpers — consistent metadata across vendor collectors."""

from __future__ import annotations

__version__ = "1.1.2"

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def make_run_dir(output: str | Path, prefix: str = "run") -> Path:
    """Create a timestamped output directory (e.g. run-20260606-173000)."""
    base = Path(output).resolve()
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run = base / f"{prefix}-{stamp}"
    run.mkdir(parents=True, exist_ok=True)
    return run


def write_manifest(
    run_dir: str | Path,
    *,
    vendor: str,
    collector: str,
    collector_version: str = "1.0.0",
    host: str = "",
    extra: dict[str, Any] | None = None,
) -> Path:
    """Write manifest.json into a collection bundle."""
    run = Path(run_dir)
    payload: dict[str, Any] = {
        "vendor": vendor,
        "collector": collector,
        "collector_version": collector_version,
        "host": host,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        payload.update(extra)
    path = run / "manifest.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
