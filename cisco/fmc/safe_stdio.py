"""Console output that survives a Windows cp1252 console.

FMC log lines use arrows / ellipses. On a default Windows console those
characters raise UnicodeEncodeError and abort the process after the JSON
bundle is already on disk, so collection.log and manifest.json are never
written. Reconfigure stdout/stderr to UTF-8, and if a write still cannot
encode, replace the offending characters instead of crashing.
"""

from __future__ import annotations

import sys
from typing import TextIO


def configure_stdio() -> None:
    """Prefer UTF-8 on stdout/stderr. No-op when the stream cannot be retargeted."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError, AttributeError):
            continue


def safe_print(
    msg: str = "",
    *,
    file: TextIO | None = None,
    end: str = "\n",
    flush: bool = True,
) -> None:
    """Write ``msg`` without raising UnicodeEncodeError."""
    stream = file if file is not None else sys.stdout
    text = f"{msg}{end}"
    try:
        stream.write(text)
        if flush:
            stream.flush()
        return
    except UnicodeEncodeError:
        pass
    encoding = getattr(stream, "encoding", None) or "ascii"
    fallback = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    stream.write(fallback)
    if flush:
        try:
            stream.flush()
        except Exception:
            pass
