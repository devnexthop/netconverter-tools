#!/usr/bin/env python3
"""Tests for gen_collectors_lock — run: python3 scripts/test_gen_collectors_lock.py"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_collectors_lock as g


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_read_version_extracts_constant():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "x.py"
        _write(f, '"""doc"""\nfrom __future__ import annotations\n__version__ = "2.3.0"\n')
        assert g.read_version(f) == "2.3.0"


def test_read_version_missing_raises():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "x.py"
        _write(f, "x = 1\n")
        try:
            g.read_version(f)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_folder_sha256_deterministic_and_content_sensitive():
    with tempfile.TemporaryDirectory() as d:
        folder = Path(d) / "c"
        _write(folder / "a.py", "print(1)\n")
        h1 = g.folder_sha256(folder)
        assert h1 == g.folder_sha256(folder)
        _write(folder / "a.py", "print(2)\n")
        assert g.folder_sha256(folder) != h1


def test_build_lock_reads_all_versions():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for key, folders, entry, status in g.COLLECTORS:
            for folder in folders:
                (root / folder).mkdir(parents=True, exist_ok=True)
            _write(root / entry, '"""x"""\n__version__ = "9.9.9"\n')
        lock = g.build_lock(root)
        assert lock["schema"] == g.SCHEMA
        assert set(lock["collectors"]) == {c[0] for c in g.COLLECTORS}
        assert lock["collectors"]["fmc"]["version"] == "9.9.9"
        assert "generated_at" not in lock


def test_folder_sha256_missing_folder_raises():
    with tempfile.TemporaryDirectory() as d:
        try:
            g.folder_sha256(Path(d) / "does_not_exist")
            assert False, "expected ValueError"
        except ValueError:
            pass


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t(); print(f"PASS {t.__name__}")
        except Exception as exc:
            failed += 1; print(f"FAIL {t.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
