"""Windows console encoding regressions. No network.

Run from cisco/fmc:
  python -B -m unittest -v test_safe_stdio
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from pathlib import Path

from safe_stdio import configure_stdio, safe_print

HERE = Path(__file__).resolve().parent
ARROW = "Done in 128.3s \u2192 run-20260919-152907"


class _Cp1252Stream:
    encoding = "cp1252"

    def __init__(self) -> None:
        self.chunks: list[str] = []

    def write(self, s: str) -> int:
        s.encode(self.encoding)
        self.chunks.append(s)
        return len(s)

    def flush(self) -> None:
        return None


class SafeStdioTests(unittest.TestCase):
    def test_cp1252_rejects_the_collect_arrow(self):
        with self.assertRaises(UnicodeEncodeError):
            ARROW.encode("cp1252")

    def test_safe_print_replaces_instead_of_raising(self):
        stream = _Cp1252Stream()
        safe_print(ARROW, file=stream)
        written = "".join(stream.chunks)
        self.assertIn("Done in 128.3s", written)
        self.assertNotIn("\u2192", written)
        self.assertIn("run-20260919-152907", written)

    def test_configure_stdio_is_idempotent_on_stringio(self):
        original = sys.stdout
        sys.stdout = io.StringIO()
        try:
            configure_stdio()
            safe_print(ARROW)
            self.assertIn("\u2192", sys.stdout.getvalue())
        finally:
            sys.stdout = original

    def test_subprocess_cp1252_arrow_exits_zero(self):
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "cp1252"
        env.pop("PYTHONUTF8", None)
        script = (
            "from safe_stdio import configure_stdio, safe_print; "
            "configure_stdio(); "
            "safe_print('Done in 1.0s \\u2192 run')"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(HERE),
            env=env,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("ascii", errors="replace"))
        stdout = result.stdout.decode("utf-8", errors="replace")
        self.assertIn("Done in 1.0s", stdout)


if __name__ == "__main__":
    unittest.main()
