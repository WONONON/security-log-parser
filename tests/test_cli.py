from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from security_log_parser.cli import main


class CliTests(unittest.TestCase):
    def test_missing_input_returns_error_code(self) -> None:
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            code = main(["does-not-exist.log"])
        self.assertEqual(2, code)
        self.assertIn("input file not found", error.getvalue())

    def test_exports_json_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "events.log"
            source.write_text(
                "2026-08-01T10:00:00+00:00,alex-demo,SUCCESS,lab-pc-01\n",
                encoding="utf-8",
            )
            output = root / "results"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(source), "--output-dir", str(output)])
            self.assertEqual(0, code)
            self.assertTrue((output / "analysis.json").is_file())
            self.assertTrue((output / "user_summary.csv").is_file())
            self.assertTrue((output / "source_failure_summary.csv").is_file())

    def test_no_failures_creates_source_csv_with_header_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "events.log"
            source.write_text(
                "2026-08-01T10:00:00+00:00,alex-demo,SUCCESS,lab-pc-01\n",
                encoding="utf-8",
            )
            output = root / "results"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(source), "--output-dir", str(output)])
            self.assertEqual(0, code)
            self.assertEqual(
                "source,failed_logins\n",
                (output / "source_failure_summary.csv").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
