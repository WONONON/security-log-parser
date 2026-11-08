from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from security_log_parser.parser import parse_stream, read_log


class ParserTests(unittest.TestCase):
    def test_normal_input(self) -> None:
        text = (
            "timestamp,user,status,source\n"
            "2026-08-01T10:00:00+10:00,alex-demo,SUCCESS,lab-pc-01\n"
            "2026-08-01T10:01:00+10:00,alex-demo,FAILURE,lab-pc-01\n"
        )
        events, warnings = parse_stream(io.StringIO(text))
        self.assertEqual(2, len(events))
        self.assertEqual("SUCCESS", events[0].status)
        self.assertEqual([], warnings)

    def test_empty_input(self) -> None:
        events, warnings = parse_stream(io.StringIO(""))
        self.assertEqual([], events)
        self.assertEqual([], warnings)

    def test_malformed_lines_are_skipped_and_reported(self) -> None:
        text = (
            "not-a-time,alex-demo,FAILURE,lab-pc-01\n"
            "2026-08-01T10:00:00+10:00,alex-demo,UNKNOWN,lab-pc-01\n"
            "2026-08-01T10:00:00+10:00,too,few\n"
            "2026-08-01T10:00:00+10:00,alex-demo,SUCCESS,lab-pc-01\n"
        )
        events, warnings = parse_stream(io.StringIO(text))
        self.assertEqual(1, len(events))
        self.assertEqual(3, len(warnings))
        self.assertEqual([1, 2, 3], [warning.line_number for warning in warnings])

    def test_naive_timestamp_is_rejected(self) -> None:
        events, warnings = parse_stream(
            io.StringIO("2026-08-01T10:00:00,alex-demo,SUCCESS,lab-pc-01\n")
        )
        self.assertEqual([], events)
        self.assertIn("UTC offset", warnings[0].message)

    def test_missing_file_raises_file_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.log"
            with self.assertRaises(FileNotFoundError):
                read_log(missing)


if __name__ == "__main__":
    unittest.main()

