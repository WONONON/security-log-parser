"""Parse fictional login logs without third-party dependencies."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import TextIO

from .models import LoginEvent, ParseWarning

EXPECTED_FIELDS = 4
VALID_STATUSES = {"SUCCESS", "FAILURE"}


def parse_stream(stream: TextIO) -> tuple[list[LoginEvent], list[ParseWarning]]:
    """Parse a CSV stream, skipping blank, comment, header, and malformed lines."""
    events: list[LoginEvent] = []
    warnings: list[ParseWarning] = []

    for line_number, raw_line in enumerate(stream, start=1):
        content = raw_line.rstrip("\n\r")
        stripped = content.strip()
        if not stripped or stripped.startswith("#"):
            continue

        try:
            fields = next(csv.reader([content], skipinitialspace=True))
        except csv.Error as exc:
            warnings.append(ParseWarning(line_number, f"invalid CSV: {exc}", content))
            continue

        if line_number == 1 and [item.strip().lower() for item in fields] == [
            "timestamp",
            "user",
            "status",
            "source",
        ]:
            continue

        if len(fields) != EXPECTED_FIELDS:
            warnings.append(
                ParseWarning(
                    line_number,
                    f"expected {EXPECTED_FIELDS} fields, found {len(fields)}",
                    content,
                )
            )
            continue

        timestamp_text, user, status, source = (item.strip() for item in fields)
        if not user or not source:
            warnings.append(ParseWarning(line_number, "user and source must not be empty", content))
            continue

        status = status.upper()
        if status not in VALID_STATUSES:
            warnings.append(
                ParseWarning(line_number, "status must be SUCCESS or FAILURE", content)
            )
            continue

        try:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        except ValueError:
            warnings.append(ParseWarning(line_number, "timestamp is not valid ISO 8601", content))
            continue

        if timestamp.tzinfo is None:
            warnings.append(ParseWarning(line_number, "timestamp must include a UTC offset", content))
            continue

        events.append(LoginEvent(timestamp, user, status, source))

    return events, warnings


def read_log(path: str | Path) -> tuple[list[LoginEvent], list[ParseWarning]]:
    """Read and parse a UTF-8 login log.

    FileNotFoundError and other OSError values are intentionally allowed to reach
    the CLI, which reports them clearly and exits with a non-zero status.
    """
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        return parse_stream(stream)

