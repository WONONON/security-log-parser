"""Write analysis results to JSON and CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import ParseWarning

SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _safe_csv_value(value: object) -> object:
    """Prevent spreadsheet applications from interpreting text as a formula."""
    if isinstance(value, str) and value.startswith(SPREADSHEET_FORMULA_PREFIXES):
        return "'" + value
    return value


def _safe_csv_row(row: dict[str, object]) -> dict[str, object]:
    return {key: _safe_csv_value(value) for key, value in row.items()}


def export_json(
    result: dict[str, object], warnings: list[ParseWarning], output_path: Path
) -> None:
    payload = dict(result)
    payload["malformed_lines"] = [
        {
            "line_number": warning.line_number,
            "message": warning.message,
            "content": warning.content,
        }
        for warning in warnings
    ]
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def export_csv(result: dict[str, object], output_path: Path) -> None:
    alerts = {str(item["user"]): item for item in result["alerts"]}  # type: ignore[index]
    fieldnames = [
        "user",
        "successful_logins",
        "failed_logins",
        "repeated_failure_detected",
        "window_start",
        "window_end",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in result["users"]:  # type: ignore[assignment]
            user = str(row["user"])
            alert = alerts.get(user, {})
            writer.writerow(
                _safe_csv_row({
                    **row,
                    "window_start": alert.get("window_start", ""),
                    "window_end": alert.get("window_end", ""),
                })
            )


def export_source_csv(result: dict[str, object], output_path: Path) -> None:
    """Write one row for each source that has at least one failed login."""
    fieldnames = ["source", "failed_logins"]
    with output_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in result["sources"]:  # type: ignore[assignment]
            writer.writerow(_safe_csv_row(row))
