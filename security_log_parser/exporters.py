"""Write analysis results to JSON and CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import ParseWarning


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
                {
                    **row,
                    "window_start": alert.get("window_start", ""),
                    "window_end": alert.get("window_end", ""),
                }
            )

