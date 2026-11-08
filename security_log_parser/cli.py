"""Command-line interface for Security Log Parser."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analysis import analyse_events
from .exporters import export_csv, export_json, export_source_csv
from .parser import read_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-log-parser",
        description="Analyse fictional CSV login logs and export JSON and CSV reports.",
    )
    parser.add_argument("input", type=Path, help="path to the login log")
    parser.add_argument(
        "--threshold", type=int, default=3, help="failures required for an alert (default: 3)"
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="inclusive detection window in minutes (default: 10)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("results"), help="report directory"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.threshold < 2:
        print("error: --threshold must be at least 2", file=sys.stderr)
        return 2
    if args.window_minutes < 1:
        print("error: --window-minutes must be at least 1", file=sys.stderr)
        return 2

    try:
        events, warnings = read_log(args.input)
    except FileNotFoundError:
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not read {args.input}: {exc}", file=sys.stderr)
        return 2

    result = analyse_events(events, args.threshold, args.window_minutes)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "analysis.json"
    csv_path = args.output_dir / "user_summary.csv"
    source_csv_path = args.output_dir / "source_failure_summary.csv"
    export_json(result, warnings, json_path)
    export_csv(result, csv_path)
    export_source_csv(result, source_csv_path)

    summary = result["summary"]
    print("Security Log Parser")
    print(f"Input: {args.input}")
    print(f"Valid events: {summary['valid_events']}")
    print(f"Successful logins: {summary['successful_logins']}")
    print(f"Failed logins: {summary['failed_logins']}")
    print("Failures by user:")
    users = result["users"]
    if users:
        for row in users:
            print(f"  {row['user']}: {row['failed_logins']}")
    else:
        print("  none")
    print("Failures by source:")
    sources = result["sources"]
    if sources:
        for row in sources:
            print(f"  {row['source']}: {row['failed_logins']}")
    else:
        print("  none")
    print(
        f"Repeated failures: threshold={args.threshold}, "
        f"window={args.window_minutes} minutes (inclusive boundary)"
    )
    alerts = result["alerts"]
    if alerts:
        for alert in alerts:
            print(
                f"  ALERT {alert['user']}: {alert['failure_count']} failures "
                f"from {alert['window_start']} to {alert['window_end']}"
            )
    else:
        print("  none")
    print(f"Malformed lines skipped: {len(warnings)}")
    for warning in warnings:
        print(
            f"warning: line {warning.line_number}: {warning.message}", file=sys.stderr
        )
    print(f"JSON: {json_path}")
    print(f"User CSV: {csv_path}")
    print(f"Source CSV: {source_csv_path}")
    return 0
