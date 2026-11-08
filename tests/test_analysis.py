from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from security_log_parser.analysis import analyse_events, detect_repeated_failures
from security_log_parser.models import LoginEvent


def event(minute: int, status: str = "FAILURE", user: str = "alex-demo") -> LoginEvent:
    start = datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
    return LoginEvent(start + timedelta(minutes=minute), user, status, "lab-pc-01")


class AnalysisTests(unittest.TestCase):
    def test_counts_success_and_failure_by_user(self) -> None:
        result = analyse_events(
            [event(0, "SUCCESS"), event(1), event(2, user="river-demo")], 3, 10
        )
        self.assertEqual(1, result["summary"]["successful_logins"])
        self.assertEqual(2, result["summary"]["failed_logins"])
        self.assertEqual(1, result["users"][0]["failed_logins"])

    def test_threshold_is_detected(self) -> None:
        alerts = detect_repeated_failures([event(0), event(3), event(8)], 3, 10)
        self.assertEqual(1, len(alerts))
        self.assertEqual("alex-demo", alerts[0]["user"])

    def test_below_threshold_is_not_detected(self) -> None:
        self.assertEqual([], detect_repeated_failures([event(0), event(3)], 3, 10))

    def test_exact_time_boundary_is_inclusive(self) -> None:
        alerts = detect_repeated_failures([event(0), event(5), event(10)], 3, 10)
        self.assertEqual(1, len(alerts))

    def test_just_outside_time_boundary_is_excluded(self) -> None:
        alerts = detect_repeated_failures([event(0), event(5), event(11)], 3, 10)
        self.assertEqual([], alerts)

    def test_out_of_order_events_are_sorted(self) -> None:
        alerts = detect_repeated_failures([event(8), event(0), event(3)], 3, 10)
        self.assertEqual(1, len(alerts))

    def test_invalid_configuration_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            detect_repeated_failures([], 1, 10)
        with self.assertRaises(ValueError):
            detect_repeated_failures([], 3, 0)


if __name__ == "__main__":
    unittest.main()

