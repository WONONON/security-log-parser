"""Summarise events and detect repeated failures."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import timedelta

from .models import LoginEvent


def detect_repeated_failures(
    events: list[LoginEvent], threshold: int, window_minutes: int
) -> list[dict[str, object]]:
    """Return one alert per user who meets the threshold inside the inclusive window.

    If the first and last failures are exactly ``window_minutes`` apart, they are
    inside the window. A sliding deque keeps the operation linear after sorting.
    """
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    failures_by_user: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        if event.status == "FAILURE":
            failures_by_user[event.user].append(event)

    window = timedelta(minutes=window_minutes)
    alerts: list[dict[str, object]] = []
    for user in sorted(failures_by_user):
        recent: deque[LoginEvent] = deque()
        for event in sorted(failures_by_user[user], key=lambda item: item.timestamp):
            recent.append(event)
            while recent and event.timestamp - recent[0].timestamp > window:
                recent.popleft()
            if len(recent) >= threshold:
                alerts.append(
                    {
                        "user": user,
                        "failure_count": len(recent),
                        "window_start": recent[0].timestamp.isoformat(),
                        "window_end": recent[-1].timestamp.isoformat(),
                        "sources": sorted({item.source for item in recent}),
                    }
                )
                break
    return alerts


def analyse_events(
    events: list[LoginEvent], threshold: int, window_minutes: int
) -> dict[str, object]:
    """Build the serialisable analysis result."""
    successes = Counter(event.user for event in events if event.status == "SUCCESS")
    failures = Counter(event.user for event in events if event.status == "FAILURE")
    users = sorted(successes.keys() | failures.keys())
    alerts = detect_repeated_failures(events, threshold, window_minutes)
    alert_by_user = {str(alert["user"]): alert for alert in alerts}

    return {
        "configuration": {
            "threshold": threshold,
            "window_minutes": window_minutes,
            "boundary_rule": "inclusive",
        },
        "summary": {
            "valid_events": len(events),
            "successful_logins": sum(successes.values()),
            "failed_logins": sum(failures.values()),
            "users_with_repeated_failures": len(alerts),
        },
        "users": [
            {
                "user": user,
                "successful_logins": successes[user],
                "failed_logins": failures[user],
                "repeated_failure_detected": user in alert_by_user,
            }
            for user in users
        ],
        "alerts": alerts,
    }

