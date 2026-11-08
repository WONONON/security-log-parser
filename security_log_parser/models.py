"""Data models used by the parser and analysis functions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LoginEvent:
    """A validated login event from one input line."""

    timestamp: datetime
    user: str
    status: str
    source: str


@dataclass(frozen=True)
class ParseWarning:
    """A non-fatal problem found while reading a line."""

    line_number: int
    message: str
    content: str
