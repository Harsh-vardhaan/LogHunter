"""Normalized records shared by parsers and future detection rules."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class LogEvent:
    timestamp: datetime | None
    source_ip: str | None
    username: str | None
    action: str
    status: str
    raw_line: str
    log_type: str
    http_method: str | None = None
    path: str | None = None
    http_status: int | None = None
    user_agent: str | None = None

    def __post_init__(self) -> None:
        if self.timestamp is not None:
            if not isinstance(self.timestamp, datetime):
                raise TypeError("timestamp must be a datetime or None")
            if self.timestamp.utcoffset() is None:
                raise ValueError("timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    file_path: str
    log_type: str
    total_lines: int
    parsed_lines: int

    @property
    def unrecognized_lines(self) -> int:
        return self.total_lines - self.parsed_lines
