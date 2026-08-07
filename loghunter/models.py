"""Normalized records shared by parsers and future detection rules."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LogEvent:
    timestamp: str | None
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


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    file_path: str
    log_type: str
    total_lines: int
    parsed_lines: int

    @property
    def unrecognized_lines(self) -> int:
        return self.total_lines - self.parsed_lines
