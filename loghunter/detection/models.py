"""Normalized, immutable security finding models."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def sort_rank(self) -> int:
        return {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}[self]


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence_summary: str
    recommendation: str
    source_ip: str | None = None
    username: str | None = None
    event_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.rule_id or not self.title:
            raise ValueError("A finding requires a rule ID and title")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity value")
        if self.event_count < 1:
            raise ValueError("event_count must be at least 1")
        for name, value in (("first_seen", self.first_seen), ("last_seen", self.last_seen)):
            if value is not None:
                if not isinstance(value, datetime):
                    raise TypeError(f"{name} must be a datetime or None")
                if value.utcoffset() is None:
                    raise ValueError(f"{name} must be timezone-aware")
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("first_seen cannot be later than last_seen")
        if tuple(sorted(set(self.source_files))) != self.source_files:
            raise ValueError("source_files must be unique and sorted")
