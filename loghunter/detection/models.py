"""Normalized, immutable security finding models."""

from dataclasses import dataclass
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
    first_seen: str | None = None
    last_seen: str | None = None

    def __post_init__(self) -> None:
        if not self.rule_id or not self.title:
            raise ValueError("A finding requires a rule ID and title")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity value")
        if self.event_count < 1:
            raise ValueError("event_count must be at least 1")
