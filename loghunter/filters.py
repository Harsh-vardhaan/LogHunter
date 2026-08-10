"""Analyst-facing finding filters applied after detection."""

from dataclasses import dataclass
from ipaddress import ip_address

from .detection.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class AnalystFilters:
    severity: Severity | None = None
    rule_id: str | None = None
    source_ip: str | None = None

    @property
    def active(self) -> bool:
        return any((self.severity, self.rule_id, self.source_ip))


def apply_filters(findings: list[Finding], filters: AnalystFilters) -> list[Finding]:
    """Return a filtered view without altering the underlying findings."""
    return [
        finding for finding in findings
        if (filters.severity is None or finding.severity is filters.severity)
        and (filters.rule_id is None or finding.rule_id == filters.rule_id)
        and (filters.source_ip is None or finding.source_ip == filters.source_ip)
    ]


def normalize_ip(value: str) -> str:
    """Validate IPv4/IPv6 syntax while preserving exact filter text."""
    ip_address(value)
    return value
