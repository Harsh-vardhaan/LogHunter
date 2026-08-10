"""Deterministic orchestration of applicable detection rules."""

from collections.abc import Mapping, Sequence

from ..models import LogEvent
from .auth_rules import AUTH_RULES
from .base import DetectionRule
from .models import Finding
from .web_rules import WEB_RULES

KNOWN_RULE_IDS = frozenset(rule.rule_id for rule in (*AUTH_RULES, *WEB_RULES))


class DetectionEngine:
    def __init__(self, rules: Mapping[str, Sequence[DetectionRule]] | None = None) -> None:
        self._rules = dict(rules or {"auth": AUTH_RULES, "web": WEB_RULES})

    def detect(self, log_type: str, events: Sequence[LogEvent]) -> list[Finding]:
        if log_type not in self._rules:
            raise ValueError(f"Unsupported detection log type: {log_type}")
        findings = [finding for rule in self._rules[log_type] for finding in rule.evaluate(events)]
        return sorted(findings, key=lambda item: (
            item.severity.sort_rank, item.rule_id, item.source_ip or "", item.username or ""
        ))
