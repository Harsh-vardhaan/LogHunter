"""Explainable web access-log heuristics."""

from collections.abc import Sequence
from urllib.parse import urlsplit

from ..models import LogEvent
from .base import DetectionRule
from .constants import SENSITIVE_PATHS, WEB_4XX_THRESHOLD, WEB_5XX_THRESHOLD
from .helpers import event_range, group_by_source, source_files
from .models import Finding, Severity


def _status_range(events: Sequence[LogEvent], start: int, end: int) -> list[LogEvent]:
    return [event for event in events if event.log_type == "web" and event.http_status is not None and start <= event.http_status <= end]


class RepeatedClientErrorsRule(DetectionRule):
    rule_id = "WEB-001"
    log_type = "web"
    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        findings = []
        for source_ip, matches in sorted(group_by_source(_status_range(events, 400, 499)).items()):
            if len(matches) >= WEB_4XX_THRESHOLD:
                findings.append(Finding(self.rule_id, "Repeated HTTP Client Errors", Severity.LOW, "web",
                    "Repeated 4xx responses may come from broken links, crawlers, outdated clients, or reconnaissance.",
                    f"{len(matches)} HTTP 4xx responses were associated with {source_ip}.",
                    "Review the requested paths and client behavior to determine whether the errors are expected.",
                    source_ip, None, len(matches), *event_range(matches), source_files=source_files(matches)))
        return findings


class SensitivePathProbingRule(DetectionRule):
    rule_id = "WEB-002"
    log_type = "web"
    @staticmethod
    def _sensitive(path: str | None) -> bool:
        if not path:
            return False
        normalized = urlsplit(path).path.lower()
        return any(
            normalized == item.rstrip("/") or normalized.startswith(item.rstrip("/") + "/")
            for item in SENSITIVE_PATHS
        )

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        matches = [event for event in events if event.log_type == "web" and self._sensitive(event.path)]
        findings = []
        for source_ip, source_events in sorted(group_by_source(matches).items()):
            paths = sorted({urlsplit(event.path or "").path.lower() for event in source_events})
            findings.append(Finding(self.rule_id, "Potential Sensitive-Path Probing", Severity.MEDIUM, "web",
                "Requests matched a small case-insensitive list of sensitive paths; security testing, accidental requests, or reconnaissance are possible explanations.",
                f"{len(source_events)} matching requests from {source_ip}; paths: {', '.join(paths)}.",
                "Review the requests and application exposure, and verify whether the activity was authorized or expected.",
                source_ip, None, len(source_events), *event_range(source_events), source_files=source_files(source_events)))
        return findings


class RepeatedServerErrorsRule(DetectionRule):
    rule_id = "WEB-003"
    log_type = "web"
    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        findings = []
        for source_ip, matches in sorted(group_by_source(_status_range(events, 500, 599)).items()):
            if len(matches) >= WEB_5XX_THRESHOLD:
                findings.append(Finding(self.rule_id, "Repeated HTTP Server Errors", Severity.MEDIUM, "web",
                    "Repeated 5xx responses may reflect application problems, malformed requests, unusual clients, or possible probing.",
                    f"{len(matches)} HTTP 5xx responses were associated with {source_ip}.",
                    "Review application health and the associated requests to identify the cause of the server errors.",
                    source_ip, None, len(matches), *event_range(matches), source_files=source_files(matches)))
        return findings


WEB_RULES = (RepeatedClientErrorsRule(), SensitivePathProbingRule(), RepeatedServerErrorsRule())
