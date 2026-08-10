"""Explainable authentication heuristics."""

from collections.abc import Sequence

from ..models import LogEvent
from .base import DetectionRule
from .constants import FAILED_AUTH_HIGH_THRESHOLD, FAILED_AUTH_MEDIUM_THRESHOLD, INVALID_USER_THRESHOLD
from .helpers import dominant_username, event_range, group_by_source
from .models import Finding, Severity


def _failed(events: Sequence[LogEvent]) -> list[LogEvent]:
    return [event for event in events if event.log_type == "auth" and event.status == "failed"]


class RepeatedFailedAuthenticationRule(DetectionRule):
    rule_id = "AUTH-001"
    log_type = "auth"

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        findings = []
        for source_ip, matches in sorted(group_by_source(_failed(events)).items()):
            if FAILED_AUTH_MEDIUM_THRESHOLD <= len(matches) < FAILED_AUTH_HIGH_THRESHOLD:
                first, last = event_range(matches)
                findings.append(Finding(
                    self.rule_id, "Repeated Failed Authentication Attempts", Severity.MEDIUM, "authentication",
                    "Repeated failures may reflect mistyped credentials, stale automation, misconfiguration, or password guessing.",
                    f"{len(matches)} failed authentication events were observed from {source_ip}.",
                    "Review authentication activity from this source, verify whether attempts are expected, and apply appropriate access controls if unauthorized.",
                    source_ip, dominant_username(matches), len(matches), first, last,
                ))
        return findings


class PotentialBruteForceRule(DetectionRule):
    rule_id = "AUTH-002"
    log_type = "auth"

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        findings = []
        for source_ip, matches in sorted(group_by_source(_failed(events)).items()):
            if len(matches) >= FAILED_AUTH_HIGH_THRESHOLD:
                first, last = event_range(matches)
                findings.append(Finding(
                    self.rule_id, "Potential Brute-Force Authentication Pattern", Severity.HIGH, "authentication",
                    "A high volume of failures from one source matched a heuristic pattern; this is not proof of compromise.",
                    f"{len(matches)} failed authentication events were observed from {source_ip}.",
                    "Review the source and associated account activity, verify whether attempts are expected, and consider appropriate authentication controls.",
                    source_ip, dominant_username(matches), len(matches), first, last,
                ))
        return findings


class RepeatedInvalidUserRule(DetectionRule):
    rule_id = "AUTH-003"
    log_type = "auth"

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        invalid = [event for event in events if event.log_type == "auth" and event.action == "invalid-user-login"]
        findings = []
        for source_ip, matches in sorted(group_by_source(invalid).items()):
            if len(matches) >= INVALID_USER_THRESHOLD:
                names = sorted({event.username for event in matches if event.username})
                findings.append(Finding(
                    self.rule_id, "Repeated Invalid-User Authentication Attempts", Severity.MEDIUM, "authentication",
                    "Invalid-user attempts may indicate enumeration, automated guessing, or a misconfigured legitimate service.",
                    f"{len(matches)} invalid-user events from {source_ip}; attempted usernames: {', '.join(names)}.",
                    "Review the source and attempted usernames, confirm whether behavior is legitimate, and apply appropriate authentication controls if necessary.",
                    source_ip, None, len(matches), *event_range(matches),
                ))
        return findings


AUTH_RULES = (PotentialBruteForceRule(), RepeatedFailedAuthenticationRule(), RepeatedInvalidUserRule())
