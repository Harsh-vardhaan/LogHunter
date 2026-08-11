"""Explainable, time-aware authentication heuristics."""

from collections.abc import Sequence
from datetime import timedelta

from ..config import AuthDetectionConfig, DEFAULT_CONFIG
from ..models import LogEvent
from .base import DetectionRule
from .helpers import dominant_username, event_range, group_by_source, source_files
from .models import Finding, Severity
from .time_utils import first_threshold_window, group_by_source_and_username


def _failed(events: Sequence[LogEvent]) -> list[LogEvent]:
    return [event for event in events if event.log_type == "auth" and event.status == "failed"]


class RepeatedFailedAuthenticationRule(DetectionRule):
    rule_id = "AUTH-001"
    log_type = "auth"

    def __init__(self, config: AuthDetectionConfig | None = None) -> None:
        self.config = config or DEFAULT_CONFIG.auth

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        window = timedelta(minutes=self.config.window_minutes)
        findings = []
        for source_ip, matches in sorted(group_by_source(_failed(events)).items()):
            window_events = first_threshold_window(matches, self.config.failed_medium_threshold, window)
            high_window = first_threshold_window(matches, self.config.failed_high_threshold, window)
            if window_events and not high_window:
                first, last = event_range(window_events)
                findings.append(Finding(
                    self.rule_id, "Repeated Failed Authentication Attempts", Severity.MEDIUM, "authentication",
                    "Repeated failures within a short period may reflect mistyped credentials, stale automation, misconfiguration, or password guessing.",
                    f"{len(window_events)} failed authentication events from {source_ip} reached the threshold within {self.config.window_minutes} minutes.",
                    "Review authentication activity from this source, verify whether attempts are expected, and apply appropriate access controls if unauthorized.",
                    source_ip, dominant_username(window_events), len(window_events), first, last,
                    source_files=source_files(window_events),
                ))
        return findings


class PotentialBruteForceRule(DetectionRule):
    rule_id = "AUTH-002"
    log_type = "auth"

    def __init__(self, config: AuthDetectionConfig | None = None) -> None:
        self.config = config or DEFAULT_CONFIG.auth

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        window = timedelta(minutes=self.config.window_minutes)
        findings = []
        for source_ip, matches in sorted(group_by_source(_failed(events)).items()):
            window_events = first_threshold_window(matches, self.config.failed_high_threshold, window)
            if window_events:
                first, last = event_range(window_events)
                findings.append(Finding(
                    self.rule_id, "Potential Brute-Force Authentication Pattern", Severity.HIGH, "authentication",
                    f"A high volume of failures from one source within {self.config.window_minutes} minutes matched a heuristic pattern; this is not proof of compromise.",
                    f"{len(window_events)} failed authentication events were correlated for {source_ip}.",
                    "Review the source and associated account activity, verify whether attempts are expected, and consider appropriate authentication controls.",
                    source_ip, dominant_username(window_events), len(window_events), first, last,
                    source_files=source_files(window_events),
                ))
        return findings


class RepeatedInvalidUserRule(DetectionRule):
    rule_id = "AUTH-003"
    log_type = "auth"

    def __init__(self, config: AuthDetectionConfig | None = None) -> None:
        self.config = config or DEFAULT_CONFIG.auth

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        window = timedelta(minutes=self.config.window_minutes)
        invalid = [event for event in events if event.log_type == "auth" and event.action == "invalid-user-login"]
        findings = []
        for source_ip, matches in sorted(group_by_source(invalid).items()):
            window_events = first_threshold_window(matches, self.config.invalid_user_threshold, window)
            if window_events:
                names = sorted({event.username for event in window_events if event.username})
                findings.append(Finding(
                    self.rule_id, "Repeated Invalid-User Authentication Attempts", Severity.MEDIUM, "authentication",
                    "Invalid-user attempts within a short period may indicate enumeration, automated guessing, or a misconfigured legitimate service.",
                    f"{len(window_events)} invalid-user events from {source_ip}; attempted usernames: {', '.join(names)}.",
                    "Review the source and attempted usernames, confirm whether behavior is legitimate, and apply appropriate authentication controls if necessary.",
                    source_ip, None, len(window_events), *event_range(window_events),
                    source_files=source_files(window_events),
                ))
        return findings


class SuccessAfterFailuresRule(DetectionRule):
    rule_id = "AUTH-004"
    log_type = "auth"

    def __init__(self, config: AuthDetectionConfig | None = None) -> None:
        self.config = config or DEFAULT_CONFIG.auth

    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        window = timedelta(minutes=self.config.window_minutes)
        auth_events = [event for event in events if event.log_type == "auth"]
        findings = []
        for (source_ip, username), matches in sorted(group_by_source_and_username(auth_events).items(), key=lambda item: (item[0][0], item[0][1] or "")):
            failures: list[LogEvent] = []
            for current in matches:
                if current.status == "failed":
                    failures.append(current)
                    continue
                if current.status != "success":
                    continue
                recent = [failure for failure in failures if current.timestamp - failure.timestamp <= window]
                if len(recent) >= self.config.success_after_failure_threshold:
                    correlated = recent[-self.config.success_after_failure_threshold:] + [current]
                    findings.append(Finding(
                        self.rule_id, "Successful Authentication After Repeated Failures", Severity.HIGH, "authentication",
                        "A successful authentication was observed after repeated failures from the same source and username within a short period. This warrants review but does not prove account compromise.",
                        f"{self.config.success_after_failure_threshold} failures followed by a success were correlated within {self.config.window_minutes} minutes.",
                        "Review the source IP, affected account, and surrounding authentication logs; verify the login was legitimate and rotate credentials only if the investigation supports it.",
                        source_ip, username, len(correlated), *event_range(correlated),
                        source_files=source_files(correlated),
                    ))
                    break
        return findings


def build_auth_rules(config: AuthDetectionConfig | None = None) -> tuple[DetectionRule, ...]:
    effective = config or DEFAULT_CONFIG.auth
    return (
        PotentialBruteForceRule(effective), SuccessAfterFailuresRule(effective),
        RepeatedFailedAuthenticationRule(effective), RepeatedInvalidUserRule(effective),
    )


AUTH_RULES = build_auth_rules()
