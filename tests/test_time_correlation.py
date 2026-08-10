import unittest
from datetime import datetime, timedelta, timezone

from loghunter.detection.auth_rules import PotentialBruteForceRule, RepeatedFailedAuthenticationRule, SuccessAfterFailuresRule
from loghunter.detection.engine import DetectionEngine
from loghunter.models import LogEvent


BASE = datetime(2026, 8, 10, 12, tzinfo=timezone.utc)


def auth_event(minute, ip="203.0.113.50", username="demo-user", status="failed"):
    return LogEvent(BASE + timedelta(minutes=minute), ip, username, "login", status, "synthetic", "auth")


class TimeCorrelationTests(unittest.TestCase):
    def test_auth_001_below_window_threshold(self):
        self.assertEqual(RepeatedFailedAuthenticationRule().evaluate([auth_event(i) for i in range(4)]), [])

    def test_auth_001_at_threshold_in_window(self):
        finding = RepeatedFailedAuthenticationRule().evaluate([auth_event(i) for i in range(5)])[0]
        self.assertEqual((finding.rule_id, finding.first_seen, finding.last_seen), ("AUTH-001", BASE, BASE + timedelta(minutes=4)))

    def test_auth_001_outside_window(self):
        self.assertEqual(RepeatedFailedAuthenticationRule().evaluate([auth_event(i * 11) for i in range(5)]), [])

    def test_auth_002_at_threshold_in_window(self):
        finding = PotentialBruteForceRule().evaluate([auth_event(i) for i in range(10)])[0]
        self.assertEqual((finding.rule_id, finding.severity.value), ("AUTH-002", "HIGH"))

    def test_auth_002_outside_window(self):
        self.assertEqual(PotentialBruteForceRule().evaluate([auth_event(i * 11) for i in range(10)]), [])

    def test_auth_002_suppresses_auth_001(self):
        rule_ids = [finding.rule_id for finding in DetectionEngine().detect("auth", [auth_event(i) for i in range(10)])]
        self.assertEqual(rule_ids, ["AUTH-002"])

    def test_auth_004_failures_then_success(self):
        events = [auth_event(i) for i in range(5)] + [auth_event(5, status="success")]
        finding = SuccessAfterFailuresRule().evaluate(events)[0]
        self.assertEqual((finding.rule_id, finding.event_count), ("AUTH-004", 6))

    def test_auth_004_outside_window(self):
        events = [auth_event(i) for i in range(5)] + [auth_event(20, status="success")]
        self.assertEqual(SuccessAfterFailuresRule().evaluate(events), [])

    def test_auth_004_success_before_failures(self):
        events = [auth_event(0, status="success")] + [auth_event(i) for i in range(1, 6)]
        self.assertEqual(SuccessAfterFailuresRule().evaluate(events), [])

    def test_auth_004_different_source(self):
        events = [auth_event(i) for i in range(5)] + [auth_event(5, ip="203.0.113.51", status="success")]
        self.assertEqual(SuccessAfterFailuresRule().evaluate(events), [])

    def test_auth_004_different_username(self):
        events = [auth_event(i) for i in range(5)] + [auth_event(5, username="analyst", status="success")]
        self.assertEqual(SuccessAfterFailuresRule().evaluate(events), [])

    def test_events_without_timestamps_are_excluded(self):
        events = [LogEvent(None, "203.0.113.50", "demo-user", "login", "failed", "synthetic", "auth") for _ in range(10)]
        self.assertEqual(DetectionEngine().detect("auth", events), [])
