import unittest
from datetime import datetime, timezone

from loghunter.detection.auth_rules import PotentialBruteForceRule, RepeatedFailedAuthenticationRule, RepeatedInvalidUserRule
from loghunter.detection.engine import DetectionEngine
from loghunter.models import LogEvent


def auth_event(ip="192.0.2.10", status="failed", action="login", username="demo-user"):
    return LogEvent(datetime(2026, 1, 15, 9, tzinfo=timezone.utc), ip, username, action, status, "synthetic", "auth")


class AuthDetectionTests(unittest.TestCase):
    def test_auth_001_below_threshold(self):
        self.assertEqual(RepeatedFailedAuthenticationRule().evaluate([auth_event() for _ in range(4)]), [])

    def test_auth_001_at_threshold(self):
        result = RepeatedFailedAuthenticationRule().evaluate([auth_event() for _ in range(5)])
        self.assertEqual((result[0].rule_id, result[0].event_count), ("AUTH-001", 5))

    def test_auth_002_below_threshold(self):
        self.assertEqual(PotentialBruteForceRule().evaluate([auth_event() for _ in range(9)]), [])

    def test_auth_002_at_threshold(self):
        result = PotentialBruteForceRule().evaluate([auth_event() for _ in range(10)])
        self.assertEqual((result[0].rule_id, result[0].severity.value), ("AUTH-002", "HIGH"))

    def test_auth_002_suppresses_auth_001(self):
        result = DetectionEngine().detect("auth", [auth_event() for _ in range(10)])
        self.assertEqual([item.rule_id for item in result], ["AUTH-002"])

    def test_auth_003_threshold(self):
        events = [auth_event(action="invalid-user-login", username=f"guest-{number}") for number in range(3)]
        result = RepeatedInvalidUserRule().evaluate(events)
        self.assertEqual((result[0].rule_id, result[0].event_count), ("AUTH-003", 3))

    def test_sources_are_independent(self):
        events = [auth_event("192.0.2.1") for _ in range(4)] + [auth_event("192.0.2.2") for _ in range(4)]
        self.assertEqual(RepeatedFailedAuthenticationRule().evaluate(events), [])

    def test_successes_do_not_count(self):
        events = [auth_event(status="success") for _ in range(10)]
        self.assertEqual(DetectionEngine().detect("auth", events), [])
