import unittest
from datetime import datetime, timezone

from loghunter.detection.engine import DetectionEngine
from loghunter.detection.models import Finding, Severity
from loghunter.models import LogEvent


def event(log_type="auth", ip="192.0.2.1", status="failed", action="login", http_status=None, path=None):
    return LogEvent(datetime(2026, 1, 15, 9, tzinfo=timezone.utc), ip, "demo-user", action, status, "synthetic", log_type,
                    path=path, http_status=http_status)


class FindingModelTests(unittest.TestCase):
    def test_finding_validation(self):
        with self.assertRaises(ValueError):
            Finding("", "Title", Severity.LOW, "test", "description", "evidence", "recommendation")
        with self.assertRaises(ValueError):
            Finding("TEST-001", "Title", Severity.LOW, "test", "description", "evidence", "recommendation", event_count=0)
        with self.assertRaises(TypeError):
            Finding("TEST-001", "Title", "HIGH", "test", "description", "evidence", "recommendation")

    def test_severity_ordering(self):
        events = [event(ip="192.0.2.1") for _ in range(10)]
        events += [event(ip="192.0.2.2", action="invalid-user-login") for _ in range(3)]
        severities = [finding.severity for finding in DetectionEngine().detect("auth", events)]
        self.assertEqual(severities, [Severity.HIGH, Severity.MEDIUM])

    def test_engine_chooses_rules_by_type(self):
        auth = DetectionEngine().detect("auth", [event() for _ in range(5)])
        web = DetectionEngine().detect("web", [event() for _ in range(5)])
        self.assertTrue(all(item.rule_id.startswith("AUTH-") for item in auth))
        self.assertEqual(web, [])

    def test_no_findings(self):
        self.assertEqual(DetectionEngine().detect("auth", [event(status="success")]), [])

    def test_unsupported_log_type(self):
        with self.assertRaises(ValueError):
            DetectionEngine().detect("unknown", [])
