import unittest

from loghunter.detection.web_rules import RepeatedClientErrorsRule, RepeatedServerErrorsRule, SensitivePathProbingRule
from loghunter.models import LogEvent


def web_event(ip="198.51.100.10", status=200, path="/index.html"):
    return LogEvent("15/Jan/2026:09:00:01 +0000", ip, None, "http-request", "recorded", "synthetic", "web",
                    http_method="GET", path=path, http_status=status)


class WebDetectionTests(unittest.TestCase):
    def test_web_001_threshold(self):
        self.assertEqual(RepeatedClientErrorsRule().evaluate([web_event(status=404) for _ in range(7)]), [])
        result = RepeatedClientErrorsRule().evaluate([web_event(status=404) for _ in range(8)])
        self.assertEqual((result[0].rule_id, result[0].event_count), ("WEB-001", 8))

    def test_web_002_sensitive_paths_case_insensitive(self):
        result = SensitivePathProbingRule().evaluate([web_event(path="/WP-ADMIN?demo=1", status=404)])
        self.assertEqual(result[0].rule_id, "WEB-002")

    def test_web_002_normal_path(self):
        self.assertEqual(SensitivePathProbingRule().evaluate([web_event(path="/administrator-guide")]), [])

    def test_web_003_threshold(self):
        self.assertEqual(RepeatedServerErrorsRule().evaluate([web_event(status=500) for _ in range(4)]), [])
        result = RepeatedServerErrorsRule().evaluate([web_event(status=500) for _ in range(5)])
        self.assertEqual((result[0].rule_id, result[0].event_count), ("WEB-003", 5))

    def test_sources_are_independent(self):
        events = [web_event("198.51.100.1", 404) for _ in range(4)] + [web_event("198.51.100.2", 404) for _ in range(4)]
        self.assertEqual(RepeatedClientErrorsRule().evaluate(events), [])

    def test_non_web_events_do_not_enter_detection(self):
        event = LogEvent("Jan 15 09:00:01", "198.51.100.10", "demo-user", "login", "failed", "synthetic", "auth", path="/.env", http_status=404)
        self.assertEqual(SensitivePathProbingRule().evaluate([event]), [])
