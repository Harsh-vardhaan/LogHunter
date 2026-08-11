import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO

from loghunter.analysis import analyze_files
from loghunter.cli import main
from loghunter.config import AuthDetectionConfig, DetectionConfig, LoadedConfig, WebDetectionConfig
from loghunter.detection.engine import DetectionEngine
from loghunter.filters import AnalystFilters
from loghunter.models import LogEvent


BASE = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)


def auth_events(count, *, step=1, action="login", statuses=None):
    statuses = statuses or ["failed"] * count
    return [LogEvent(BASE + timedelta(minutes=i * step), "203.0.113.88", "analyst", action, status, "synthetic", "auth") for i, status in enumerate(statuses)]


def web_events(count, status):
    return [LogEvent(BASE + timedelta(seconds=i), "198.51.100.88", None, "http-request", "recorded", "synthetic", "web", http_status=status) for i in range(count)]


def configured_auth(**changes):
    values = AuthDetectionConfig().__dict__ if hasattr(AuthDetectionConfig(), "__dict__") else {
        name: getattr(AuthDetectionConfig(), name) for name in AuthDetectionConfig.__dataclass_fields__
    }
    values.update(changes)
    return DetectionConfig(auth=AuthDetectionConfig(**values))


class ConfiguredDetectionTests(unittest.TestCase):
    def test_default_auth_001_unchanged(self):
        self.assertEqual(DetectionEngine().detect("auth", auth_events(4)), [])

    def test_custom_auth_001_and_auth_002_thresholds(self):
        medium = DetectionEngine(config=configured_auth(failed_medium_threshold=3)).detect("auth", auth_events(3))
        self.assertEqual([item.rule_id for item in medium], ["AUTH-001"])
        high = DetectionEngine(config=configured_auth(failed_medium_threshold=2, failed_high_threshold=3)).detect("auth", auth_events(3))
        self.assertEqual([item.rule_id for item in high], ["AUTH-002"])

    def test_custom_window_changes_correlation(self):
        config = configured_auth(failed_medium_threshold=3, window_minutes=1)
        self.assertEqual(DetectionEngine(config=config).detect("auth", auth_events(3, step=2)), [])

    def test_custom_auth_003_threshold(self):
        config = configured_auth(invalid_user_threshold=2)
        findings = DetectionEngine(config=config).detect("auth", auth_events(2, action="invalid-user-login"))
        self.assertEqual([item.rule_id for item in findings], ["AUTH-003"])

    def test_custom_auth_004_threshold(self):
        config = configured_auth(success_after_failure_threshold=2)
        events = auth_events(3, statuses=["failed", "failed", "success"])
        self.assertEqual([item.rule_id for item in DetectionEngine(config=config).detect("auth", events)], ["AUTH-004"])

    def test_custom_web_thresholds(self):
        config = DetectionConfig(web=WebDetectionConfig(client_error_threshold=2, server_error_threshold=2))
        self.assertEqual([item.rule_id for item in DetectionEngine(config=config).detect("web", web_events(2, 404))], ["WEB-001"])
        self.assertEqual([item.rule_id for item in DetectionEngine(config=config).detect("web", web_events(2, 500))], ["WEB-003"])

    def test_filters_and_multifile_work_with_config(self):
        loaded = LoadedConfig(configured_auth(failed_medium_threshold=4, failed_high_threshold=9), "synthetic-config.json")
        result = analyze_files(["samples/auth_sample.log", "samples/auth_extra.log"], "auth", configuration=loaded, filters=AnalystFilters(rule_id="AUTH-002"), reference_year=2026)
        self.assertTrue(result.all_findings)
        self.assertTrue(all(item.rule_id == "AUTH-002" for item in result.findings))

    def test_cross_file_correlation_respects_custom_window(self):
        loaded = LoadedConfig(configured_auth(failed_medium_threshold=4, window_minutes=1), "synthetic-config.json")
        result = analyze_files(["samples/auth_sample.log", "samples/auth_extra.log"], "auth", configuration=loaded, reference_year=2026)
        self.assertNotIn("192.0.2.11", [item.source_ip for item in result.findings])

    def test_json_configuration_metadata_and_no_detect(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["analyze", "samples/auth_sample.log", "--type", "auth", "--config", "examples/loghunter-config.json", "--no-detect", "--format", "json"]), 0)
        report = json.loads(output.getvalue())
        self.assertFalse(report["analysis"]["detection_enabled"])
        self.assertEqual(report["configuration"]["source"], "examples/loghunter-config.json")
        self.assertEqual(report["configuration"]["effective"]["auth"]["failed_medium_threshold"], 4)

    def test_text_configuration_metadata(self):
        output = StringIO()
        with redirect_stdout(output):
            main(["analyze", "samples/auth_sample.log", "--type", "auth", "--config", "examples/loghunter-config.json", "--severity", "HIGH"])
        self.assertIn("LOGHUNTER 1.0.0", output.getvalue())
        self.assertIn("Configuration: examples/loghunter-config.json (schema 1.0)", output.getvalue())
