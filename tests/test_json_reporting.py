import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from loghunter.cli import main


class JsonReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output = StringIO()
        with redirect_stdout(output):
            cls.exit_code = main(["analyze", "samples/auth_sample.log", "--type", "auth", "--format", "json"])
        cls.raw = output.getvalue()
        cls.report = json.loads(cls.raw)

    def test_json_stdout_is_valid_without_banner(self):
        self.assertEqual(self.exit_code, 0)
        self.assertTrue(self.raw.lstrip().startswith("{"))

    def test_json_contains_version_and_summary(self):
        self.assertEqual(self.report["tool"]["version"], "1.0.0")
        self.assertEqual(self.report["summary"]["lines_processed"], 35)

    def test_json_contains_findings_and_disclaimer(self):
        self.assertTrue(self.report["findings"])
        self.assertIn("do not prove compromise", self.report["disclaimer"])

    def test_datetime_fields_are_iso_strings(self):
        finding = next(item for item in self.report["findings"] if item["rule_id"] == "AUTH-004")
        self.assertIsInstance(finding["first_seen"], str)
        self.assertIn("T", finding["last_seen"])

    def test_json_no_detect(self):
        output = StringIO()
        with redirect_stdout(output):
            main(["analyze", "samples/auth_sample.log", "--type", "auth", "--format", "json", "--no-detect"])
        report = json.loads(output.getvalue())
        self.assertFalse(report["analysis"]["detection_enabled"])
        self.assertEqual(report["findings"], [])
