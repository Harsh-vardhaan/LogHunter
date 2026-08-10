import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from loghunter.analysis import analyze_files
from loghunter.cli import main
from loghunter.filters import AnalystFilters
from loghunter.detection.models import Severity


class AnalystFilterTests(unittest.TestCase):
    def test_exact_high_severity_filter(self):
        result = analyze_files(["samples/auth_sample.log"], "auth", filters=AnalystFilters(severity=Severity.HIGH))
        self.assertTrue(result.findings)
        self.assertTrue(all(item.severity is Severity.HIGH for item in result.findings))

    def test_exact_medium_severity_filter(self):
        result = analyze_files(["samples/auth_sample.log"], "auth", filters=AnalystFilters(severity=Severity.MEDIUM))
        self.assertTrue(all(item.severity is Severity.MEDIUM for item in result.findings))

    def test_rule_filter(self):
        result = analyze_files(["samples/auth_sample.log"], "auth", filters=AnalystFilters(rule_id="AUTH-004"))
        self.assertEqual([item.rule_id for item in result.findings], ["AUTH-004"])

    def test_exact_source_ip_filter(self):
        result = analyze_files(["samples/auth_sample.log"], "auth", filters=AnalystFilters(source_ip="203.0.113.50"))
        self.assertTrue(result.findings)
        self.assertTrue(all(item.source_ip == "203.0.113.50" for item in result.findings))

    def test_combined_filters(self):
        filters = AnalystFilters(Severity.HIGH, "AUTH-004", "203.0.113.50")
        result = analyze_files(["samples/auth_sample.log"], "auth", filters=filters)
        self.assertEqual([item.rule_id for item in result.findings], ["AUTH-004"])

    def test_filters_do_not_change_detection_results(self):
        unfiltered = analyze_files(["samples/auth_sample.log"], "auth")
        filtered = analyze_files(["samples/auth_sample.log"], "auth", filters=AnalystFilters(rule_id="AUTH-004"))
        self.assertEqual(unfiltered.all_findings, filtered.all_findings)
        self.assertGreater(len(filtered.all_findings), len(filtered.findings))

    def test_no_match_filter_has_distinct_message(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["analyze", "samples/auth_sample.log", "--type", "auth", "--source-ip", "192.0.2.200"]), 0)
        self.assertIn("none matched the active analyst filters", output.getvalue())

    def test_invalid_severity_rule_and_ip_rejected(self):
        for arguments in (("--severity", "critical"), ("--rule", "AUTH-999"), ("--source-ip", "not-an-ip")):
            with self.subTest(arguments=arguments), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                main(["analyze", "samples/auth_sample.log", "--type", "auth", *arguments])

    def test_no_detect_filter_conflicts_rejected(self):
        for arguments in (("--severity", "HIGH"), ("--rule", "AUTH-004"), ("--source-ip", "203.0.113.50")):
            with self.subTest(arguments=arguments), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                main(["analyze", "samples/auth_sample.log", "--type", "auth", "--no-detect", *arguments])
