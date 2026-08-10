import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from loghunter.cli import main


def run_json(*arguments):
    output = StringIO()
    with redirect_stdout(output):
        exit_code = main(["analyze", *arguments, "--format", "json"])
    return exit_code, json.loads(output.getvalue())


class Phase4ReportingTests(unittest.TestCase):
    def test_schema_and_tool_versions_are_separate(self):
        _, report = run_json("samples/auth_sample.log", "--type", "auth")
        self.assertEqual(report["schema"], {"name": "loghunter-report", "version": "1.0"})
        self.assertEqual(report["tool"], {"name": "LogHunter", "version": "0.4.0"})

    def test_json_multifile_files_and_aggregate_summary(self):
        _, report = run_json("samples/auth_sample.log", "samples/auth_extra.log", "--type", "auth")
        self.assertEqual(len(report["files"]), 2)
        self.assertEqual((report["summary"]["lines_processed"], report["summary"]["parsed_records"], report["summary"]["unrecognized_records"]), (40, 37, 3))

    def test_json_filters_and_filtered_summary(self):
        _, report = run_json("samples/auth_sample.log", "--type", "auth", "--severity", "HIGH")
        self.assertEqual(report["filters"]["severity"], "HIGH")
        self.assertTrue(all(item["severity"] == "HIGH" for item in report["findings"]))
        self.assertGreater(report["summary"]["pre_filter_findings_total"], report["summary"]["findings_total"])

    def test_json_finding_source_files(self):
        _, report = run_json("samples/auth_sample.log", "samples/auth_extra.log", "--type", "auth", "--source-ip", "192.0.2.11")
        self.assertTrue(all(len(item["source_files"]) == 2 for item in report["findings"]))

    def test_text_multifile_summary(self):
        output = StringIO()
        with redirect_stdout(output):
            main(["analyze", "samples/auth_sample.log", "samples/auth_extra.log", "--type", "auth"])
        self.assertIn("Files analyzed: 2", output.getvalue())
        self.assertIn("auth_extra.log: 5 lines / 5 parsed", output.getvalue())
