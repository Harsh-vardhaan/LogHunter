import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from loghunter.cli import analyze_file, format_summary, main
from loghunter.models import AnalysisSummary

class CliTests(unittest.TestCase):
    def test_help(self):
        result = subprocess.run([sys.executable, "-m", "loghunter", "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("analyze", result.stdout)
    def test_analyze_valid_sample(self):
        self.assertEqual(main(["analyze", "samples/auth_sample.log", "--type", "auth"]), 0)
    def test_analysis_counts(self):
        summary = analyze_file("samples/auth_sample.log", "auth")
        self.assertEqual((summary.total_lines, summary.parsed_lines, summary.unrecognized_lines), (22, 20, 2))

    def test_cli_displays_findings_and_disclaimer(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["analyze", "samples/auth_sample.log", "--type", "auth"]), 0)
        self.assertIn("AUTH-002", output.getvalue())
        self.assertIn("do not prove compromise", output.getvalue())

    def test_no_detect_skips_rules(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["analyze", "samples/auth_sample.log", "--type", "auth", "--no-detect"]), 0)
        self.assertIn("Detection was skipped", output.getvalue())
        self.assertNotIn("AUTH-002", output.getvalue())

    def test_no_findings_message_is_careful(self):
        output = format_summary(AnalysisSummary("synthetic.log", "auth", 1, 1), [])
        self.assertIn("No security findings matched the current rule set", output)
        self.assertNotIn("system is secure", output.lower())
