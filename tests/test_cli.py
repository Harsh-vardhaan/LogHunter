import subprocess
import sys
import unittest
from loghunter.cli import analyze_file, main

class CliTests(unittest.TestCase):
    def test_help(self):
        result = subprocess.run([sys.executable, "-m", "loghunter", "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("analyze", result.stdout)
    def test_analyze_valid_sample(self):
        self.assertEqual(main(["analyze", "samples/auth_sample.log", "--type", "auth"]), 0)
    def test_analysis_counts(self):
        summary = analyze_file("samples/auth_sample.log", "auth")
        self.assertEqual((summary.total_lines, summary.parsed_lines, summary.unrecognized_lines), (5, 3, 2))
