import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from loghunter.analysis import analyze_files
from loghunter.cli import main
from loghunter.loader import LogLoadError


def auth_line(minute, status="Failed", ip="203.0.113.90", username="analyst"):
    verb = f"{status} password for"
    return f"Jan 15 13:{minute:02d}:00 host sshd[{3000 + minute}]: {verb} {username} from {ip} port {52000 + minute} ssh2"


class MultiFileAnalysisTests(unittest.TestCase):
    def test_aggregate_and_per_file_counts(self):
        result = analyze_files(["samples/auth_sample.log", "samples/auth_extra.log"], "auth", reference_year=2026)
        self.assertEqual([(item.total_lines, item.parsed_lines, item.unrecognized_lines) for item in result.files], [(35, 32, 3), (5, 5, 0)])
        self.assertEqual((sum(item.total_lines for item in result.files), len(result.events)), (40, 37))

    def test_source_file_attached_to_events(self):
        result = analyze_files(["samples/auth_extra.log"], "auth", reference_year=2026)
        self.assertTrue(all(event.source_file == "samples/auth_extra.log" for event in result.events))

    def test_cross_file_auth_001_and_auth_004(self):
        result = analyze_files(["samples/auth_sample.log", "samples/auth_extra.log"], "auth", reference_year=2026)
        matches = [item for item in result.findings if item.source_ip == "192.0.2.11"]
        self.assertEqual([item.rule_id for item in matches], ["AUTH-004", "AUTH-001"])
        self.assertEqual(matches[0].source_files, ("samples/auth_extra.log", "samples/auth_sample.log"))

    def test_cross_file_auth_002(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.log"
            second = Path(directory) / "second.log"
            first.write_text("\n".join(auth_line(i) for i in range(5)), encoding="utf-8")
            second.write_text("\n".join(auth_line(i) for i in range(5, 10)), encoding="utf-8")
            result = analyze_files([str(first), str(second)], "auth", reference_year=2026)
            finding = next(item for item in result.findings if item.rule_id == "AUTH-002")
            self.assertEqual(finding.event_count, 10)
            self.assertEqual(finding.source_files, tuple(sorted((str(first), str(second)))))

    def test_cross_file_events_are_chronological(self):
        result = analyze_files(["samples/auth_extra.log", "samples/auth_sample.log"], "auth", reference_year=2026)
        timestamps = [event.timestamp for event in result.events if event.timestamp]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_missing_second_file_fails_full_analysis(self):
        with self.assertRaises(LogLoadError):
            analyze_files(["samples/auth_sample.log", "samples/missing.log"], "auth")

    def test_missing_second_file_cli_error_has_no_traceback(self):
        error = StringIO()
        with redirect_stderr(error):
            exit_code = main(["analyze", "samples/auth_sample.log", "samples/missing.log", "--type", "auth", "--format", "json"])
        self.assertEqual(exit_code, 2)
        self.assertIn("does not exist", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())

    def test_duplicate_file_is_rejected(self):
        with self.assertRaises(LogLoadError):
            analyze_files(["samples/auth_sample.log", "samples/auth_sample.log"], "auth")

    def test_identical_records_across_files_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / "one.log", Path(directory) / "two.log"]
            content = "\n".join(auth_line(i) for i in range(5))
            for path in paths:
                path.write_text(content, encoding="utf-8")
            result = analyze_files([str(path) for path in paths], "auth", reference_year=2026)
            self.assertEqual(len(result.events), 5)
            self.assertNotIn("AUTH-002", [item.rule_id for item in result.findings])
            finding = next(item for item in result.findings if item.rule_id == "AUTH-001")
            self.assertEqual(finding.source_files, tuple(sorted(str(path) for path in paths)))

    def test_source_files_are_not_modified(self):
        paths = [Path("samples/auth_sample.log"), Path("samples/auth_extra.log")]
        before = [path.read_bytes() for path in paths]
        analyze_files([str(path) for path in paths], "auth", reference_year=2026)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_web_cross_file_compatibility(self):
        template = '{} - - [15/Jan/2026:14:00:{:02d} +0000] "GET /missing HTTP/1.1" 404 10 "-" "Demo"'
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / "one.log", Path(directory) / "two.log"]
            paths[0].write_text("\n".join(template.format("198.51.100.90", i) for i in range(4)), encoding="utf-8")
            paths[1].write_text("\n".join(template.format("198.51.100.90", i + 4) for i in range(4)), encoding="utf-8")
            result = analyze_files([str(path) for path in paths], "web")
            self.assertIn("WEB-001", [item.rule_id for item in result.findings])

    def test_no_detect_multifile_parses_without_findings(self):
        result = analyze_files(["samples/auth_sample.log", "samples/auth_extra.log"], "auth", detect=False)
        self.assertEqual((len(result.events), result.all_findings, result.findings), (37, (), ()))
