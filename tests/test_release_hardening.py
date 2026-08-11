import json
import subprocess
import sys
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError
from io import StringIO
from pathlib import Path

from loghunter import __version__
from loghunter.cli import main
from loghunter.config import CONFIG_SCHEMA_VERSION, DEFAULT_CONFIG, load_config
from loghunter.reporting import REPORT_SCHEMA_VERSION


def module_command(*arguments):
    return subprocess.run([sys.executable, "-m", "loghunter", *arguments], capture_output=True, text=True, check=False)


class ReleaseHardeningTests(unittest.TestCase):
    def test_module_version(self):
        result = module_command("--version")
        self.assertEqual((result.returncode, result.stdout.strip(), result.stderr), (0, "LogHunter 1.0.0", ""))

    def test_module_help_is_professional(self):
        result = module_command("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("defensive", result.stdout.lower())
        self.assertIn("analyze", result.stdout)
        self.assertIn("config-check", result.stdout)

    def test_findings_are_successful_exit(self):
        result = module_command("analyze", "samples/auth_sample.log", "--type", "auth", "--rule", "AUTH-004")
        self.assertEqual(result.returncode, 0)
        self.assertIn("AUTH-004", result.stdout)

    def test_expected_errors_are_nonzero_without_tracebacks(self):
        cases = (
            ("analyze", "samples/missing.log", "--type", "auth"),
            ("analyze", "samples/auth_sample.log", "--type", "auth", "--config", "examples/missing.json"),
            ("analyze", "samples/auth_sample.log", "--type", "auth", "--severity", "CRITICAL"),
            ("analyze", "samples/auth_sample.log", "--type", "auth", "--rule", "AUTH-999"),
            ("analyze", "samples/auth_sample.log", "--type", "auth", "--source-ip", "invalid"),
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = module_command(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_json_output_is_byte_deterministic(self):
        arguments = ("analyze", "samples/auth_sample.log", "samples/auth_extra.log", "--type", "auth", "--format", "json")
        first = module_command(*arguments)
        second = module_command(*arguments)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)
        json.loads(first.stdout)

    def test_deterministic_report_ordering(self):
        result = module_command("analyze", "samples/auth_sample.log", "samples/auth_extra.log", "--type", "auth", "--format", "json")
        report = json.loads(result.stdout)
        finding_keys = [(item["severity"], item["rule_id"], item["source_ip"] or "") for item in report["findings"]]
        severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        self.assertEqual(finding_keys, sorted(finding_keys, key=lambda item: (severity_rank[item[0]], item[1], item[2])))
        self.assertEqual(report["summary"]["rules_triggered"], sorted(report["summary"]["rules_triggered"]))
        self.assertTrue(all(item["source_files"] == sorted(item["source_files"]) for item in report["findings"]))

    def test_default_configuration_is_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            DEFAULT_CONFIG.auth.failed_medium_threshold = 1

    def test_custom_config_does_not_mutate_defaults(self):
        before = DEFAULT_CONFIG
        custom = load_config("examples/loghunter-config.json")
        self.assertNotEqual(custom.config.auth.failed_medium_threshold, before.auth.failed_medium_threshold)
        self.assertEqual(DEFAULT_CONFIG, before)

    def test_config_check_is_deterministic(self):
        first = module_command("config-check", "examples/loghunter-config.json")
        second = module_command("config-check", "examples/loghunter-config.json")
        self.assertEqual((first.returncode, first.stdout), (second.returncode, second.stdout))

    def test_release_versions(self):
        self.assertEqual((__version__, REPORT_SCHEMA_VERSION, CONFIG_SCHEMA_VERSION), ("1.0.0", "1.0", "1.0"))

    def test_all_source_logs_remain_unchanged(self):
        paths = tuple(Path("samples").glob("*.log"))
        before = {path: path.read_bytes() for path in paths}
        module_command("analyze", *(str(path) for path in paths if "auth" in path.name), "--type", "auth", "--no-detect")
        module_command("analyze", "samples/access_sample.log", "--type", "web")
        self.assertEqual({path: path.read_bytes() for path in paths}, before)

    def test_packaging_metadata_and_console_entry_point(self):
        data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["requires-python"], ">=3.11")
        self.assertEqual(data["project"]["scripts"]["loghunter"], "loghunter.cli:main")
        self.assertEqual(data["tool"]["setuptools"]["dynamic"]["version"]["attr"], "loghunter.__version__")
