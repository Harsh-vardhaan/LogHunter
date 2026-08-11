import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path

from loghunter.cli import main
from loghunter.config import CONFIG_SCHEMA_VERSION, ConfigError, DEFAULT_CONFIG, load_config, parse_config


def valid_data():
    return DEFAULT_CONFIG.to_dict()


class ConfigurationTests(unittest.TestCase):
    def test_default_configuration(self):
        loaded = load_config()
        self.assertEqual((loaded.source, loaded.config), ("default", DEFAULT_CONFIG))

    def test_custom_configuration_loads_read_only(self):
        path = Path("examples/loghunter-config.json")
        before = path.read_bytes()
        loaded = load_config(str(path))
        self.assertEqual(loaded.config.auth.failed_medium_threshold, 4)
        self.assertEqual(path.read_bytes(), before)

    def test_malformed_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_missing_and_directory_config_rejected(self):
        with self.assertRaises(ConfigError):
            load_config("examples/missing.json")
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ConfigError):
            load_config(directory)

    def test_symlink_config_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            link = Path(directory) / "link.json"
            target.write_text(json.dumps(valid_data()), encoding="utf-8")
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable in this environment")
            with self.assertRaises(ConfigError):
                load_config(str(link))

    def test_unknown_keys_rejected(self):
        for section, key in ((None, "extra"), ("auth", "extra"), ("web", "extra")):
            with self.subTest(section=section):
                data = valid_data()
                data[key] = 1 if section is None else data.get(key)
                if section:
                    data[section][key] = 1
                    data.pop(key, None)
                with self.assertRaises(ConfigError):
                    parse_config(data)

    def test_unsupported_or_missing_version_rejected(self):
        data = valid_data()
        data["version"] = "2.0"
        with self.assertRaises(ConfigError):
            parse_config(data)
        data = valid_data()
        del data["version"]
        with self.assertRaises(ConfigError):
            parse_config(data)

    def test_non_integer_and_boolean_thresholds_rejected(self):
        for value in ("5", True):
            data = valid_data()
            data["auth"]["failed_medium_threshold"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_config(data)

    def test_threshold_bounds_rejected(self):
        for value in (0, -1, 100_001):
            data = valid_data()
            data["web"]["client_error_threshold"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_config(data)

    def test_window_bounds_rejected(self):
        for value in (0, -1, 1_441):
            data = valid_data()
            data["auth"]["window_minutes"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                parse_config(data)

    def test_high_threshold_cannot_be_lower_than_medium(self):
        data = valid_data()
        data["auth"]["failed_medium_threshold"] = 10
        data["auth"]["failed_high_threshold"] = 5
        with self.assertRaises(ConfigError):
            parse_config(data)

    def test_config_check_valid(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["config-check", "examples/loghunter-config.json"]), 0)
        self.assertIn("Status: VALID", output.getvalue())
        self.assertIn("No analysis was performed", output.getvalue())
        self.assertNotIn("SECURITY FINDINGS", output.getvalue())

    def test_config_check_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{}", encoding="utf-8")
            error = StringIO()
            with redirect_stderr(error):
                self.assertEqual(main(["config-check", str(path)]), 2)
            self.assertIn("Configuration error", error.getvalue())
            self.assertNotIn("Traceback", error.getvalue())

    def test_schema_version_constant(self):
        self.assertEqual(CONFIG_SCHEMA_VERSION, "1.0")
