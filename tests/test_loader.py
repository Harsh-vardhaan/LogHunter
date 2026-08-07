import tempfile
import unittest
from pathlib import Path
from loghunter.loader import LogLoadError, iter_log_lines

class LoaderTests(unittest.TestCase):
    def test_valid_auth_log_loads(self):
        self.assertEqual(len(list(iter_log_lines("samples/auth_sample.log"))), 5)
    def test_missing_file_is_controlled(self):
        with self.assertRaises(LogLoadError):
            list(iter_log_lines("samples/not-present.log"))
    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.log"
            path.touch()
            self.assertEqual(list(iter_log_lines(path)), [])
    def test_source_is_not_modified(self):
        path = Path("samples/auth_sample.log")
        before = path.read_bytes()
        list(iter_log_lines(path))
        self.assertEqual(path.read_bytes(), before)
