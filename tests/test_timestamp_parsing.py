import unittest
from datetime import datetime, timedelta, timezone

from loghunter.parsers.auth import AuthLogParser
from loghunter.parsers.web import WebLogParser
from loghunter.models import LogEvent


class TimestampParsingTests(unittest.TestCase):
    def test_auth_timestamp_uses_fixed_reference_year(self):
        parser = AuthLogParser(reference_year=2024)
        event = parser.parse_line("Jan 10 12:34:56 host sshd[1]: Failed password for demo-user from 192.0.2.10 port 50 ssh2")
        self.assertEqual(event.timestamp, datetime(2024, 1, 10, 12, 34, 56, tzinfo=timezone.utc))

    def test_auth_timestamp_is_timezone_aware(self):
        event = AuthLogParser(reference_year=2026).parse_line("Jan 10 12:34:56 host sshd[1]: Accepted password for demo-user from 192.0.2.10 port 50 ssh2")
        self.assertIsNotNone(event.timestamp.utcoffset())

    def test_malformed_auth_timestamp_is_ignored(self):
        line = "Feb 31 12:34:56 host sshd[1]: Failed password for demo-user from 192.0.2.10 port 50 ssh2"
        self.assertIsNone(AuthLogParser(reference_year=2026).parse_line(line))

    def test_web_timestamp_and_offset(self):
        line = '192.0.2.10 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 10 "-" "Demo"'
        event = WebLogParser().parse_line(line)
        self.assertEqual(event.timestamp, datetime(2000, 10, 10, 13, 55, 36, tzinfo=timezone(-timedelta(hours=7))))
        self.assertEqual(event.timestamp.utcoffset(), -timedelta(hours=7))

    def test_malformed_web_timestamp_is_ignored(self):
        line = '192.0.2.10 - - [32/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 10 "-" "Demo"'
        self.assertIsNone(WebLogParser().parse_line(line))

    def test_event_rejects_arbitrary_timestamp_string(self):
        with self.assertRaises(TypeError):
            LogEvent("not-normalized", "192.0.2.10", None, "login", "failed", "synthetic", "auth")
