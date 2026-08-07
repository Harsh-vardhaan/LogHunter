import unittest
from loghunter.parsers.auth import AuthLogParser

class AuthParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = AuthLogParser()
    def test_success(self):
        event = self.parser.parse_line("Jan 15 09:10:01 host sshd[1]: Accepted password for demo-user from 192.0.2.10 port 50 ssh2")
        self.assertEqual((event.username, event.status), ("demo-user", "success"))
    def test_failure(self):
        event = self.parser.parse_line("Jan 15 09:10:01 host sshd[1]: Failed password for admin-test from 198.51.100.20 port 50 ssh2")
        self.assertEqual((event.source_ip, event.status), ("198.51.100.20", "failed"))
    def test_invalid_user(self):
        event = self.parser.parse_line("Jan 15 09:10:01 host sshd[1]: Failed password for invalid user analyst from 203.0.113.25 port 50 ssh2")
        self.assertEqual((event.username, event.action), ("analyst", "invalid-user-login"))
    def test_malformed_is_ignored(self):
        self.assertIsNone(self.parser.parse_line("not a valid auth record"))
