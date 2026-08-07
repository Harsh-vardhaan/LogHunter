"""Parser for a small subset of Linux OpenSSH auth messages."""
import re
from ..models import LogEvent
from .base import LogParser

class AuthLogParser(LogParser):
    log_type = "auth"
    _PREFIX = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    _PATTERNS = (
        (re.compile(_PREFIX + r"Accepted password for (?P<username>\S+) from (?P<ip>\S+) port \d+ ssh2$"), "login", "success"),
        (re.compile(_PREFIX + r"Failed password for (?P<username>\S+) from (?P<ip>\S+) port \d+ ssh2$"), "login", "failed"),
        (re.compile(_PREFIX + r"Failed password for invalid user (?P<username>\S+) from (?P<ip>\S+) port \d+ ssh2$"), "invalid-user-login", "failed"),
        (re.compile(_PREFIX + r"Invalid user (?P<username>\S+) from (?P<ip>\S+)(?: port \d+)?$"), "invalid-user-login", "failed"),
    )
    def parse_line(self, line: str) -> LogEvent | None:
        for pattern, action, status in self._PATTERNS:
            match = pattern.fullmatch(line)
            if match:
                return LogEvent(match["timestamp"], match["ip"], match["username"], action, status, line, self.log_type)
        return None
