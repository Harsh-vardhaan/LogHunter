"""Apache/Nginx common and combined access-log parser."""
import re
from datetime import datetime
from ..models import LogEvent
from .base import LogParser

class WebLogParser(LogParser):
    log_type = "web"
    _PATTERN = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^]]+)] "(?P<method>[A-Z]+) (?P<path>\S+) HTTP/\d(?:\.\d)?" (?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agent>[^"]*)")?$')
    def parse_line(self, line: str) -> LogEvent | None:
        match = self._PATTERN.fullmatch(line)
        if not match:
            return None
        try:
            timestamp = datetime.strptime(match["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        return LogEvent(timestamp, match["ip"], None, "http-request", "recorded", line, self.log_type, match["method"], match["path"], int(match["status"]), match["agent"])
