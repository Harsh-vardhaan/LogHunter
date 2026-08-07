"""Common parser interface."""
from abc import ABC, abstractmethod
from ..models import LogEvent

class LogParser(ABC):
    log_type: str
    @abstractmethod
    def parse_line(self, line: str) -> LogEvent | None:
        """Return a normalized event, or None for an unrecognized line."""
