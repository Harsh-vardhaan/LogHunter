"""Parser registry for supported log formats."""

from .auth import AuthLogParser
from .base import LogParser
from .web import WebLogParser

PARSERS: dict[str, type[LogParser]] = {"auth": AuthLogParser, "web": WebLogParser}

__all__ = ["AuthLogParser", "LogParser", "PARSERS", "WebLogParser"]
