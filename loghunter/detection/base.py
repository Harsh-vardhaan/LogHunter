"""Common detection-rule contract."""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from ..models import LogEvent
from .models import Finding


class DetectionRule(ABC):
    rule_id: str
    log_type: str

    @abstractmethod
    def evaluate(self, events: Sequence[LogEvent]) -> list[Finding]:
        """Evaluate normalized events and return zero or more findings."""
