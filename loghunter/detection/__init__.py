"""Rule-based detection interfaces and defaults."""

from .engine import DetectionEngine
from .models import Finding, Severity

__all__ = ["DetectionEngine", "Finding", "Severity"]
