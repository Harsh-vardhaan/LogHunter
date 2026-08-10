"""Stable machine-readable reporting for LogHunter analyses."""

from collections.abc import Sequence
from typing import Any

from . import __version__
from .detection.models import Finding
from .models import AnalysisSummary

DISCLAIMER = "Findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation."


def _iso(value: object | None) -> str | None:
    return value.isoformat() if value is not None else None


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "category": finding.category,
        "description": finding.description,
        "evidence_summary": finding.evidence_summary,
        "recommendation": finding.recommendation,
        "source_ip": finding.source_ip,
        "username": finding.username,
        "event_count": finding.event_count,
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
    }


def build_json_report(summary: AnalysisSummary, findings: Sequence[Finding] | None) -> dict[str, Any]:
    return {
        "tool": "LogHunter",
        "version": __version__,
        "file": summary.file_path,
        "log_type": summary.log_type,
        "summary": {
            "lines_processed": summary.total_lines,
            "parsed_records": summary.parsed_lines,
            "unrecognized_records": summary.unrecognized_lines,
        },
        "detection_enabled": findings is not None,
        "findings": [finding_to_dict(finding) for finding in findings or ()],
        "disclaimer": DISCLAIMER,
    }
