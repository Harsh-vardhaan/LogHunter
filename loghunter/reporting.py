"""Stable text and machine-readable reporting for investigations."""

from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import Investigation
from .detection.models import Finding

DISCLAIMER = "Findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation."
REPORT_SCHEMA_NAME = "loghunter-report"
REPORT_SCHEMA_VERSION = "1.0"


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
        "source_files": list(finding.source_files),
    }


def _summary(investigation: Investigation) -> dict[str, Any]:
    counts = Counter(finding.severity.value.lower() for finding in investigation.findings)
    return {
        "files_analyzed": len(investigation.files),
        "lines_processed": sum(item.total_lines for item in investigation.files),
        "parsed_records": sum(item.parsed_lines for item in investigation.files),
        "unrecognized_records": sum(item.unrecognized_lines for item in investigation.files),
        "pre_filter_findings_total": len(investigation.all_findings),
        "findings_total": len(investigation.findings),
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts["info"],
        "unique_source_ips": len({item.source_ip for item in investigation.findings if item.source_ip}),
        "rules_triggered": sorted({item.rule_id for item in investigation.findings}),
    }


def _filters(investigation: Investigation) -> dict[str, str | None]:
    return {
        "severity": investigation.filters.severity.value if investigation.filters.severity else None,
        "rule": investigation.filters.rule_id,
        "source_ip": investigation.filters.source_ip,
    }


def build_json_report(investigation: Investigation) -> dict[str, Any]:
    return {
        "schema": {"name": REPORT_SCHEMA_NAME, "version": REPORT_SCHEMA_VERSION},
        "tool": {"name": "LogHunter", "version": __version__},
        "analysis": {
            "log_type": investigation.log_type,
            "detection_enabled": investigation.detection_enabled,
            "files_analyzed": len(investigation.files),
        },
        "filters": _filters(investigation),
        "summary": _summary(investigation),
        "files": [
            {
                "file": item.file_path,
                "lines_processed": item.total_lines,
                "parsed_records": item.parsed_lines,
                "unrecognized_records": item.unrecognized_lines,
            }
            for item in investigation.files
        ],
        "findings": [finding_to_dict(finding) for finding in investigation.findings],
        "disclaimer": DISCLAIMER,
    }


def format_text_report(investigation: Investigation) -> str:
    rule = "=" * 48
    lines = [rule, "                   LOGHUNTER", rule, "", f"Log type: {investigation.log_type}",
             f"Files analyzed: {len(investigation.files)}", "", "FILE SUMMARY"]
    for item in investigation.files:
        lines.append(f"- {Path(item.file_path).name}: {item.total_lines} lines / {item.parsed_lines} parsed / {item.unrecognized_lines} unrecognized")

    lines.extend(("", "-" * 48, "SECURITY FINDINGS", "-" * 48, ""))
    if not investigation.detection_enabled:
        lines.append("Parsing complete. Detection was skipped (--no-detect).")
    elif not investigation.findings and investigation.all_findings:
        lines.append("Security findings were generated, but none matched the active analyst filters.")
    elif not investigation.findings:
        lines.extend(("No security findings matched the current rule set.",
                      "Only implemented rules were evaluated against the supplied data."))
    for finding in investigation.findings:
        lines.extend(_format_finding(finding))

    summary = _summary(investigation)
    lines.extend(("", "INVESTIGATION SUMMARY", f"Files: {summary['files_analyzed']}",
                  f"Lines processed: {summary['lines_processed']}", f"Parsed records: {summary['parsed_records']}",
                  f"Unrecognized records: {summary['unrecognized_records']}", f"Findings: {summary['findings_total']}",
                  f"High: {summary['high']}", f"Medium: {summary['medium']}", f"Low: {summary['low']}",
                  f"Info: {summary['info']}", f"Unique source IPs: {summary['unique_source_ips']}",
                  f"Rules triggered: {', '.join(summary['rules_triggered']) or 'None'}"))
    if investigation.filters.active:
        filters = _filters(investigation)
        lines.extend(("", "Active filters:"))
        for name, value in filters.items():
            if value:
                label = {"severity": "Severity", "rule": "Rule", "source_ip": "Source IP"}[name]
                lines.append(f"{label}: {value}")
    lines.extend(("", DISCLAIMER, rule))
    return "\n".join(lines)


def _format_finding(finding: Finding) -> list[str]:
    lines = [f"[{finding.severity.value}] {finding.rule_id}", finding.title]
    if finding.source_ip:
        lines.append(f"Source IP: {finding.source_ip}")
    if finding.username:
        lines.append(f"Username: {finding.username}")
    if finding.source_files:
        lines.append(f"Source files: {', '.join(Path(item).name for item in finding.source_files)}")
    lines.append(f"Events: {finding.event_count}")
    if finding.first_seen:
        lines.append(f"First seen: {finding.first_seen.isoformat()}")
    if finding.last_seen:
        lines.append(f"Last seen:  {finding.last_seen.isoformat()}")
    lines.extend(("", finding.description, f"Evidence: {finding.evidence_summary}", "",
                  f"Recommendation: {finding.recommendation}", "", "-" * 48, ""))
    return lines
