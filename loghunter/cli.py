"""Command-line orchestration and presentation."""
import argparse
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from .detection import DetectionEngine, Finding, Severity
from .loader import LogLoadError, iter_log_lines, validate_log_file
from .models import AnalysisSummary, LogEvent
from .parsers import PARSERS


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    summary: AnalysisSummary
    events: tuple[LogEvent, ...]

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loghunter", description="Parse local logs and evaluate transparent security detection rules.")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="parse a local log and report basic counts")
    analyze.add_argument("file", help="path to a local log file")
    analyze.add_argument("--type", choices=sorted(PARSERS), dest="log_type", help="log format (otherwise inferred from filename)")
    analyze.add_argument("--no-detect", action="store_true", help="parse records without running detection rules")
    return parser

def infer_log_type(path: Path) -> str:
    name = path.name.lower()
    if "auth" in name:
        return "auth"
    if "access" in name or "web" in name:
        return "web"
    raise LogLoadError("Unable to infer log type from filename; specify --type auth or --type web.")

def parse_file(file_path: str, log_type: str | None = None) -> AnalysisResult:
    path = validate_log_file(file_path)
    selected = log_type or infer_log_type(path)
    parser = PARSERS[selected]()
    total = 0
    events: list[LogEvent] = []
    for line in iter_log_lines(path):
        total += 1
        event = parser.parse_line(line)
        if event is not None:
            events.append(event)
    summary = AnalysisSummary(str(path), selected, total, len(events))
    return AnalysisResult(summary, tuple(events))


def analyze_file(file_path: str, log_type: str | None = None) -> AnalysisSummary:
    """Compatibility wrapper retained for Phase 1 callers."""
    return parse_file(file_path, log_type).summary

def format_summary(summary: AnalysisSummary, findings: Sequence[Finding] | None = None) -> str:
    rule = "=" * 40
    lines = [rule, "              LOGHUNTER", rule, "", f"File: {summary.file_path}",
             f"Log type: {summary.log_type}", "", f"Lines processed: {summary.total_lines}",
             f"Parsed records: {summary.parsed_lines}", f"Unrecognized records: {summary.unrecognized_lines}"]
    if findings is None:
        lines.extend(("", "Parsing complete. Detection was skipped (--no-detect)."))
    else:
        lines.extend(("", "-" * 40, "SECURITY FINDINGS", "-" * 40, ""))
        if not findings:
            lines.extend(("No security findings matched the current rule set.",
                          "Only implemented rules were evaluated against the supplied dataset."))
        for finding in findings:
            lines.extend(_format_finding(finding))
        counts = Counter(finding.severity for finding in findings)
        severity_order = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        lines.extend(("", "Findings:", *(f"{severity.value.title()}: {counts[severity]}" for severity in severity_order),
                      "", "LogHunter findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation."))
    lines.extend(("", rule))
    return "\n".join(lines)


def _format_finding(finding: Finding) -> list[str]:
    lines = [f"[{finding.severity.value}] {finding.rule_id}", finding.title]
    if finding.source_ip:
        lines.append(f"Source IP: {finding.source_ip}")
    if finding.username:
        lines.append(f"Username: {finding.username}")
    lines.extend((f"Events: {finding.event_count}", "", finding.description,
                  f"Evidence: {finding.evidence_summary}", "", f"Recommendation: {finding.recommendation}", "", "-" * 40, ""))
    return lines

def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = parse_file(args.file, args.log_type)
        findings = None if args.no_detect else DetectionEngine().detect(result.summary.log_type, result.events)
        print(format_summary(result.summary, findings))
        return 0
    except LogLoadError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
