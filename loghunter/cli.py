"""Command-line orchestration and presentation."""
import argparse
import sys
from pathlib import Path
from typing import Sequence
from .loader import LogLoadError, iter_log_lines, validate_log_file
from .models import AnalysisSummary
from .parsers import PARSERS

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loghunter", description="Parse local authentication and web logs (Phase 1; no threat detection).")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="parse a local log and report basic counts")
    analyze.add_argument("file", help="path to a local log file")
    analyze.add_argument("--type", choices=sorted(PARSERS), dest="log_type", help="log format (otherwise inferred from filename)")
    return parser

def infer_log_type(path: Path) -> str:
    name = path.name.lower()
    if "auth" in name:
        return "auth"
    if "access" in name or "web" in name:
        return "web"
    raise LogLoadError("Unable to infer log type from filename; specify --type auth or --type web.")

def analyze_file(file_path: str, log_type: str | None = None) -> AnalysisSummary:
    path = validate_log_file(file_path)
    selected = log_type or infer_log_type(path)
    parser = PARSERS[selected]()
    total = parsed = 0
    for line in iter_log_lines(path):
        total += 1
        parsed += parser.parse_line(line) is not None
    return AnalysisSummary(str(path), selected, total, parsed)

def format_summary(summary: AnalysisSummary) -> str:
    rule = "=" * 40
    return "\n".join((rule, "              LOGHUNTER", rule, "", f"File: {summary.file_path}", f"Log type: {summary.log_type}", "", f"Lines processed: {summary.total_lines}", f"Parsed records: {summary.parsed_lines}", f"Unrecognized records: {summary.unrecognized_lines}", "", "Phase 1 parsing complete.", "Threat detection is not enabled yet.", "", rule))

def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(format_summary(analyze_file(args.file, args.log_type)))
        return 0
    except LogLoadError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
