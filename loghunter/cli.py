"""Command-line validation and orchestration."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .analysis import Investigation, analyze_files, infer_log_type, parse_file
from .config import ConfigError, load_config
from .detection import Finding
from .detection.engine import KNOWN_RULE_IDS
from .detection.models import Severity
from .filters import AnalystFilters, normalize_ip
from .loader import LogLoadError
from .models import AnalysisSummary
from .parsers import PARSERS
from .reporting import build_json_report, format_config_check, format_text_report


def _severity(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("severity must be INFO, LOW, MEDIUM, or HIGH") from exc


def _rule_id(value: str) -> str:
    normalized = value.upper()
    if normalized not in KNOWN_RULE_IDS:
        raise argparse.ArgumentTypeError(f"unknown rule ID: {value}")
    return normalized


def _source_ip(value: str) -> str:
    try:
        return normalize_ip(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP address: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loghunter", description="Analyze one or more explicit local logs with transparent security rules.")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="parse local logs and report investigation findings")
    analyze.add_argument("files", nargs="+", help="one or more local log files")
    analyze.add_argument("--type", choices=sorted(PARSERS), dest="log_type", help="shared log format (required for multiple files)")
    analyze.add_argument("--no-detect", action="store_true", help="parse records without running detection rules")
    analyze.add_argument("--format", choices=("text", "json"), default="text", help="report format (default: text)")
    analyze.add_argument("--severity", type=_severity, help="show findings with this exact severity")
    analyze.add_argument("--rule", type=_rule_id, help="show findings for one validated rule ID")
    analyze.add_argument("--source-ip", type=_source_ip, help="show findings for one exact IPv4/IPv6 address")
    analyze.add_argument("--config", help="explicit local JSON detection configuration")
    config_check = commands.add_parser("config-check", help="validate and describe a local JSON configuration")
    config_check.add_argument("file", help="local configuration file")
    return parser


def analyze_file(file_path: str, log_type: str | None = None) -> AnalysisSummary:
    """Compatibility wrapper retained for earlier callers."""
    return parse_file(file_path, log_type).summary


def format_summary(summary: AnalysisSummary, findings: Sequence[Finding] | None = None) -> str:
    """Compatibility text formatter for earlier tests and integrations."""
    filters = AnalystFilters()
    investigation = Investigation(
        summary.log_type, (summary,), (), findings is not None,
        tuple(findings or ()), tuple(findings or ()), filters,
    )
    return format_text_report(investigation)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "config-check":
        try:
            print(format_config_check(load_config(args.file)))
            return 0
        except ConfigError as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2
    if len(args.files) > 1 and not args.log_type:
        parser.error("--type is required when analyzing multiple files")
    if args.no_detect and any((args.severity, args.rule, args.source_ip)):
        parser.error("finding filters cannot be used together with --no-detect")

    try:
        configuration = load_config(args.config)
        selected = args.log_type or infer_log_type(Path(args.files[0]))
        filters = AnalystFilters(args.severity, args.rule, args.source_ip)
        investigation = analyze_files(
            args.files, selected, detect=not args.no_detect, filters=filters,
            configuration=configuration,
        )
        if args.format == "json":
            print(json.dumps(build_json_report(investigation), indent=2, sort_keys=True))
        else:
            print(format_text_report(investigation))
        return 0
    except (LogLoadError, ConfigError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
