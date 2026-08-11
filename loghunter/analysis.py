"""Safe single- and multi-file analysis orchestration."""

from dataclasses import dataclass, replace
from pathlib import Path

from .config import DEFAULT_LOADED_CONFIG, LoadedConfig
from .detection import DetectionEngine, Finding
from .filters import AnalystFilters, apply_filters
from .loader import LogLoadError, iter_log_lines, validate_log_file
from .models import AnalysisSummary, LogEvent
from .parsers import PARSERS


@dataclass(frozen=True, slots=True)
class FileAnalysis:
    summary: AnalysisSummary
    events: tuple[LogEvent, ...]


@dataclass(frozen=True, slots=True)
class Investigation:
    log_type: str
    files: tuple[AnalysisSummary, ...]
    events: tuple[LogEvent, ...]
    detection_enabled: bool
    all_findings: tuple[Finding, ...]
    findings: tuple[Finding, ...]
    filters: AnalystFilters
    configuration: LoadedConfig = DEFAULT_LOADED_CONFIG


def infer_log_type(path: Path) -> str:
    name = path.name.lower()
    if "auth" in name:
        return "auth"
    if "access" in name or "web" in name:
        return "web"
    raise LogLoadError("Unable to infer log type from filename; specify --type auth or --type web.")


def parse_file(file_path: str, log_type: str | None = None, *, reference_year: int | None = None) -> FileAnalysis:
    path = validate_log_file(file_path)
    selected = log_type or infer_log_type(path)
    parser = PARSERS[selected](reference_year=reference_year) if selected == "auth" else PARSERS[selected]()
    total = 0
    events: list[LogEvent] = []
    for line in iter_log_lines(path):
        total += 1
        event = parser.parse_line(line)
        if event is not None:
            events.append(replace(event, source_file=file_path, source_files=(file_path,)))
    return FileAnalysis(AnalysisSummary(file_path, selected, total, len(events)), tuple(events))


def analyze_files(
    file_paths: list[str],
    log_type: str,
    *,
    detect: bool = True,
    filters: AnalystFilters | None = None,
    reference_year: int | None = None,
    configuration: LoadedConfig = DEFAULT_LOADED_CONFIG,
) -> Investigation:
    if not file_paths:
        raise LogLoadError("At least one log file is required.")
    resolved = [validate_log_file(path).resolve() for path in file_paths]
    if len(set(resolved)) != len(resolved):
        raise LogLoadError("The same log file cannot be supplied more than once.")

    analyses = [parse_file(path, log_type, reference_year=reference_year) for path in file_paths]
    combined = [event for analysis in analyses for event in analysis.events]
    deduplicated: dict[tuple[object, ...], LogEvent] = {}
    for event in combined:
        fingerprint = (
            event.timestamp, event.source_ip, event.username, event.action, event.status,
            event.raw_line, event.log_type, event.http_method, event.path,
            event.http_status, event.user_agent,
        )
        previous = deduplicated.get(fingerprint)
        if previous is None:
            deduplicated[fingerprint] = event
        else:
            files = tuple(sorted(set(previous.source_files + event.source_files)))
            deduplicated[fingerprint] = replace(previous, source_files=files)
    events = tuple(sorted(
        deduplicated.values(),
        key=lambda event: (event.timestamp is None, event.timestamp, event.source_file or "", event.raw_line),
    ))
    active_filters = filters or AnalystFilters()
    all_findings = DetectionEngine(config=configuration.config).detect(log_type, events) if detect else []
    filtered = apply_filters(all_findings, active_filters) if detect else []
    return Investigation(
        log_type, tuple(item.summary for item in analyses), events, detect,
        tuple(all_findings), tuple(filtered), active_filters, configuration,
    )
