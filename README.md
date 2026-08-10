# LogHunter

A Python command-line defensive security tool for safely parsing local authentication and web logs, correlating events, and presenting transparent rule-based findings for analyst review.

## Overview

LogHunter analyzes one or more explicitly supplied local files. It normalizes supported records, correlates compatible timestamps across files, applies detection rules, filters the resulting findings, and produces text or JSON investigation reports. It never treats a heuristic as proof of compromise.

## Phase 4 Status

Version 0.4.0 adds safe multi-file analysis, cross-file correlation, analyst-facing filters, aggregate and per-file summaries, source-file provenance, and report schema version 1.0.

## Multi-File Analysis

Multiple files can be analyzed when they share one explicit log type:

```powershell
python -m loghunter analyze samples/auth_sample.log samples/auth_extra.log --type auth
```

All paths are validated before parsing. Missing files, directories, symbolic links, and duplicate path arguments fail the complete invocation with a controlled error. LogHunter never discovers files recursively or analyzes paths that were not supplied explicitly.

Each file is parsed independently and receives its own summary. Normalized events are combined and sorted chronologically for detection. This supports split or rotated logs while retaining their supplied source paths. Cross-file correlation assumes timestamps and inferred auth years are compatible.

## Source Context

Every parsed `LogEvent` carries `source_file`. Each finding contains a sorted, unique `source_files` tuple derived only from events that contributed to that finding. Text output shows compact filenames; JSON preserves the supplied path strings. Raw file contents are never merged or included in reports.

## Analyst Filters

Filters are applied after the complete detection result is generated, so they narrow the analyst’s view without changing detection behavior or confidence.

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --severity HIGH
python -m loghunter analyze samples/auth_sample.log --type auth --rule AUTH-004
python -m loghunter analyze samples/auth_sample.log --type auth --source-ip 203.0.113.50
python -m loghunter analyze samples/auth_sample.log --type auth --severity HIGH --source-ip 203.0.113.50
```

- `--severity` is an exact, case-insensitive match for INFO, LOW, MEDIUM, or HIGH.
- `--rule` accepts one known rule ID and rejects unknown IDs.
- `--source-ip` performs an exact IPv4/IPv6 match using standard-library validation. CIDR, geolocation, and reputation lookup are not supported.

When detections exist but filters remove all of them, LogHunter reports that findings were generated but none matched the active filters. It never says that no threats exist.

## Detection and Correlation

Authentication rules use timezone-aware timestamps and a centralized 10-minute window. Traditional syslog auth records omit the year and timezone, so the parser uses an explicit reference year and treats them as UTC; the CLI defaults to the current UTC year. Web timestamps preserve their recorded numeric offset. Untimestamped events do not participate in time-aware rules.

| Rule | Description | Severity | Threshold / window |
|---|---|---:|---:|
| AUTH-001 | Repeated failed authentication | MEDIUM | 5 / 10 minutes |
| AUTH-002 | Potential brute-force pattern | HIGH | 10 / 10 minutes |
| AUTH-003 | Repeated invalid-user attempts | MEDIUM | 3 / 10 minutes |
| AUTH-004 | Success after repeated failures | HIGH | 5 failures + success / 10 minutes |
| WEB-001 | Repeated HTTP client errors | LOW | 8 / combined dataset |
| WEB-002 | Potential sensitive-path probing | MEDIUM | 1 match / combined dataset |
| WEB-003 | Repeated HTTP server errors | MEDIUM | 5 / combined dataset |

AUTH-002 suppresses redundant AUTH-001 output for the same source. Web rules remain dataset-wide but support combined explicitly supplied files and populate finding timestamps.

## Investigation Summaries

Text and JSON reports include:

- files analyzed;
- aggregate processed, parsed, and unrecognized counts;
- per-file parsing summaries;
- filtered and pre-filter finding totals;
- severity counts;
- unique source-IP count;
- triggered rule IDs;
- active analyst filters.

LogHunter does not calculate an overall numeric risk score.

## Text and JSON Output

Text is the default:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth
```

Machine-readable output:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --format json
python -m loghunter analyze samples/auth_sample.log samples/auth_extra.log --type auth --format json
```

JSON stdout contains valid JSON only. Routine analysis errors go to stderr with a nonzero exit status.

## JSON Report Schema

The application version and report schema version are independent:

```json
{
  "schema": {
    "name": "loghunter-report",
    "version": "1.0"
  },
  "tool": {
    "name": "LogHunter",
    "version": "0.4.0"
  },
  "analysis": {
    "log_type": "auth",
    "detection_enabled": true,
    "files_analyzed": 2
  },
  "filters": {
    "severity": null,
    "rule": null,
    "source_ip": null
  },
  "summary": {},
  "files": [],
  "findings": [],
  "disclaimer": "Findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation."
}
```

`REPORT_SCHEMA_VERSION` is the authoritative schema version. Finding timestamps use ISO 8601 and source provenance is represented by `source_files`. Raw log lines are excluded.

## Parsing Without Detection

Multi-file parsing works with `--no-detect`:

```powershell
python -m loghunter analyze samples/auth_sample.log samples/auth_extra.log --type auth --no-detect
```

Finding filters cannot be combined with `--no-detect`; the CLI rejects those combinations clearly.

## False-Positive and Analyst Guidance

Filters help focus an investigation but do not increase detection confidence. Multi-file correlation adds context but remains heuristic. Repeated failures can arise from mistakes, stale credentials, password-manager problems, or misconfiguration. Client errors may come from broken links or crawlers; sensitive-path requests may be authorized testing; server errors may be application defects. Findings always require analyst review.

## Security and Privacy

LogHunter opens only explicitly supplied regular local files in read-only streaming mode. It performs no network calls, scanning, credential testing, exploitation, threat-intelligence queries, blocking, account changes, firewall changes, or active response. It executes no log content and modifies no source log. Repository fixtures contain only synthetic identities and documentation-safe IP addresses.

## Installation

Python 3.11 or newer is required. Runtime dependencies are standard-library only.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Testing

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall loghunter
```

Tests are deterministic, local, synthetic, and make no network calls.

## Limitations

All files in one invocation must share a log type. Auth year and UTC timezone remain contextual assumptions. Cross-file analysis does not persist state or detect rotation automatically. Duplicate paths are rejected; byte-for-byte-equivalent parsed records with identical normalized fields are collapsed for detection while their source provenance is merged. Web rules remain dataset-wide. Only one rule ID can be selected per invocation.

## Roadmap

1. Phase 1: safe loading, normalization, parsers, CLI, and tests.
2. Phase 2: structured findings and transparent rules.
3. Phase 3: normalized timestamps, time correlation, AUTH-004, and JSON reporting.
4. Phase 4: safe multi-file workflows, filters, provenance, and schema metadata.
5. Phase 5: external threshold configuration and formal schema validation, without active response.
