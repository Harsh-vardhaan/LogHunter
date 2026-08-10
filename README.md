# LogHunter

A Python command-line defensive security tool that parses local authentication and web logs, normalizes supported records, and evaluates transparent rule-based heuristics.

## Overview

LogHunter helps analysts identify patterns worth reviewing without making unsupported claims. It operates offline on an explicitly supplied local file and reports structured findings without dumping raw records.

## Phase 3 Status

Version 0.3.0 adds timezone-aware timestamp normalization, reusable time-window correlation, AUTH-004 success-after-failures detection, and deterministic JSON reports. Findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation.

## Timestamp Normalization

Successfully parsed `LogEvent.timestamp` values are timezone-aware Python `datetime` objects. Events with missing or malformed timestamps are safely ignored by time-dependent rules rather than being assigned invented times.

Linux syslog-style authentication records contain month, day, and time but no year or timezone. `AuthLogParser` therefore accepts an explicit reference year; CLI analysis uses the current UTC year by default and treats the timestamp as UTC. The inferred year and UTC assumption come from analysis context, not the log line, and remain a documented limitation.

Apache/Nginx timestamps include a year and numeric UTC offset. LogHunter parses both and preserves the recorded offset. Malformed timestamp fields make that record unrecognized without crashing analysis.

## Time-Window Correlation

Authentication rules use a centralized 10-minute window. Correlation sorts timestamped events deterministically and groups them by source IP or by source IP plus username where appropriate. Untimestamped events do not participate in time-aware rules.

AUTH-001 now requires five failures from one source within ten minutes. AUTH-002 requires ten failures within ten minutes and suppresses redundant AUTH-001 output for that source. AUTH-003 requires three invalid-user events within ten minutes.

AUTH-004 correlates five failures followed by a success from the same source IP and username within ten minutes. It highlights an event sequence worth review, not proof that credentials or an account were compromised.

## Detection Engine

Parsers produce immutable normalized events. Applicable rules return immutable `Finding` objects, which the engine sorts by severity, rule ID, source IP, and username. Loading, parsing, correlation, detection, reporting, and CLI presentation remain separated.

## Rule Table

| Rule | Description | Severity | Threshold / window |
|---|---|---:|---:|
| AUTH-001 | Repeated failed authentication | MEDIUM | 5 / 10 minutes |
| AUTH-002 | Potential brute-force pattern | HIGH | 10 / 10 minutes |
| AUTH-003 | Repeated invalid-user attempts | MEDIUM | 3 / 10 minutes |
| AUTH-004 | Success after repeated failures | HIGH | 5 failures + success / 10 minutes |
| WEB-001 | Repeated HTTP client errors | LOW | 8 responses / dataset |
| WEB-002 | Potential sensitive-path probing | MEDIUM | 1 path match / dataset |
| WEB-003 | Repeated HTTP server errors | MEDIUM | 5 responses / dataset |

Web thresholds remain dataset-wide in Phase 3, but findings use normalized web timestamps for `first_seen` and `last_seen`.

## Severity Meanings

- **HIGH:** A stronger heuristic pattern warranting timely review; not proof of compromise.
- **MEDIUM:** A notable pattern requiring contextual validation.
- **LOW:** An observation with common benign explanations that may still help an investigation.
- **INFO:** Contextual information. No current rule emits INFO.

## Installation

LogHunter requires Python 3.11 or newer and has no third-party runtime dependencies.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## CLI Examples

Human-readable analysis:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth
python -m loghunter analyze samples/access_sample.log --type web
python -m loghunter analyze samples/auth_sample.log --type auth --no-detect
```

Machine-readable analysis:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --format json
```

`--format text` is the default. JSON stdout contains only valid JSON with tool/version metadata, parse summary, detection state, structured findings, ISO 8601 timestamps, and the safety disclaimer. Raw log lines are excluded. `--no-detect` works with either output format.

## JSON Structure

```json
{
  "tool": "LogHunter",
  "version": "0.3.0",
  "file": "samples/auth_sample.log",
  "log_type": "auth",
  "summary": {
    "lines_processed": 35,
    "parsed_records": 32,
    "unrecognized_records": 3
  },
  "detection_enabled": true,
  "findings": [],
  "disclaimer": "Findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation."
}
```

## False-Positive Considerations

Time correlation improves context but does not establish intent. Repeated failures and a later success can result from password mistakes, stale credential caches, password-manager problems, or a legitimate user eventually entering the correct password. Client errors can originate from broken links or crawlers; sensitive-path requests can be authorized testing; server errors can be application defects. Every finding requires investigation.

## Security & Privacy

LogHunter analyzes only an explicitly supplied local regular file in read-only streaming mode. It makes no network requests, scans, authentication attempts, external reputation queries, or active-response changes. It executes no log-derived commands, modifies no source logs, blocks no address, and changes no firewall rule. Fixtures contain only synthetic identities and documentation-safe IP addresses.

## Testing

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall loghunter
```

Tests are deterministic, local, synthetic, and make no network calls.

## Limitations

Auth years and UTC timezone are contextual assumptions because traditional syslog records omit them. Cross-year log sets require the caller to choose an appropriate reference year. Phase 3 produces at most one finding per rule/group, does not correlate across files, does not persist state, and leaves web thresholds dataset-wide. Parser coverage remains intentionally narrow.

## Roadmap

1. Phase 1: safe loading, normalization, parsers, CLI, fixtures, and tests.
2. Phase 2: structured findings and transparent rules.
3. Phase 3: normalized timestamps, time-window correlation, AUTH-004, and JSON reporting.
4. Phase 4: analyst-oriented report filtering, schemas, and careful multi-file workflows without active response.
