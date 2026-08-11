# LogHunter 1.0.0 Release Notes

LogHunter 1.0.0 is a defensive command-line security log analysis and portfolio project. It parses explicitly supplied local authentication and web access logs, normalizes supported events, applies transparent heuristics, and produces analyst-friendly text or JSON reports.

## Major Capabilities

- OpenSSH authentication and Apache/Nginx common/combined access-log parsing.
- AUTH-001–004 and WEB-001–003 rule-based findings.
- Time-aware authentication and success-after-failure correlation.
- Multi-file analysis, cross-file provenance, and deterministic deduplication.
- Exact severity, rule-ID, and source-IP filters.
- Versioned immutable local JSON configuration and `config-check`.
- Deterministic JSON reporting with report schema 1.0 and formal JSON Schema.

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
loghunter --version
```

## Quick Start

```powershell
loghunter analyze samples/auth_sample.log --type auth
loghunter analyze samples/access_sample.log --type web --format json
```

## Safety Boundaries

LogHunter makes no network calls, performs no scanning or credential testing, executes no log or configuration content, modifies no inputs, and takes no active response. Findings do not prove compromise or malicious intent.

## Known Limitations

Parser coverage is narrow, auth years/timezones require assumptions, web error rules are dataset-wide, and analysis has no persistent state or automatic log discovery. See `docs/LIMITATIONS.md`.

## Release Validation

The release candidate is validated with the full deterministic unit suite, package compilation, editable installation, module/console smoke tests, formal report-schema contract checks, and Git whitespace/security hygiene checks. The exact final test count is recorded in the Phase 6 implementation report.
