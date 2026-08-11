# LogHunter

LogHunter is a defensive Python CLI for parsing explicitly supplied local authentication and web logs, correlating normalized events, and presenting transparent heuristic findings for analyst review.

Version 1.0.0 is release-ready on this branch. Findings do not prove compromise, malicious intent, or successful exploitation.

## Features

- Safe, read-only streaming of explicit regular local files; directories and symbolic links are rejected.
- OpenSSH authentication and Apache/Nginx common/combined access-log parsers.
- Time-aware AUTH-001–004 and dataset-wide WEB-001–003 rules.
- Multi-file analysis, cross-file correlation, deduplication, and source provenance.
- Exact severity, rule-ID, and source-IP analyst filters.
- Deterministic text and JSON reports with ISO timestamps and report schema 1.0.
- Immutable local JSON configuration, strict bounds, and `config-check` diagnostics.
- Standard-library runtime with Python 3.11+ and module/console entry points.

## Architecture

```text
CLI -> validation -> read-only loading -> parsing -> normalization
    -> deduplication/correlation -> detection -> filtering -> reporting
```

Configuration is loaded once, validated into immutable dataclasses, and passed to rule instances. Detection completes before analyst filters are applied. See [Architecture](docs/ARCHITECTURE.md).

## Detection Rules

| Rule | Description | Severity | Default |
|---|---|---:|---:|
| AUTH-001 | Repeated failed authentication | MEDIUM | 5 / 10 min |
| AUTH-002 | Potential brute-force pattern | HIGH | 10 / 10 min |
| AUTH-003 | Repeated invalid-user attempts | MEDIUM | 3 / 10 min |
| AUTH-004 | Success after repeated failures | HIGH | 5 + success / 10 min |
| WEB-001 | Repeated HTTP client errors | LOW | 8 / dataset |
| WEB-002 | Sensitive-path probing | MEDIUM | 1 match / dataset |
| WEB-003 | Repeated HTTP server errors | MEDIUM | 5 / dataset |

Every finding includes a description, concise evidence, recommendation, severity, count, timestamps where available, and contributing files. Rules document plausible benign explanations.

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Both entry points remain supported:

```powershell
python -m loghunter --version
loghunter --version
```

## Quick Start

```powershell
python -m loghunter --help
python -m loghunter analyze samples/auth_sample.log --type auth
python -m loghunter analyze samples/access_sample.log --type web
python -m loghunter analyze samples/auth_sample.log --type auth --format json
```

Security findings do not change the successful exit code. Expected input/configuration errors use nonzero exits, stderr, and no traceback.

## Multi-File Analysis

```powershell
python -m loghunter analyze samples/auth_sample.log samples/auth_extra.log --type auth
```

Files are validated and parsed independently, then compatible normalized events are deduplicated and correlated chronologically. Per-file counts and merged provenance remain visible. All files in one invocation must share an explicit log type.

## Analyst Filters

Filters narrow the completed finding set; they do not change detection or confidence.

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --severity HIGH
python -m loghunter analyze samples/auth_sample.log --type auth --rule AUTH-004
python -m loghunter analyze samples/auth_sample.log --type auth --source-ip 203.0.113.50
```

## Configuration

Built-in defaults are immutable. Custom configuration is loaded only from an explicit local JSON file:

```powershell
python -m loghunter config-check examples/loghunter-config.json
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json
```

Configuration schema version is 1.0. Unknown/missing keys, wrong types, unsupported versions, thresholds outside 1–100,000, and windows outside 1–1,440 minutes are rejected. No remote loading, discovery, inheritance, or input mutation occurs.

## JSON Reporting

JSON output contains separate metadata for:

- application version `1.0.0`;
- report schema version `1.0`;
- configuration schema version `1.0` and effective settings.

It also contains active filters, aggregate/per-file summaries, deterministic findings, provenance, and the disclaimer—never raw log lines. The formal Draft 2020-12 contract is [loghunter-report.schema.json](schemas/loghunter-report.schema.json). It supports contract testing/documentation and is not required at runtime.

## Example Output

```text
[HIGH] AUTH-004
Successful Authentication After Repeated Failures
Source IP: 203.0.113.50
Username: demo-user
Events: 6

A successful authentication was observed after repeated failures...
```

## Security Boundaries

LogHunter performs offline defensive analysis only. It makes no network calls, scans, authentication attempts, exploitation attempts, reputation queries, blocking changes, firewall changes, account actions, or active response. It executes no input content and modifies no logs or configuration. Use it only with data you are authorized to access. See [Security Policy](SECURITY.md).

## Limitations

Parser coverage is narrow; auth years/timezones require explicit assumptions; findings can be false positives; web error rules remain dataset-wide; and there is no persistent state, streaming ingestion, external enrichment, automatic rotation discovery, or active response. See [Known Limitations](docs/LIMITATIONS.md).

## Testing

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall loghunter
```

Tests use synthetic fixtures and documentation-safe IP ranges only. A Windows symlink-policy test may skip when the environment lacks permission to create symlinks; rejection behavior remains enforced.

## Project Structure

```text
loghunter/   application, configuration, parsers, detection, reporting
samples/     synthetic auth and web fixtures
examples/    safe example configuration
schemas/     formal report JSON Schema
tests/       deterministic regression and contract tests
docs/        architecture, demo, limitations, release notes/checklist
```

## Demo and Release Documentation

- [3–5 minute demo](docs/DEMO.md)
- [Release notes](docs/RELEASE_NOTES_1.0.0.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)

## Future Work

Potential later work includes rule enable/disable configuration and configuration migration diagnostics. These are intentionally outside 1.0.0 stabilization. Active response and unsupported claims of compromise remain out of scope.

## Versioning and License

Application, report schema, and configuration schema versions evolve independently. This repository currently has no `LICENSE` file; no legal license is implied by this README.
