# LogHunter

A Python command-line defensive security tool that parses local authentication and web logs, normalizes supported records, and evaluates transparent rule-based heuristics.

## Overview

LogHunter helps analysts identify patterns worth reviewing without making unsupported claims. It operates offline on an explicitly supplied local file and reports structured findings rather than dumping raw log contents.

## Phase 2 Status

Version 0.2.0 adds a deterministic detection engine and six documented authentication and web rules. Findings are heuristic indicators and do not prove compromise, malicious intent, or successful exploitation.

## Detection Engine

Parsers produce immutable `LogEvent` records. The detection engine selects rules for the chosen log type, passes them only normalized events, collects immutable `Finding` objects, and sorts them by severity, rule ID, source IP, and username. Rules remain separate from loading, parsing, CLI orchestration, and presentation.

## Authentication Rules

- Repeated failures are grouped by source IP. Five through nine failures trigger AUTH-001.
- Ten or more failures trigger AUTH-002; AUTH-001 is suppressed for that source to avoid redundant noise.
- Three invalid-user events from one source trigger AUTH-003.

Mistyped credentials, stale automation, and misconfigured services are possible benign explanations for authentication findings.

## Web Rules

- WEB-001 groups HTTP 4xx responses by source. Its severity is LOW because broken links, crawlers, and outdated clients commonly generate client errors.
- WEB-002 uses a small, deterministic, case-insensitive path list: `/.env`, `/.git/`, `/wp-admin`, `/phpmyadmin`, and `/admin`. Query strings are ignored for matching.
- WEB-003 groups HTTP 5xx responses by source. Application faults are a primary possible explanation.

## Rule ID Table

| Rule | Description | Severity | Default threshold |
|---|---|---:|---:|
| AUTH-001 | Repeated failed authentication | MEDIUM | 5 failures |
| AUTH-002 | Potential brute-force pattern | HIGH | 10 failures |
| AUTH-003 | Repeated invalid-user attempts | MEDIUM | 3 attempts |
| WEB-001 | Repeated HTTP client errors | LOW | 8 responses |
| WEB-002 | Potential sensitive-path probing | MEDIUM | 1 path match |
| WEB-003 | Repeated HTTP server errors | MEDIUM | 5 responses |

## Severity Meanings

- **HIGH:** A stronger heuristic pattern that warrants timely review; it is not proof of compromise.
- **MEDIUM:** A notable pattern that merits investigation and contextual validation.
- **LOW:** An observation with common benign explanations that may still be useful during review.
- **INFO:** Contextual information. No Phase 2 rule currently emits INFO findings.

## Thresholds

Thresholds are centralized in `loghunter/detection/constants.py`. Phase 2 intentionally has no external configuration format or overall numeric risk score.

## Installation

LogHunter requires Python 3.11 or newer and has no third-party runtime dependencies.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## CLI Examples

```powershell
python -m loghunter --help
python -m loghunter analyze samples/auth_sample.log --type auth
python -m loghunter analyze samples/access_sample.log --type web
python -m loghunter analyze samples/auth_sample.log --type auth --no-detect
```

The `--no-detect` option retains parsing and counting while skipping all detection rules. If no rule matches, LogHunter states that no findings matched the current rule set—not that the system is secure or free from threats.

## Security Boundaries

LogHunter analyzes only an explicitly supplied local regular file in read-only streaming mode. It makes no network requests, scans, authentication attempts, external reputation queries, or active-response changes. It executes no log-derived commands, modifies no source log, blocks no address, and changes no firewall rule. Repository fixtures contain only synthetic identities and documentation-safe IP addresses.

## False-Positive Considerations

Findings require analyst context. Failed logins can result from typing errors, stale automation, misconfiguration, or guessing. Repeated 404 responses can come from broken links, crawlers, outdated clients, or reconnaissance. Sensitive-path requests can arise from authorized security testing, accidental clients, or probing. Server errors can reflect application defects rather than hostile behavior.

## Testing

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall loghunter
```

Tests are deterministic, local, synthetic, and make no network calls.

## Limitations

Rules operate across the supplied dataset, not reliable time windows. Source timestamps remain strings, IPv4/IPv6 values are not semantically validated, parser coverage is intentionally narrow, and findings require human review. AUTH-004 success-after-failures and request-rate rules are deferred until timestamps are normalized reliably.

## Roadmap

1. Phase 1: safe loading, normalization, parsing, CLI, fixtures, and tests.
2. Phase 2: structured findings and transparent authentication/web rules.
3. Phase 3: normalized timestamps, time-window correlation, and richer reporting.
4. Later: simple external threshold configuration and additional well-tested defensive rules.
