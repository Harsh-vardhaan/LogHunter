# LogHunter

A command-line security log analysis tool built in Python for parsing authentication and web server logs and preparing them for rule-based threat detection.

## Overview

LogHunter normalizes supported local log records and reports parsing statistics. Phase 1 performs log parsing only; threat detection is not enabled.

## Why LogHunter Exists

This portfolio project demonstrates safe ingestion, extensible parser design, testing, and defensive-security boundaries in an interview-ready Python codebase.

## Current Phase

Version 0.1.0 establishes the CLI, read-only streaming loader, normalized event model, SSH authentication parser, and Apache/Nginx access parser.

## Planned Capabilities

Later phases may add transparent, tested rules for suspicious authentication and web activity. LogHunter currently does not claim to detect brute-force attacks, malware, compromised hosts, confirmed intrusions, or malicious IPs.

## Supported Log Types

- `auth`: selected synthetic OpenSSH accepted, failed-password, and invalid-user events.
- `web`: Apache/Nginx common or combined access records with method, path, status, and optional user agent.

Inference is conservative: filenames containing `auth` select auth; `access` or `web` select web. Use `--type` for ambiguous names.

## Project Structure

```text
loghunter/          Application, model, loader, CLI, and parsers
samples/            Synthetic demonstration logs
tests/              Standard-library unit tests
pyproject.toml      Package metadata and CLI entry point
```

## Installation

Requires Python 3.11+. Runtime dependencies are standard-library only.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Usage

```powershell
python -m loghunter --help
python -m loghunter analyze samples/auth_sample.log
python -m loghunter analyze samples/access_sample.log --type web
```

## Example Output

```text
========================================
              LOGHUNTER
========================================

File: samples/auth_sample.log
Log type: auth

Lines processed: 5
Parsed records: 3
Unrecognized records: 2

Phase 1 parsing complete.
Threat detection is not enabled yet.
```

## Testing

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall loghunter
```

Tests use only local synthetic data and make no network calls.

## Security & Privacy

Phase 1 reads explicitly supplied local regular files in read-only streaming mode. It does not crawl directories, execute log content, scan systems, call external services, or modify logs. Fixtures contain synthetic identities and documentation-safe IPs. Raw records are not printed by default.

## Limitations

Parsing covers a deliberately small subset. Timestamps remain source strings, IPs are extracted but not classified, multiline records are unsupported, and invalid UTF-8 is replaced. Type inference uses filenames rather than content.

## Roadmap

1. Phase 1: safe loading, normalization, parsing, CLI, fixtures, and tests.
2. Phase 2: explicit rule interfaces and tested authentication/web detection rules.
3. Later: reporting improvements and carefully scoped enrichment when implemented.
