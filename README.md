# LogHunter

A Python command-line defensive security tool for safely parsing local authentication and web logs, correlating events, and presenting transparent rule-based findings for analyst review.

## Phase 5 Status

LogHunter 0.5.0 adds strictly validated local JSON detection configuration, configuration diagnostics, effective-configuration report metadata, and a formal Draft 2020-12 JSON Schema document.

Three versions are maintained independently:

| Component | Version |
|---|---:|
| Application | 0.5.0 |
| Report schema | 1.0 |
| Configuration schema | 1.0 |

Findings remain heuristic indicators and do not prove compromise, malicious intent, or successful exploitation.

## Configuration Overview

Without `--config`, immutable built-in defaults preserve Phase 4 behavior exactly. A custom configuration is loaded only from an explicitly supplied local JSON file:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json
```

LogHunter never searches home directories, environment variables, registries, URLs, or cloud services for configuration. The file is opened read-only and is never executed or modified. Missing files, directories, and symbolic links are rejected.

The authoritative example is [examples/loghunter-config.json](examples/loghunter-config.json):

```json
{
  "version": "1.0",
  "auth": {
    "failed_medium_threshold": 4,
    "failed_high_threshold": 9,
    "invalid_user_threshold": 3,
    "success_after_failure_threshold": 4,
    "window_minutes": 10
  },
  "web": {
    "client_error_threshold": 7,
    "server_error_threshold": 4
  }
}
```

## Default Detection Settings

| Setting | Default |
|---|---:|
| AUTH-001 threshold | 5 |
| AUTH-002 threshold | 10 |
| AUTH-003 threshold | 3 |
| AUTH-004 prior failures | 5 |
| Auth window | 10 minutes |
| WEB-001 threshold | 8 |
| WEB-003 threshold | 5 |

Rules receive an immutable configuration object from the analysis layer. Rules never read files and there is no global mutable configuration.

## Strict Validation

Configuration validation rejects:

- malformed JSON or a non-object root;
- missing or unsupported `version` values;
- missing or unknown top-level, `auth`, or `web` keys;
- strings or booleans where integers are required;
- thresholds outside 1–100,000;
- auth windows outside 1–1,440 minutes;
- a high failure threshold lower than the medium threshold.

Values are never silently clamped. Expected errors produce a concise message, nonzero exit status, and no traceback.

## Configuration Diagnostics

Validate a configuration without analyzing logs:

```powershell
python -m loghunter config-check examples/loghunter-config.json
```

The command reports the file, schema version, validation status, and effective settings, followed by `No analysis was performed.` Invalid files exit nonzero.

## Multi-File and Filter Compatibility

Custom configuration works with safe cross-file correlation:

```powershell
python -m loghunter analyze samples/auth_sample.log samples/auth_extra.log --type auth --config examples/loghunter-config.json
```

Analyst filters still run after detection:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json --severity HIGH
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json --rule AUTH-004
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json --source-ip 203.0.113.50
```

`--severity` is an exact case-insensitive match, `--rule` validates known IDs, and `--source-ip` validates exact IPv4/IPv6 syntax. Filtering narrows the view; it does not change detection logic or confidence.

## Configuration with `--no-detect`

`--config` is allowed with `--no-detect`. LogHunter validates and records the configuration but does not run rules:

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json --no-detect
```

Finding-specific filters remain incompatible with `--no-detect`.

## Reporting Metadata

Text reports identify the application and configuration source:

```text
LOGHUNTER 0.5.0
Configuration: examples/loghunter-config.json (schema 1.0)
```

JSON reports contain distinct metadata:

```json
{
  "schema": {"name": "loghunter-report", "version": "1.0"},
  "tool": {"name": "LogHunter", "version": "0.5.0"},
  "configuration": {
    "source": "examples/loghunter-config.json",
    "schema_version": "1.0",
    "effective": {
      "auth": {},
      "web": {}
    }
  }
}
```

The effective section contains only validated detection settings. No arbitrary configuration content is copied into reports.

## Formal Report Schema

The formal report schema is [schemas/loghunter-report.schema.json](schemas/loghunter-report.schema.json). It uses [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/schema) and defines metadata, configuration, filters, aggregate/per-file summaries, findings, severity enums, nullable fields, timestamps, counters, provenance, and disclaimer.

Report schema version remains 1.0. The Phase 5 `configuration` property is optional in the schema, preserving structural compatibility with Phase 4 version 1.0 reports. Tests validate the schema contract without adding a runtime JSON Schema dependency.

## Multi-File Safety and Provenance

Every supplied path is validated before parsing. LogHunter rejects directories, symbolic links, missing paths, and duplicate file arguments. Files are parsed independently, records are deduplicated for detection, provenance is merged, and events are sorted chronologically. All files in one invocation must share an explicit log type.

## Security and Analyst Guidance

LogHunter analyzes only explicitly supplied local files and reads configuration only from explicitly supplied local paths. It makes no network calls, scans, authentication attempts, reputation queries, or active-response changes. It executes no log or configuration content, modifies no inputs, blocks nothing, and changes no firewall or account settings.

Configuration changes sensitivity, not certainty. Lower thresholds or wider windows can increase findings and false positives. Cross-file correlation assumes compatible timestamps and inferred auth years. Findings always require contextual analyst review.

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

Only configuration schema 1.0 is supported. Configuration cannot disable individual rules or change sensitive-path patterns. Report contract validation is performed in tests rather than at runtime. Auth year and UTC timezone remain contextual assumptions. No configuration inheritance, remote loading, automatic discovery, persisted analysis state, or active response exists.

## Roadmap

1. Phases 1–4: safe parsing, transparent rules, time correlation, JSON, multi-file analysis, and filters.
2. Phase 5: immutable external configuration, diagnostics, and formal report schema.
3. Phase 6: rule enable/disable controls, configuration migration guidance, and packaged schema distribution—without active response.
