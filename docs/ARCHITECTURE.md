# LogHunter Architecture

## Analysis Pipeline

```text
CLI
  -> argument and configuration validation
  -> explicit local file validation
  -> read-only streaming loader
  -> source-specific parser
  -> normalized immutable events
  -> cross-file deduplication and chronological ordering
  -> time-aware or dataset-wide detection rules
  -> post-detection analyst filters
  -> deterministic text or JSON reporting
```

## Responsibilities

- `cli.py` validates command combinations and selects output format.
- `config.py` loads explicit local JSON into immutable validated settings.
- `loader.py` validates and streams regular, non-symlink local files.
- `parsers/` converts supported auth or web lines into normalized events.
- `analysis.py` preserves per-file summaries and provenance, deduplicates records, and combines events.
- `detection/` contains rule interfaces, correlation helpers, immutable findings, and configured rules.
- `filters.py` narrows the complete finding set without changing detection.
- `reporting.py` produces deterministic human and machine-readable reports.

## Configuration Flow

The CLI loads either the immutable built-in defaults or one explicitly supplied configuration file. The validated object is passed through analysis to a newly constructed detection engine and rule instances. Rules never access configuration files or global mutable state.

## Multi-File Provenance

All files in one invocation share a log type. They are parsed independently, then normalized events are deduplicated and sorted. Each event retains supplied source context; each finding lists the files that contributed correlated evidence.

## Schemas and Versioning

Application version, report schema version, and configuration schema version are independent. The report JSON Schema in `schemas/` supports documentation and contract testing and is not required at runtime.

## Security Boundaries

The pipeline operates only on explicit local inputs, makes no network calls, executes no input content, and performs no active response. Expected input errors are controlled; unexpected programming errors are not silently swallowed.
