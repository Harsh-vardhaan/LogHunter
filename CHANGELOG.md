# Changelog

All notable changes to LogHunter are documented in this file.

## 1.0.0 - Unreleased

### Added

- Defensive CLI analysis for explicit local OpenSSH authentication and Apache/Nginx access logs.
- Immutable normalized events, safe read-only streaming, and source-file provenance.
- Explainable authentication rules AUTH-001 through AUTH-004 and web rules WEB-001 through WEB-003.
- Time-aware authentication correlation, success-after-failure analysis, and cross-file correlation.
- Multi-file summaries, deduplication, severity/rule/source-IP filters, and parsing-only mode.
- Deterministic text and JSON reports with schema version 1.0.
- Immutable versioned configuration with strict validation and `config-check` diagnostics.
- Formal report JSON Schema, synthetic fixtures, security documentation, architecture notes, and demo guidance.
- Local console entry point and release-readiness regression coverage.

### Security

- Local explicit inputs only; no network calls, scanning, credential testing, blocking, exploitation, or active response.
