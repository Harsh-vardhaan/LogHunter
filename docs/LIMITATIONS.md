# Known Limitations

- Parser coverage is intentionally narrow: selected OpenSSH authentication messages and common/combined Apache or Nginx access records.
- Traditional auth syslog timestamps omit a year and timezone. LogHunter uses an explicit reference year and treats them as UTC; the CLI defaults to the current UTC year.
- Findings are heuristic and may have benign explanations. Time correlation improves context but does not establish intent or compromise.
- Web error rules remain dataset-wide rather than time-windowed.
- Analysis has no persistent state, streaming ingestion, or correlation between separate invocations.
- Log rotation is not discovered automatically. Every analyzed file must be supplied explicitly.
- Multi-file invocations require one shared log type and compatible timestamps.
- Identical normalized records are deduplicated, but semantically equivalent records with different text may remain distinct.
- There is no external enrichment, IP reputation, threat intelligence, geolocation, or SIEM integration.
- Configuration schema 1.0 changes thresholds and the auth window only; it cannot disable rules or change sensitive-path patterns.
- JSON Schema compatibility is checked during tests, not enforced at runtime.
- No automatic blocking, account lockout, firewall modification, credential rotation, or other active response exists.
- LogHunter is a defensive analysis and portfolio project, not a production SIEM or complete intrusion-detection system.
