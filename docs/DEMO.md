# LogHunter Interview Demo

This flow takes approximately three to five minutes from the repository root.

## 1. Establish Scope

```powershell
python -m loghunter --version
python -m loghunter --help
```

Explain that LogHunter performs offline defensive analysis on explicit local files and reports heuristics rather than confirmed compromise.

## 2. Analyze Authentication Activity

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth
```

Highlight normalized timestamps, AUTH-002, and AUTH-004. Explain a reasonable benign cause for each.

## 3. Demonstrate Cross-File Correlation

```powershell
python -m loghunter analyze samples/auth_sample.log samples/auth_extra.log --type auth
```

Point out the per-file summary and the finding whose `source_files` includes both fixtures.

## 4. Narrow the Investigation

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --severity HIGH
python -m loghunter analyze samples/auth_sample.log --type auth --rule AUTH-004
```

Explain that filtering happens after detection and does not increase confidence.

## 5. Validate and Use Configuration

```powershell
python -m loghunter config-check examples/loghunter-config.json
python -m loghunter analyze samples/auth_sample.log --type auth --config examples/loghunter-config.json
```

Show immutable defaults, strict bounds, versioned configuration, and how lower example thresholds change evidence counts.

## 6. Show Machine-Readable Output

```powershell
python -m loghunter analyze samples/auth_sample.log --type auth --format json
```

Mention deterministic ordering, separate tool/report/config versions, ISO timestamps, provenance, disclaimer, and the absence of raw log dumps.

## 7. Close with Boundaries

Reference `SECURITY.md` and `docs/LIMITATIONS.md`: no scanning, network access, exploitation, reputation lookup, persistent state, or active response.
