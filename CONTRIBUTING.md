# Contributing to LogHunter

## Development Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -p "test_*.py"
```

## Expectations

- Keep loading, parsing, detection, filtering, configuration, and reporting concerns separated.
- Add deterministic tests for behavior changes and preserve controlled error handling.
- Use only synthetic test data and documentation-safe IP ranges.
- Never commit real logs, credentials, tokens, secrets, or personal data.
- Preserve offline defensive boundaries; proposals involving active response, scanning, blocking, or external services require explicit design discussion.
- Document false-positive considerations and avoid claims of confirmed compromise.

## Pull Requests

Keep changes focused, explain security and compatibility impact, list validation commands and results, and update relevant documentation. Do not bundle unrelated formatting or refactors with functional changes.
