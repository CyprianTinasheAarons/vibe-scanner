# Contributing

Thanks for helping improve Vibe Scanner. Changes should keep the scanner local,
read-only, deterministic, and conservative about security claims.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,mcp]'
```

Before opening a pull request, run:

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest -q
python scripts/export_skill.py skill
```

## Pull requests

- Add focused tests for behavior changes and false-positive fixes.
- Do not include real credentials in fixtures, logs, screenshots, or issues.
- Keep check messages actionable without exposing matched secret values.
- Describe heuristic limitations and compatibility implications.
- Keep `skill/core.py`, `skill/scanner.py`, and `skill/url_scanner.py` generated
  from their canonical top-level sources.

For new checks, document the threat being detected, expected severity, known
false positives, and why the detection can run without modifying the target.
