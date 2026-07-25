# Vibe Scanner

[![CI](https://github.com/CyprianTinasheAarons/vibe-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/CyprianTinasheAarons/vibe-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Vibe Scanner is a read-only security scanner for Next.js/Supabase repositories
and deployed websites. It provides human-readable terminal output and stable
JSON for CI, MCP clients, and coding agents.

## Quick start

Vibe Scanner requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e .
vibe-scanner .
```

Scan another repository or a deployed URL:

```bash
vibe-scanner /absolute/path/to/project
vibe-scanner https://topiax.xyz
```

If the console command is unavailable, run `python cli.py <target>` from this
repository.

## JSON and CI

Use `--json` for automation:

```bash
vibe-scanner --json /absolute/path/to/project > report.json
vibe-scanner --json https://topiax.xyz > url-report.json
```

Exit codes:

- `0`: no FAIL results; warnings may still be present
- `1`: one or more FAIL results
- `2`: invalid target, network failure, or scanner error

Each JSON report includes the scanner version, target type, normalized target,
severity counts, and complete results. Secret values are never included in
messages.

## Checks

Repository scans run nine checks:

1. `.env` files not excluded by `.gitignore`
2. Hardcoded Stripe, OpenAI, GitHub, or AWS credentials
3. Supabase tables without matching RLS enablement
4. Admin/dashboard pages without a recognized authentication check
5. Git-tracked environment or credential files
6. Sensitive-looking `NEXT_PUBLIC_*` variables
7. Next.js API handlers without a recognized authentication check
8. Wildcard CORS configuration
9. Missing baseline browser security headers

URL scans run six checks: reachability, final HTTPS transport, deployed
security headers, wildcard CORS, cookie flags, and `X-Powered-By` disclosure.
They make one public GET request chain, follow redirects, and do not crawl,
submit forms, or attempt exploitation. Localhost and private-network URLs are
rejected.

Authentication, RLS, CORS, and header checks are static heuristics. Confirm
their context before treating a warning as a vulnerability. Repository
findings are capped at 50 results per check.

## MCP setup

Install the MCP extra:

```bash
python -m pip install -e '.[mcp]'
```

Register the local stdio server in an MCP client:

```json
{
  "mcpServers": {
    "vibe-scanner": {
      "command": "/absolute/path/to/vibe-scanner/.venv/bin/python",
      "args": ["/absolute/path/to/vibe-scanner/mcp_server.py"]
    }
  }
}
```

The `scan_vibe_project` tool accepts an absolute repository path or public
HTTP(S) URL and returns the same structured report as the CLI.

## Codex skill

The `skill/` folder is a self-contained, dependency-free Codex skill. Export a
fresh bundle after changing the canonical scanner:

```bash
python scripts/export_skill.py /path/to/vibe-scanner-skill
python /path/to/vibe-scanner-skill/scan.py --json /path/to/project
```

To install it for Codex, export or copy the bundle to
`~/.codex/skills/vibe-scanner`. Codex will discover the skill on the next turn.

## Development

Install test dependencies and run the suite:

```bash
python -m pip install -e '.[dev,mcp]'
python -m pytest -q
```

Validate and synchronize the portable skill:

```bash
python scripts/export_skill.py skill
python ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py skill
```

Project layout:

```text
core.py                 canonical repository checks and result model
url_scanner.py          deployed URL checks
scanner.py              directory/URL dispatcher
cli.py                  terminal and JSON interface
mcp_server.py           MCP wrapper
scripts/export_skill.py portable skill generator
skill/                  generated Codex skill
tests/                  automated tests
```
