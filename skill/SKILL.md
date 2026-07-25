---
name: vibe-scanner
description: Scan local Next.js/Supabase repositories and public HTTP(S) websites for common security exposures. Use when a user asks to security-check, audit, or review a vibe-coded app before deployment; check exposed environment files or credentials; inspect Supabase RLS, route authentication, CORS, browser headers, or cookie flags; or assess whether an app is safe to ship.
---

# Vibe Scanner

## Run the scan

Resolve the target from the user's request. Use the current working directory
only when it is clearly the intended repository; otherwise ask for the path or
URL.

Run the bundled scanner from this skill directory:

```bash
python3 scan.py --json "<absolute-project-path-or-public-url>"
```

Do not install dependencies. The bundled scanner uses only the Python standard
library. Repository scans stay local and read-only. URL scans make one public
GET request chain and inspect response metadata without crawling or attempting
exploitation.

Exit code `1` means the report contains FAIL results; still read and relay its
JSON output. Exit code `2` means the scan could not run and should be reported
as an error.

## Report the result

1. Lead with FAIL results, then warnings, then a short pass summary.
2. Include file paths and line numbers when present.
3. Never reproduce or infer secret values.
4. Label authentication, RLS, CORS, and header findings as heuristic when the
   result requires human confirmation.
5. Explain that a clean result covers only this scanner's checks, not a full
   penetration test or architecture review.

Do not modify the target unless the user separately asks for fixes.
