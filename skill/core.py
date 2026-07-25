"""Read-only static security checks for Next.js and Supabase projects."""

from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

SCANNER_VERSION = "1.0.0"
MAX_FINDINGS_PER_CHECK = 50
IGNORED_DIRECTORIES = {
    ".git",
    ".next",
    ".venv",
    "__pycache__",
    "__tests__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "test",
    "tests",
    "vendor",
    "venv",
}
SOURCE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}


class Severity(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass(frozen=True)
class CheckResult:
    check_name: str
    severity: Severity
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None

    def to_dict(self) -> dict:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


def _relative(target_dir: Path, path: Path) -> str:
    try:
        return path.relative_to(target_dir).as_posix()
    except ValueError:
        return path.as_posix()


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _iter_files(target_dir: Path, extensions: Optional[set[str]] = None) -> Iterable[Path]:
    for path in target_dir.rglob("*"):
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        if extensions is None or path.suffix.lower() in extensions:
            yield path


def _pass(check_name: str, message: str) -> list[CheckResult]:
    return [CheckResult(check_name, Severity.PASS, message)]


def _cap(results: list[CheckResult], check_name: str) -> list[CheckResult]:
    if len(results) <= MAX_FINDINGS_PER_CHECK:
        return results
    capped = results[:MAX_FINDINGS_PER_CHECK]
    capped.append(
        CheckResult(
            check_name,
            Severity.WARNING,
            f"More than {MAX_FINDINGS_PER_CHECK} findings detected; report truncated.",
        )
    )
    return capped


def _is_gitignored(path: Path, patterns: list[str], target_dir: Path) -> bool:
    relative = _relative(target_dir, path)
    name = path.name
    ignored = False
    for raw_pattern in patterns:
        pattern = raw_pattern.strip()
        if not pattern or pattern.startswith("#"):
            continue
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        pattern = pattern.lstrip("/")
        matches = fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern)
        matches = matches or (
            pattern.endswith("/") and relative.startswith(pattern.rstrip("/") + "/")
        )
        if matches:
            ignored = not negated
    return ignored


def check_env_exposure(target_dir: Path) -> list[CheckResult]:
    check = "env_exposure"
    template_suffixes = (".example", ".sample", ".template")
    env_files = [
        path
        for path in target_dir.glob(".env*")
        if path.is_file() and not path.name.endswith(template_suffixes)
    ]
    if not env_files:
        return _pass(check, "No local .env files found.")
    gitignore = target_dir / ".gitignore"
    patterns = _read(gitignore).splitlines() if gitignore.exists() else []
    findings = [
        CheckResult(
            check,
            Severity.FAIL,
            "Environment file is not excluded by .gitignore.",
            _relative(target_dir, path),
        )
        for path in env_files
        if not _is_gitignored(path, patterns, target_dir)
    ]
    if findings:
        return _cap(findings, check)
    return _pass(check, "Local .env files are excluded by .gitignore.")


SECRET_PATTERNS = {
    "Stripe live secret key": (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), Severity.FAIL),
    "Stripe live publishable key": (
        re.compile(r"\bpk_live_[A-Za-z0-9]{16,}\b"),
        Severity.WARNING,
    ),
    "OpenAI API key": (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), Severity.FAIL),
    "GitHub token": (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), Severity.FAIL),
    "AWS access key": (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), Severity.FAIL),
}


def check_hardcoded_keys(target_dir: Path) -> list[CheckResult]:
    check = "hardcoded_keys"
    findings: list[CheckResult] = []
    for path in _iter_files(target_dir, SOURCE_EXTENSIONS):
        content = _read(path)
        for label, (pattern, severity) in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                findings.append(
                    CheckResult(
                        check,
                        severity,
                        f"Possible {label} hardcoded in source; value is redacted.",
                        _relative(target_dir, path),
                        _line_number(content, match.start()),
                    )
                )
    if findings:
        return _cap(findings, check)
    return _pass(check, "No supported hardcoded secret patterns found in source files.")


CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r'(?:[\w"]+\.)?[\"]?([\w-]+)[\"]?',
    re.IGNORECASE,
)
ENABLE_RLS = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:[\w\"]+\.)?"
    r"[\"]?([\w-]+)[\"]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)


def check_supabase_rls(target_dir: Path) -> list[CheckResult]:
    check = "supabase_rls"
    migrations = target_dir / "supabase" / "migrations"
    if not migrations.is_dir():
        return _pass(check, "Not applicable: no Supabase migrations directory found.")
    created: dict[str, tuple[Path, int]] = {}
    rls_enabled: set[str] = set()
    for path in sorted(migrations.glob("*.sql")):
        content = _read(path)
        for match in CREATE_TABLE.finditer(content):
            created.setdefault(
                match.group(1).lower(),
                (path, _line_number(content, match.start())),
            )
        rls_enabled.update(match.group(1).lower() for match in ENABLE_RLS.finditer(content))
    if not created:
        return _pass(check, "No CREATE TABLE statements found in Supabase migrations.")
    findings = [
        CheckResult(
            check,
            Severity.WARNING,
            f"Table '{table}' has no matching RLS enablement (static heuristic).",
            _relative(target_dir, path),
            line,
        )
        for table, (path, line) in created.items()
        if table not in rls_enabled
    ]
    if findings:
        return _cap(findings, check)
    return _pass(check, "All tables created in migrations have matching RLS enable statements.")


AUTH_PATTERN = re.compile(
    r"\b(?:getServerSession|auth|requireAuth|requireUser|verifyToken|verifySession|getUser)"
    r"\s*\(|supabase\.auth\.getUser|clerkMiddleware|withAuth",
    re.IGNORECASE,
)


def _next_pages(target_dir: Path, names: tuple[str, ...]) -> list[Path]:
    paths: list[Path] = []
    for app_dir in target_dir.rglob("app"):
        if any(part in IGNORED_DIRECTORIES for part in app_dir.parts):
            continue
        for name in names:
            paths.extend(path for path in app_dir.rglob(name) if path.suffix in SOURCE_EXTENSIONS)
    return sorted(set(paths))


def _unauthenticated(
    target_dir: Path,
    check: str,
    candidates: Iterable[Path],
    label: str,
) -> list[CheckResult]:
    findings = []
    for path in candidates:
        if not AUTH_PATTERN.search(_read(path)):
            findings.append(
                CheckResult(
                    check,
                    Severity.WARNING,
                    f"{label} has no recognized authentication check (static heuristic).",
                    _relative(target_dir, path),
                    1,
                )
            )
    return _cap(findings, check)


def check_ghost_admin(target_dir: Path) -> list[CheckResult]:
    check = "ghost_admin"
    candidates = []
    for segment in ("admin", "dashboard"):
        pages = _next_pages(
            target_dir,
            ("page.ts", "page.tsx", "page.js", "page.jsx"),
        )
        candidates.extend(path for path in pages if f"/app/{segment}/" in path.as_posix())
    if not candidates:
        return _pass(check, "Not applicable: no Next.js admin or dashboard pages found.")
    findings = _unauthenticated(target_dir, check, candidates, "Admin/dashboard page")
    return findings or _pass(
        check,
        "Recognized authentication checks found in admin/dashboard pages.",
    )


SENSITIVE_PUBLIC_NAME = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PRIVATE|SERVICE_ROLE|API_KEY|ACCESS_KEY|DATABASE_URL)",
    re.IGNORECASE,
)


def check_public_env_secrets(target_dir: Path) -> list[CheckResult]:
    check = "public_env_secrets"
    findings: list[CheckResult] = []
    for path in target_dir.glob(".env*"):
        if not path.is_file():
            continue
        content = _read(path)
        for match in re.finditer(
            r"^\s*(NEXT_PUBLIC_[A-Za-z0-9_]+)\s*=\s*(.+)$",
            content,
            re.MULTILINE,
        ):
            if SENSITIVE_PUBLIC_NAME.search(match.group(1)):
                findings.append(
                    CheckResult(
                        check,
                        Severity.FAIL,
                        f"Sensitive-looking variable '{match.group(1)}' uses NEXT_PUBLIC_; "
                        "value is redacted.",
                        _relative(target_dir, path),
                        _line_number(content, match.start()),
                    )
                )
    if findings:
        return _cap(findings, check)
    return _pass(
        check,
        "No sensitive-looking NEXT_PUBLIC_ variables found in local environment files.",
    )


def _tracked_files(target_dir: Path) -> set[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(target_dir), "ls-files", "-z"],
            capture_output=True,
            text=False,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode != 0:
        return set()
    return {entry.decode("utf-8", errors="ignore") for entry in result.stdout.split(b"\0") if entry}


def check_git_tracked_sensitive_files(target_dir: Path) -> list[CheckResult]:
    check = "git_tracked_sensitive_files"
    tracked = _tracked_files(target_dir)
    if not tracked:
        return _pass(check, "Not applicable: no readable Git index found.")
    sensitive = re.compile(
        r"(?:^|/)(?:\.env(?:\..+)?|.*(?:id_rsa|id_ed25519|private[_-]?key|"
        r"service[_-]?account|credentials?).*\.(?:json|pem|key)|.*\.(?:pem|key|p12))$",
        re.IGNORECASE,
    )
    findings = [
        CheckResult(
            check,
            Severity.FAIL,
            "Sensitive environment or credential file is tracked by Git.",
            path,
        )
        for path in sorted(tracked)
        if sensitive.search(path) and not path.endswith(".example")
    ]
    if findings:
        return _cap(findings, check)
    return _pass(check, "No sensitive environment or credential files are tracked by Git.")


CORS_WILDCARD = re.compile(
    r"(?:Access-Control-Allow-Origin[\"\']?\s*[:=]\s*[\"\']\*|"
    r"origin\s*:\s*[\"\']\*|allow_origin\s*=\s*[\"\']\*)",
    re.IGNORECASE,
)
CORS_CREDENTIALS = re.compile(
    r"(?:Access-Control-Allow-Credentials[\"\']?\s*[:=]\s*[\"\']?true|"
    r"credentials\s*:\s*true|allow_credentials\s*=\s*True)",
    re.IGNORECASE,
)


def check_permissive_cors(target_dir: Path) -> list[CheckResult]:
    check = "permissive_cors"
    findings = []
    for path in _iter_files(target_dir, SOURCE_EXTENSIONS):
        content = _read(path)
        wildcard = CORS_WILDCARD.search(content)
        if wildcard:
            severity = Severity.FAIL if CORS_CREDENTIALS.search(content) else Severity.WARNING
            if severity == Severity.FAIL:
                message = "Wildcard CORS origin is combined with credentials."
            else:
                message = (
                    "Wildcard CORS origin detected; review whether unrestricted "
                    "cross-origin access is intended."
                )
            findings.append(
                CheckResult(
                    check,
                    severity,
                    message,
                    _relative(target_dir, path),
                    _line_number(content, wildcard.start()),
                )
            )
    if findings:
        return _cap(findings, check)
    return _pass(check, "No permissive wildcard CORS configuration found.")


HEADER_PATTERNS = {
    "Content-Security-Policy": re.compile(r"content-security-policy", re.IGNORECASE),
    "X-Frame-Options": re.compile(r"x-frame-options|frame-ancestors", re.IGNORECASE),
    "X-Content-Type-Options": re.compile(r"x-content-type-options", re.IGNORECASE),
    "Referrer-Policy": re.compile(r"referrer-policy", re.IGNORECASE),
}


def check_security_headers(target_dir: Path) -> list[CheckResult]:
    check = "security_headers"
    config_names = (
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "middleware.ts",
        "middleware.js",
    )
    config_files = [target_dir / name for name in config_names]
    contents = "\n".join(_read(path) for path in config_files if path.is_file())
    package_json = _read(target_dir / "package.json")
    is_next_project = bool(re.search(r'"next"\s*:', package_json)) or any(
        path.is_file() for path in config_files
    )
    if not is_next_project:
        return _pass(check, "Not applicable: no Next.js project detected.")
    missing = [name for name, pattern in HEADER_PATTERNS.items() if not pattern.search(contents)]
    if not missing:
        return _pass(check, "Baseline browser security headers are configured.")
    location = next((path for path in config_files if path.is_file()), target_dir / "package.json")
    return [
        CheckResult(
            check,
            Severity.WARNING,
            f"Missing baseline browser security headers: {', '.join(missing)} (static heuristic).",
            _relative(target_dir, location),
            1,
        )
    ]


def check_api_route_auth(target_dir: Path) -> list[CheckResult]:
    check = "api_route_auth"
    candidates = _next_pages(target_dir, ("route.ts", "route.tsx", "route.js", "route.jsx"))
    pages_api = target_dir / "pages" / "api"
    if pages_api.is_dir():
        candidates.extend(_iter_files(pages_api, SOURCE_EXTENSIONS))
    if not candidates:
        return _pass(check, "Not applicable: no Next.js API handlers found.")
    findings = _unauthenticated(target_dir, check, sorted(set(candidates)), "API handler")
    return findings or _pass(check, "Recognized authentication checks found in API handlers.")


CHECKS: tuple[Callable[[Path], list[CheckResult]], ...] = (
    check_env_exposure,
    check_hardcoded_keys,
    check_supabase_rls,
    check_ghost_admin,
    check_git_tracked_sensitive_files,
    check_public_env_secrets,
    check_api_route_auth,
    check_permissive_cors,
    check_security_headers,
)


def run_all_checks(target_dir: Path) -> list[CheckResult]:
    """Run all nine checks in a fixed order against an existing directory."""
    return [result for check in CHECKS for result in check(target_dir)]


def build_report(target_dir: Path) -> dict:
    results = run_all_checks(target_dir)
    counts = {
        severity.value: sum(result.severity == severity for result in results)
        for severity in Severity
    }
    return {
        "scanner_version": SCANNER_VERSION,
        "target": str(target_dir.resolve()),
        "summary": {
            "checks": len(CHECKS),
            "findings": counts["WARNING"] + counts["FAIL"],
            "severity_counts": counts,
        },
        "results": [result.to_dict() for result in results],
    }
