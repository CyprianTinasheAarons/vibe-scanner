from __future__ import annotations

import subprocess
from pathlib import Path

from core import (
    MAX_FINDINGS_PER_CHECK,
    Severity,
    build_report,
    check_hardcoded_keys,
    run_all_checks,
)


def write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def by_check(results, name):
    return [result for result in results if result.check_name == name]


def fake_stripe_key() -> str:
    """Build a recognizable test token without committing a scanner-triggering literal."""
    return "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz"


def test_clean_non_app_project_reports_nine_passes(tmp_path: Path):
    results = run_all_checks(tmp_path)
    assert len(results) == 9
    assert all(result.severity == Severity.PASS for result in results)


def test_vulnerable_project_reports_locations_and_redacts_values(tmp_path: Path):
    write(tmp_path, ".env", "NEXT_PUBLIC_API_KEY=super-secret\n")
    write(tmp_path, "src/leak.ts", f"const key = '{fake_stripe_key()}';\n")
    write(tmp_path, "app/admin/page.tsx", "export default function Page() { return null }\n")
    write(
        tmp_path,
        "app/api/data/route.ts",
        "export async function GET() { return Response.json({}) }\n",
    )
    write(tmp_path, "app/api/cors/route.ts", "const cors = { origin: '*', credentials: true };\n")
    write(tmp_path, "next.config.js", "module.exports = {}\n")
    write(tmp_path, "supabase/migrations/001.sql", "CREATE TABLE profiles (id uuid);\n")
    results = run_all_checks(tmp_path)
    assert by_check(results, "env_exposure")[0].severity == Severity.FAIL
    assert by_check(results, "hardcoded_keys")[0].file_path == "src/leak.ts"
    assert by_check(results, "hardcoded_keys")[0].line_number == 1
    assert "abcdefghijklmnopqrstuvwxyz" not in by_check(results, "hardcoded_keys")[0].message
    assert by_check(results, "supabase_rls")[0].severity == Severity.WARNING
    assert by_check(results, "ghost_admin")[0].severity == Severity.WARNING
    assert by_check(results, "api_route_auth")[0].severity == Severity.WARNING
    assert by_check(results, "permissive_cors")[0].severity == Severity.FAIL
    assert by_check(results, "security_headers")[0].severity == Severity.WARNING
    assert by_check(results, "public_env_secrets")[0].severity == Severity.FAIL


def test_git_tracked_environment_file_is_a_failure(tmp_path: Path):
    write(tmp_path, ".env", "SAFE=value\n")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, check=True, capture_output=True)
    result = by_check(run_all_checks(tmp_path), "git_tracked_sensitive_files")[0]
    assert result.severity == Severity.FAIL
    assert result.file_path == ".env"


def test_generated_directories_are_not_scanned(tmp_path: Path):
    write(
        tmp_path,
        "node_modules/pkg/leak.js",
        f"const key = '{fake_stripe_key()}';\n",
    )
    assert by_check(run_all_checks(tmp_path), "hardcoded_keys")[0].severity == Severity.PASS


def test_findings_are_capped(tmp_path: Path):
    for index in range(MAX_FINDINGS_PER_CHECK + 2):
        write(tmp_path, f"src/{index}.ts", f"const key = '{fake_stripe_key()}';\n")
    results = check_hardcoded_keys(tmp_path)
    assert len(results) == MAX_FINDINGS_PER_CHECK + 1
    assert "truncated" in results[-1].message


def test_report_is_machine_readable(tmp_path: Path):
    report = build_report(tmp_path)
    assert report["scanner_version"] == "1.0.0"
    assert report["summary"]["checks"] == 9
    assert report["results"][0]["severity"] == "PASS"


def test_gitignore_negation_is_honored(tmp_path: Path):
    write(tmp_path, ".env", "SAFE=value\n")
    write(tmp_path, ".gitignore", ".env*\n!.env\n")
    result = by_check(run_all_checks(tmp_path), "env_exposure")[0]
    assert result.severity == Severity.FAIL


def test_next_project_without_header_configuration_warns(tmp_path: Path):
    write(tmp_path, "package.json", '{"dependencies":{"next":"16.0.0"}}')
    result = by_check(run_all_checks(tmp_path), "security_headers")[0]
    assert result.severity == Severity.WARNING
