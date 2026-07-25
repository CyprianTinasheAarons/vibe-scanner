from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cli import app

runner = CliRunner()


def test_json_scan_returns_stable_report(tmp_path: Path):
    result = runner.invoke(app, ["--json", str(tmp_path)])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["target_type"] == "directory"
    assert report["summary"]["checks"] == 9


def test_confirmed_exposure_returns_exit_one(tmp_path: Path):
    (tmp_path / ".env").write_text("SECRET=redacted\n")

    result = runner.invoke(app, ["--json", str(tmp_path)])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["summary"]["severity_counts"]["FAIL"] >= 1


def test_invalid_target_returns_machine_readable_error():
    result = runner.invoke(app, ["--json", "/path/that/does/not/exist"])

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"] == "invalid_target"
