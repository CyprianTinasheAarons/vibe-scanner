from __future__ import annotations

from pathlib import Path

from mcp_server import scan_vibe_project


def test_mcp_tool_returns_structured_directory_report(tmp_path: Path):
    report = scan_vibe_project(str(tmp_path))

    assert report["target_type"] == "directory"
    assert report["summary"]["checks"] == 9
    assert report["human_summary"].startswith("Scan completed:")


def test_mcp_tool_returns_structured_target_error():
    report = scan_vibe_project("/path/that/does/not/exist")

    assert report["error"] == "invalid_target"
