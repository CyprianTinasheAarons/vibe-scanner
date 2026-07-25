from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_exported_skill_contains_standalone_engine(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    destination = tmp_path / "portable-skill"
    subprocess.run(
        [sys.executable, str(root / "scripts" / "export_skill.py"), str(destination)],
        check=True,
    )
    assert (destination / "core.py").read_text() == (root / "core.py").read_text()
    assert (destination / "url_scanner.py").is_file()
    assert (destination / "agents" / "openai.yaml").is_file()
    assert not (destination / "requirements.txt").exists()
    subprocess.run(
        [sys.executable, "-c", "import core, scanner; assert len(core.CHECKS) == 9"],
        cwd=destination,
        check=True,
    )

    target = tmp_path / "target"
    target.mkdir()
    run = subprocess.run(
        [sys.executable, str(destination / "scan.py"), "--json", str(target)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(run.stdout)["summary"]["checks"] == 9


def test_checked_in_skill_engine_matches_canonical_sources():
    root = Path(__file__).resolve().parents[1]
    for name in ("core.py", "scanner.py", "url_scanner.py"):
        assert (root / "skill" / name).read_text() == (root / name).read_text()
