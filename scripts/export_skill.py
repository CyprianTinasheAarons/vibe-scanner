"""Create a portable copy of the Vibe Scanner skill from canonical sources."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_SOURCE = ROOT / "skill"


def export(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("SKILL.md", "scan.py"):
        source = SKILL_SOURCE / name
        target = destination / name
        if source.resolve() != target.resolve():
            shutil.copy2(source, target)
    agents_source = SKILL_SOURCE / "agents"
    agents_target = destination / "agents"
    if agents_source.resolve() != agents_target.resolve():
        shutil.copytree(agents_source, agents_target, dirs_exist_ok=True)
    for name in ("core.py", "scanner.py", "url_scanner.py"):
        shutil.copy2(ROOT / name, destination / name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Export a self-contained Vibe Scanner skill folder."
    )
    parser.add_argument(
        "destination",
        type=Path,
        help="Directory that will receive the portable skill files.",
    )
    export(parser.parse_args().destination)
