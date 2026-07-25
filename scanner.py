"""Dispatch filesystem and deployed-URL scans through one public interface."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from core import SCANNER_VERSION, build_report
from url_scanner import build_url_report


def is_url_target(target: str) -> bool:
    parsed = urlparse(target.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def scan_target(target: str) -> dict:
    if is_url_target(target):
        return build_url_report(target, scanner_version=SCANNER_VERSION)

    target_path = Path(target)
    if not target_path.exists() or not target_path.is_dir():
        raise ValueError(f"'{target}' is not a valid directory or HTTP(S) URL.")
    report = build_report(target_path)
    report["target_type"] = "directory"
    return report
