"""Dependency-free command runner for the portable Vibe Scanner skill."""

from __future__ import annotations

import argparse
import json
import sys

from scanner import scan_target


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a repository or public URL for common security exposures."
    )
    parser.add_argument("target", help="Absolute project directory or public HTTP(S) URL")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print the stable JSON report",
    )
    args = parser.parse_args()

    try:
        report = scan_target(args.target)
    except ValueError as error:
        payload = {"error": "invalid_target", "message": str(error)}
        print(json.dumps(payload) if args.json_output else f"Error: {error}")
        return 2
    except RuntimeError as error:
        payload = {"error": "scanner_error", "message": str(error)}
        print(json.dumps(payload) if args.json_output else f"Error: {error}")
        return 2

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        for result in report["results"]:
            location = ""
            if result.get("file_path"):
                location = f" ({result['file_path']}:{result.get('line_number')})"
            print(f"[{result['severity']}] {result['message']}{location}")
        counts = report["summary"]["severity_counts"]
        print(
            f"\nSummary: {counts['FAIL']} fail, {counts['WARNING']} warning, {counts['PASS']} pass"
        )

    return 1 if report["summary"]["severity_counts"]["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
