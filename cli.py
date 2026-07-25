"""Command-line interface for Vibe Scanner."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.panel import Panel

from core import Severity
from scanner import scan_target

app = typer.Typer(help="Scan a Next.js/Supabase repository or deployed URL for security exposures.")
console = Console()

SEVERITY_STYLE = {
    Severity.PASS: "bold green",
    Severity.WARNING: "bold yellow",
    Severity.FAIL: "bold red",
}


def _exit_code(report: dict) -> int:
    return 1 if report["summary"]["severity_counts"][Severity.FAIL.value] else 0


@app.command()
def run(
    target: str = typer.Argument(".", help="Project directory or deployed HTTP(S) URL to scan."),
    json_output: bool = typer.Option(
        False, "--json", help="Print the stable machine-readable report."
    ),
) -> None:
    """Scan TARGET and report pass, warning, and failure results."""
    try:
        if json_output:
            report = scan_target(target)
        else:
            with console.status("[bold blue]Analyzing target...", spinner="dots"):
                report = scan_target(target)
    except ValueError as error:
        payload = {"error": "invalid_target", "message": str(error)}
        typer.echo(json.dumps(payload) if json_output else f"Error: {error}")
        raise typer.Exit(code=2) from error
    except RuntimeError as error:
        payload = {"error": "scanner_error", "message": str(error)}
        typer.echo(json.dumps(payload) if json_output else f"Scanner error: {error}")
        raise typer.Exit(code=2) from error

    if json_output:
        typer.echo(json.dumps(report, indent=2))
        exit_code = _exit_code(report)
        if exit_code:
            raise typer.Exit(code=exit_code)
        return

    console.print()
    for result in report["results"]:
        severity = Severity(result["severity"])
        style = SEVERITY_STYLE[severity]
        location = ""
        if result.get("file_path"):
            location = f" ({result['file_path']}:{result.get('line_number')})"
        console.print(f"[{style}][{severity.value}][/{style}] {result['message']}{location}")

    counts = report["summary"]["severity_counts"]
    summary = f"{counts['FAIL']} fail · {counts['WARNING']} warning · {counts['PASS']} pass"
    border = "red" if counts["FAIL"] else "yellow" if counts["WARNING"] else "green"
    console.print()
    console.print(Panel(summary, title="Scan complete", border_style=border, expand=False))

    exit_code = _exit_code(report)
    if exit_code:
        raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
