"""
mcp_server.py — MCP server wrapping vibe-scanner as an LLM-callable tool.

Intended usage: register this as a local MCP server in Cursor / Claude
Desktop / Claude Code, so the assistant can invoke `scan_vibe_project`
directly when a user asks something like "check my app for security
issues" or "is this safe to ship".

Requires: pip install "mcp[cli]"
Run directly for local testing:
    python mcp_server.py
Or via the MCP CLI dev tool:
    mcp dev mcp_server.py

The tool returns the same structured report used by the CLI.
"""

from mcp.server.fastmcp import FastMCP

from scanner import scan_target

mcp = FastMCP("VibeScanner")


@mcp.tool()
def scan_vibe_project(target: str) -> dict:
    """
    Scan a local Next.js/Supabase project or a deployed HTTP(S) URL for
    common security exposures.

    Use this when a user asks for a security check, audit, or review
    of a codebase they've just built or are about to deploy.

    Args:
        target: absolute project directory or deployed HTTP(S) URL.

    Returns:
        The stable report object, including a concise human-readable summary.
    """
    try:
        report = scan_target(target)
    except ValueError as error:
        return {"error": "invalid_target", "message": str(error)}
    except RuntimeError as error:
        return {"error": "scanner_error", "message": str(error)}
    counts = report["summary"]["severity_counts"]
    report["human_summary"] = (
        f"Scan completed: {counts['FAIL']} fail(s), "
        f"{counts['WARNING']} warning(s), and {counts['PASS']} pass result(s)."
    )
    return report


if __name__ == "__main__":
    # stdio transport — this is what lets Cursor/Claude Desktop/Claude
    # Code talk to this process as a local MCP server.
    mcp.run()
