"""bounty-hunter-mcp: AI-powered bug bounty hunting toolkit."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "bounty-hunter",
    instructions=(
        "Bug bounty hunting toolkit. Use these tools to find targets, "
        "analyze codebases, test endpoints, check for duplicates, and generate reports. "
        "Repos are auto-cloned to ~/Projects/bounty-targets/ — use your own Read/Grep/Glob "
        "on local_path returned by recon tools."
    ),
)


# ── Platform Intelligence ──────────────────────────────────────────────


@mcp.tool()
async def hunt_programs(
    language: str | None = None,
    min_bounty: int | None = None,
    max_reports: int | None = None,
    sort_by: str = "saturation_asc",
) -> dict:
    """Search huntr.com for bounty programs.

    Args:
        language: Filter by primary language (python, javascript, go, rust, etc.)
        min_bounty: Minimum bounty amount in USD
        max_reports: Only show programs with fewer than N reports (low saturation)
        sort_by: Sort order — saturation_asc, bounty_desc, reports_asc, recent
    """
    from bounty_hunter.platforms.huntr import search_programs

    return await search_programs(
        language=language,
        min_bounty=min_bounty,
        max_reports=max_reports,
        sort_by=sort_by,
    )


@mcp.tool()
async def hunt_reports(
    repo_url: str,
    vuln_type: str | None = None,
    description: str | None = None,
) -> dict:
    """Check existing vulnerability reports for a repo + duplicate detection.

    Args:
        repo_url: GitHub repository URL
        vuln_type: Vulnerability type to check for duplicates (e.g. "SSRF", "NoSQL Injection")
        description: Short description of your finding for duplicate matching
    """
    from bounty_hunter.platforms.huntr import check_reports

    return await check_reports(
        repo_url=repo_url,
        vuln_type=vuln_type,
        description=description,
    )


@mcp.tool()
async def hunt_submit(
    report_path: str,
    dry_run: bool = True,
) -> dict:
    """Fill huntr.com submission form via Chrome CDP.

    Args:
        report_path: Path to the JSON report file
        dry_run: If True, only validate. If False, fill the form in Chrome.
    """
    from bounty_hunter.platforms.huntr import submit_report

    return await submit_report(report_path=report_path, dry_run=dry_run)


# ── Recon ──────────────────────────────────────────────────────────────


@mcp.tool()
async def map_routes(
    repo_url: str,
    verbose: bool = False,
) -> dict:
    """Extract HTTP routes + auth status from a codebase. Auto-clones the repo.

    Returns local_path so you can Read/Grep files directly. By default only
    returns interesting routes (unprotected, admin, debug, upload endpoints).

    Args:
        repo_url: GitHub repository URL
        verbose: If True, return all routes instead of just interesting ones
    """
    from bounty_hunter.recon.routes import extract_routes

    return await extract_routes(repo_url=repo_url, verbose=verbose)


@mcp.tool()
async def map_surface(
    repo_url: str,
) -> dict:
    """Attack surface summary: framework, auth, validation, sinks, dep CVEs, prior notes.

    Auto-clones the repo. Returns local_path for direct file access.
    One call replaces 10+ Read/Grep calls for initial recon.

    Args:
        repo_url: GitHub repository URL
    """
    from bounty_hunter.recon.surface import analyze_surface

    return await analyze_surface(repo_url=repo_url)


# ── Live Testing ───────────────────────────────────────────────────────


@mcp.tool()
async def test_endpoint(
    url: str,
    checks: list[str] | None = None,
    mode: str = "passive",
    auth_header: str | None = None,
) -> dict:
    """Run HTTP security checks against a live endpoint.

    Passive mode (default): HEAD/OPTIONS only, safe. Active mode: probes auth bypass, methods.

    Args:
        url: Target URL to test
        checks: Which checks to run — cors, headers, auth, methods, info_leak. Default: cors, headers.
        mode: "passive" (safe, HEAD/OPTIONS only) or "active" (sends real requests)
        auth_header: Authorization header value for authenticated checks (e.g. "Bearer sk-...")
    """
    from bounty_hunter.testing.endpoint import run_checks

    return await run_checks(
        url=url,
        checks=checks or ["cors", "headers"],
        mode=mode,
        auth_header=auth_header,
    )


@mcp.tool()
async def test_ssrf(
    timeout_seconds: int = 15,
) -> dict:
    """Start an SSRF callback catcher via interactsh. Returns a unique URL to inject.

    Polls for out-of-band interactions for timeout_seconds, then returns results.

    Args:
        timeout_seconds: How long to wait for callbacks (default 15)
    """
    from bounty_hunter.testing.ssrf import catch_ssrf

    return await catch_ssrf(timeout_seconds=timeout_seconds)


# ── Intelligence ───────────────────────────────────────────────────────


@mcp.tool()
async def check_vulns(
    package_name: str | None = None,
    repo_url: str | None = None,
    ecosystem: str | None = None,
) -> dict:
    """Search NVD + GitHub advisories for known vulnerabilities in one call.

    Args:
        package_name: Package name (e.g. "litellm", "express")
        repo_url: GitHub repo URL (alternative to package_name)
        ecosystem: Package ecosystem — npm, pypi, go, maven, etc.
    """
    from bounty_hunter.intel.cve import search_vulns

    return await search_vulns(
        package_name=package_name,
        repo_url=repo_url,
        ecosystem=ecosystem,
    )


# ── Investigation ──────────────────────────────────────────────────────


@mcp.tool()
async def note(
    repo_url: str,
    action: str = "list",
    content: str | None = None,
    tag: str | None = None,
) -> dict:
    """Save/retrieve investigation notes per target. Persists across sessions.

    Args:
        repo_url: Target repository URL
        action: "save" to add a note, "list" to retrieve, "clear" to delete all
        content: Note text (required for save)
        tag: Optional tag — checked, interesting, dead_end, todo, finding
    """
    from bounty_hunter.db import BountyDB

    db = BountyDB()
    if action == "save":
        if not content:
            return {"error": "content is required for save action"}
        db.save_note(repo_url, content, tag)
        return {"status": "saved", "repo_url": repo_url, "tag": tag}
    elif action == "list":
        notes = db.get_notes(repo_url)
        return {"repo_url": repo_url, "notes": notes}
    elif action == "clear":
        db.clear_notes(repo_url)
        return {"status": "cleared", "repo_url": repo_url}
    else:
        return {"error": f"Unknown action: {action}. Use save, list, or clear."}


# ── Reporting ──────────────────────────────────────────────────────────


@mcp.tool()
async def make_report(
    platform: str,
    repo_url: str,
    vuln_type: str,
    title: str,
    description: str,
    impact: str,
    occurrences: list[dict],
    cvss: dict,
    references: list[dict] | None = None,
) -> dict:
    """Generate a vulnerability report + CVSS score for a bounty platform.

    Args:
        platform: Target platform — "huntr" or "github"
        repo_url: GitHub repository URL
        vuln_type: Vulnerability type (e.g. "NoSQL Injection", "SSRF")
        title: Report title
        description: Full vulnerability description (markdown)
        impact: Impact statement
        occurrences: List of {permalink, description} for affected code locations
        cvss: CVSS dimensions — {attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability}
        references: Optional list of {url, name} for references
    """
    from bounty_hunter.reporting.generator import generate_report

    return await generate_report(
        platform=platform,
        repo_url=repo_url,
        vuln_type=vuln_type,
        title=title,
        description=description,
        impact=impact,
        occurrences=occurrences,
        cvss=cvss,
        references=references,
    )


# ── Prompts ────────────────────────────────────────────────────────────


@mcp.prompt()
def analyze_target(repo_url: str) -> str:
    """Full recon workflow for a new bounty target."""
    return (
        f"Analyze {repo_url} as a bounty target.\n\n"
        "1. Use map_routes to extract all HTTP routes and identify unprotected endpoints\n"
        "2. Use map_surface for attack surface summary (framework, auth, sinks, dep CVEs)\n"
        "3. Use check_vulns to find known CVEs in this project\n"
        "4. Use hunt_reports to check existing bounty reports and saturation\n"
        "5. Read the vulnerability_checklists resource for framework-specific patterns\n\n"
        "Present a prioritized list of attack vectors to investigate, noting:\n"
        "- Which areas are already saturated (many existing reports)\n"
        "- Which areas look promising (unprotected routes, known sink patterns)\n"
        "- Recommended next steps for manual analysis"
    )


@mcp.prompt()
def verify_finding(repo_url: str, vuln_type: str, endpoint_url: str = "") -> str:
    """Pre-submission check: is this finding novel and reportable?"""
    result = (
        f"Verify whether a suspected {vuln_type} vulnerability in {repo_url} is novel.\n\n"
        "1. Use hunt_reports to check for duplicate reports on huntr\n"
        "2. Use check_vulns to search NVD/GitHub for existing CVEs\n"
    )
    if endpoint_url:
        result += f"3. Use test_endpoint on {endpoint_url} to validate the issue\n"
    result += (
        "\nAssess:\n"
        "- Is this a duplicate of an existing report?\n"
        "- Is there already a CVE for this?\n"
        "- Is the finding confirmed and exploitable?\n"
        "- What's the likely bounty eligibility?"
    )
    return result


# ── Resources ──────────────────────────────────────────────────────────


@mcp.resource("bounty://checklists")
def vulnerability_checklists() -> str:
    """Framework-specific vulnerability checklists for bounty hunting."""
    from pathlib import Path

    checklist_path = Path(__file__).parent / "data" / "checklists.yaml"
    if checklist_path.exists():
        return checklist_path.read_text()
    return "# No checklists loaded yet. Run setup to populate."


# ── Entry point ────────────────────────────────────────────────────────


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
