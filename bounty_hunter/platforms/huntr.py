"""Huntr.com platform client — program search, report checking, submission."""

# TODO: Implement full scraper in Step 8
# For now, return placeholder responses so the server can start


async def search_programs(
    language: str | None = None,
    min_bounty: int | None = None,
    max_reports: int | None = None,
    sort_by: str = "saturation_asc",
) -> dict:
    return {
        "status": "not_implemented",
        "message": "Huntr program search not yet implemented. Coming in Step 8.",
        "programs": [],
    }


async def check_reports(
    repo_url: str,
    vuln_type: str | None = None,
    description: str | None = None,
) -> dict:
    return {
        "status": "not_implemented",
        "message": "Huntr report checking not yet implemented. Coming in Step 8.",
        "repo_url": repo_url,
        "total_reports": 0,
        "reports": [],
    }


async def submit_report(report_path: str, dry_run: bool = True) -> dict:
    return {
        "status": "not_implemented",
        "message": "Huntr submission not yet implemented. Coming in Step 9.",
    }
