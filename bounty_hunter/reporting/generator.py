"""Multi-format report generator — huntr JSON, GitHub markdown."""

import json
import re
import subprocess
from pathlib import Path

from bounty_hunter.reporting.cvss import calculate_cvss
from bounty_hunter.config import WORKSPACE_DIR
from bounty_hunter.db import BountyDB

# Package manager detection from repo contents
PM_INDICATORS = {
    "npm": ["package.json"],
    "pypi": ["pyproject.toml", "setup.py", "requirements.txt"],
    "go": ["go.mod"],
    "maven": ["pom.xml"],
    "cargo": ["Cargo.toml"],
    "nuget": ["*.csproj"],
    "rubygems": ["Gemfile"],
    "composer": ["composer.json"],
}


def _detect_package_manager(local_path: str) -> str:
    """Detect package manager from repo contents."""
    root = Path(local_path)
    for pm, indicators in PM_INDICATORS.items():
        for indicator in indicators:
            if "*" in indicator:
                if list(root.rglob(indicator)):
                    return pm
            elif (root / indicator).exists():
                return pm
    return "other"


def _get_latest_version(local_path: str, pm: str) -> str:
    """Try to get latest version from repo."""
    root = Path(local_path)

    if pm == "npm":
        pkg = root / "package.json"
        if pkg.exists():
            data = json.loads(pkg.read_text())
            return data.get("version", "latest")

    if pm == "pypi":
        for fname in ["pyproject.toml", "setup.py"]:
            f = root / fname
            if f.exists():
                content = f.read_text()
                match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return match.group(1)

    if pm == "cargo":
        cargo = root / "Cargo.toml"
        if cargo.exists():
            match = re.search(r'version\s*=\s*"([^"]+)"', cargo.read_text())
            if match:
                return match.group(1)

    if pm == "go":
        # Try git tag
        try:
            result = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                cwd=local_path, capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

    return "latest"


def _generate_huntr_json(
    repo_url: str,
    vuln_type: str,
    title: str,
    description: str,
    impact: str,
    occurrences: list[dict],
    cvss_result: dict,
    references: list[dict] | None,
    local_path: str | None,
) -> dict:
    """Generate huntr.com compatible JSON report."""
    pm = _detect_package_manager(local_path) if local_path else "other"
    version = _get_latest_version(local_path, pm) if local_path else "latest"

    report = {
        "repo_url": repo_url,
        "package_manager": pm,
        "version_affected": version,
        "vulnerability_type": vuln_type,
        "cvss": cvss_result["dict"],
        "title": title,
        "description": description,
        "impact": impact,
        "occurrences": occurrences,
    }

    if references:
        report["references"] = references

    return report


def _generate_github_markdown(
    repo_url: str,
    vuln_type: str,
    title: str,
    description: str,
    impact: str,
    occurrences: list[dict],
    cvss_result: dict,
    references: list[dict] | None,
) -> str:
    """Generate GitHub private vulnerability report markdown."""
    occ_text = ""
    for i, occ in enumerate(occurrences, 1):
        occ_text += f"\n### Occurrence {i}\n"
        occ_text += f"- **Location**: {occ.get('permalink', 'N/A')}\n"
        occ_text += f"- **Description**: {occ.get('description', 'N/A')}\n"

    ref_text = ""
    if references:
        ref_text = "\n## References\n"
        for ref in references:
            ref_text += f"- [{ref.get('name', ref.get('url', ''))}]({ref.get('url', '')})\n"

    return f"""# {title}

## Summary

**Vulnerability Type**: {vuln_type}
**CVSS Score**: {cvss_result['score']} ({cvss_result['severity']})
**CVSS Vector**: `{cvss_result['vector']}`

## Description

{description}

## Impact

{impact}

## Affected Code
{occ_text}
{ref_text}
"""


async def generate_report(
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
    """Generate a vulnerability report for the specified platform."""
    # Calculate CVSS
    cvss_result = calculate_cvss(cvss)

    # Get local path if repo is cloned
    db = BountyDB()
    repo_record = db.get_repo(repo_url)
    local_path = repo_record["local_path"] if repo_record else None

    # Determine output path
    if local_path:
        output_dir = Path(local_path)
    else:
        # Use workspace dir with repo name
        match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
        dir_name = f"{match.group(1)}_{match.group(2)}" if match else "report"
        output_dir = WORKSPACE_DIR / dir_name
        output_dir.mkdir(parents=True, exist_ok=True)

    validation_errors = []

    # Validate required fields
    if not title:
        validation_errors.append("title is required")
    if not description:
        validation_errors.append("description is required")
    if not impact:
        validation_errors.append("impact is required")
    if not occurrences:
        validation_errors.append("at least one occurrence is required")

    if platform == "huntr":
        report_data = _generate_huntr_json(
            repo_url, vuln_type, title, description, impact,
            occurrences, cvss_result, references, local_path,
        )
        report_path = output_dir / "report.json"
        report_path.write_text(json.dumps(report_data, indent=2))

        # Mark repo as reported
        if repo_record:
            db.mark_repo_reported(repo_url)

        return {
            "report_path": str(report_path),
            "platform": "huntr",
            "cvss_score": cvss_result["score"],
            "cvss_severity": cvss_result["severity"],
            "cvss_vector": cvss_result["vector"],
            "package_manager": report_data["package_manager"],
            "version_affected": report_data["version_affected"],
            "validation_errors": validation_errors,
        }

    elif platform == "github":
        markdown = _generate_github_markdown(
            repo_url, vuln_type, title, description, impact,
            occurrences, cvss_result, references,
        )
        report_path = output_dir / "vulnerability-report.md"
        report_path.write_text(markdown)

        if repo_record:
            db.mark_repo_reported(repo_url)

        return {
            "report_path": str(report_path),
            "platform": "github",
            "cvss_score": cvss_result["score"],
            "cvss_severity": cvss_result["severity"],
            "cvss_vector": cvss_result["vector"],
            "validation_errors": validation_errors,
        }

    else:
        return {"error": f"Unknown platform: {platform}. Use 'huntr' or 'github'."}
