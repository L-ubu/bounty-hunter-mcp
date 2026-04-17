"""CVE search — NVD API + GitHub advisories via gh CLI."""

import asyncio
import json
import re
import subprocess
import time

import httpx

from bounty_hunter.config import NVD_API_KEY, NVD_RATE_LIMIT, CVE_CACHE_TTL
from bounty_hunter.db import BountyDB

# NVD rate limiting
_last_nvd_request = 0.0
_nvd_request_count = 0


async def _rate_limit_nvd():
    """Enforce NVD rate limits."""
    global _last_nvd_request, _nvd_request_count
    now = time.time()
    if now - _last_nvd_request > 30:
        _nvd_request_count = 0
        _last_nvd_request = now

    if _nvd_request_count >= NVD_RATE_LIMIT:
        wait = 30 - (now - _last_nvd_request)
        if wait > 0:
            await asyncio.sleep(wait)
        _nvd_request_count = 0
        _last_nvd_request = time.time()

    _nvd_request_count += 1


async def _search_nvd(keyword: str) -> list[dict]:
    """Search NVD for CVEs matching a keyword."""
    await _rate_limit_nvd()

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 20}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return [{"error": f"NVD API error: {e}"}]

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Get description (English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break

        # Get CVSS score
        severity = "unknown"
        score = None
        metrics = cve.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "unknown").lower()
                break

        # Get published date
        published = cve.get("published", "")[:10]

        results.append({
            "id": cve_id,
            "title": desc[:100],
            "severity": severity,
            "score": score,
            "date": published,
            "summary": desc,
        })

    return results


def _search_github_advisories(repo_url: str) -> list[dict]:
    """Search GitHub security advisories via gh CLI."""
    # Extract owner/repo from URL
    match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if not match:
        return []

    owner, repo = match.group(1), match.group(2)

    # Use gh api to query advisories
    query = """
    query($owner: String!, $repo: String!) {
      repository(owner: $owner, name: $repo) {
        vulnerabilityAlerts(first: 20) {
          nodes {
            securityAdvisory {
              ghsaId
              summary
              severity
              publishedAt
              identifiers { type value }
              vulnerabilities(first: 5) {
                nodes {
                  package { name ecosystem }
                  vulnerableVersionRange
                  firstPatchedVersion { identifier }
                }
              }
            }
          }
        }
        securityAdvisories: vulnerabilityAlerts(first: 0) {
          totalCount
        }
      }
    }
    """

    try:
        result = subprocess.run(
            ["gh", "api", "graphql", "-f",
             f"query={query}", "-f", f"owner={owner}", "-f", f"repo={repo}"],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode != 0:
            # Fallback: try REST API for security advisories
            return _search_github_advisories_rest(owner, repo)

        data = json.loads(result.stdout)
        repo_data = data.get("data", {}).get("repository", {})
        alerts = repo_data.get("vulnerabilityAlerts", {}).get("nodes", [])

        advisories = []
        for alert in alerts:
            adv = alert.get("securityAdvisory", {})
            cve_id = ""
            for ident in adv.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve_id = ident.get("value", "")
                    break

            patched = []
            for vuln in adv.get("vulnerabilities", {}).get("nodes", []):
                fpv = vuln.get("firstPatchedVersion", {})
                if fpv:
                    patched.append(fpv.get("identifier", ""))

            advisories.append({
                "ghsa_id": adv.get("ghsaId", ""),
                "cve_id": cve_id,
                "title": adv.get("summary", "")[:100],
                "severity": adv.get("severity", "").lower(),
                "published": adv.get("publishedAt", "")[:10],
                "patched_versions": patched,
            })

        return advisories

    except Exception:
        return _search_github_advisories_rest(owner, repo)


def _search_github_advisories_rest(owner: str, repo: str) -> list[dict]:
    """Fallback: search GitHub advisories via REST API."""
    try:
        result = subprocess.run(
            ["gh", "api", f"/repos/{owner}/{repo}/security-advisories",
             "--jq", ".[] | {ghsa_id: .ghsa_id, cve_id: .cve_id, summary: .summary, severity: .severity}"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Parse individual JSON objects
            advisories = []
            for line in result.stdout.strip().split("\n"):
                try:
                    adv = json.loads(line)
                    advisories.append({
                        "ghsa_id": adv.get("ghsa_id", ""),
                        "cve_id": adv.get("cve_id", ""),
                        "title": adv.get("summary", "")[:100],
                        "severity": adv.get("severity", "").lower(),
                        "patched_versions": [],
                    })
                except json.JSONDecodeError:
                    continue
            return advisories
    except Exception:
        pass

    return []


async def search_vulns(
    package_name: str | None = None,
    repo_url: str | None = None,
    ecosystem: str | None = None,
) -> dict:
    """Search for known vulnerabilities across NVD + GitHub."""
    db = BountyDB()

    # Build cache key
    cache_key = f"vulns:{package_name or ''}:{repo_url or ''}:{ecosystem or ''}"
    cached = db.cache_get(cache_key)
    if cached:
        cached["from_cache"] = True
        return cached

    keyword = package_name
    if not keyword and repo_url:
        match = re.search(r"github\.com/[^/]+/([^/]+?)(?:\.git)?$", repo_url)
        keyword = match.group(1) if match else None

    cves = []
    advisories = []

    # Search NVD
    if keyword:
        cves = await _search_nvd(keyword)
        # Filter out errors
        cves = [c for c in cves if "error" not in c]

    # Search GitHub advisories
    if repo_url:
        advisories = _search_github_advisories(repo_url)

    result = {
        "cves": cves,
        "advisories": advisories,
        "total": len(cves) + len(advisories),
        "from_cache": False,
    }

    # Cache the result
    db.cache_set(cache_key, result, CVE_CACHE_TTL)

    return result
