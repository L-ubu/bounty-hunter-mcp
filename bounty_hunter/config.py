"""Configuration constants and paths."""

import os
from pathlib import Path

# Workspace where repos are cloned for analysis
WORKSPACE_DIR = Path(os.environ.get(
    "BOUNTY_WORKSPACE", Path.home() / "Projects" / "bounty-targets"
))

# SQLite database location
DB_PATH = Path(os.environ.get(
    "BOUNTY_DB", Path.home() / ".cache" / "bounty-hunter" / "bounty.db"
))

# Cache TTLs (hours)
PROGRAM_CACHE_TTL = 6
REPORT_CACHE_TTL = 6
CVE_CACHE_TTL = 24

# Stale repo cleanup (days)
REPO_MAX_AGE_DAYS = 7

# NVD API
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_RATE_LIMIT = 50 if NVD_API_KEY else 5  # requests per 30s

# Platform auth
HUNTR_SESSION_COOKIE = os.environ.get("HUNTR_SESSION_COOKIE", "")
