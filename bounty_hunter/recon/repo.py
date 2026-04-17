"""Git clone/cache/cleanup manager for target repos."""

import subprocess
import re
from pathlib import Path

from bounty_hunter.config import WORKSPACE_DIR
from bounty_hunter.db import BountyDB


def _repo_dir_name(repo_url: str) -> str:
    """Convert repo URL to directory name: owner_repo."""
    match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if match:
        return f"{match.group(1)}_{match.group(2)}"
    # Fallback: use last two path segments
    parts = repo_url.rstrip("/").split("/")
    return f"{parts[-2]}_{parts[-1]}" if len(parts) >= 2 else parts[-1]


def _get_dir_size(path: Path) -> int:
    """Get total size of directory in bytes."""
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


async def ensure_repo(repo_url: str, branch: str | None = None) -> dict:
    """Clone repo if not cached, return local path and metadata.

    Returns: {local_path, commit_hash, size_mb, fresh}
    """
    db = BountyDB()
    existing = db.get_repo(repo_url)

    if existing and Path(existing["local_path"]).exists():
        return {
            "local_path": existing["local_path"],
            "commit_hash": existing["commit_hash"],
            "size_mb": round(existing.get("size_bytes", 0) / (1024 * 1024), 1),
            "fresh": False,
        }

    # Clone the repo
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    dir_name = _repo_dir_name(repo_url)
    local_path = WORKSPACE_DIR / dir_name

    if local_path.exists():
        # Dir exists but not tracked — re-use it
        pass
    else:
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([repo_url, str(local_path)])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return {"error": f"Clone failed: {result.stderr.strip()}"}

    # Get commit hash
    hash_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(local_path),
        capture_output=True,
        text=True,
    )
    commit_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else "unknown"

    size_bytes = _get_dir_size(local_path)

    db.track_repo(repo_url, str(local_path), commit_hash, size_bytes)

    return {
        "local_path": str(local_path),
        "commit_hash": commit_hash,
        "size_mb": round(size_bytes / (1024 * 1024), 1),
        "fresh": True,
    }
