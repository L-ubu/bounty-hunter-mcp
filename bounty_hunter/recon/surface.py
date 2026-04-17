"""Attack surface analysis — framework, auth, validation, sinks, dep CVEs."""

import json
import re
import subprocess
from pathlib import Path

from bounty_hunter.recon.repo import ensure_repo
from bounty_hunter.db import BountyDB

# ── Sink patterns for different vulnerability classes ───────────────────

SINK_PATTERNS = {
    "outbound_http": {
        "description": "SSRF surfaces — outbound HTTP with potentially user-controlled URLs",
        "patterns": {
            "*.py": [
                r"requests\.(get|post|put|delete|patch|head)\s*\(",
                r"httpx\.(get|post|put|delete|patch|head|AsyncClient)\s*\(",
                r"urllib\.request\.(urlopen|urlretrieve)\s*\(",
                r"aiohttp\.ClientSession\(\)",
            ],
            "*.js|*.ts": [
                r"fetch\s*\(",
                r"axios\.(get|post|put|delete|patch)\s*\(",
                r"(?:http|https)\.(?:get|request)\s*\(",
                r"got\s*\(",
                r"node-fetch",
            ],
            "*.go": [
                r"http\.(Get|Post|Do|NewRequest)\s*\(",
            ],
            "*.rs": [
                r"reqwest::(get|Client)",
                r"hyper::Client",
            ],
        },
    },
    "db_queries": {
        "description": "Injection surfaces — database queries that may accept raw input",
        "patterns": {
            "*.py": [
                r"\.execute\s*\(\s*f['\"]",
                r"\.execute\s*\(\s*['\"].*%s",
                r"\.raw\s*\(",
                r"\.find\s*\(\s*\{",
                r"\.aggregate\s*\(",
            ],
            "*.js|*.ts": [
                r"\.query\s*\(\s*[`'\"]",
                r"\.find\s*\(\s*\{",
                r"\.findOne\s*\(\s*\{",
                r"\.aggregate\s*\(",
                r"\.updateOne\s*\(",
                r"\$where",
            ],
            "*.go": [
                r"\.Query\s*\(\s*fmt\.Sprintf",
                r"\.Exec\s*\(\s*fmt\.Sprintf",
            ],
        },
    },
    "file_ops": {
        "description": "Path traversal surfaces — file operations",
        "patterns": {
            "*.py": [
                r"open\s*\(\s*(?:f['\"]|request|os\.path\.join)",
                r"send_file\s*\(",
                r"FileResponse\s*\(",
            ],
            "*.js|*.ts": [
                r"fs\.(readFile|writeFile|createReadStream)\s*\(",
                r"path\.join\s*\(.*req\.",
                r"res\.sendFile\s*\(",
            ],
        },
    },
    "exec_calls": {
        "description": "Command injection surfaces — process execution",
        "patterns": {
            "*.py": [
                r"subprocess\.(run|call|Popen|check_output)\s*\(",
                r"os\.(system|popen)\s*\(",
                r"exec\s*\(",
                r"eval\s*\(",
            ],
            "*.js|*.ts": [
                r"child_process\.(exec|spawn|execSync)\s*\(",
                r"eval\s*\(",
                r"Function\s*\(",
            ],
            "*.go": [
                r"exec\.Command\s*\(",
                r"os\.StartProcess\s*\(",
            ],
            "*.rs": [
                r"Command::new\s*\(",
                r"std::process::Command",
            ],
        },
    },
}

# ── Validation library detection ───────────────────────────────────────

VALIDATION_LIBS = {
    "zod": {"files": ["*.ts", "*.js"], "pattern": r"z\.(string|object|number|array)\("},
    "joi": {"files": ["*.ts", "*.js"], "pattern": r"Joi\.(string|object|number|array)\("},
    "yup": {"files": ["*.ts", "*.js"], "pattern": r"yup\.(string|object|number|array)\("},
    "pydantic": {"files": ["*.py"], "pattern": r"class\s+\w+\(BaseModel\)"},
    "marshmallow": {"files": ["*.py"], "pattern": r"class\s+\w+\(Schema\)"},
    "cerberus": {"files": ["*.py"], "pattern": r"Validator\(\{"},
}


def _find_sinks(local_path: str) -> dict:
    """Find interesting code sinks across the codebase."""
    root = Path(local_path)
    results = {}

    for sink_type, config in SINK_PATTERNS.items():
        findings = []
        for ext_glob, patterns in config["patterns"].items():
            for ext in ext_glob.split("|"):
                for filepath in root.rglob(ext):
                    rel = str(filepath.relative_to(root))
                    if any(skip in rel for skip in [
                        "node_modules", ".git", "venv", "__pycache__",
                        "dist", "build", ".next", "test", "spec", "mock"
                    ]):
                        continue

                    try:
                        content = filepath.read_text(errors="ignore")
                    except Exception:
                        continue

                    for pattern in patterns:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count("\n") + 1
                            # Get the matching line for context
                            lines = content.split("\n")
                            line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                            findings.append({
                                "file": rel,
                                "line": line_num,
                                "snippet": line_text[:120],
                            })

        # Deduplicate and limit
        seen = set()
        unique = []
        for f in findings:
            key = (f["file"], f["line"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        results[sink_type] = unique[:10]  # Cap at 10 per type

    return results


def _detect_validation(local_path: str) -> dict:
    """Detect input validation library usage."""
    root = Path(local_path)

    for lib_name, config in VALIDATION_LIBS.items():
        for ext in config["files"]:
            for filepath in root.rglob(ext):
                rel = str(filepath.relative_to(root))
                if any(skip in rel for skip in ["node_modules", ".git", "venv", "__pycache__"]):
                    continue
                try:
                    content = filepath.read_text(errors="ignore")
                    if re.search(config["pattern"], content):
                        # Check coverage: how many route files use it?
                        return {"lib": lib_name, "coverage": "detected"}
                except Exception:
                    continue

    return {"lib": "none detected", "coverage": "none"}


def _detect_auth(local_path: str, framework: str | None) -> dict:
    """Detect authentication patterns."""
    root = Path(local_path)

    auth_patterns = {
        "jwt": [r"jsonwebtoken", r"jwt", r"JWT", r"PyJWT", r"jose"],
        "session": [r"express-session", r"flask-session", r"SessionMiddleware"],
        "oauth": [r"oauth", r"OAuth", r"passport"],
        "api_key": [r"api.?key", r"x-api-key", r"apikey", r"bearer"],
        "basic": [r"BasicAuth", r"basic.?auth", r"HTTPBasicCredentials"],
    }

    detected = {}
    middleware = None

    for auth_type, patterns in auth_patterns.items():
        for ext in ["*.py", "*.js", "*.ts", "*.go", "*.rs"]:
            for filepath in root.rglob(ext):
                rel = str(filepath.relative_to(root))
                if any(skip in rel for skip in ["node_modules", ".git", "venv", "__pycache__", "test"]):
                    continue
                try:
                    content = filepath.read_text(errors="ignore")
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            detected[auth_type] = True
                            break
                except Exception:
                    continue

    auth_type = ", ".join(detected.keys()) if detected else "none detected"
    coverage = "partial" if detected else "none"

    return {"type": auth_type, "middleware": middleware, "coverage": coverage}


def _get_language(local_path: str) -> str:
    """Detect primary language."""
    root = Path(local_path)
    counts = {}
    for ext, lang in [("*.py", "python"), ("*.js", "javascript"), ("*.ts", "typescript"),
                       ("*.go", "go"), ("*.rs", "rust"), ("*.java", "java"), ("*.rb", "ruby")]:
        count = sum(1 for _ in root.rglob(ext))
        if count > 0:
            counts[lang] = count
    return max(counts, key=counts.get) if counts else "unknown"


def _get_deps_with_cves(local_path: str) -> list[dict]:
    """Check if deps have known CVEs (uses cached data if available)."""
    # This will be enhanced in Step 5 when check_vulns is implemented
    return []


async def analyze_surface(repo_url: str) -> dict:
    """Full attack surface analysis."""
    repo = await ensure_repo(repo_url)
    if "error" in repo:
        return repo

    local_path = repo["local_path"]

    # Detect framework (reuse from routes module)
    from bounty_hunter.recon.routes import _detect_framework
    framework = _detect_framework(local_path)

    language = _get_language(local_path)
    auth = _detect_auth(local_path, framework)
    validation = _detect_validation(local_path)
    sinks = _find_sinks(local_path)

    # Get investigation notes
    db = BountyDB()
    notes = db.get_notes(repo_url)

    # Check staleness
    repo_record = db.get_repo(repo_url)
    stale = False
    if repo_record:
        from datetime import datetime, timedelta
        cloned = datetime.fromisoformat(repo_record["cloned_at"])
        stale = (datetime.now() - cloned) > timedelta(hours=24)

    # Count total sinks for summary
    total_sinks = sum(len(v) for v in sinks.values())

    # Get route count
    from bounty_hunter.recon.routes import extract_routes
    route_data = await extract_routes(repo_url, verbose=False)
    route_count = route_data.get("total_routes", 0)

    return {
        "local_path": local_path,
        "commit_hash": repo["commit_hash"],
        "language": language,
        "framework": framework or "unknown",
        "route_count": route_count,
        "auth": auth,
        "validation": validation,
        "interesting_sinks": sinks,
        "total_sinks": total_sinks,
        "deps_with_cves": _get_deps_with_cves(local_path),
        "previous_investigations": [
            {"content": n["content"], "tag": n["tag"], "date": n["created_at"]}
            for n in notes[:5]
        ],
        "stale": stale,
    }
