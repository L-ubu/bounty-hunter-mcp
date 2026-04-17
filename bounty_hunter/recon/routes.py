"""HTTP route extraction from codebases — multi-framework support."""

import re
import subprocess
from pathlib import Path

from bounty_hunter.recon.repo import ensure_repo

# ── Framework-specific route patterns ──────────────────────────────────

# Each pattern: (regex, group_indices_for_method_and_path)
FRAMEWORK_PATTERNS = {
    "express": {
        "extensions": ["*.js", "*.ts", "*.mjs"],
        "patterns": [
            # app.get('/path', ...) or router.post('/path', ...)
            (r"""(?:app|router)\.(get|post|put|delete|patch|options|all)\s*\(\s*['"`]([^'"`]+)['"`]""", 1, 2),
        ],
        "auth_indicators": [
            r"auth", r"isAuthenticated", r"requireAuth", r"protect",
            r"verifyToken", r"jwt", r"passport\.authenticate",
            r"isAdmin", r"requireRole",
        ],
    },
    "fastapi": {
        "extensions": ["*.py"],
        "patterns": [
            # @app.get("/path") or @router.post("/path")
            (r"""@(?:app|router)\.(get|post|put|delete|patch|options)\s*\(\s*['"]([^'"]+)['"]""", 1, 2),
        ],
        "auth_indicators": [
            r"Depends\(", r"Security\(", r"get_current_user",
            r"oauth2_scheme", r"HTTPBearer", r"api_key_header",
        ],
    },
    "flask": {
        "extensions": ["*.py"],
        "patterns": [
            # @app.route("/path", methods=["GET"])
            (r"""@(?:app|bp|blueprint)\s*\.route\s*\(\s*['"]([^'"]+)['"](?:.*methods\s*=\s*\[([^\]]+)\])?""", None, 1),
        ],
        "auth_indicators": [
            r"login_required", r"@auth", r"current_user",
            r"flask_login", r"jwt_required",
        ],
    },
    "django": {
        "extensions": ["*.py"],
        "patterns": [
            # path('url/', view), re_path(r'^url/$', view)
            (r"""path\s*\(\s*['"]([^'"]+)['"]""", None, 1),
            (r"""re_path\s*\(\s*r?['"]([^'"]+)['"]""", None, 1),
        ],
        "auth_indicators": [
            r"login_required", r"permission_required", r"IsAuthenticated",
            r"@csrf_exempt", r"authentication_classes",
        ],
    },
    "nextjs": {
        "extensions": ["*.js", "*.ts", "*.jsx", "*.tsx"],
        "patterns": [
            # export async function GET/POST/PUT/DELETE
            (r"""export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)""", 1, None),
        ],
        "auth_indicators": [
            r"getServerSession", r"auth\(\)", r"requireAuth",
            r"NextAuth", r"getToken",
        ],
    },
    "nestjs": {
        "extensions": ["*.ts"],
        "patterns": [
            # @Get('/path'), @Post('/path')
            (r"""@(Get|Post|Put|Delete|Patch)\s*\(\s*(?:['"]([^'"]*)['"]\s*)?\)""", 1, 2),
        ],
        "auth_indicators": [
            r"@UseGuards", r"AuthGuard", r"@Auth",
            r"JwtAuthGuard", r"RolesGuard",
        ],
    },
    "hono": {
        "extensions": ["*.js", "*.ts"],
        "patterns": [
            (r"""(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]""", 1, 2),
        ],
        "auth_indicators": [
            r"bearerAuth", r"jwt\(", r"auth\(",
        ],
    },
    "go": {
        "extensions": ["*.go"],
        "patterns": [
            # r.HandleFunc("/path", handler).Methods("GET")
            (r"""\.HandleFunc\s*\(\s*"([^"]+)".*\.Methods\s*\(\s*"(\w+)"(?:\s*,\s*"(\w+)")*\)""", 2, 1),
            # r.GET("/path", handler) — chi/gin
            (r"""\.(?:GET|POST|PUT|DELETE|PATCH|Handle)\s*\(\s*"([^"]+)"[,\s]""", None, 1),
        ],
        "auth_indicators": [
            r"AuthMiddleware", r"RequireAuth", r"JWTMiddleware",
            r"apiKeyAuth", r"BasicAuth",
        ],
    },
    "rust_axum": {
        "extensions": ["*.rs"],
        "patterns": [
            # .route("/path", get(handler))
            (r"""\.route\s*\(\s*"([^"]+)"\s*,\s*(get|post|put|delete|patch)""", 2, 1),
        ],
        "auth_indicators": [
            r"auth", r"middleware::from_fn\(auth",
            r"RequireAuth", r"api_key",
        ],
    },
}

# Fallback grep patterns for unknown frameworks
FALLBACK_PATTERNS = [
    (r"""['"]/(api|v[0-9]|auth|admin|debug|health|internal|webhook|callback)[/'"]""", None, 1),
]

# Keywords that make a route "interesting" for bounty hunting
INTERESTING_KEYWORDS = {
    "admin", "debug", "internal", "upload", "file", "download",
    "exec", "eval", "proxy", "redirect", "callback", "webhook",
    "reset", "password", "token", "secret", "config", "settings",
    "register", "oauth", "mcp", "graphql", "import", "export",
}


def _grep_patterns(local_path: str, extensions: list[str], patterns: list, auth_indicators: list[str]) -> list[dict]:
    """Run grep-based route extraction."""
    routes = []
    root = Path(local_path)

    for ext in extensions:
        for filepath in root.rglob(ext):
            # Skip node_modules, venv, .git, etc.
            rel = str(filepath.relative_to(root))
            if any(skip in rel for skip in ["node_modules", ".git", "venv", "__pycache__", "dist", "build", ".next"]):
                continue

            try:
                content = filepath.read_text(errors="ignore")
                lines = content.split("\n")
            except Exception:
                continue

            for pattern, method_group, path_group in patterns:
                for match in re.finditer(pattern, content):
                    # Get line number
                    start = match.start()
                    line_num = content[:start].count("\n") + 1

                    # Extract method and path
                    method = match.group(method_group).upper() if method_group and match.group(method_group) else "ANY"
                    route_path = match.group(path_group) if path_group and match.group(path_group) else ""

                    # Check surrounding context (5 lines before, 3 after) for auth
                    ctx_start = max(0, line_num - 6)
                    ctx_end = min(len(lines), line_num + 3)
                    context = "\n".join(lines[ctx_start:ctx_end])
                    has_auth = any(re.search(ind, context, re.IGNORECASE) for ind in auth_indicators)

                    # Determine if "interesting"
                    path_lower = route_path.lower()
                    reason = None
                    if not has_auth:
                        reason = "unprotected"
                    for kw in INTERESTING_KEYWORDS:
                        if kw in path_lower:
                            reason = f"contains '{kw}'"
                            break

                    routes.append({
                        "method": method,
                        "path": route_path,
                        "file": rel,
                        "line": line_num,
                        "has_auth": has_auth,
                        "reason": reason,
                    })

    return routes


def _detect_framework(local_path: str) -> str | None:
    """Detect web framework from project files."""
    root = Path(local_path)

    # Check package.json
    pkg_json = root / "package.json"
    if pkg_json.exists():
        content = pkg_json.read_text(errors="ignore")
        if "express" in content:
            return "express"
        if "next" in content:
            return "nextjs"
        if "@nestjs" in content:
            return "nestjs"
        if "hono" in content:
            return "hono"

    # Check pyproject.toml / requirements.txt
    for pyfile in ["pyproject.toml", "requirements.txt", "setup.py"]:
        path = root / pyfile
        if path.exists():
            content = path.read_text(errors="ignore")
            if "fastapi" in content.lower():
                return "fastapi"
            if "flask" in content.lower():
                return "flask"
            if "django" in content.lower():
                return "django"

    # Check go.mod
    go_mod = root / "go.mod"
    if go_mod.exists():
        return "go"

    # Check Cargo.toml
    cargo = root / "Cargo.toml"
    if cargo.exists():
        content = cargo.read_text(errors="ignore")
        if "axum" in content:
            return "rust_axum"
        return "rust_axum"  # Default Rust web = Axum

    return None


async def extract_routes(repo_url: str, verbose: bool = False) -> dict:
    """Extract HTTP routes from a codebase."""
    repo = await ensure_repo(repo_url)
    if "error" in repo:
        return repo

    local_path = repo["local_path"]
    framework = _detect_framework(local_path)

    all_routes = []

    if framework and framework in FRAMEWORK_PATTERNS:
        fp = FRAMEWORK_PATTERNS[framework]
        all_routes = _grep_patterns(
            local_path, fp["extensions"], fp["patterns"], fp["auth_indicators"]
        )

    # Also try fallback patterns if we found few routes
    if len(all_routes) < 5:
        for ext in ["*.py", "*.js", "*.ts", "*.go", "*.rs"]:
            fallback = _grep_patterns(
                local_path, [ext], FALLBACK_PATTERNS, []
            )
            all_routes.extend(fallback)

    # Deduplicate
    seen = set()
    unique_routes = []
    for r in all_routes:
        key = (r["method"], r["path"], r["file"], r["line"])
        if key not in seen:
            seen.add(key)
            unique_routes.append(r)

    # Split into interesting vs normal
    interesting = [r for r in unique_routes if r.get("reason")]
    unprotected = [r for r in unique_routes if not r.get("has_auth")]

    auth_types = set()
    if framework and framework in FRAMEWORK_PATTERNS:
        for r in unique_routes:
            if r.get("has_auth"):
                # Rough auth type detection from the framework's indicators
                auth_types.add("middleware")

    result = {
        "local_path": local_path,
        "commit_hash": repo["commit_hash"],
        "framework": framework or "unknown",
        "total_routes": len(unique_routes),
        "unprotected_count": len(unprotected),
        "auth_types": list(auth_types) or ["none detected"],
        "interesting": interesting[:20],  # Cap at 20 to save tokens
    }

    if verbose:
        result["all_routes"] = unique_routes

    return result
