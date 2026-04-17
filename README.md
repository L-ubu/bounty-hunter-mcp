<p align="center">
  <h1 align="center">bounty-hunter-mcp</h1>
  <p align="center">
    AI-powered bug bounty hunting toolkit — MCP server for Claude Code
  </p>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.13+-blue?logo=python&logoColor=white" alt="Python 3.13+"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjEwIi8+PC9zdmc+" alt="MCP Compatible"></a>
  <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/badge/uv-package%20manager-blueviolet?logo=astral&logoColor=white" alt="uv"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"></a>
</p>

---

An [MCP](https://modelcontextprotocol.io) server that gives AI assistants like Claude a structured toolkit for bug bounty hunting. Instead of ad-hoc file reading and manual curl commands, the AI gets purpose-built tools for recon, testing, intelligence gathering, and report generation — all optimized for token efficiency.

## Why

Bounty hunting with AI wastes tokens on repetitive tasks:
- **10+ Read/Grep calls** to understand a codebase's attack surface → **1 `map_surface` call**
- **Manual curl for CORS/header checks** → **1 `test_endpoint` call**
- **Browsing NVD + GitHub advisories separately** → **1 `check_vulns` call**
- **Writing reports from scratch each time** → **1 `make_report` call** with auto CVSS

Repos are auto-cloned to `~/Projects/bounty-targets/` so the AI uses its native file tools (Read, Grep, Glob) on local code. Investigation state persists across sessions via SQLite.

## Features

### 10 Tools

| Category | Tool | Description |
|----------|------|-------------|
| **Platform** | `hunt_programs` | Search huntr.com for bounty targets with filters |
| | `hunt_reports` | Check existing reports + duplicate detection |
| | `hunt_submit` | Fill huntr submission form via Chrome CDP |
| **Recon** | `map_routes` | Extract HTTP routes + auth status (9 frameworks) |
| | `map_surface` | Full attack surface: sinks, auth, deps, prior notes |
| **Testing** | `test_endpoint` | CORS, headers, auth bypass, method enum (passive/active) |
| | `test_ssrf` | SSRF callback catcher via interactsh |
| **Intel** | `check_vulns` | Search NVD + GitHub advisories in one call |
| **Notes** | `note` | Save/retrieve investigation notes per target |
| **Reporting** | `make_report` | Generate report + CVSS for huntr or GitHub |

### 2 Prompts

- **`analyze_target`** — Full recon workflow: routes, surface, CVEs, existing reports
- **`verify_finding`** — Pre-submission check: duplicates, CVEs, live validation

### 1 Resource

- **`bounty://checklists`** — Framework-specific vulnerability patterns (Express, FastAPI, Django, Next.js, Go, Rust)

## Supported Frameworks

Route extraction and surface analysis work across:

| Framework | Language | Route Detection | Auth Detection |
|-----------|----------|:-:|:-:|
| Express | JavaScript/TypeScript | ✓ | ✓ |
| FastAPI | Python | ✓ | ✓ |
| Flask | Python | ✓ | ✓ |
| Django | Python | ✓ | ✓ |
| Next.js API | JavaScript/TypeScript | ✓ | ✓ |
| NestJS | TypeScript | ✓ | ✓ |
| Hono | TypeScript | ✓ | ✓ |
| Go (chi/gin/mux) | Go | ✓ | ✓ |
| Axum/Actix | Rust | ✓ | ✓ |

Falls back to HTTP method pattern grep for unsupported frameworks.

## Installation

### Prerequisites

- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- [Claude Code](https://claude.ai/code) CLI

### Setup

```bash
# Clone the repo
git clone https://github.com/lucavdw/bounty-hunter-mcp.git
cd bounty-hunter-mcp

# Install dependencies
uv sync

# Register with Claude Code (global — available in all sessions)
claude mcp add bounty-hunter -s user -- uv --directory /path/to/bounty-hunter-mcp run python -m bounty_hunter.server
```

### Environment Variables (Optional)

```bash
export NVD_API_KEY="..."              # NVD rate limit: 5 → 50 req/30s
export HUNTR_SESSION_COOKIE="..."     # Authenticated huntr.com scraping
export GITHUB_TOKEN="..."             # For gh CLI (usually already configured)
```

## Usage

Once registered, the tools appear automatically in Claude Code sessions. Verify with `/mcp`.

### Typical Workflow

```
You: Analyze https://github.com/org/target-app as a bounty target

Claude: [uses map_routes → map_surface → check_vulns → hunt_reports]
        Here's what I found:
        - 47 routes, 12 unprotected
        - SSRF sinks in 3 files
        - 2 known CVEs (patched)
        - 8 existing huntr reports (none for SSRF)
        → Recommending SSRF investigation on /api/proxy endpoint

You: Test the /api/proxy endpoint for SSRF

Claude: [uses test_ssrf to get callback URL]
        [uses test_endpoint in active mode]
        Confirmed: endpoint makes outbound requests without validation.
        Callback received from target IP.

You: Generate a huntr report for this SSRF

Claude: [uses make_report with CVSS calculation]
        Report saved to ~/Projects/bounty-targets/org_target-app/report.json
        CVSS: 7.5 High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
```

### Tool Examples

**Recon a target:**
```
map_routes("https://github.com/org/app")
→ {local_path, total_routes: 47, unprotected_count: 12, interesting: [...]}
```

**Check for duplicates before reporting:**
```
hunt_reports("https://github.com/org/app", vuln_type="SSRF")
→ {total_reports: 8, by_category: {xss: 3, auth_bypass: 5}, duplicate_check: {likely_dup: false}}
```

**Passive endpoint testing:**
```
test_endpoint("https://app.example.com/api/users", checks=["cors", "headers"])
→ {cors: {reflects_origin: true, exploitable: true}, headers: {missing: ["CSP", "HSTS"]}}
```

## Architecture

```
bounty_hunter/
├── server.py              # FastMCP server — 10 tools, 2 prompts, 1 resource
├── config.py              # Paths, TTLs, env vars
├── db.py                  # SQLite (WAL mode) — programs, reports, repos, notes, cache
├── platforms/
│   ├── base.py            # PlatformClient ABC
│   └── huntr.py           # Huntr.com client (stub — scraper pending)
├── recon/
│   ├── repo.py            # Auto-clone/cache/cleanup manager
│   ├── routes.py          # Multi-framework route extraction
│   └── surface.py         # Attack surface analysis + sink detection
├── intel/
│   └── cve.py             # NVD API + GitHub advisory search
├── testing/
│   ├── endpoint.py        # HTTP security checks (passive/active)
│   └── ssrf.py            # SSRF callback via interactsh + local fallback
├── reporting/
│   ├── cvss.py            # CVSS 3.1 calculator
│   └── generator.py       # Huntr JSON + GitHub markdown reports
└── data/
    └── checklists.yaml    # Framework vulnerability patterns
```

### Design Principles

- **Token-efficient** — Summary-first responses. Full data only via `verbose` param.
- **Passive by default** — Live testing tools default to safe mode. Active probing requires explicit opt-in.
- **Auto-clone internally** — Any tool needing local code auto-clones to `~/Projects/bounty-targets/` and returns the path for native file access.
- **Investigation persistence** — Notes and state survive across sessions via SQLite.
- **Auto-cleanup** — Reported repos auto-cleaned. Stale repos (>7 days) pruned on server startup.

### Sink Detection

`map_surface` identifies dangerous code patterns across languages:

| Sink Type | What It Finds |
|-----------|---------------|
| Outbound HTTP | `requests.get`, `fetch`, `http.Get` — SSRF surfaces |
| Database Queries | Raw SQL, `$where`, string interpolation in queries |
| File Operations | `open()`, `readFile`, `os.Open` — path traversal surfaces |
| Exec Calls | `subprocess`, `exec`, `os/exec` — command injection surfaces |

## Roadmap

- [x] Route extraction (9 frameworks + fallback)
- [x] Attack surface analysis with sink detection
- [x] NVD + GitHub advisory intelligence
- [x] HTTP security testing (passive/active modes)
- [x] SSRF callback catcher (interactsh + local)
- [x] CVSS 3.1 calculator
- [x] Multi-format report generator (huntr + GitHub)
- [x] Investigation notes with persistence
- [x] Vulnerability checklists resource
- [ ] Huntr.com scraper (program search + duplicate detection)
- [ ] Huntr form submission via CDP
- [ ] Intigriti platform support
- [ ] HackerOne platform support

## License

MIT
