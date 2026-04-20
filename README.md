<div align="center">

# bounty-hunter-mcp

**Give your AI superpowers for bug bounty hunting.**

An MCP server that turns Claude Code into a structured bug bounty toolkit —<br>
recon, live testing, intelligence, and report generation in single tool calls.

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-compatible-00d084?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjEwIi8+PC9zdmc+)](https://modelcontextprotocol.io)
[![uv](https://img.shields.io/badge/uv-package%20manager-7c3aed?style=for-the-badge&logo=astral&logoColor=white)](https://github.com/astral-sh/uv)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude-Code-d97706?style=for-the-badge&logo=anthropic&logoColor=white)](https://claude.ai/code)

<br>

<img src="https://img.shields.io/badge/10_tools-blue?style=flat-square" alt="10 tools">
<img src="https://img.shields.io/badge/2_prompts-green?style=flat-square" alt="2 prompts">
<img src="https://img.shields.io/badge/1_resource-orange?style=flat-square" alt="1 resource">
<img src="https://img.shields.io/badge/9_frameworks-purple?style=flat-square" alt="9 frameworks">
<img src="https://img.shields.io/badge/CVSS_3.1-red?style=flat-square" alt="CVSS 3.1">

</div>

---

## The Problem

Bug bounty hunting with AI burns tokens on repetitive grunt work:

| Without this toolkit                             | With this toolkit                              |
| ------------------------------------------------ | ---------------------------------------------- |
| 10+ Read/Grep calls to understand attack surface | **1 `map_surface` call**                       |
| Manual curl for CORS, headers, auth checks       | **1 `test_endpoint` call**                     |
| Browsing NVD + GitHub advisories separately      | **1 `check_vulns` call**                       |
| Writing reports from scratch every time          | **1 `make_report` call** with auto CVSS        |
| Losing investigation context between sessions    | **`note` tool** persists across sessions       |
| Re-cloning and navigating repos manually         | **Auto-clone** to `~/Projects/bounty-targets/` |

The AI gets structured recon data back instead of raw file contents. You spend tokens on _thinking_, not _plumbing_.

---

## How It Works

```
+---------------------------------------------------+
|              Claude Code CLI                       |
|                                                    |
|  "Analyze this repo for bounty targets"            |
+------------------------+---------------------------+
                         | MCP Protocol
+------------------------v---------------------------+
|           bounty-hunter-mcp server                 |
|                                                    |
|  +-------------+ +-------------+ +-------------+   |
|  |    Recon    | |   Testing   | |    Intel    |   |
|  |             | |             | |             |   |
|  |  Routes     | |  CORS       | |  NVD        |   |
|  |  Surface    | |  Headers    | |  GitHub     |   |
|  |  Sinks      | |  Auth       | |  CVEs       |   |
|  |  Deps       | |  SSRF       | |             |   |
|  +------+------+ +------+------+ +------+------+   |
|         |               |               |          |
|  +------v---------------v---------------v------+   |
|  |       SQLite Intelligence Store             |   |
|  |    notes . cache . repos . vulns            |   |
|  +---------------------------------------------+   |
+----------------------------------------------------+
                         |
+------------------------v---------------------------+
|    ~/Projects/bounty-targets/                      |
|                                                    |
|  owner_repo/        <- auto-cloned                 |
|  |-- src/           <- Claude reads with           |
|  |-- routes/           native Read/Grep            |
|  +-- report.json    <- generated report            |
+----------------------------------------------------+
```

Repos are cloned locally so Claude uses its **native file tools** (Read, Grep, Glob) for deep analysis. The MCP tools handle the _structured_ parts — route extraction, sink detection, CVSS scoring, report formatting.

---

## Tools

### Recon

| Tool              | What it does                                                                                                                                                                            |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`map_routes`**  | Auto-clones repo. Extracts all HTTP routes with auth status across 9 frameworks. Returns only interesting routes (unprotected, admin, debug, upload) by default.                        |
| **`map_surface`** | One-call attack surface summary: framework, auth type, validation coverage, dangerous sinks (SSRF/injection/traversal/RCE surfaces), dependency CVEs, and previous investigation notes. |

### Live Testing

| Tool                | What it does                                                                                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`test_endpoint`** | HTTP security checks against live URLs. Passive mode (default): CORS preflight + header analysis. Active mode: auth bypass probing, method enumeration, info leak detection.                                       |
| **`test_ssrf`**     | Starts an SSRF callback catcher via [interactsh](https://github.com/projectdiscovery/interactsh). Returns a unique `*.oast.fun` URL to inject. Polls for out-of-band callbacks. Falls back to local HTTP listener. |

### Intelligence

| Tool              | What it does                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **`check_vulns`** | Searches NVD + GitHub security advisories in one call. Rate-limited (5 req/30s free, 50 with API key). Results cached 24h. |

### Investigation

| Tool       | What it does                                                                                                                                                                                 |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`note`** | Save/retrieve investigation notes per target with tags (`checked`, `interesting`, `dead_end`, `todo`, `finding`). Persists in SQLite across sessions. Loaded automatically by `map_surface`. |

### Reporting

| Tool              | What it does                                                                                                                                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`make_report`** | Generates platform-ready vulnerability reports. Huntr: JSON with auto-detected package manager + version. GitHub: private vulnerability report markdown. Includes full CVSS 3.1 calculation. |

### Platform _(stubs — scraper coming)_

| Tool                | What it does                                                                       |
| ------------------- | ---------------------------------------------------------------------------------- |
| **`hunt_programs`** | Search huntr.com for bounty targets with language, bounty, and saturation filters. |
| **`hunt_reports`**  | Check existing vulnerability reports + CWE-based duplicate detection.              |
| **`hunt_submit`**   | Fill huntr.com submission form via Chrome CDP.                                     |

---

## Framework Support

Route extraction, auth detection, and vulnerability checklists cover:

| Framework        | Language   | Routes | Auth | Sinks |
| ---------------- | ---------- | :----: | :--: | :---: |
| Express          | JS/TS      |   ✓    |  ✓   |   ✓   |
| FastAPI          | Python     |   ✓    |  ✓   |   ✓   |
| Flask            | Python     |   ✓    |  ✓   |   ✓   |
| Django           | Python     |   ✓    |  ✓   |   ✓   |
| Next.js API      | JS/TS      |   ✓    |  ✓   |   ✓   |
| NestJS           | TypeScript |   ✓    |  ✓   |   ✓   |
| Hono             | TypeScript |   ✓    |  ✓   |   ✓   |
| Go (chi/gin/mux) | Go         |   ✓    |  ✓   |   ✓   |
| Axum / Actix     | Rust       |   ✓    |  ✓   |   ✓   |

Unsupported frameworks fall back to HTTP method pattern grep with lower confidence.

### Sink Detection

`map_surface` identifies dangerous code patterns across all supported languages:

| Sink Type            | Patterns                                      | Attack Surface    |
| -------------------- | --------------------------------------------- | ----------------- |
| **Outbound HTTP**    | `requests.get`, `fetch`, `httpx`, `http.Get`  | SSRF              |
| **Database Queries** | Raw SQL, `$where`, f-string queries, `query(` | Injection         |
| **File Operations**  | `open()`, `readFile`, `os.Open`, `Path(`      | Path Traversal    |
| **Exec Calls**       | `subprocess`, `child_process`, `os/exec`      | Command Injection |

---

## Quick Start

### Prerequisites

- **Python 3.13+**
- **[uv](https://github.com/astral-sh/uv)** package manager
- **[Claude Code](https://claude.ai/code)** CLI
- **[gh](https://cli.github.com/)** CLI _(optional — for GitHub advisory search)_

### Install

```bash
git clone https://github.com/L-ubu/bounty-hunter-mcp.git
cd bounty-hunter-mcp
uv sync
```

### Register with Claude Code

```bash
# Global — available in every session
claude mcp add bounty-hunter -s user -- \
  uv --directory /path/to/bounty-hunter-mcp run python -m bounty_hunter.server
```

### Verify

```
/mcp
# → bounty-hunter: 10 tools, 2 prompts, 1 resource
```

### Environment Variables _(optional)_

| Variable               | Effect                                                             |
| ---------------------- | ------------------------------------------------------------------ |
| `NVD_API_KEY`          | NVD rate limit: 5 → 50 requests per 30s                            |
| `HUNTR_SESSION_COOKIE` | Authenticated huntr.com scraping                                   |
| `GITHUB_TOKEN`         | For `gh` CLI _(usually already configured)_                        |
| `BOUNTY_WORKSPACE`     | Override clone directory _(default: `~/Projects/bounty-targets/`)_ |

---

## Usage

### Full Recon Workflow

```
You: Analyze https://github.com/org/target-app as a bounty target

Claude: [map_routes] Found 47 routes — 12 unprotected, 3 admin endpoints
        [map_surface] Express app, JWT auth (partial coverage), Zod validation
                      Sinks: 4 outbound HTTP (SSRF), 2 raw SQL queries
                      Dependencies: lodash 4.17.20 has CVE-2021-23337
        [check_vulns] 3 NVD results, 1 GitHub advisory
        [hunt_reports] 8 existing reports — XSS (3), auth bypass (5), no SSRF reports

        Priority targets:
        1. /api/proxy — SSRF sink, no auth, no existing reports
        2. /admin/users — raw SQL, JWT bypass possible
        3. lodash dep — known prototype pollution
```

### SSRF Testing

```
You: Test /api/proxy for SSRF

Claude: [test_ssrf] Callback URL: https://abc123.oast.fun
        [test_endpoint mode=active] Endpoint accepts arbitrary URLs
        Injecting callback URL...
        Callback received! Source IP matches target server.
        Confirmed: blind SSRF via /api/proxy

You: Save that as a finding

Claude: [note tag=finding] Saved: "Blind SSRF via /api/proxy — confirmed with
        interactsh callback. No URL validation or allowlist."
```

### Report Generation

```
You: Generate a huntr report for this SSRF

Claude: [make_report platform=huntr]
        Report: ~/Projects/bounty-targets/org_target-app/report.json
        CVSS: 7.5 High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
        Package: npm, version: 2.1.0
        Validation: ✓ all fields present
```

---

## Architecture

```
bounty_hunter/
├── server.py              # FastMCP server — 10 tools, 2 prompts, 1 resource
├── config.py              # Paths, TTLs, env vars
├── db.py                  # SQLite (WAL mode) — programs, reports, repos, notes, cache
│
├── platforms/
│   ├── base.py            # PlatformClient ABC
│   └── huntr.py           # Huntr.com client (stub — scraper pending)
│
├── recon/
│   ├── repo.py            # Auto-clone/cache/cleanup manager
│   ├── routes.py          # Multi-framework route extraction
│   └── surface.py         # Attack surface analysis + sink detection
│
├── intel/
│   └── cve.py             # NVD API + GitHub advisory search
│
├── testing/
│   ├── endpoint.py        # HTTP security checks (passive/active)
│   └── ssrf.py            # SSRF callback via interactsh + local fallback
│
├── reporting/
│   ├── cvss.py            # CVSS 3.1 calculator
│   └── generator.py       # Huntr JSON + GitHub markdown reports
│
└── data/
    └── checklists.yaml    # Framework vulnerability patterns (MCP resource)
```

### Design Principles

| Principle              | Implementation                                                                      |
| ---------------------- | ----------------------------------------------------------------------------------- |
| **Token-efficient**    | Summary-first responses. Full data only with `verbose=true`.                        |
| **Passive by default** | Live testing defaults to safe mode (HEAD/OPTIONS). Active requires explicit opt-in. |
| **Native file access** | Repos cloned locally so the AI uses Read/Grep/Glob directly — no extra tool calls.  |
| **Persistent state**   | Investigation notes + cache survive across sessions via SQLite.                     |
| **Auto-cleanup**       | Reported repos auto-deleted. Stale repos (>7 days) pruned on server startup.        |

### Data Flow

```
hunt_programs → pick target
       ↓
map_routes + map_surface → understand codebase
       ↓
check_vulns + hunt_reports → check for duplicates
       ↓
test_endpoint + test_ssrf → validate findings
       ↓
note → save investigation state
       ↓
make_report → generate submission
       ↓
hunt_submit → fill platform form
       ↓
auto-cleanup → remove cloned repo
```

---

## Roadmap

- [x] Multi-framework route extraction (9 frameworks + fallback grep)
- [x] Attack surface analysis with sink detection
- [x] NVD + GitHub advisory intelligence with caching
- [x] HTTP security testing (passive + active modes)
- [x] SSRF out-of-band callback catcher (interactsh + local)
- [x] CVSS 3.1 base score calculator
- [x] Multi-format report generator (huntr JSON + GitHub markdown)
- [x] Investigation notes with tag-based persistence
- [x] Framework-specific vulnerability checklists (MCP resource)
- [ ] Huntr.com scraper (program search + CWE-based duplicate detection)
- [ ] Huntr form submission via Chrome CDP
- [ ] Intigriti platform support
- [ ] HackerOne platform support
- [ ] Custom vulnerability pattern plugins

---

## License

[MIT](LICENSE) — use it, break things, find bugs, get paid.
