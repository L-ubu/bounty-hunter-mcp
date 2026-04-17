"""SQLite intelligence store for bounty hunting data."""

import json
import sqlite3
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from bounty_hunter.config import DB_PATH, REPO_MAX_AGE_DAYS, WORKSPACE_DIR


class BountyDB:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS programs (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                name TEXT,
                repo_url TEXT,
                language TEXT,
                bounty_range TEXT,
                report_count INTEGER,
                saturation_score REAL,
                cached_at DATETIME
            );

            CREATE TABLE IF NOT EXISTS known_reports (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                program_id TEXT,
                title TEXT,
                vulnerability_type TEXT,
                cwe_category TEXT,
                status TEXT,
                date TEXT,
                cached_at DATETIME
            );

            CREATE TABLE IF NOT EXISTS repos (
                repo_url TEXT PRIMARY KEY,
                local_path TEXT NOT NULL,
                commit_hash TEXT,
                cloned_at DATETIME,
                last_accessed DATETIME,
                size_bytes INTEGER,
                status TEXT DEFAULT 'active'
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_url TEXT NOT NULL,
                content TEXT NOT NULL,
                tag TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at DATETIME
            );
        """)
        self._conn.commit()

    # ── Cache helpers ──────────────────────────────────────────────────

    def cache_get(self, key: str) -> dict | None:
        row = self._conn.execute(
            "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._conn.commit()
            return None
        return json.loads(row["value"])

    def cache_set(self, key: str, value: dict, ttl_hours: int):
        expires = datetime.now() + timedelta(hours=ttl_hours)
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
            (key, json.dumps(value), expires.isoformat()),
        )
        self._conn.commit()

    # ── Repo tracking ──────────────────────────────────────────────────

    def track_repo(self, repo_url: str, local_path: str, commit_hash: str, size_bytes: int):
        now = datetime.now().isoformat()
        self._conn.execute(
            """INSERT OR REPLACE INTO repos
               (repo_url, local_path, commit_hash, cloned_at, last_accessed, size_bytes, status)
               VALUES (?, ?, ?, ?, ?, ?, 'active')""",
            (repo_url, local_path, commit_hash, now, now, size_bytes),
        )
        self._conn.commit()

    def get_repo(self, repo_url: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM repos WHERE repo_url = ?", (repo_url,)
        ).fetchone()
        if row:
            # Update last_accessed
            self._conn.execute(
                "UPDATE repos SET last_accessed = ? WHERE repo_url = ?",
                (datetime.now().isoformat(), repo_url),
            )
            self._conn.commit()
            return dict(row)
        return None

    def mark_repo_reported(self, repo_url: str):
        self._conn.execute(
            "UPDATE repos SET status = 'reported' WHERE repo_url = ?", (repo_url,)
        )
        self._conn.commit()

    def get_stale_repos(self) -> list[dict]:
        cutoff = (datetime.now() - timedelta(days=REPO_MAX_AGE_DAYS)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM repos WHERE status = 'reported' OR cloned_at < ?",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_repo_record(self, repo_url: str):
        self._conn.execute("DELETE FROM repos WHERE repo_url = ?", (repo_url,))
        self._conn.commit()

    # ── Notes ──────────────────────────────────────────────────────────

    def save_note(self, repo_url: str, content: str, tag: str | None = None):
        self._conn.execute(
            "INSERT INTO notes (repo_url, content, tag) VALUES (?, ?, ?)",
            (repo_url, content, tag),
        )
        self._conn.commit()

    def get_notes(self, repo_url: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT content, tag, created_at FROM notes WHERE repo_url = ? ORDER BY created_at DESC",
            (repo_url,),
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_notes(self, repo_url: str):
        self._conn.execute("DELETE FROM notes WHERE repo_url = ?", (repo_url,))
        self._conn.commit()

    # ── Startup cleanup ────────────────────────────────────────────────

    def startup_cleanup(self) -> list[dict]:
        """Remove stale/reported repos on server startup. Returns removed repos."""
        stale = self.get_stale_repos()
        removed = []
        for repo in stale:
            path = Path(repo["local_path"])
            size_mb = repo.get("size_bytes", 0) / (1024 * 1024)
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
            self.delete_repo_record(repo["repo_url"])
            removed.append({"repo_url": repo["repo_url"], "size_mb": round(size_mb, 1)})
        return removed

    # ── Programs cache ─────────────────────────────────────────────────

    def cache_programs(self, platform: str, programs: list[dict], ttl_hours: int):
        now = datetime.now().isoformat()
        for p in programs:
            self._conn.execute(
                """INSERT OR REPLACE INTO programs
                   (id, platform, name, repo_url, language, bounty_range,
                    report_count, saturation_score, cached_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    p.get("id", p.get("name", "")),
                    platform,
                    p.get("name"),
                    p.get("repo_url"),
                    p.get("language"),
                    p.get("bounty_range"),
                    p.get("report_count"),
                    p.get("saturation_score"),
                    now,
                ),
            )
        self._conn.commit()

    def get_cached_programs(self, platform: str, ttl_hours: int) -> list[dict] | None:
        cutoff = (datetime.now() - timedelta(hours=ttl_hours)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM programs WHERE platform = ? AND cached_at > ?",
            (platform, cutoff),
        ).fetchall()
        return [dict(r) for r in rows] if rows else None

    # ── Reports cache ──────────────────────────────────────────────────

    def cache_reports(self, platform: str, program_id: str, reports: list[dict], ttl_hours: int):
        now = datetime.now().isoformat()
        for r in reports:
            self._conn.execute(
                """INSERT OR REPLACE INTO known_reports
                   (id, platform, program_id, title, vulnerability_type,
                    cwe_category, status, date, cached_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    r.get("id", f"{program_id}_{r.get('title', '')[:50]}"),
                    platform,
                    program_id,
                    r.get("title"),
                    r.get("vulnerability_type"),
                    r.get("cwe_category"),
                    r.get("status"),
                    r.get("date"),
                    now,
                ),
            )
        self._conn.commit()

    def close(self):
        self._conn.close()
