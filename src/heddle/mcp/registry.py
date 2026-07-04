"""SQLite registry of all Heddle agents and their MCP tool manifests."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".heddle" / "registry.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    name TEXT PRIMARY KEY, version TEXT NOT NULL, description TEXT DEFAULT '',
    config_path TEXT DEFAULT '', host TEXT DEFAULT 'localhost',
    port INTEGER DEFAULT 0, transport TEXT DEFAULT 'streamable-http',
    status TEXT DEFAULT 'registered', trust_tier INTEGER DEFAULT 2,
    registered_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT NOT NULL REFERENCES agents(name) ON DELETE CASCADE,
    name TEXT NOT NULL, description TEXT DEFAULT '',
    parameters TEXT DEFAULT '{}', returns TEXT DEFAULT '{}',
    bridge_type TEXT DEFAULT 'none',
    UNIQUE(agent_name, name)
);
CREATE INDEX IF NOT EXISTS idx_tools_agent ON tools(agent_name);
"""


class Registry:
    def __init__(self, db_path: str | Path | None = None):
        self._db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._ensure_hmac_column()
        self._signing_key = self._load_or_create_key()

    def _ensure_hmac_column(self) -> None:
        """Add row_hmac column if it doesn't exist (schema migration)."""
        cols = [r[1] for r in self._conn.execute("PRAGMA table_info(agents)").fetchall()]
        if "row_hmac" not in cols:
            self._conn.execute("ALTER TABLE agents ADD COLUMN row_hmac TEXT DEFAULT ''")
            self._conn.commit()

    def _load_or_create_key(self) -> bytes:
        """Load or generate the registry signing key."""
        key_path = self._db_path.parent / "registry.key"
        if key_path.exists():
            return key_path.read_bytes()
        key = os.urandom(32)
        key_path.write_bytes(key)
        key_path.chmod(0o600)
        return key

    def _compute_row_hmac(self, name: str, version: str, description: str,
                          config_path: str, trust_tier: int, status: str) -> str:
        """Compute HMAC-SHA256 over agent row content."""
        payload = f"{name}|{version}|{description}|{config_path}|{trust_tier}|{status}"
        return hmac.new(self._signing_key, payload.encode(), hashlib.sha256).hexdigest()

    def register_agent(self, name: str, version: str, description: str = "",
                       config_path: str = "", host: str = "localhost",
                       port: int = 0, transport: str = "streamable-http",
                       trust_tier: int = 2, tools: list[dict[str, Any]] | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO agents (name, version, description, config_path,
                                   host, port, transport, status, trust_tier,
                                   registered_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'registered', ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                   version=excluded.version, description=excluded.description,
                   config_path=excluded.config_path, host=excluded.host,
                   port=excluded.port, transport=excluded.transport,
                   trust_tier=excluded.trust_tier, status='registered',
                   updated_at=excluded.updated_at""",
            (name, version, description, config_path, host, port, transport, trust_tier, now, now))
        self._conn.execute("DELETE FROM tools WHERE agent_name = ?", (name,))
        for t in (tools or []):
            self._conn.execute(
                "INSERT INTO tools (agent_name, name, description, parameters, returns, bridge_type) VALUES (?, ?, ?, ?, ?, ?)",
                (name, t["name"], t.get("description", ""),
                 json.dumps(t.get("parameters", {})), json.dumps(t.get("returns", {})),
                 t.get("bridge_type", "none")))
        row_hmac = self._compute_row_hmac(name, version, description, config_path, trust_tier, "registered")
        self._conn.execute("UPDATE agents SET row_hmac=? WHERE name=?", (row_hmac, name))
        self._conn.commit()

    def set_status(self, name: str, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute("UPDATE agents SET status=?, updated_at=? WHERE name=?", (status, now, name))
        # Recompute HMAC with new status
        row = self._conn.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
        if row:
            row_hmac = self._compute_row_hmac(row["name"], row["version"], row["description"],
                                              row["config_path"], row["trust_tier"], status)
            self._conn.execute("UPDATE agents SET row_hmac=? WHERE name=?", (row_hmac, name))
        self._conn.commit()

    def unregister_agent(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM agents WHERE name=?", (name,))
        self._conn.commit()
        return cur.rowcount > 0

    def get_agent(self, name: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
        if not row:
            return None
        agent = dict(row)
        agent["tools"] = [dict(r) for r in self._conn.execute("SELECT * FROM tools WHERE agent_name=?", (name,))]
        return agent

    def list_agents(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM agents ORDER BY name").fetchall()
        agents = []
        for row in rows:
            a = dict(row)
            a["tools"] = [dict(r) for r in self._conn.execute("SELECT * FROM tools WHERE agent_name=?", (a["name"],))]
            agents.append(a)
        return agents

    def list_all_tools(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """SELECT t.*, a.host, a.port, a.transport, a.status as agent_status
               FROM tools t JOIN agents a ON t.agent_name = a.name
               ORDER BY t.agent_name, t.name""").fetchall()
        return [dict(r) for r in rows]

    def search_tools(self, query: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """SELECT t.*, a.host, a.port, a.transport
               FROM tools t JOIN agents a ON t.agent_name = a.name
               WHERE t.name LIKE ? OR t.description LIKE ?
               ORDER BY t.agent_name, t.name""",
            (f"%{query}%", f"%{query}%")).fetchall()
        return [dict(r) for r in rows]

    def discovery_manifest(self) -> dict[str, Any]:
        agents = self.list_agents()
        return {
            "heddle_version": "0.1.0",
            "agents": [{
                "name": a["name"], "version": a["version"],
                "description": a["description"], "status": a["status"],
                "endpoint": f"http://{a['host']}:{a['port']}/mcp" if a["port"] else None,
                "tools": [{"name": t["name"], "description": t["description"]} for t in a["tools"]],
            } for a in agents],
        }

    def verify_registry(self) -> tuple[bool, int, list[str]]:
        """Verify HMAC integrity of all agent rows.

        Returns (all_valid, rows_checked, list_of_issues).
        """
        rows = self._conn.execute("SELECT * FROM agents ORDER BY name").fetchall()
        issues = []
        for row in rows:
            expected = self._compute_row_hmac(
                row["name"], row["version"], row["description"],
                row["config_path"], row["trust_tier"], row["status"],
            )
            stored = row["row_hmac"] if "row_hmac" in row.keys() else ""
            if not stored:
                issues.append(f"{row['name']}: no HMAC (unsigned row)")
            elif stored != expected:
                issues.append(f"{row['name']}: HMAC mismatch (row modified outside broker)")
        return len(issues) == 0, len(rows), issues

    def close(self) -> None:
        self._conn.close()
