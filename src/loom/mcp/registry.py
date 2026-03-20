"""SQLite registry of all LOOM agents and their MCP tool manifests."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".loom" / "registry.db"

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
        self._conn.commit()

    def set_status(self, name: str, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute("UPDATE agents SET status=?, updated_at=? WHERE name=?", (status, now, name))
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
            "loom_version": "0.1.0",
            "agents": [{
                "name": a["name"], "version": a["version"],
                "description": a["description"], "status": a["status"],
                "endpoint": f"http://{a['host']}:{a['port']}/mcp" if a["port"] else None,
                "tools": [{"name": t["name"], "description": t["description"]} for t in a["tools"]],
            } for a in agents],
        }

    def close(self) -> None:
        self._conn.close()
