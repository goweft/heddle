"""Heddle Web Dashboard — FastAPI backend.

Exposes Heddle's registry, audit log, agent configs, and health data
as REST endpoints for the React frontend dashboard.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from heddle.config.loader import load_agent_config, discover_configs
from heddle.mcp.registry import Registry
from heddle.security.audit import AuditLogger, get_audit_logger
from heddle.security.credentials import get_credential_broker
from heddle.security.signing import ConfigSigner, AgentQuarantine
from heddle.security.sandbox import SandboxManager

AGENTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "agents"
WEB_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="Heddle Dashboard", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Health ───────────────────────────────────────────────────

    @app.get("/api/health")
    async def health():
        audit = get_audit_logger()
        valid, count, msg = audit.verify_chain()
        configs = list(discover_configs(AGENTS_DIR))
        return {
            "status": "healthy",
            "agents": len(configs),
            "audit_entries": count,
            "audit_chain_valid": valid,
            "timestamp": time.time(),
        }

    # ── Agents ───────────────────────────────────────────────────

    @app.get("/api/agents")
    async def list_agents():
        agents = []
        for config_path in sorted(discover_configs(AGENTS_DIR)):
            try:
                config = load_agent_config(config_path)
                spec = config.agent
                bridge_names = {ep.tool_name for ep in spec.http_bridge}
                agents.append({
                    "name": spec.name,
                    "version": spec.version,
                    "description": spec.description,
                    "trust_tier": spec.runtime.trust_tier,
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "parameters": list(t.parameters.keys()),
                            "bridge": "http" if t.name in bridge_names else "custom",
                        }
                        for t in spec.exposes
                    ],
                    "tool_count": len(spec.exposes),
                    "model_provider": spec.model.provider if spec.model else "none",
                    "http_bridges": [
                        {
                            "tool": ep.tool_name,
                            "method": ep.method,
                            "url": ep.url,
                        }
                        for ep in spec.http_bridge
                    ],
                    "consumes": [
                        {"uri": c.uri, "tools": c.tools}
                        for c in spec.consumes
                    ],
                    "sandbox": spec.runtime.sandbox,
                    "max_execution_time": spec.runtime.max_execution_time,
                    "file": config_path.name,
                })
            except Exception as exc:
                agents.append({
                    "name": config_path.stem,
                    "error": str(exc),
                    "file": config_path.name,
                })
        return {"agents": agents, "total": len(agents)}

    @app.get("/api/agents/{name}")
    async def get_agent(name: str):
        for config_path in discover_configs(AGENTS_DIR):
            try:
                config = load_agent_config(config_path)
                if config.agent.name == name:
                    spec = config.agent
                    return {
                        "name": spec.name,
                        "version": spec.version,
                        "description": spec.description,
                        "trust_tier": spec.runtime.trust_tier,
                        "config_yaml": config_path.read_text(),
                    }
            except Exception:
                continue
        raise HTTPException(404, f"Agent '{name}' not found")

    # ── Mesh topology ────────────────────────────────────────────

    @app.get("/api/mesh")
    async def mesh_topology():
        """Return the agent mesh as a graph structure for visualization."""
        nodes = []
        edges = []
        services = set()

        for config_path in sorted(discover_configs(AGENTS_DIR)):
            try:
                config = load_agent_config(config_path)
                spec = config.agent
                agent_id = spec.name

                nodes.append({
                    "id": agent_id,
                    "type": "agent",
                    "label": spec.name,
                    "tools": len(spec.exposes),
                    "trust_tier": spec.runtime.trust_tier,
                    "model": spec.model.provider if spec.model else "none",
                })

                # Extract backend services from http_bridge URLs
                for ep in spec.http_bridge:
                    from urllib.parse import urlparse
                    parsed = urlparse(ep.url)
                    service_id = f"{parsed.hostname}:{parsed.port or 80}"
                    if service_id not in services:
                        services.add(service_id)
                        nodes.append({
                            "id": service_id,
                            "type": "service",
                            "label": service_id,
                        })
                    edges.append({
                        "source": agent_id,
                        "target": service_id,
                        "method": ep.method,
                        "tool": ep.tool_name,
                    })

                # Cross-agent connections from consumes
                for c in spec.consumes:
                    edges.append({
                        "source": agent_id,
                        "target": c.uri,
                        "type": "mcp",
                        "tools": c.tools,
                    })

            except Exception:
                continue

        # Add Claude Desktop as the MCP client node
        nodes.insert(0, {
            "id": "claude-desktop",
            "type": "client",
            "label": "Claude Desktop",
        })
        edges.insert(0, {
            "source": "claude-desktop",
            "target": "heddle-mesh",
            "type": "mcp-stdio",
        })
        nodes.insert(1, {
            "id": "heddle-mesh",
            "type": "runtime",
            "label": "Heddle Mesh (39 tools)",
        })
        # Connect mesh to each agent
        for n in nodes:
            if n["type"] == "agent":
                edges.append({
                    "source": "heddle-mesh",
                    "target": n["id"],
                    "type": "internal",
                })

        return {"nodes": nodes, "edges": edges}

    # ── Audit ────────────────────────────────────────────────────

    @app.get("/api/audit")
    async def audit_log(n: int = 50, event: str | None = None):
        audit = get_audit_logger()
        entries = audit.recent(n, event_type=event)
        valid, count, msg = audit.verify_chain()
        return {
            "entries": entries,
            "total_entries": count,
            "chain_valid": valid,
            "chain_message": msg,
        }

    @app.get("/api/audit/stats")
    async def audit_stats():
        audit = get_audit_logger()
        entries = audit.recent(1000)
        events = {}
        agents = {}
        for e in entries:
            evt = e.get("event", "unknown")
            events[evt] = events.get(evt, 0) + 1
            agent = e.get("agent", "unknown")
            agents[agent] = agents.get(agent, 0) + 1
        valid, count, msg = audit.verify_chain()
        return {
            "total": count,
            "chain_valid": valid,
            "by_event": events,
            "by_agent": agents,
        }

    # ── Security ─────────────────────────────────────────────────

    @app.get("/api/security/policy")
    async def credential_policy():
        broker = get_credential_broker()
        agents_data = []
        for config_path in discover_configs(AGENTS_DIR):
            try:
                config = load_agent_config(config_path)
                name = config.agent.name
                grants = broker.list_agent_grants(name)
                agents_data.append({"agent": name, "secrets": grants})
            except Exception:
                continue
        return {
            "secrets": broker.list_secrets(),
            "policy": agents_data,
        }

    @app.get("/api/security/signatures")
    async def signatures():
        try:
            signer = ConfigSigner()
            results = signer.verify_all(AGENTS_DIR)
            return {"signatures": results, "all_valid": all(r["status"] == "valid" for r in results)}
        except Exception as exc:
            return {"error": str(exc)}

    @app.get("/api/security/sandbox/{name}")
    async def sandbox_report(name: str):
        for config_path in discover_configs(AGENTS_DIR):
            try:
                config = load_agent_config(config_path)
                if config.agent.name == name:
                    mgr = SandboxManager()
                    return mgr.validate_sandbox(config)
            except Exception:
                continue
        raise HTTPException(404, f"Agent '{name}' not found")

    # ── Static files (React frontend) ────────────────────────────

    @app.get("/")
    async def index():
        index_path = WEB_DIR / "index.html"
        if index_path.exists():
            return HTMLResponse(index_path.read_text())
        return HTMLResponse("<h1>Heddle Dashboard</h1><p>Frontend not found. Place index.html in src/heddle/web/static/</p>")

    return app
