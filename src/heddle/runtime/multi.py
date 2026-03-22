"""Heddle multi-agent runner — run and wire multiple agents together.

Handles starting several agents, registering them, and setting up
the mesh connections so agents can discover and call each other.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path
from typing import Any

from heddle.config.loader import load_agent_config, discover_configs, ConfigError
from heddle.config.schema import AgentConfig
from heddle.mcp.server import build_mcp_server
from heddle.mcp.registry import Registry
from heddle.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

DEFAULT_BASE_PORT = 8200


class MultiAgentRunner:
    """Run multiple Heddle agents simultaneously.

    Each agent gets its own port and MCP server. The registry tracks
    all of them, enabling cross-agent discovery via the mesh.
    """

    def __init__(self, registry: Registry | None = None):
        self._registry = registry or Registry()
        self._agents: list[dict[str, Any]] = []
        self._audit = get_audit_logger()

    def add(self, config_path: str | Path, port: int | None = None) -> dict[str, Any]:
        """Add an agent to the run list."""
        config = load_agent_config(config_path)
        spec = config.agent

        if port is None:
            port = DEFAULT_BASE_PORT + len(self._agents)

        entry = {
            "config": config,
            "config_path": str(config_path),
            "port": port,
            "name": spec.name,
        }
        self._agents.append(entry)
        logger.info("Queued agent: %s on port %d", spec.name, port)
        return entry

    def add_directory(self, directory: str | Path, base_port: int = DEFAULT_BASE_PORT) -> int:
        """Add all agent configs from a directory."""
        configs = discover_configs(directory)
        for i, path in enumerate(configs):
            self.add(path, port=base_port + i)
        return len(configs)

    def register_all(self) -> None:
        """Register all queued agents in the registry."""
        from heddle.runtime.engine import AgentRunner
        runner = AgentRunner(registry=self._registry)

        for entry in self._agents:
            runner.register(
                entry["config"],
                config_path=entry["config_path"],
                port=entry["port"],
            )

    async def run_all(
        self,
        host: str = "0.0.0.0",
        transport: str = "streamable-http",
    ) -> None:
        """Start all agents concurrently.

        Each agent runs as an async task. Ctrl-C stops them all.
        """
        self.register_all()

        self._audit.log_agent_lifecycle(
            "heddle-mesh", "start",
            f"Starting {len(self._agents)} agents",
        )

        tasks = []
        for entry in self._agents:
            task = asyncio.create_task(
                self._run_one(entry, host, transport),
                name=f"agent-{entry['name']}",
            )
            tasks.append(task)

        logger.info("Started %d agents", len(tasks))

        # Wait for all — if one fails, log it but keep others running
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for entry, result in zip(self._agents, results):
            if isinstance(result, Exception):
                logger.error("Agent %s failed: %s", entry["name"], result)
                self._registry.set_status(entry["name"], "error")

    async def _run_one(self, entry: dict, host: str, transport: str) -> None:
        """Run a single agent (called as async task)."""
        config = entry["config"]
        spec = config.agent
        port = entry["port"]

        mcp = build_mcp_server(config)
        self._registry.set_status(spec.name, "running")
        self._audit.log_agent_lifecycle(spec.name, "start", f"port={port}")

        logger.info("Starting %s on %s:%d", spec.name, host, port)

        try:
            # FastMCP's run() blocks — wrap it for async
            await asyncio.to_thread(
                mcp.run, transport=transport, host=host, port=port,
            )
        except Exception as exc:
            self._audit.log_agent_lifecycle(spec.name, "error", str(exc))
            self._registry.set_status(spec.name, "error")
            raise
        finally:
            self._audit.log_agent_lifecycle(spec.name, "stop", "")
            self._registry.set_status(spec.name, "stopped")

    def status(self) -> list[dict[str, Any]]:
        """Get status of all queued agents from registry."""
        result = []
        for entry in self._agents:
            agent = self._registry.get_agent(entry["name"])
            if agent:
                result.append({
                    "name": agent["name"],
                    "version": agent["version"],
                    "status": agent["status"],
                    "port": agent["port"],
                    "tools": len(agent["tools"]),
                })
            else:
                result.append({
                    "name": entry["name"],
                    "status": "not_registered",
                    "port": entry["port"],
                })
        return result
