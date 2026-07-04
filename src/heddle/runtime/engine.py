"""Heddle Agent Runtime Engine — load config, build MCP server, register, run."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from heddle.config.loader import load_agent_config, ConfigError
from heddle.config.schema import AgentConfig
from heddle.mcp.server import build_mcp_server
from heddle.mcp.registry import Registry

logger = logging.getLogger(__name__)

DEFAULT_AGENTS_DIR = Path.home() / ".heddle" / "agents"


class AgentRunner:
    def __init__(self, registry: Registry | None = None):
        self._registry = registry or Registry()

    def load(self, config_path: str | Path) -> AgentConfig:
        config = load_agent_config(config_path)
        logger.info(f"Loaded agent config: {config.agent.name} v{config.agent.version}")
        return config

    def register(self, config: AgentConfig, config_path: str = "", port: int = 0) -> None:
        spec = config.agent
        bridge_names = {ep.tool_name for ep in spec.http_bridge}
        tools: list[dict[str, Any]] = []
        for t in spec.exposes:
            tools.append({
                "name": t.name, "description": t.description,
                "parameters": {pname: {"type": pdef.type, "description": pdef.description, "required": pdef.required}
                               for pname, pdef in t.parameters.items()},
                "returns": {"type": t.returns.type, "description": t.returns.description},
                "bridge_type": "http" if t.name in bridge_names else "none",
            })
        self._registry.register_agent(
            name=spec.name, version=spec.version, description=spec.description,
            config_path=str(config_path), port=port,
            trust_tier=spec.runtime.trust_tier, tools=tools)
        logger.info(f"Registered agent '{spec.name}' with {len(tools)} tool(s) (port={port})")

    def run(self, config: AgentConfig, host: str = "0.0.0.0", port: int = 8200,
            transport: str = "streamable-http") -> None:
        spec = config.agent
        mcp = build_mcp_server(config)
        self._registry.set_status(spec.name, "running")
        logger.info(f"Starting agent '{spec.name}' on {host}:{port} (transport={transport})")
        try:
            mcp.run(transport=transport, host=host, port=port)
        except KeyboardInterrupt:
            logger.info(f"Agent '{spec.name}' stopped by user")
        except Exception as exc:
            logger.error(f"Agent '{spec.name}' crashed: {exc}")
            self._registry.set_status(spec.name, "error")
            raise
        finally:
            self._registry.set_status(spec.name, "stopped")

    def run_agent(self, config_path: str | Path, host: str = "0.0.0.0",
                  port: int = 8200, transport: str = "streamable-http") -> None:
        config = self.load(config_path)
        self.register(config, config_path=str(config_path), port=port)
        self.run(config, host=host, port=port, transport=transport)

    def dry_run(self, config_path: str | Path) -> dict[str, Any]:
        config = self.load(config_path)
        spec = config.agent
        bridge_names = {ep.tool_name for ep in spec.http_bridge}
        return {
            "agent": spec.name, "version": spec.version,
            "description": spec.description, "trust_tier": spec.runtime.trust_tier,
            "tools": [{"name": t.name, "description": t.description,
                       "bridge_type": "http" if t.name in bridge_names else "stub",
                       "parameters": list(t.parameters.keys())} for t in spec.exposes],
            "consumes": [{"uri": c.uri, "tools": c.tools} for c in spec.consumes],
            "triggers": [{"type": tr.type, "schedule": tr.schedule} for tr in spec.triggers],
        }
