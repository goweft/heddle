#!/usr/bin/env python3
"""LOOM unified stdio launcher for Claude Desktop.

Loads ALL agent configs from agents/ and merges their tools into a
single MCP server. Claude Desktop gets every tool through one connection.
"""
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

sys.path.insert(0, "/mnt/workspace/projects/loom/src")

from pathlib import Path
from fastmcp import FastMCP
from loom.config.loader import load_agent_config, discover_configs
from loom.mcp.server import _register_http_tool, _register_passthrough_tool
from loom.security.audit import get_audit_logger
from loom.security.trust import TrustEnforcer
from loom.security.credentials import get_credential_broker

AGENTS_DIR = Path("/mnt/workspace/projects/loom/agents")

# Agents to exclude from the unified mesh
EXCLUDE = {
    "uptime-kuma-bridge",  # WebSocket API, not REST
    "gitea-bridge",        # Wrong URLs, superseded by gitea-api-bridge
    "daily-ops",           # Orchestrator, needs custom handlers (not HTTP bridge)
}

unified = FastMCP(name="loom-mesh")
audit = get_audit_logger()
broker = get_credential_broker()

configs = discover_configs(AGENTS_DIR)
total_tools = 0
loaded_agents = 0

for config_path in sorted(configs):
    try:
        config = load_agent_config(config_path)
        name = config.agent.name
        if name in EXCLUDE:
            logging.info(f"Skipping: {name}")
            continue

        spec = config.agent
        trust = TrustEnforcer(spec.name, spec.runtime.trust_tier)
        bridge_map = {ep.tool_name: ep for ep in spec.http_bridge}

        for tool in spec.exposes:
            endpoint = bridge_map.get(tool.name)
            if endpoint:
                _register_http_tool(unified, tool, endpoint, spec.name, trust, audit, broker)
            else:
                _register_passthrough_tool(unified, tool, spec.name, audit)

        total_tools += len(spec.exposes)
        loaded_agents += 1
        logging.info(f"Loaded {name}: {len(spec.exposes)} tools")

    except Exception as exc:
        logging.error(f"Failed to load {config_path.name}: {exc}")

logging.info(f"Unified MCP server: {total_tools} tools from {loaded_agents} agents")
unified.run(transport="stdio")
