#!/usr/bin/env python3
"""LOOM stdio launcher for Claude Desktop.

Builds the MCP server from agent config and runs it in stdio mode
with no console output (all logging goes to stderr).
"""
import logging
import sys

# Send all logging to stderr so stdout stays clean for MCP protocol
logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

sys.path.insert(0, "/mnt/workspace/projects/loom/src")

from loom.config.loader import load_agent_config
from loom.mcp.server import build_mcp_server

config = load_agent_config("/mnt/workspace/projects/loom/agents/weft-intel-bridge.yaml")
mcp = build_mcp_server(config)
mcp.run(transport="stdio")
