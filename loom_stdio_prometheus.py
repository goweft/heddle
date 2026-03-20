#!/usr/bin/env python3
"""LOOM stdio launcher for Claude Desktop — Prometheus bridge."""
import logging, sys
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
sys.path.insert(0, "/mnt/workspace/projects/loom/src")
from loom.config.loader import load_agent_config
from loom.mcp.server import build_mcp_server
config = load_agent_config("/mnt/workspace/projects/loom/agents/prometheus-bridge.yaml")
mcp = build_mcp_server(config)
mcp.run(transport="stdio")
