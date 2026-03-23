#!/usr/bin/env python3
"""Heddle unified stdio launcher for Claude Desktop.

Loads ALL agent configs from agents/ and merges their tools into a
single MCP server. Also registers custom handler agents (daily-ops,
vram-orchestrator) that have Python implementations instead of HTTP bridges.

Claude Desktop gets every tool through one connection.
"""
import logging
import sys
from pathlib import Path

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from fastmcp import FastMCP
from heddle.config.loader import load_agent_config, discover_configs
from heddle.mcp.server import _register_http_tool, _register_passthrough_tool
from heddle.security.audit import get_audit_logger
from heddle.security.trust import TrustEnforcer
from heddle.security.credentials import get_credential_broker

AGENTS_DIR = Path(__file__).resolve().parent / "agents"

# Agents to exclude from HTTP bridge loading (custom handlers registered below)
EXCLUDE = {
    "uptime-kuma-bridge",   # WebSocket API, not REST
    "gitea-bridge",         # Wrong URLs, superseded by gitea-api-bridge
    "daily-ops",            # Custom handlers below
    "vram-orchestrator",    # Custom handlers below
}

unified = FastMCP(name="heddle-mesh")
audit = get_audit_logger()
broker = get_credential_broker()

configs = discover_configs(AGENTS_DIR)
total_tools = 0
loaded_agents = 0

# ── Register HTTP bridge agents ─────────────────────────────────────

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

# ── Register custom handler agents ──────────────────────────────────

# daily-ops: LLM-powered briefing agent
try:
    from heddle.agents.daily_ops import daily_briefing, system_health_check, threat_landscape

    @unified.tool()
    async def daily_briefing_tool() -> str:
        """Generate a comprehensive daily operations briefing covering system health, intelligence trends, and model status. Uses a local LLM to synthesize data from Prometheus, intel-rag, and Ollama."""
        return await daily_briefing()

    @unified.tool()
    async def system_health_check_tool() -> str:
        """Quick system health check — queries Prometheus for memory, CPU, disk, load, and scrape target status."""
        return await system_health_check()

    @unified.tool()
    async def threat_landscape_tool() -> str:
        """Get a synthesized view of the current threat landscape from intel-rag, summarized by the local LLM."""
        return await threat_landscape()

    total_tools += 3
    loaded_agents += 1
    logging.info("Loaded daily-ops: 3 tools (custom handlers)")
except Exception as exc:
    logging.error(f"Failed to load daily-ops: {exc}")

# vram-orchestrator: GPU VRAM management agent
try:
    from heddle.agents.vram_orchestrator import (
        vram_status, list_all_models, smart_load, smart_generate,
        optimize_vram, unload_model, model_library,
    )

    @unified.tool()
    async def vram_status_tool() -> str:
        """Get comprehensive GPU VRAM status: utilization, temperature, power, loaded models with VRAM usage, and available capacity. AMD RX 7900 XTX with 24GB VRAM."""
        return await vram_status()

    @unified.tool()
    async def list_all_models_tool() -> str:
        """List ALL available models across Ollama (7 installed) and the GGUF library (30 models on NVMe). Shows which are currently loaded and their VRAM requirements."""
        return await list_all_models()

    @unified.tool()
    async def smart_load_tool(model_name: str) -> str:
        """Intelligently load a model by name. Checks VRAM, evicts least-recently-used models if needed, and loads the requested model. E.g. 'qwen3:14b', 'deepseek-r1:14b', 'qwen3.5:9b'."""
        return await smart_load(model_name)

    @unified.tool()
    async def smart_generate_tool(model_name: str, prompt: str, system: str = "") -> str:
        """Generate text with automatic VRAM management. Ensures the model is loaded (evicting others if VRAM is full), then runs generation. Returns the response and VRAM state."""
        return await smart_generate(model_name, prompt, system)

    @unified.tool()
    async def optimize_vram_tool() -> str:
        """Analyze current VRAM usage and suggest optimizations. Uses the local LLM to reason about which models should be loaded based on recent usage patterns."""
        return await optimize_vram()

    @unified.tool()
    async def unload_model_tool(model_name: str) -> str:
        """Unload a specific model from Ollama to free VRAM. Returns freed VRAM amount."""
        return await unload_model(model_name)

    @unified.tool()
    async def model_library_tool() -> str:
        """Browse the full GGUF model library on the NVMe tier. 30 models, 124GB total. Shows sizes and storage stats."""
        return await model_library()

    total_tools += 7
    loaded_agents += 1
    logging.info("Loaded vram-orchestrator: 7 tools (custom handlers)")
except Exception as exc:
    logging.error(f"Failed to load vram-orchestrator: {exc}")

logging.info(f"Unified MCP server: {total_tools} tools from {loaded_agents} agents")
unified.run(transport="stdio")
