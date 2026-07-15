#!/usr/bin/env python3
"""Heddle unified stdio launcher for Claude Desktop.

Loads ALL agent configs from agents/ and merges their tools into a
single MCP server. Also registers custom handler agents (daily-ops,
vram-orchestrator, weft-dev) that have Python implementations instead
of HTTP bridges.

Every tool -- HTTP-bridged or custom -- dispatches through the shared
ToolPolicy pipeline (rate limit -> access mode -> escalation ->
validation -> execute -> audit). Custom handler agents load their
policy surface (trust tier, escalation rules, per-tool access, param
schemas) from their YAML configs in agents/, so declarative rules like
vram-orchestrator's large-model-load hold apply on this path too.

Claude Desktop gets every tool through one connection.

Entry point: `heddle-mesh` (registered in pyproject.toml).
"""
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")


def build_mesh(agents_dir: Path | None = None):
    """Build the unified FastMCP mesh server without running it.

    Separated from main() so the mesh construction -- including policy
    wiring for custom handlers -- is testable in-process.
    """
    from fastmcp import FastMCP
    from heddle.config.loader import load_agent_config, discover_configs
    from heddle.mcp.server import _register_http_tool, _register_passthrough_tool
    from heddle.mcp.pipeline import ToolPolicy, guard, schema_for
    from heddle.security.audit import get_audit_logger
    from heddle.security.trust import TrustEnforcer
    from heddle.security.credentials import get_credential_broker
    from heddle.security.validation import InputValidator, RateLimiter
    from heddle.security.escalation import EscalationEngine

    # Project root is three levels up from src/heddle/stdio_mesh.py
    _project_root = Path(__file__).resolve().parent.parent.parent
    AGENTS_DIR = Path(agents_dir) if agents_dir else Path(os.environ.get(
        "HEDDLE_AGENTS_DIR", str(_project_root / "agents")))

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

    # ── Policy factories ────────────────────────────────────────────

    def _enforcement_stack(spec):
        """Build the per-agent enforcement components from a config spec."""
        trust = TrustEnforcer(spec.name, spec.runtime.trust_tier)
        validator = InputValidator(spec.name)
        rate_limiter = RateLimiter(default_rpm=120)
        escalation = EscalationEngine.from_config(
            spec.name,
            [r.model_dump() for r in spec.escalation_rules],
        ) if spec.escalation_rules else None
        return trust, validator, rate_limiter, escalation

    def _config_policies(agent_yaml: str):
        """ToolPolicy factory driven by an agent YAML config.

        Loads trust tier, escalation rules, per-tool access modes, and
        parameter schemas so custom Python handlers get the same
        declarative enforcement as HTTP-bridged tools. Raises if the
        config cannot be loaded.
        """
        spec = load_agent_config(AGENTS_DIR / f"{agent_yaml}.yaml").agent
        trust, validator, rate_limiter, escalation = _enforcement_stack(spec)
        tools = {t.name: t for t in spec.exposes}

        def make(tool_name: str) -> ToolPolicy:
            t = tools.get(tool_name)
            return ToolPolicy(
                agent_name=spec.name, tool_name=tool_name,
                access=getattr(t, "access", "read") if t is not None else "read",
                trust=trust, audit=audit, validator=validator,
                rate_limiter=rate_limiter, escalation=escalation,
                tool_schema=schema_for(t) if t is not None and t.parameters else None,
            )
        return make

    def _default_policies(agent_name: str):
        """Fallback factory for code-only agents with no YAML config.

        Provides audit + rate limiting; declared access is recorded on
        the policy for audit context and future enforcement once the
        agent gains a config.
        """
        rate_limiter = RateLimiter(default_rpm=120)

        def make(tool_name: str, access: str = "read") -> ToolPolicy:
            return ToolPolicy(agent_name=agent_name, tool_name=tool_name,
                              access=access, audit=audit,
                              rate_limiter=rate_limiter)
        return make

    def _policies_or_default(agent_yaml: str):
        try:
            return _config_policies(agent_yaml)
        except Exception as exc:
            logging.warning(
                f"{agent_yaml}: config not loaded ({exc}); using default policy")
            fallback = _default_policies(agent_yaml)
            return lambda tool_name: fallback(tool_name)

    configs = discover_configs(AGENTS_DIR)
    total_tools = 0
    loaded_agents = 0

    # ── Register HTTP bridge agents ─────────────────────────────────

    for config_path in sorted(configs):
        try:
            config = load_agent_config(config_path)
            name = config.agent.name
            if name in EXCLUDE:
                logging.info(f"Skipping: {name}")
                continue

            spec = config.agent
            trust, validator, rate_limiter, escalation = _enforcement_stack(spec)
            bridge_map = {ep.tool_name: ep for ep in spec.http_bridge}

            for tool in spec.exposes:
                endpoint = bridge_map.get(tool.name)
                if endpoint:
                    _register_http_tool(unified, tool, endpoint, spec.name,
                                        trust, audit, broker,
                                        validator, rate_limiter, escalation)
                else:
                    _register_passthrough_tool(unified, tool, spec.name, audit)

            total_tools += len(spec.exposes)
            loaded_agents += 1
            logging.info(f"Loaded {name}: {len(spec.exposes)} tools")

        except Exception as exc:
            logging.error(f"Failed to load {config_path.name}: {exc}")

    # ── Register custom handler agents ──────────────────────────────

    # daily-ops: LLM-powered briefing agent
    try:
        from heddle.agents.daily_ops import daily_briefing, system_health_check, threat_landscape

        _p = _policies_or_default("daily-ops")
        _daily_briefing = guard(_p("daily_briefing"), daily_briefing)
        _system_health_check = guard(_p("system_health_check"), system_health_check)
        _threat_landscape = guard(_p("threat_landscape"), threat_landscape)

        @unified.tool()
        async def daily_briefing_tool() -> str:
            """Generate a comprehensive daily operations briefing covering system health, intelligence trends, and model status. Uses a local LLM to synthesize data from Prometheus, intel-rag, and Ollama."""
            return await _daily_briefing()

        @unified.tool()
        async def system_health_check_tool() -> str:
            """Quick system health check — queries Prometheus for memory, CPU, disk, load, and scrape target status."""
            return await _system_health_check()

        @unified.tool()
        async def threat_landscape_tool() -> str:
            """Get a synthesized view of the current threat landscape from intel-rag, summarized by the local LLM."""
            return await _threat_landscape()

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

        _p = _policies_or_default("vram-orchestrator")
        _vram_status = guard(_p("vram_status"), vram_status)
        _list_all_models = guard(_p("list_all_models"), list_all_models)
        _smart_load = guard(_p("smart_load"), smart_load)
        _smart_generate = guard(_p("smart_generate"), smart_generate)
        _optimize_vram = guard(_p("optimize_vram"), optimize_vram)
        _unload_model = guard(_p("unload_model"), unload_model)
        _model_library = guard(_p("model_library"), model_library)

        @unified.tool()
        async def vram_status_tool() -> str:
            """Get comprehensive GPU VRAM status: utilization, temperature, power, loaded models with VRAM usage, and available capacity. AMD RX 7900 XTX with 24GB VRAM."""
            return await _vram_status()

        @unified.tool()
        async def list_all_models_tool() -> str:
            """List ALL available models across Ollama (7 installed) and the GGUF library (30 models on NVMe). Shows which are currently loaded and their VRAM requirements."""
            return await _list_all_models()

        @unified.tool()
        async def smart_load_tool(model_name: str) -> str:
            """Intelligently load a model by name. Checks VRAM, evicts least-recently-used models if needed, and loads the requested model. E.g. 'qwen3:14b', 'deepseek-r1:14b', 'qwen3.5:9b'."""
            return await _smart_load(model_name)

        @unified.tool()
        async def smart_generate_tool(model_name: str, prompt: str, system: str = "") -> str:
            """Generate text with automatic VRAM management. Ensures the model is loaded (evicting others if VRAM is full), then runs generation. Returns the response and VRAM state."""
            return await _smart_generate(model_name, prompt, system)

        @unified.tool()
        async def optimize_vram_tool() -> str:
            """Analyze current VRAM usage and suggest optimizations. Uses the local LLM to reason about which models should be loaded based on recent usage patterns."""
            return await _optimize_vram()

        @unified.tool()
        async def unload_model_tool(model_name: str) -> str:
            """Unload a specific model from Ollama to free VRAM. Returns freed VRAM amount."""
            return await _unload_model(model_name)

        @unified.tool()
        async def model_library_tool() -> str:
            """Browse the full GGUF model library on the NVMe tier. 30 models, 124GB total. Shows sizes and storage stats."""
            return await _model_library()

        total_tools += 7
        loaded_agents += 1
        logging.info("Loaded vram-orchestrator: 7 tools (custom handlers)")
    except Exception as exc:
        logging.error(f"Failed to load vram-orchestrator: {exc}")

    # weft-dev: build, test, and interactive TUI testing agent
    try:
        from heddle.agents.weft_dev import (
            build, run_tests, git_status, read_file,
            run_tui, send_keys, capture_screen, kill_session, list_sessions,
        )

        # Code-only agent (no YAML yet): default policy with declared access.
        _p = _default_policies("weft-dev")
        _build = guard(_p("build", access="write"), build)
        _run_tests = guard(_p("run_tests", access="write"), run_tests)
        _git_status = guard(_p("git_status", access="read"), git_status)
        _read_file = guard(_p("read_file", access="read"), read_file)
        _run_tui = guard(_p("run_tui", access="write"), run_tui)
        _send_keys = guard(_p("send_keys", access="write"), send_keys)
        _capture_screen = guard(_p("capture_screen", access="read"), capture_screen)
        _kill_session = guard(_p("kill_session", access="write"), kill_session)
        _list_sessions = guard(_p("list_sessions", access="read"), list_sessions)

        @unified.tool()
        async def weft_build(project: str, flags: str = "") -> str:
            """Build a goweft project. project: cas-go | cas | heddle, or absolute path. flags: extra go build flags."""
            return await _build(project, flags)

        @unified.tool()
        async def weft_test(project: str, pattern: str = "./...") -> str:
            """Run Go tests for a project. project: cas-go | cas | heddle. pattern: e.g. './internal/intent/...' or '-run TestDetect ./...'"""
            return await _run_tests(project, pattern)

        @unified.tool()
        async def weft_git_status(project: str) -> str:
            """Get git status for a project: branch, dirty files, last 5 commits. project: cas-go | cas | heddle."""
            return await _git_status(project)

        @unified.tool()
        async def weft_read_file(path: str) -> str:
            """Read a file from the server filesystem. Path may use ~ for home directory."""
            return await _read_file(path)

        @unified.tool()
        async def weft_run_tui(binary: str, session: str, args: str = "") -> str:
            """Spawn a TUI binary in a detached tmux session. binary: path to binary (e.g. ~/projects/cas-go/cas), session: short name, args: extra args (e.g. --memory). Returns initial screen capture."""
            return await _run_tui(binary, session, args)

        @unified.tool()
        async def weft_send_keys(session: str, keys: str) -> str:
            """Send keystrokes to a running tmux session. keys in tmux format: 'hello world' for text, 'Enter' for enter, 'Tab', 'C-c', 'Escape'. Returns screen after keypress."""
            return await _send_keys(session, keys)

        @unified.tool()
        async def weft_capture_screen(session: str) -> str:
            """Capture current terminal contents of a tmux session as text. Shows exactly what is rendered in the TUI."""
            return await _capture_screen(session)

        @unified.tool()
        async def weft_kill_session(session: str) -> str:
            """Kill a tmux session started by weft_run_tui."""
            return await _kill_session(session)

        @unified.tool()
        async def weft_list_sessions() -> str:
            """List all active weft-dev tmux sessions."""
            return await _list_sessions()

        total_tools += 9
        loaded_agents += 1
        logging.info("Loaded weft-dev: 9 tools (custom handlers)")
    except Exception as exc:
        logging.error(f"Failed to load weft-dev: {exc}")

    logging.info(f"Unified MCP server: {total_tools} tools from {loaded_agents} agents")
    return unified


def main():
    unified = build_mesh()
    unified.run(transport="stdio")


if __name__ == "__main__":
    main()
