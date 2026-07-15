"""Adversarial tests for the unified ToolPolicy dispatch pipeline.

These assert the *negatives*: that policy layers fire on every handler
shape (typed HTTP, zero-parameter HTTP, custom mesh handlers) and that
prohibited calls never reach execution. Regression coverage for the
v0.2.0 gaps where the escalation engine was dropped during registration
and zero-parameter tools bypassed the pipeline entirely.
"""
import inspect

import pytest

from heddle.config.schema import (
    AgentConfig, ExposedTool, HttpEndpoint, ParameterDef,
)
from heddle.mcp.pipeline import ToolPolicy, guard, schema_for
from heddle.mcp.server import (
    build_mcp_server, _build_no_params_handler, _build_typed_handler,
)
from heddle.security.escalation import EscalationEngine, EscalationHold
from heddle.security.trust import TrustEnforcer, TrustViolation
from heddle.security.validation import InputValidator, RateLimiter, ValidationError


class AuditStub:
    def __init__(self):
        self.calls = []

    def log_tool_call(self, *args, **kwargs):
        self.calls.append((args, kwargs))


def _counting_executor(results):
    async def executor(params):
        results.append(params)
        return "ok"
    return executor


def _escalation_27b(agent="test-agent"):
    return EscalationEngine.from_config(agent, [{
        "name": "large-model-load",
        "reason": "27b consumes most VRAM",
        "tool": "smart_load",
        "param_contains": {"model_name": "27b"},
    }])


# ── ToolPolicy unit behavior (stub executor, no network) ─────────────

async def test_dispatch_executes_and_audits_success():
    audit = AuditStub()
    ran = []
    policy = ToolPolicy(agent_name="a", tool_name="t", audit=audit)
    result = await policy.dispatch({"x": 1}, _counting_executor(ran))
    assert result == "ok"
    assert ran == [{"x": 1}]
    assert audit.calls[-1][0][3] == "success"


async def test_rate_limit_blocks_before_executor():
    ran = []
    policy = ToolPolicy(
        agent_name="a", tool_name="t",
        rate_limiter=RateLimiter(default_rpm=1),
    )
    await policy.dispatch({}, _counting_executor(ran))
    with pytest.raises(ValidationError):
        await policy.dispatch({}, _counting_executor(ran))
    assert len(ran) == 1  # second call never executed


async def test_access_mode_blocks_t1_write_before_executor():
    ran = []
    policy = ToolPolicy(
        agent_name="a", tool_name="restart_service", access="write",
        trust=TrustEnforcer("a", 1),
    )
    with pytest.raises(TrustViolation):
        await policy.dispatch({}, _counting_executor(ran))
    assert ran == []


async def test_escalation_blocks_before_executor():
    ran = []
    policy = ToolPolicy(
        agent_name="a", tool_name="smart_load", access="write",
        escalation=_escalation_27b("a"),
    )
    with pytest.raises(EscalationHold):
        await policy.dispatch({"model_name": "qwen:27b"}, _counting_executor(ran))
    assert ran == []
    # non-matching value passes through
    assert await policy.dispatch({"model_name": "qwen3:9b"}, _counting_executor(ran)) == "ok"


async def test_strict_validation_blocks_injection_before_executor():
    ran = []
    policy = ToolPolicy(
        agent_name="a", tool_name="read_file",
        validator=InputValidator("a", strict=True),
        tool_schema={"path": {"type": "string", "required": True, "default": None}},
    )
    with pytest.raises(ValidationError):
        await policy.dispatch({"path": "../../etc/passwd"}, _counting_executor(ran))
    assert ran == []


# ── Handler builders: the v0.2.0 bypass regressions ──────────────────

def _tool(name="smart_load", access="write", params=True):
    return ExposedTool(
        name=name, access=access, description="test tool",
        parameters={"model_name": ParameterDef(type="string", required=True)} if params else {},
    )


def _endpoint(name="smart_load"):
    return HttpEndpoint(tool_name=name, method="GET", url="http://127.0.0.1:1/never-reached")


async def test_typed_handler_escalation_fires():
    """Escalation passed into _build_typed_handler holds the call pre-HTTP."""
    handler = _build_typed_handler(
        _tool(), _endpoint(), "test-agent",
        trust=TrustEnforcer("test-agent", 3),
        escalation=_escalation_27b(),
    )
    with pytest.raises(EscalationHold):
        await handler(model_name="qwen:27b")


async def test_zero_param_handler_enforces_access_mode():
    """v0.2.0 bypass: zero-param tools skipped access-mode checks.

    A T1 agent with a zero-parameter write tool over GET would previously
    execute the HTTP call. It must now raise TrustViolation before any
    request is constructed.
    """
    handler = _build_no_params_handler(
        _tool(name="restart_service", access="write", params=False),
        _endpoint("restart_service"), "test-agent",
        trust=TrustEnforcer("test-agent", 1),
    )
    with pytest.raises(TrustViolation):
        await handler()


async def test_zero_param_handler_enforces_escalation():
    """v0.2.0 bypass: zero-param tools skipped escalation rules."""
    engine = EscalationEngine.from_config("test-agent", [{
        "name": "hold-all-loads", "reason": "test",
        "tool": "smart_load", "param_contains": {},
    }])
    handler = _build_no_params_handler(
        _tool(access="read", params=False), _endpoint(), "test-agent",
        trust=TrustEnforcer("test-agent", 3),
        escalation=engine,
    )
    with pytest.raises(EscalationHold):
        await handler()


async def test_zero_param_handler_rate_limited():
    handler = _build_no_params_handler(
        _tool(name="get_alerts", access="read", params=False),
        _endpoint("get_alerts"), "test-agent",
        rate_limiter=RateLimiter(default_rpm=1),
    )
    with pytest.raises(Exception):
        await handler()  # first call reaches HTTP and fails on the dead port
    with pytest.raises(ValidationError):
        await handler()  # second call blocked by rate limit before HTTP


# ── Full stack: config -> build_mcp_server -> FastMCP invocation ─────

ESC_AGENT_YAML = {
    "agent": {
        "name": "esc-agent",
        "version": "1.0.0",
        "description": "Escalation wiring regression agent",
        "model": {"provider": "none"},
        "exposes": [{
            "name": "smart_load",
            "access": "write",
            "description": "load a model",
            "parameters": {"model_name": {"type": "string", "required": True}},
        }],
        "http_bridge": [{
            "tool_name": "smart_load",
            "method": "GET",
            "url": "http://127.0.0.1:1/never-reached",
        }],
        "runtime": {"trust_tier": 3},
        "escalation_rules": [{
            "name": "large-model-load",
            "reason": "27b consumes most VRAM",
            "tool": "smart_load",
            "param_contains": {"model_name": "27b"},
        }],
    }
}


async def test_escalation_enforced_through_build_mcp_server():
    """Regression: v0.2.0 constructed the EscalationEngine in
    build_mcp_server but dropped it in _register_http_tool, so rules
    never executed. The rule must now hold the call end-to-end."""
    config = AgentConfig(**ESC_AGENT_YAML)
    mcp = build_mcp_server(config)
    tool = await mcp.get_tool("smart_load")
    with pytest.raises(EscalationHold):
        await tool.run(arguments={"model_name": "qwen:27b"})


# ── guard(): custom handlers on the same pipeline ────────────────────

async def test_guard_preserves_signature_and_enforces():
    async def smart_load(model_name: str) -> str:
        return f"loaded {model_name}"

    wrapped = guard(
        ToolPolicy(agent_name="vram-orchestrator", tool_name="smart_load",
                   access="write", escalation=_escalation_27b("vram-orchestrator")),
        smart_load,
    )
    assert inspect.signature(wrapped) == inspect.signature(smart_load)
    assert await wrapped("qwen3:9b") == "loaded qwen3:9b"
    with pytest.raises(EscalationHold):
        await wrapped(model_name="qwen:27b")


# ── Mesh end-to-end: the deployed path ───────────────────────────────

VRAM_CONFIG_YAML = """
agent:
  name: vram-orchestrator
  version: "1.0.0"
  description: "VRAM orchestrator policy surface (test copy)"
  model:
    provider: none
  exposes:
    - name: smart_load
      access: write
      description: "load a model"
      parameters:
        model_name: { type: string, required: true }
  runtime:
    trust_tier: 3
  escalation_rules:
    - name: large-model-load
      reason: "27b consumes most VRAM"
      tool: "smart_load"
      param_contains:
        model_name: "27b"
"""

ESC_HTTP_YAML = """
agent:
  name: esc-agent
  version: "1.0.0"
  description: "Escalation wiring regression agent"
  model:
    provider: none
  exposes:
    - name: smart_load
      access: write
      description: "load a model"
      parameters:
        model_name: { type: string, required: true }
  http_bridge:
    - tool_name: smart_load
      method: GET
      url: "http://127.0.0.1:1/never-reached"
  runtime:
    trust_tier: 3
  escalation_rules:
    - name: large-model-load
      reason: "27b consumes most VRAM"
      tool: "smart_load"
      param_contains:
        model_name: "27b"
"""


async def test_mesh_http_agent_escalation_end_to_end(tmp_path):
    """HTTP-bridged agents loaded by the mesh enforce escalation rules."""
    from heddle.stdio_mesh import build_mesh
    (tmp_path / "esc-agent.yaml").write_text(ESC_HTTP_YAML)
    unified = build_mesh(agents_dir=tmp_path)
    tool = await unified.get_tool("smart_load")
    with pytest.raises(EscalationHold):
        await tool.run(arguments={"model_name": "qwen:27b"})


async def test_mesh_custom_smart_load_escalation_end_to_end(tmp_path):
    """The deployed-path regression: vram-orchestrator's large-model-load
    rule must hold smart_load_tool on the stdio mesh — the path Claude
    Desktop actually uses. In v0.2.0 custom handlers bypassed the
    pipeline entirely and this rule could never fire."""
    from heddle.stdio_mesh import build_mesh
    (tmp_path / "vram-orchestrator.yaml").write_text(VRAM_CONFIG_YAML)
    unified = build_mesh(agents_dir=tmp_path)
    tool = await unified.get_tool("smart_load_tool")
    with pytest.raises(EscalationHold):
        await tool.run(arguments={"model_name": "qwen:27b"})
