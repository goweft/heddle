"""Auto-generate a FastMCP server from an agent's config.

FastMCP 3.x infers tool parameters from the function signature and
docstring. We dynamically build typed async functions so each tool
gets the correct parameter schema in MCP.

Phase 3 integrations:
- Audit logging on every tool call and HTTP bridge request
- Trust tier enforcement before HTTP execution
- Credential broker resolution for {{secret:key}} templates
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

import httpx
from fastmcp import FastMCP

from heddle.config.schema import AgentConfig, ExposedTool, HttpEndpoint
from heddle.security.audit import get_audit_logger
from heddle.security.trust import TrustEnforcer, TrustViolation
from heddle.security.credentials import get_credential_broker
from heddle.security.validation import InputValidator, RateLimiter
from heddle.security.escalation import EscalationEngine, EscalationHold

logger = logging.getLogger(__name__)

_TYPE_MAP = {
    "string": "str", "str": "str",
    "integer": "int", "int": "int",
    "number": "float", "float": "float",
    "boolean": "bool", "bool": "bool",
    "array": "list", "object": "dict",
}


def build_mcp_server(config: AgentConfig) -> FastMCP:
    """Build a FastMCP server from an AgentConfig."""
    spec = config.agent
    mcp = FastMCP(name=f"heddle-{spec.name}")

    # Initialize security components
    trust = TrustEnforcer(spec.name, spec.runtime.trust_tier)
    audit = get_audit_logger()
    broker = get_credential_broker()
    validator = InputValidator(spec.name)
    rate_limiter = RateLimiter(default_rpm=120)
    escalation = EscalationEngine.from_config(
        spec.name,
        [r.model_dump() for r in spec.escalation_rules],
    ) if spec.escalation_rules else None

    audit.log_agent_lifecycle(spec.name, "build", f"Building MCP server with {len(spec.exposes)} tools")

    bridge_map: dict[str, HttpEndpoint] = {
        ep.tool_name: ep for ep in spec.http_bridge
    }

    for tool in spec.exposes:
        endpoint = bridge_map.get(tool.name)
        if endpoint:
            _register_http_tool(mcp, tool, endpoint, spec.name, trust, audit, broker, validator, rate_limiter, escalation)
        else:
            _register_passthrough_tool(mcp, tool, spec.name, audit)

    return mcp


# ── Template rendering ───────────────────────────────────────────────

def _render_template(template: str, params: dict[str, Any]) -> str:
    """Replace {{param_name}} placeholders (NOT {{secret:...}})."""
    def replacer(match: re.Match) -> str:
        key = match.group(1).strip()
        if key.startswith("secret:"):
            return match.group(0)  # leave for credential broker
        return str(params.get(key, ""))
    return re.sub(r"\{\{(\S+?)\}\}", replacer, template)


def _render_body(template: dict | list | str | Any, params: dict[str, Any]) -> Any:
    """Recursively render {{placeholders}} in a JSON body template."""
    if isinstance(template, str):
        return _render_template(template, params)
    if isinstance(template, dict):
        return {k: _render_body(v, params) for k, v in template.items()}
    if isinstance(template, list):
        return [_render_body(item, params) for item in template]
    return template


# ── Core HTTP bridge with security ───────────────────────────────────

async def _execute_http_bridge(
    endpoint: HttpEndpoint, agent_name: str, tool_name: str,
    params: dict[str, Any],
    trust: TrustEnforcer, audit, broker,
) -> str:
    """Execute an HTTP bridge call with trust + audit + credentials."""
    start = time.monotonic()
    url = _render_template(endpoint.url, params)

    # 1. TRUST: check HTTP method is allowed for this tier
    try:
        trust.check_http_method(endpoint.method, url)
    except TrustViolation as exc:
        audit.log_tool_call(
            agent_name, tool_name, parameters=params,
            result_status="trust_violation", error=str(exc),
        )
        raise

    # 2. Build request components
    query = {}
    for tool_param, query_key in endpoint.query_params.items():
        if tool_param in params and params[tool_param] is not None:
            query[query_key] = params[tool_param]

    headers = {k: _render_template(v, params) for k, v in endpoint.headers.items()}

    # 3. CREDENTIALS: resolve {{secret:key}} in headers and URL
    headers = broker.resolve_headers(agent_name, headers)
    url = broker.resolve_template(agent_name, url)

    body = None
    if endpoint.body_template is not None:
        body = _render_body(endpoint.body_template, params)

    # 4. Execute HTTP call
    status_code = None
    error_msg = None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.request(
                method=endpoint.method, url=url,
                params=query or None, json=body, headers=headers or None,
            )
            status_code = resp.status_code
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        error_msg = f"{exc.response.status_code} {exc.response.reason_phrase}"
        duration = (time.monotonic() - start) * 1000
        audit.log_http_bridge(
            agent_name, tool_name, endpoint.method, url,
            status_code=exc.response.status_code,
            duration_ms=duration, error=error_msg,
        )
        raise
    except Exception as exc:
        error_msg = str(exc)
        duration = (time.monotonic() - start) * 1000
        audit.log_http_bridge(
            agent_name, tool_name, endpoint.method, url,
            duration_ms=duration, error=error_msg,
        )
        raise

    duration = (time.monotonic() - start) * 1000

    # 5. AUDIT: log successful bridge call
    audit.log_http_bridge(
        agent_name, tool_name, endpoint.method, url,
        status_code=status_code, duration_ms=duration,
    )

    # 6. Parse response
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        return resp.text

    if endpoint.response_path:
        for key in endpoint.response_path.split("."):
            if isinstance(data, dict):
                data = data.get(key, data)
            else:
                break

    if isinstance(data, str):
        return data
    return json.dumps(data, indent=2, default=str)


# ── Dynamic function builders ────────────────────────────────────────

def _build_typed_handler(
    tool: ExposedTool, endpoint: HttpEndpoint | None, agent_name: str,
    trust: TrustEnforcer | None = None, audit=None, broker=None,
    validator: InputValidator | None = None, rate_limiter: RateLimiter | None = None,
    escalation: EscalationEngine | None = None,
) -> Any:
    """Dynamically create an async function with a typed signature."""
    sig_parts: list[str] = []
    for pname, pdef in tool.parameters.items():
        py_type = _TYPE_MAP.get(pdef.type, "str")
        if not pdef.required or pdef.default is not None:
            default = repr(pdef.default) if pdef.default is not None else "None"
            sig_parts.append(f"{pname}: {py_type} | None = {default}")
        else:
            sig_parts.append(f"{pname}: {py_type}")

    sig = ", ".join(sig_parts)
    fn_name = tool.name
    docstring = (tool.description.strip() if tool.description else f"Heddle tool: {tool.name}").replace("'", "\\'")

    collect_lines = []
    for pname in tool.parameters:
        collect_lines.append(f"    _params['{pname}'] = {pname}")
    collect_block = "\n".join(collect_lines) if collect_lines else "    pass"

    func_code = f"""\
async def {fn_name}({sig}) -> str:
    '''{docstring}'''
    _params = {{}}
{collect_block}
    return await _dispatch(_params)
"""

    if endpoint:
        _ep, _an, _tn = endpoint, agent_name, tool.name
        _trust, _audit, _broker = trust, audit, broker
        _validator, _rate_limiter = validator, rate_limiter
        _access = getattr(tool, 'access', 'read')
        _escalation = escalation
        _tool_schema = {pn: {"type": pd.type, "required": pd.required, "default": pd.default}
                        for pn, pd in tool.parameters.items()}

        async def _dispatch(params: dict[str, Any]) -> str:
            start = time.monotonic()
            try:
                if _rate_limiter:
                    _rate_limiter.check(_an, _tn)
                if _trust and _access:
                    _trust.check_access_mode(_tn, _access)
                if _escalation:
                    _escalation.check(_tn, params, _access)
                if _validator and _tool_schema:
                    params = _validator.validate_params(_tn, params, _tool_schema)
                result = await _execute_http_bridge(_ep, _an, _tn, params, _trust, _audit, _broker)
                duration = (time.monotonic() - start) * 1000
                if _audit:
                    _audit.log_tool_call(_an, _tn, params, "success", duration_ms=duration)
                return result
            except Exception as exc:
                duration = (time.monotonic() - start) * 1000
                if _audit:
                    _audit.log_tool_call(_an, _tn, params, "error", error=str(exc), duration_ms=duration)
                raise
    else:
        _an2, _tn2, _audit2 = agent_name, tool.name, audit

        async def _dispatch(params: dict[str, Any]) -> str:
            if _audit2:
                _audit2.log_tool_call(_an2, _tn2, params, "stub")
            return json.dumps({
                "status": "not_implemented", "agent": _an2, "tool": _tn2,
                "message": f"Tool '{_tn2}' has no http_bridge or custom handler.",
                "received_params": params,
            }, indent=2)

    namespace: dict[str, Any] = {"_dispatch": _dispatch, "json": json, "time": time}
    exec(func_code, namespace)
    return namespace[fn_name]


def _build_no_params_handler(
    tool: ExposedTool, endpoint: HttpEndpoint | None, agent_name: str,
    trust: TrustEnforcer | None = None, audit=None, broker=None,
    validator: InputValidator | None = None, rate_limiter: RateLimiter | None = None,
) -> Any:
    """Build a handler for tools with zero parameters."""
    if endpoint:
        _ep, _an, _tn = endpoint, agent_name, tool.name
        _trust, _audit, _broker = trust, audit, broker

        async def handler() -> str:
            start = time.monotonic()
            try:
                result = await _execute_http_bridge(_ep, _an, _tn, {}, _trust, _audit, _broker)
                duration = (time.monotonic() - start) * 1000
                if _audit:
                    _audit.log_tool_call(_an, _tn, {}, "success", duration_ms=duration)
                return result
            except Exception as exc:
                duration = (time.monotonic() - start) * 1000
                if _audit:
                    _audit.log_tool_call(_an, _tn, {}, "error", error=str(exc), duration_ms=duration)
                raise
    else:
        _an2, _tn2, _audit2 = agent_name, tool.name, audit

        async def handler() -> str:
            if _audit2:
                _audit2.log_tool_call(_an2, _tn2, {}, "stub")
            return json.dumps({"status": "not_implemented", "agent": _an2, "tool": _tn2,
                               "message": f"Tool '{_tn2}' has no http_bridge or custom handler."}, indent=2)

    handler.__name__ = tool.name
    handler.__doc__ = tool.description or f"Heddle tool: {tool.name}"
    return handler


# ── Registration ─────────────────────────────────────────────────────

def _register_http_tool(mcp, tool, endpoint, agent_name, trust, audit, broker, validator=None, rate_limiter=None, escalation=None):
    if tool.parameters:
        handler = _build_typed_handler(tool, endpoint, agent_name, trust, audit, broker, validator, rate_limiter)
    else:
        handler = _build_no_params_handler(tool, endpoint, agent_name, trust, audit, broker, validator, rate_limiter)
    mcp.add_tool(handler)
    logger.info(f"Registered HTTP-bridged tool: {tool.name} -> {endpoint.method} {endpoint.url}")


def _register_passthrough_tool(mcp, tool, agent_name, audit):
    if tool.parameters:
        handler = _build_typed_handler(tool, None, agent_name, audit=audit)
    else:
        handler = _build_no_params_handler(tool, None, agent_name, audit=audit)
    mcp.add_tool(handler)
    logger.info(f"Registered stub tool: {tool.name} (no http_bridge)")
