"""Auto-generate a FastMCP server from an agent's config.

FastMCP 3.x infers tool parameters from the function signature and
docstring.  We dynamically build typed async functions so each tool
gets the correct parameter schema in MCP.
"""

from __future__ import annotations

import json
import logging
import re
import textwrap
from typing import Any, Optional

import httpx
from fastmcp import FastMCP

from loom.config.schema import AgentConfig, ExposedTool, HttpEndpoint

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
    mcp = FastMCP(name=f"loom-{spec.name}")

    bridge_map: dict[str, HttpEndpoint] = {
        ep.tool_name: ep for ep in spec.http_bridge
    }

    for tool in spec.exposes:
        endpoint = bridge_map.get(tool.name)
        if endpoint:
            _register_http_tool(mcp, tool, endpoint, spec.name)
        else:
            _register_passthrough_tool(mcp, tool, spec.name)

    return mcp


def _render_template(template: str, params: dict[str, Any]) -> str:
    """Replace {{param_name}} placeholders."""
    def replacer(match: re.Match) -> str:
        key = match.group(1).strip()
        return str(params.get(key, ""))
    return re.sub(r"\{\{(\w+)\}\}", replacer, template)


def _render_body(template: dict | list | str | Any, params: dict[str, Any]) -> Any:
    """Recursively render {{placeholders}} in a JSON body template."""
    if isinstance(template, str):
        return _render_template(template, params)
    if isinstance(template, dict):
        return {k: _render_body(v, params) for k, v in template.items()}
    if isinstance(template, list):
        return [_render_body(item, params) for item in template]
    return template


async def _execute_http_bridge(
    endpoint: HttpEndpoint, agent_name: str,
    tool_name: str, params: dict[str, Any],
) -> str:
    """Execute an HTTP bridge call."""
    url = _render_template(endpoint.url, params)

    query = {}
    for tool_param, query_key in endpoint.query_params.items():
        if tool_param in params and params[tool_param] is not None:
            query[query_key] = params[tool_param]

    headers = {k: _render_template(v, params) for k, v in endpoint.headers.items()}

    body = None
    if endpoint.body_template is not None:
        body = _render_body(endpoint.body_template, params)

    logger.info("HTTP bridge: %s.%s -> %s %s", agent_name, tool_name, endpoint.method, url)

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.request(
            method=endpoint.method, url=url,
            params=query or None, json=body, headers=headers or None,
        )
        resp.raise_for_status()

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


def _build_typed_handler(tool: ExposedTool, endpoint: HttpEndpoint | None, agent_name: str) -> Any:
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

    doc_lines = [tool.description.strip() if tool.description else f"LOOM tool: {tool.name}"]
    docstring = doc_lines[0].replace("'", "\\'")

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
        async def _dispatch(params: dict[str, Any]) -> str:
            return await _execute_http_bridge(_ep, _an, _tn, params)
    else:
        _an2, _tn2 = agent_name, tool.name
        async def _dispatch(params: dict[str, Any]) -> str:
            return json.dumps({
                "status": "not_implemented", "agent": _an2, "tool": _tn2,
                "message": f"Tool '{_tn2}' has no http_bridge or custom handler.",
                "received_params": params,
            }, indent=2)

    namespace: dict[str, Any] = {"_dispatch": _dispatch, "_execute_http_bridge": _execute_http_bridge, "json": json}
    exec(func_code, namespace)
    return namespace[fn_name]


def _build_no_params_handler(tool: ExposedTool, endpoint: HttpEndpoint | None, agent_name: str) -> Any:
    """Build a handler for tools with zero parameters."""
    if endpoint:
        _ep, _an, _tn = endpoint, agent_name, tool.name
        async def handler() -> str:
            return await _execute_http_bridge(_ep, _an, _tn, {})
    else:
        _an2, _tn2 = agent_name, tool.name
        async def handler() -> str:
            return json.dumps({"status": "not_implemented", "agent": _an2, "tool": _tn2,
                               "message": f"Tool '{_tn2}' has no http_bridge or custom handler."}, indent=2)

    handler.__name__ = tool.name
    handler.__doc__ = tool.description or f"LOOM tool: {tool.name}"
    return handler


def _register_http_tool(mcp: FastMCP, tool: ExposedTool, endpoint: HttpEndpoint, agent_name: str) -> None:
    if tool.parameters:
        handler = _build_typed_handler(tool, endpoint, agent_name)
    else:
        handler = _build_no_params_handler(tool, endpoint, agent_name)
    mcp.add_tool(handler)
    logger.info(f"Registered HTTP-bridged tool: {tool.name} -> {endpoint.method} {endpoint.url}")


def _register_passthrough_tool(mcp: FastMCP, tool: ExposedTool, agent_name: str) -> None:
    if tool.parameters:
        handler = _build_typed_handler(tool, None, agent_name)
    else:
        handler = _build_no_params_handler(tool, None, agent_name)
    mcp.add_tool(handler)
    logger.info(f"Registered stub tool: {tool.name} (no http_bridge)")
