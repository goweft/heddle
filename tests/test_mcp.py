"""Tests for LOOM MCP server generation."""
import pytest
from loom.config.schema import AgentConfig
from loom.mcp.server import build_mcp_server, _render_template, _render_body

def test_render_simple_template():
    assert _render_template("http://localhost/api/{{name}}", {"name": "test"}) == "http://localhost/api/test"

def test_render_template_multiple():
    result = _render_template("{{host}}:{{port}}/{{path}}", {"host": "localhost", "port": "9090", "path": "api/query"})
    assert result == "localhost:9090/api/query"

def test_render_template_missing_key():
    assert _render_template("{{missing}}/api", {}) == "/api"

def test_render_body_nested():
    template = {"query": "{{question}}", "options": {"model": "{{model}}", "temp": 0.3}, "tags": ["{{tag}}", "fixed"]}
    result = _render_body(template, {"question": "What happened?", "model": "mistral", "tag": "news"})
    assert result == {"query": "What happened?", "options": {"model": "mistral", "temp": 0.3}, "tags": ["news", "fixed"]}

BRIDGE_CONFIG = {
    "agent": {
        "name": "test-bridge", "version": "1.0.0",
        "exposes": [
            {"name": "get_data", "description": "Fetch data",
             "parameters": {"query": {"type": "string", "required": True}}, "returns": {"type": "string"}},
            {"name": "stub_tool", "description": "No bridge for this one"},
        ],
        "http_bridge": [
            {"tool_name": "get_data", "method": "GET", "url": "http://localhost:9090/api/search",
             "query_params": {"query": "q"}},
        ],
    }
}

def test_build_mcp_server():
    config = AgentConfig.model_validate(BRIDGE_CONFIG)
    mcp = build_mcp_server(config)
    assert mcp.name == "loom-test-bridge"

def test_build_mcp_server_minimal():
    config = AgentConfig.model_validate({"agent": {"name": "empty", "version": "1.0.0"}})
    mcp = build_mcp_server(config)
    assert mcp.name == "loom-empty"
