"""Tests for LOOM agent generator."""
import pytest
import yaml

from loom.generator.agent_gen import _extract_yaml, _build_prompt, SYSTEM_PROMPT, SCHEMA_REF
from loom.config.loader import validate_config


# ── YAML extraction tests ────────────────────────────────────────────

def test_extract_yaml_clean():
    raw = "agent:\n  name: test-agent\n  version: '1.0.0'"
    assert _extract_yaml(raw).startswith("agent:")

def test_extract_yaml_with_fences():
    raw = "```yaml\nagent:\n  name: test-agent\n```"
    result = _extract_yaml(raw)
    assert result.startswith("agent:")
    assert "```" not in result

def test_extract_yaml_with_preamble():
    raw = "Here is the config:\n\nagent:\n  name: test-agent\n  version: '1.0.0'"
    assert _extract_yaml(raw).startswith("agent:")

def test_extract_yaml_with_think_tags():
    raw = "<think>Let me think about this...</think>\nagent:\n  name: test-agent"
    result = _extract_yaml(raw)
    assert "<think>" not in result
    assert result.startswith("agent:")


# ── Prompt building tests ────────────────────────────────────────────

def test_build_prompt_basic():
    prompt = _build_prompt("a weather API bridge")
    assert "a weather API bridge" in prompt
    assert "YAML SCHEMA" in prompt
    assert "EXAMPLE" in prompt

def test_build_prompt_with_context():
    prompt = _build_prompt("wrap this API", context="API at localhost:8080 with /health and /status")
    assert "localhost:8080" in prompt
    assert "ADDITIONAL CONTEXT" in prompt

def test_system_prompt_exists():
    assert "LOOM Agent Generator" in SYSTEM_PROMPT
    assert "YAML" in SYSTEM_PROMPT


# ── Validation of hand-crafted "generated" configs ───────────────────

def test_validate_minimal_generated():
    """A minimal but valid generated config should pass validation."""
    yaml_text = """\
agent:
  name: weather-bridge
  version: "1.0.0"
  description: "Bridge to a weather API"
  model:
    provider: none
  exposes:
    - name: get_weather
      description: "Get current weather for a city"
      parameters:
        city:
          type: string
          description: "City name"
          required: true
      returns:
        type: string
        description: "JSON weather data"
  http_bridge:
    - tool_name: get_weather
      method: GET
      url: "http://localhost:5000/weather/{{city}}"
  runtime:
    sandbox: none
    trust_tier: 1
  triggers:
    - type: on_demand
"""
    parsed = yaml.safe_load(yaml_text)
    config = validate_config(parsed, source="<test>")
    assert config.agent.name == "weather-bridge"
    assert len(config.agent.exposes) == 1
    assert len(config.agent.http_bridge) == 1
    assert config.agent.http_bridge[0].tool_name == "get_weather"


def test_validate_multi_tool_generated():
    """A generated config with multiple tools and bridge entries."""
    yaml_text = """\
agent:
  name: uptime-kuma-bridge
  version: "1.0.0"
  description: "Bridge to Uptime Kuma monitoring"
  model:
    provider: none
  exposes:
    - name: get_monitors
      description: "List all monitors"
      returns:
        type: string
        description: "JSON array of monitors"
    - name: get_heartbeats
      description: "Get heartbeat data for a monitor"
      parameters:
        monitor_id:
          type: integer
          description: "Monitor ID"
          required: true
      returns:
        type: string
        description: "JSON heartbeat data"
  http_bridge:
    - tool_name: get_monitors
      method: GET
      url: "http://localhost:3001/api/monitors"
    - tool_name: get_heartbeats
      method: GET
      url: "http://localhost:3001/api/monitor/{{monitor_id}}/heartbeats"
  runtime:
    sandbox: none
    trust_tier: 1
  triggers:
    - type: on_demand
"""
    parsed = yaml.safe_load(yaml_text)
    config = validate_config(parsed, source="<test>")
    assert config.agent.name == "uptime-kuma-bridge"
    assert len(config.agent.exposes) == 2
    assert len(config.agent.http_bridge) == 2
