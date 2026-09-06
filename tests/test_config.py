"""Tests for Heddle config schema and loader."""
import tempfile
from pathlib import Path
import pytest
import yaml
from heddle.config.schema import AgentConfig, AgentSpec, ModelProvider, TrustTier
from heddle.config.loader import load_agent_config, validate_config, ConfigError

MINIMAL_CONFIG = {"agent": {"name": "test-agent", "version": "1.0.0", "description": "A test agent"}}

FULL_CONFIG = {
    "agent": {
        "name": "intel-bridge", "version": "2.0.0", "description": "Wraps intel-rag",
        "model": {"provider": "none"},
        "exposes": [
            {"name": "ask_intel", "description": "Ask a question",
             "parameters": {"question": {"type": "string", "description": "The question", "required": True}},
             "returns": {"type": "string"}},
            {"name": "get_trending", "description": "Get trending entities",
             "parameters": {"hours": {"type": "integer", "required": False, "default": 24}}},
        ],
        "http_bridge": [
            {"tool_name": "ask_intel", "method": "POST", "url": "http://localhost:9090/api/query",
             "body_template": {"question": "{{question}}"}},
            {"tool_name": "get_trending", "method": "GET", "url": "http://localhost:9090/api/trending",
             "query_params": {"hours": "hours"}},
        ],
        "runtime": {"sandbox": "none", "trust_tier": 1},
        "triggers": [{"type": "on_demand"}],
    }
}

def test_minimal_config():
    cfg = AgentConfig.model_validate(MINIMAL_CONFIG)
    assert cfg.agent.name == "test-agent"
    assert cfg.agent.model.provider == ModelProvider.none
    assert cfg.agent.runtime.trust_tier == TrustTier.worker

def test_full_config():
    cfg = AgentConfig.model_validate(FULL_CONFIG)
    assert cfg.agent.name == "intel-bridge"
    assert len(cfg.agent.exposes) == 2
    assert len(cfg.agent.http_bridge) == 2
    assert cfg.agent.runtime.trust_tier == TrustTier.observer

def test_invalid_agent_name():
    with pytest.raises(Exception):
        AgentConfig.model_validate({"agent": {"name": "has spaces!!"}})

def test_tool_name_validation():
    with pytest.raises(Exception):
        AgentConfig.model_validate({"agent": {"name": "ok", "exposes": [{"name": "bad name!"}]}})

def test_load_from_file():
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        yaml.dump(MINIMAL_CONFIG, f)
        f.flush()
        cfg = load_agent_config(f.name)
        assert cfg.agent.name == "test-agent"

def test_load_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_agent_config("/nonexistent/path.yaml")

def test_load_bad_extension():
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write("agent:\n  name: test\n")
        f.flush()
        with pytest.raises(ConfigError, match=".yaml"):
            load_agent_config(f.name)

def test_validate_config():
    cfg = validate_config(FULL_CONFIG)
    assert cfg.agent.name == "intel-bridge"

def test_validate_bad_bridge_ref():
    bad = {"agent": {"name": "test", "exposes": [{"name": "tool_a", "description": "A tool"}],
                     "http_bridge": [{"tool_name": "nonexistent_tool", "method": "GET", "url": "http://x"}]}}
    with pytest.raises(ConfigError, match="nonexistent_tool"):
        validate_config(bad)

def test_http_bridge_body_template():
    cfg = AgentConfig.model_validate(FULL_CONFIG)
    bridge = cfg.agent.http_bridge[0]
    assert bridge.body_template == {"question": "{{question}}"}

def test_http_bridge_query_params():
    cfg = AgentConfig.model_validate(FULL_CONFIG)
    bridge = cfg.agent.http_bridge[1]
    assert bridge.query_params == {"hours": "hours"}


# -- Unknown keys are errors, not silent no-ops -----------------------------

from pydantic import ValidationError


def _spec(**overrides):
    base = {"name": "strict-agent", "version": "1.0.0", "description": "x"}
    base.update(overrides)
    return {"agent": base}


def test_unknown_top_level_agent_key_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentConfig(**_spec(identity={"role": "worker"}))


def test_misspelled_escalation_rules_rejected():
    # Historically this would validate and the agent would run with NO
    # escalation rules -- the exact "claimed control not wired" gap.
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentConfig(**_spec(escalation_rule=[{"name": "r", "reason": "x", "tool": "t"}]))


def test_misspelled_trust_tier_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentConfig(**_spec(runtime={"trust_teir": 1}))


def test_unknown_key_in_exposed_tool_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentConfig(**_spec(exposes=[{"name": "t", "description": "d", "acess": "read"}]))


def test_unknown_key_in_http_bridge_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentConfig(**_spec(
            exposes=[{"name": "t", "description": "d"}],
            http_bridge=[{"tool_name": "t", "method": "GET", "url": "http://x", "headerz": {}}],
        ))


def test_unknown_key_in_escalation_rule_rejected():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentConfig(**_spec(escalation_rules=[
            {"name": "r", "reason": "x", "tool": "t", "param_contain": {"m": "27b"}}]))
