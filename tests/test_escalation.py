"""Tests for escalation rules — conditional hold-for-review."""
import pytest

from heddle.security.escalation import EscalationEngine, EscalationRule, EscalationHold


@pytest.fixture(autouse=True)
def _reset_singletons():
    import heddle.security.audit as mod
    mod._global_audit = None
    yield
    mod._global_audit = None


# ── Rule Matching ────────────────────────────────────────────────────

def test_rule_matches_tool_pattern():
    rule = EscalationRule(name="r1", reason="blocked", tool="delete_*")
    assert rule.matches("delete_user", {}) is not None
    assert rule.matches("get_user", {}) is None


def test_rule_matches_param_gt():
    rule = EscalationRule(name="r1", reason="over budget", tool="purchase", param_gt={"amount": 2000})
    assert rule.matches("purchase", {"amount": 5000}) is not None
    assert rule.matches("purchase", {"amount": 500}) is None


def test_rule_matches_param_eq():
    rule = EscalationRule(name="r1", reason="prod target", tool="deploy", param_eq={"env": "production"})
    assert rule.matches("deploy", {"env": "production"}) is not None
    assert rule.matches("deploy", {"env": "staging"}) is None


def test_rule_matches_param_contains():
    rule = EscalationRule(name="r1", reason="large model", param_contains={"model": "27b"})
    assert rule.matches("load", {"model": "qwen3.5:27b"}) is not None
    assert rule.matches("load", {"model": "qwen3:14b"}) is None


def test_rule_matches_access_mode():
    rule = EscalationRule(name="r1", reason="write op", access="write")
    assert rule.matches("any_tool", {}, tool_access="write") is not None
    assert rule.matches("any_tool", {}, tool_access="read") is None


def test_rule_no_match_wrong_tool():
    rule = EscalationRule(name="r1", reason="x", tool="delete_*", param_gt={"count": 10})
    # Right tool, under threshold
    assert rule.matches("delete_items", {"count": 5}) is None
    # Wrong tool, over threshold
    assert rule.matches("get_items", {"count": 50}) is None


def test_rule_combined_tool_and_param():
    rule = EscalationRule(name="r1", reason="big delete", tool="delete_*", param_gt={"count": 100})
    # Right tool + over threshold
    assert rule.matches("delete_records", {"count": 500}) is not None
    # Right tool + under threshold
    assert rule.matches("delete_records", {"count": 50}) is None


def test_rule_param_eq_case_insensitive():
    rule = EscalationRule(name="r1", reason="x", param_eq={"env": "production"})
    assert rule.matches("deploy", {"env": "PRODUCTION"}) is not None


# ── Engine ───────────────────────────────────────────────────────────

def test_engine_holds_on_match():
    engine = EscalationEngine("test-agent", [
        EscalationRule(name="big-purchase", reason="over budget", tool="purchase", param_gt={"amount": 2000}),
    ])
    with pytest.raises(EscalationHold, match="over budget"):
        engine.check("purchase", {"amount": 5000})


def test_engine_passes_no_match():
    engine = EscalationEngine("test-agent", [
        EscalationRule(name="big-purchase", reason="over budget", tool="purchase", param_gt={"amount": 2000}),
    ])
    engine.check("purchase", {"amount": 500})  # should not raise


def test_engine_multiple_rules_first_match_wins():
    engine = EscalationEngine("test-agent", [
        EscalationRule(name="rule1", reason="reason1", tool="deploy", param_eq={"env": "production"}),
        EscalationRule(name="rule2", reason="reason2", tool="deploy"),
    ])
    with pytest.raises(EscalationHold, match="reason1"):
        engine.check("deploy", {"env": "production"})


def test_engine_empty_rules_passes():
    engine = EscalationEngine("test-agent", [])
    engine.check("anything", {"any": "param"})  # should not raise


def test_engine_from_config():
    rules_data = [
        {"name": "r1", "reason": "test", "tool": "delete_*"},
        {"name": "r2", "reason": "test2", "param_gt": {"amount": 1000}},
    ]
    engine = EscalationEngine.from_config("test-agent", rules_data)
    assert len(engine.rules) == 2
    assert engine.rules[0].name == "r1"


def test_engine_list_rules():
    engine = EscalationEngine("test-agent", [
        EscalationRule(name="r1", reason="x", tool="delete_*"),
    ])
    rules = engine.list_rules()
    assert len(rules) == 1
    assert rules[0]["name"] == "r1"
    assert rules[0]["tool"] == "delete_*"


# ── Schema Integration ───────────────────────────────────────────────

def test_config_with_escalation_rules():
    import yaml
    from heddle.config.loader import validate_config
    raw = yaml.safe_load("""
agent:
  name: test-agent
  version: "1.0.0"
  exposes:
    - name: purchase
      access: write
      description: "Buy something"
      parameters:
        amount: { type: integer, required: true }
  runtime:
    trust_tier: 2
  triggers:
    - type: on_demand
  escalation_rules:
    - name: big-purchase
      reason: "Purchases over 2000 require approval"
      tool: "purchase"
      param_gt:
        amount: 2000
""")
    config = validate_config(raw, source="<test>")
    assert len(config.agent.escalation_rules) == 1
    assert config.agent.escalation_rules[0].name == "big-purchase"
    assert config.agent.escalation_rules[0].param_gt == {"amount": 2000.0}


def test_config_without_escalation_rules():
    import yaml
    from heddle.config.loader import validate_config
    raw = yaml.safe_load("""
agent:
  name: simple-agent
  version: "1.0.0"
  exposes:
    - name: get_data
      description: "Read data"
  runtime:
    trust_tier: 1
  triggers:
    - type: on_demand
""")
    config = validate_config(raw, source="<test>")
    assert config.agent.escalation_rules == []


def test_real_vram_orchestrator_config():
    """Validate the actual vram-orchestrator config with escalation rules."""
    from heddle.config.loader import load_agent_config
    config = load_agent_config("agents/vram-orchestrator.yaml")
    assert len(config.agent.escalation_rules) == 3
    rule_names = [r.name for r in config.agent.escalation_rules]
    assert "large-model-load" in rule_names
    assert "bulk-unload-protection" in rule_names
    assert "generate-with-large-model" in rule_names
