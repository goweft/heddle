"""Tests for Heddle security: audit, trust, credentials."""
import json
import pytest
from pathlib import Path

from heddle.security.audit import AuditLogger
from heddle.security.trust import TrustEnforcer, TrustViolation
from heddle.security.credentials import CredentialBroker, CredentialDenied


# ── Audit Logger ─────────────────────────────────────────────────────

@pytest.fixture
def audit(tmp_path):
    return AuditLogger(log_dir=tmp_path / "audit")


def test_audit_log_tool_call(audit):
    audit.log_tool_call("test-agent", "get_stats", {"foo": "bar"}, "success", duration_ms=42.5)
    entries = audit.recent(10)
    assert len(entries) == 1
    assert entries[0]["event"] == "tool_call"
    assert entries[0]["agent"] == "test-agent"
    assert entries[0]["tool"] == "get_stats"
    assert entries[0]["duration_ms"] == 42.5


def test_audit_log_http_bridge(audit):
    audit.log_http_bridge("agent-x", "fetch", "GET", "http://localhost/api", status_code=200, duration_ms=15.0)
    entries = audit.recent(10)
    assert entries[0]["event"] == "http_bridge"
    assert entries[0]["status_code"] == 200


def test_audit_log_trust_violation(audit):
    audit.log_trust_violation("bad-agent", 1, "http_POST", "T1 cannot POST")
    entries = audit.recent(10)
    assert entries[0]["event"] == "trust_violation"
    assert entries[0]["severity"] == "high"


def test_audit_log_credential_access(audit):
    audit.log_credential_access("my-agent", "api-token", granted=True)
    audit.log_credential_access("my-agent", "admin-key", granted=False)
    entries = audit.recent(10)
    assert len(entries) == 2
    assert entries[0]["granted"] is True
    assert entries[1]["granted"] is False


def test_audit_chain_integrity(audit):
    audit.log_tool_call("a", "t1", {}, "success")
    audit.log_tool_call("a", "t2", {}, "success")
    audit.log_tool_call("a", "t3", {}, "success")

    valid, count, msg = audit.verify_chain()
    assert valid is True
    assert count == 3
    assert "valid" in msg.lower()


def test_audit_chain_detects_tampering(audit):
    audit.log_tool_call("a", "t1", {}, "success")
    audit.log_tool_call("a", "t2", {}, "success")

    # Tamper: rewrite the log with a modified entry
    log_file = audit._log_dir / "audit.jsonl"
    lines = log_file.read_text().strip().split("\n")
    entry = json.loads(lines[0])
    entry["agent"] = "TAMPERED"
    lines[0] = json.dumps(entry, separators=(",", ":"))
    log_file.write_text("\n".join(lines) + "\n")

    valid, count, msg = audit.verify_chain()
    assert valid is False
    assert "broken" in msg.lower()


def test_audit_secret_redaction(audit):
    audit.log_tool_call("a", "t1", {"Authorization": "Bearer abc123xyz", "name": "safe"}, "success")
    entries = audit.recent(1)
    assert entries[0]["parameters"]["Authorization"] == "***REDACTED***"
    assert entries[0]["parameters"]["name"] == "safe"


def test_audit_filter_by_event(audit):
    audit.log_tool_call("a", "t1", {}, "success")
    audit.log_http_bridge("a", "t1", "GET", "http://x", status_code=200)
    audit.log_tool_call("a", "t2", {}, "success")

    tool_entries = audit.recent(10, event_type="tool_call")
    assert len(tool_entries) == 2
    http_entries = audit.recent(10, event_type="http_bridge")
    assert len(http_entries) == 1


# ── Trust Enforcer ───────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_audit_singleton():
    """Reset the global audit logger so tests get isolated instances."""
    import heddle.security.audit as mod
    mod._global_audit = None
    yield
    mod._global_audit = None


def test_trust_t1_allows_get():
    t = TrustEnforcer("reader", 1)
    t.check_http_method("GET", "http://localhost/api")  # should not raise


def test_trust_t1_blocks_post():
    t = TrustEnforcer("reader", 1)
    with pytest.raises(TrustViolation, match="POST"):
        t.check_http_method("POST", "http://localhost/api")


def test_trust_t1_blocks_delete():
    t = TrustEnforcer("reader", 1)
    with pytest.raises(TrustViolation, match="DELETE"):
        t.check_http_method("DELETE", "http://localhost/api")


def test_trust_t2_allows_post():
    t = TrustEnforcer("worker", 2)
    t.check_http_method("POST", "http://localhost/api")  # should not raise
    t.check_http_method("GET", "http://localhost/api")


def test_trust_t2_blocks_delete():
    t = TrustEnforcer("worker", 2)
    with pytest.raises(TrustViolation, match="DELETE"):
        t.check_http_method("DELETE", "http://localhost/api")


def test_trust_t3_allows_delete():
    t = TrustEnforcer("operator", 3)
    t.check_http_method("DELETE", "http://localhost/api")  # should not raise


def test_trust_t1_blocks_write_operation():
    t = TrustEnforcer("reader", 1)
    with pytest.raises(TrustViolation):
        t.check_write_operation("file_write", "/tmp/data")


def test_trust_t2_allows_write_operation():
    t = TrustEnforcer("worker", 2)
    t.check_write_operation("file_write", "/tmp/data")  # should not raise


def test_trust_t2_blocks_agent_invocation():
    t = TrustEnforcer("worker", 2)
    with pytest.raises(TrustViolation, match="T3"):
        t.check_agent_invocation("other-agent")


def test_trust_t3_allows_agent_invocation():
    t = TrustEnforcer("operator", 3)
    t.check_agent_invocation("other-agent")  # should not raise


def test_trust_t4_requires_human():
    t = TrustEnforcer("admin", 4)
    assert t.requires_human_approval() is True
    t2 = TrustEnforcer("worker", 2)
    assert t2.requires_human_approval() is False


# ── Credential Broker ────────────────────────────────────────────────

@pytest.fixture
def broker(tmp_path):
    secrets_file = tmp_path / "secrets.json"
    policy_file = tmp_path / "policy.json"
    secrets_file.write_text(json.dumps({
        "intel-token": "abc123secret",
        "gitea-token": "giteaxyz789",
        "admin-key": "supersecretadmin",
    }))
    policy_file.write_text(json.dumps({
        "intel-bridge": ["intel-token"],
        "gitea-bridge": ["gitea-token"],
        "super-agent": ["intel-token", "gitea-token", "admin-key"],
    }))
    return CredentialBroker(secrets_file=secrets_file, policy_file=policy_file)


def test_broker_get_allowed(broker):
    val = broker.get_credential("intel-bridge", "intel-token")
    assert val == "abc123secret"


def test_broker_get_denied_not_in_policy(broker):
    with pytest.raises(CredentialDenied, match="Not in agent"):
        broker.get_credential("intel-bridge", "admin-key")


def test_broker_get_denied_unknown_agent(broker):
    with pytest.raises(CredentialDenied):
        broker.get_credential("unknown-agent", "intel-token")


def test_broker_resolve_template(broker):
    text = "Bearer {{secret:intel-token}}"
    resolved = broker.resolve_template("intel-bridge", text)
    assert resolved == "Bearer abc123secret"


def test_broker_resolve_denied_template(broker):
    text = "Bearer {{secret:admin-key}}"
    resolved = broker.resolve_template("intel-bridge", text)
    assert "CREDENTIAL_DENIED" in resolved


def test_broker_resolve_headers(broker):
    headers = {
        "Authorization": "Bearer {{secret:intel-token}}",
        "Accept": "application/json",
    }
    resolved = broker.resolve_headers("intel-bridge", headers)
    assert resolved["Authorization"] == "Bearer abc123secret"
    assert resolved["Accept"] == "application/json"


def test_broker_grant_revoke(broker):
    assert "admin-key" not in broker.list_agent_grants("intel-bridge")
    broker.grant_access("intel-bridge", "admin-key")
    assert "admin-key" in broker.list_agent_grants("intel-bridge")
    broker.get_credential("intel-bridge", "admin-key")  # should work now
    broker.revoke_access("intel-bridge", "admin-key")
    with pytest.raises(CredentialDenied):
        broker.get_credential("intel-bridge", "admin-key")


def test_broker_set_remove_secret(broker):
    broker.set_secret("new-key", "new-value")
    assert "new-key" in broker.list_secrets()
    broker.grant_access("intel-bridge", "new-key")
    assert broker.get_credential("intel-bridge", "new-key") == "new-value"
    broker.remove_secret("new-key")
    assert "new-key" not in broker.list_secrets()



# ── Access Mode Enforcement ──────────────────────────────────────────

def test_trust_t1_blocks_write_tool():
    trust = TrustEnforcer("t1-agent", 1)
    with pytest.raises(TrustViolation, match="write"):
        trust.check_access_mode("dangerous_tool", "write")


def test_trust_t1_allows_read_tool():
    trust = TrustEnforcer("t1-agent", 1)
    trust.check_access_mode("safe_tool", "read")  # should not raise


def test_trust_t2_allows_write_tool():
    trust = TrustEnforcer("t2-agent", 2)
    trust.check_access_mode("write_tool", "write")  # should not raise


def test_trust_t3_allows_write_tool():
    trust = TrustEnforcer("t3-agent", 3)
    trust.check_access_mode("write_tool", "write")  # should not raise



# ── Access Mode Config Validation ────────────────────────────────────

def test_access_mode_t1_write_rejected():
    """T1 agent config with a write tool should fail validation."""
    import yaml
    from heddle.config.loader import validate_config, ConfigError
    raw = yaml.safe_load("""
agent:
  name: bad-agent
  version: "1.0.0"
  description: "T1 with write tool"
  exposes:
    - name: delete_stuff
      access: write
      description: "Deletes things"
  runtime:
    trust_tier: 1
  triggers:
    - type: on_demand
""")
    with pytest.raises(ConfigError, match="write.*T1"):
        validate_config(raw, source="<test>")


def test_access_mode_t2_write_accepted():
    """T2 agent config with a write tool should validate fine."""
    import yaml
    from heddle.config.loader import validate_config
    raw = yaml.safe_load("""
agent:
  name: ok-agent
  version: "1.0.0"
  description: "T2 with write tool"
  exposes:
    - name: create_stuff
      access: write
      description: "Creates things"
  runtime:
    trust_tier: 2
  triggers:
    - type: on_demand
""")
    config = validate_config(raw, source="<test>")
    assert config.agent.exposes[0].access == "write"


def test_access_mode_defaults_to_read():
    """Tools without explicit access should default to read."""
    import yaml
    from heddle.config.loader import validate_config
    raw = yaml.safe_load("""
agent:
  name: default-agent
  version: "1.0.0"
  exposes:
    - name: get_stuff
      description: "Gets things"
  runtime:
    trust_tier: 1
  triggers:
    - type: on_demand
""")
    config = validate_config(raw, source="<test>")
    assert config.agent.exposes[0].access == "read"
