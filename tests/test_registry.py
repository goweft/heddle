"""Tests for Heddle agent registry."""
import pytest
from heddle.mcp.registry import Registry

@pytest.fixture
def registry(tmp_path):
    reg = Registry(db_path=tmp_path / "test_registry.db")
    yield reg
    reg.close()

def test_register_and_get(registry):
    registry.register_agent(name="test-agent", version="1.0.0", description="A test", port=8200,
                            tools=[{"name": "tool_a", "description": "Does A"},
                                   {"name": "tool_b", "description": "Does B", "bridge_type": "http"}])
    agent = registry.get_agent("test-agent")
    assert agent is not None
    assert agent["name"] == "test-agent"
    assert len(agent["tools"]) == 2

def test_list_agents(registry):
    registry.register_agent(name="agent-a", version="1.0.0")
    registry.register_agent(name="agent-b", version="2.0.0")
    agents = registry.list_agents()
    assert len(agents) == 2

def test_set_status(registry):
    registry.register_agent(name="agent-x", version="1.0.0")
    assert registry.get_agent("agent-x")["status"] == "registered"
    registry.set_status("agent-x", "running")
    assert registry.get_agent("agent-x")["status"] == "running"

def test_unregister(registry):
    registry.register_agent(name="doomed", version="1.0.0")
    assert registry.unregister_agent("doomed") is True
    assert registry.get_agent("doomed") is None

def test_unregister_nonexistent(registry):
    assert registry.unregister_agent("ghost") is False

def test_upsert_agent(registry):
    registry.register_agent(name="evolving", version="1.0.0", tools=[{"name": "old_tool"}])
    registry.register_agent(name="evolving", version="2.0.0", tools=[{"name": "new_tool"}])
    agent = registry.get_agent("evolving")
    assert agent["version"] == "2.0.0"
    assert len(agent["tools"]) == 1
    assert agent["tools"][0]["name"] == "new_tool"

def test_list_all_tools(registry):
    registry.register_agent(name="a", version="1.0.0", tools=[{"name": "t1", "description": "tool 1"}])
    registry.register_agent(name="b", version="1.0.0", tools=[{"name": "t2", "description": "tool 2"},
                                                                {"name": "t3", "description": "tool 3"}])
    assert len(registry.list_all_tools()) == 3

def test_search_tools(registry):
    registry.register_agent(name="intel", version="1.0.0",
                            tools=[{"name": "ask_intel", "description": "Ask a question about news"},
                                   {"name": "get_trending", "description": "Get trending entities"}])
    results = registry.search_tools("trending")
    assert len(results) == 1
    assert results[0]["name"] == "get_trending"

def test_discovery_manifest(registry):
    registry.register_agent(name="demo", version="1.0.0", port=8200, tools=[{"name": "hello", "description": "Say hello"}])
    manifest = registry.discovery_manifest()
    assert manifest["heddle_version"] == "0.1.0"
    assert len(manifest["agents"]) == 1
    assert manifest["agents"][0]["endpoint"] == "http://localhost:8200/mcp"


# ── Registry HMAC integrity ──────────────────────────────────────────

def test_register_sets_hmac(registry):
    registry.register_agent(name="signed-agent", version="1.0.0", description="test")
    row = registry._conn.execute("SELECT row_hmac FROM agents WHERE name='signed-agent'").fetchone()
    assert row["row_hmac"] != ""
    assert len(row["row_hmac"]) == 64  # SHA-256 hex


def test_verify_passes_for_clean_registry(registry):
    registry.register_agent(name="agent-a", version="1.0.0")
    registry.register_agent(name="agent-b", version="2.0.0")
    valid, count, issues = registry.verify_registry()
    assert valid is True
    assert count == 2
    assert issues == []


def test_verify_detects_tampered_row(registry):
    registry.register_agent(name="target", version="1.0.0", description="original")
    # Tamper: modify description directly in SQLite, bypassing the broker
    registry._conn.execute("UPDATE agents SET description='TAMPERED' WHERE name='target'")
    registry._conn.commit()
    valid, count, issues = registry.verify_registry()
    assert valid is False
    assert len(issues) == 1
    assert "HMAC mismatch" in issues[0]


def test_verify_detects_unsigned_row(registry):
    registry.register_agent(name="legit", version="1.0.0")
    # Insert a row directly without HMAC
    registry._conn.execute(
        "INSERT INTO agents (name, version, registered_at, updated_at, row_hmac) "
        "VALUES ('rogue', '0.0.0', '2026-01-01', '2026-01-01', '')"
    )
    registry._conn.commit()
    valid, count, issues = registry.verify_registry()
    assert valid is False
    assert any("unsigned" in i for i in issues)


def test_set_status_updates_hmac(registry):
    registry.register_agent(name="agent", version="1.0.0")
    old_hmac = registry._conn.execute("SELECT row_hmac FROM agents WHERE name='agent'").fetchone()["row_hmac"]
    registry.set_status("agent", "running")
    new_hmac = registry._conn.execute("SELECT row_hmac FROM agents WHERE name='agent'").fetchone()["row_hmac"]
    assert old_hmac != new_hmac  # HMAC changed because status changed
    # But verify should still pass
    valid, _, _ = registry.verify_registry()
    assert valid is True


def test_upsert_updates_hmac(registry):
    registry.register_agent(name="evolving", version="1.0.0")
    registry.register_agent(name="evolving", version="2.0.0")
    valid, _, _ = registry.verify_registry()
    assert valid is True
