"""Tests for Heddle Phase 4: MCP client, agent mesh, multi-agent runner."""
import pytest
import json
from pathlib import Path

from heddle.mcp.client import LoomMCPClient, AgentMesh, MCPClientError
from heddle.runtime.multi import MultiAgentRunner
from heddle.mcp.registry import Registry
from heddle.config.loader import load_agent_config


# ── MCP Client ───────────────────────────────────────────────────────

def test_client_init():
    client = LoomMCPClient("my-agent", "http://localhost:9999/mcp")
    assert client.agent_name == "my-agent"
    assert client.target_uri == "http://localhost:9999/mcp"


# ── Agent Mesh ───────────────────────────────────────────────────────

def test_mesh_connect():
    mesh = AgentMesh("orchestrator")
    mesh.connect("http://localhost:8200/mcp")
    mesh.connect("http://localhost:8201/mcp")
    assert len(mesh.connections) == 2
    assert "http://localhost:8200/mcp" in mesh.connections


def test_mesh_no_duplicate_connections():
    mesh = AgentMesh("orchestrator")
    mesh.connect("http://localhost:8200/mcp")
    mesh.connect("http://localhost:8200/mcp")
    assert len(mesh.connections) == 1  # dict key dedup


@pytest.mark.asyncio
async def test_mesh_call_not_connected():
    mesh = AgentMesh("test")
    with pytest.raises(MCPClientError, match="Not connected"):
        await mesh.call("http://localhost:9999/mcp", "some_tool")


# ── Multi-Agent Runner ───────────────────────────────────────────────

@pytest.fixture
def tmp_agents(tmp_path):
    """Create temp agent configs."""
    a1 = tmp_path / "agent-a.yaml"
    a1.write_text("""
agent:
  name: agent-a
  version: "1.0.0"
  description: "Test agent A"
  model:
    provider: none
  exposes:
    - name: hello_a
      description: "Says hello from A"
  runtime:
    trust_tier: 1
  triggers:
    - type: on_demand
""")
    a2 = tmp_path / "agent-b.yaml"
    a2.write_text("""
agent:
  name: agent-b
  version: "1.0.0"
  description: "Test agent B"
  model:
    provider: none
  exposes:
    - name: hello_b
      description: "Says hello from B"
  runtime:
    trust_tier: 2
  triggers:
    - type: on_demand
""")
    return tmp_path


def test_multi_add(tmp_agents, tmp_path):
    reg = Registry(db_path=tmp_path / "test.db")
    runner = MultiAgentRunner(registry=reg)
    entry = runner.add(tmp_agents / "agent-a.yaml", port=9100)
    assert entry["name"] == "agent-a"
    assert entry["port"] == 9100
    reg.close()


def test_multi_add_directory(tmp_agents, tmp_path):
    reg = Registry(db_path=tmp_path / "test.db")
    runner = MultiAgentRunner(registry=reg)
    count = runner.add_directory(tmp_agents, base_port=9200)
    assert count == 2
    assert runner._agents[0]["port"] == 9200
    assert runner._agents[1]["port"] == 9201
    reg.close()


def test_multi_register_all(tmp_agents, tmp_path):
    reg = Registry(db_path=tmp_path / "test.db")
    runner = MultiAgentRunner(registry=reg)
    runner.add_directory(tmp_agents, base_port=9300)
    runner.register_all()
    agents = reg.list_agents()
    assert len(agents) == 2
    names = {a["name"] for a in agents}
    assert "agent-a" in names
    assert "agent-b" in names
    reg.close()


def test_multi_status(tmp_agents, tmp_path):
    reg = Registry(db_path=tmp_path / "test.db")
    runner = MultiAgentRunner(registry=reg)
    runner.add_directory(tmp_agents, base_port=9400)
    runner.register_all()
    status = runner.status()
    assert len(status) == 2
    assert all(s["status"] == "registered" for s in status)
    assert status[0]["port"] == 9400
    assert status[1]["port"] == 9401
    reg.close()


def test_multi_auto_port_assignment(tmp_agents, tmp_path):
    reg = Registry(db_path=tmp_path / "test.db")
    runner = MultiAgentRunner(registry=reg)
    runner.add(tmp_agents / "agent-a.yaml")  # auto port
    runner.add(tmp_agents / "agent-b.yaml")  # auto port
    assert runner._agents[0]["port"] == 8200  # default base
    assert runner._agents[1]["port"] == 8201
    reg.close()


# ── Integration: build MCP servers for mesh agents ───────────────────

def test_build_server_from_temp_config(tmp_agents):
    from heddle.mcp.server import build_mcp_server
    config = load_agent_config(tmp_agents / "agent-a.yaml")
    mcp = build_mcp_server(config)
    assert mcp.name == "heddle-agent-a"


# ── Integration: real agent config loads correctly ───────────────────

def test_real_configs_validate():
    """All agent configs in the project should validate."""
    agents_dir = Path(__file__).resolve().parent.parent / "agents"
    configs = list(agents_dir.glob("*.yaml"))
    assert len(configs) >= 1, "Expected at least 1 agent config"
    for path in configs:
        config = load_agent_config(path)
        assert config.agent.name, f"Agent in {path.name} has no name"
