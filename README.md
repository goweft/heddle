<p align="center">
  <h1 align="center">LOOM</h1>
  <p align="center"><strong>Config-driven AI agents that become MCP servers automatically.</strong></p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> ·
    <a href="#how-it-works">How It Works</a> ·
    <a href="#security">Security</a> ·
    <a href="docs/threat-model.md">Threat Model</a>
  </p>
</p>

---

LOOM is a runtime that turns YAML into MCP servers. Define an agent config, point it at a REST API, and LOOM generates a [Model Context Protocol](https://modelcontextprotocol.io/) server that Claude Desktop or any MCP client can use. No code required.

<p align="center">
  <img src="docs/assets/demo.svg" alt="LOOM CLI demo" width="750">
</p>

## Why LOOM?

Every API you want to expose to an LLM requires custom integration code. LOOM eliminates that. Write a YAML config with the endpoint URL and parameter schema, and LOOM handles MCP server generation, HTTP bridging, credential management, and security enforcement.

```yaml
agent:
  name: prometheus-bridge
  exposes:
    - name: query_prometheus
      description: "Run a PromQL query"
      parameters:
        query: { type: string, required: true }
  http_bridge:
    - tool_name: query_prometheus
      method: GET
      url: "http://localhost:9092/api/v1/query"
      query_params: { query: query }
  runtime:
    trust_tier: 1   # read-only, enforced at runtime
```

```bash
$ loom run agents/prometheus-bridge.yaml --port 8200
▶ MCP server loom-prometheus-bridge on http://0.0.0.0:8200/mcp
```

Claude can now query Prometheus in natural language.

## How It Works

```
Claude Desktop / MCP Client
    │ stdio or streamable-http
    ▼
┌────────────────────────────────────┐
│          LOOM Runtime              │
│                                    │
│  YAML Config                       │
│    → Pydantic validation           │
│    → FastMCP server generation     │
│    → Typed tool registration       │
│                                    │
│  Security Layer                    │
│    → Trust enforcement (T1–T4)     │
│    → Credential broker             │
│    → Input validation              │
│    → Hash-chained audit log        │
│    → Config signing                │
│                                    │
│  HTTP Bridge                       │
│    → Template rendering {{param}}  │
│    → Response parsing              │
│    → Error handling                │
└──────────────┬─────────────────────┘
               │ HTTP
    ┌──────────▼──────────────┐
    │    Backend Services     │
    │  Prometheus · Grafana   │
    │  Ollama · Gitea · APIs  │
    └─────────────────────────┘
```

## Features

### Config-Driven Agents
Agents are YAML, not code. The runtime interprets the config, generates typed MCP tools with proper parameter schemas, and handles HTTP bridging with `{{param}}` template rendering. Cross-field validation catches bad configs before they run.

### AI Agent Generator
Describe an agent in English → a local LLM (Ollama) generates valid YAML → schema validation with self-correcting retry → save. Produces working configs in ~20 seconds.

```bash
$ loom generate "agent that wraps the Gitea API" --model qwen3:14b
✓ Generated gitea-api-bridge.yaml (2 tools) in 20.3s
```

### Agent Mesh
Multiple agents share a single MCP connection. The unified mesh launcher loads all configs, merges tools, and serves them through one stdio connection to Claude Desktop. Currently serving **46 tools from 9 agents**.

### Advanced Orchestration
Agents can have their own LLM brain. The `daily-ops` agent queries Prometheus, an intelligence API, and Ollama in parallel, feeds all data to a local model, and synthesizes a daily operations briefing. The `vram-orchestrator` manages GPU memory across 37 models with intelligent eviction.

### Web Dashboard
FastAPI backend with a React frontend showing mesh topology, agent status, live audit stream, and security overview.

## Security

LOOM's security architecture maps to three industry frameworks. See the full [threat model](docs/threat-model.md) and [security controls reference](docs/security-controls.md).

| Control | Description | Framework |
|---------|-------------|-----------|
| **Trust tiers** | 4 levels (observer → privileged), runtime-enforced | OWASP Agentic #3 |
| **Credential broker** | Per-agent secret access policy, `{{secret:key}}` templates | OWASP Agentic #7 |
| **Audit log** | Hash-chained JSON Lines, tamper-evident, 5 event types | OWASP Agentic #9 |
| **Input validation** | Type checking, length limits, injection detection | OWASP Agentic #1 |
| **Config signing** | HMAC-SHA256, tamper detection on all agent configs | OWASP Agentic #8 |
| **Agent quarantine** | AI-generated configs staged for review before promotion | OWASP Agentic #8 |
| **Rate limiting** | Sliding window per-agent per-tool | OWASP Agentic #4 |
| **Sandbox framework** | Docker container config generation, network policies | OWASP Agentic #6 |

The trust enforcer caught a real bug during development: an agent declared as T1 (read-only) attempted a POST request and was blocked. The violation was logged to the audit trail, forcing a config correction.

## Quick Start

```bash
# Clone and install
git clone https://github.com/goweft/loom.git && cd loom
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Validate an agent config
loom validate agents/prometheus-bridge.yaml

# Run a single agent (serves MCP over streamable-http)
loom run agents/prometheus-bridge.yaml --port 8200

# Generate a new agent from natural language (requires Ollama)
loom generate "agent that wraps the weather API at localhost:5000"

# Start all agents as a unified mesh
loom mesh agents/

# Security operations
loom audit show -n 20          # view recent audit entries
loom audit verify               # verify hash chain integrity
loom sign all agents/           # sign all configs
loom sign verify agents/        # verify all signatures
loom secrets policy             # show credential access policy
loom sandbox agents/my-agent.yaml  # show sandbox config
```

### Claude Desktop Integration

Add LOOM as an MCP server in your Claude Desktop config:

```json
{
  "mcpServers": {
    "loom-mesh": {
      "command": "/path/to/loom/venv/bin/python",
      "args": ["/path/to/loom/loom_stdio_mesh.py"]
    }
  }
}
```

Restart Claude Desktop. All LOOM tools are now available.

## CLI Reference

| Command | Description |
|---------|-------------|
| `loom run <config>` | Run a single agent from YAML config |
| `loom validate <config>` | Validate config without running |
| `loom generate <description>` | Generate config from natural language |
| `loom mesh <dir>` | Start all agents as a unified mesh |
| `loom list` | List registered agents |
| `loom registry` | Show all registered tools |
| `loom info <agent>` | Detailed agent info |
| `loom probe <uri>` | Discover tools on a running MCP server |
| `loom audit show` | View audit log entries |
| `loom audit verify` | Verify audit chain integrity |
| `loom secrets` | Credential broker management |
| `loom sign` | Config signing and verification |
| `loom quarantine` | AI-generated agent staging |
| `loom sandbox <config>` | Show Docker sandbox configuration |

## Project Structure

```
loom/
├── agents/              # YAML agent configs (11 configs)
├── docs/
│   ├── threat-model.md  # 8 threat categories, framework-mapped
│   └── security-controls.md
├── src/loom/
│   ├── cli.py           # 14-command Click CLI
│   ├── config/          # Pydantic v2 schema, YAML loader
│   ├── mcp/             # MCP server builder, client, registry
│   ├── runtime/         # Agent runner, multi-agent mesh
│   ├── generator/       # AI agent generator, API discovery
│   ├── security/        # Trust, credentials, audit, validation,
│   │                    # signing, sandbox (6 modules)
│   ├── agents/          # Custom handler agents (daily-ops,
│   │                    # vram-orchestrator)
│   ├── evolve/          # Passive research, coverage gaps
│   └── web/             # FastAPI dashboard + React frontend
├── tests/               # 102 tests across 7 files
├── loom_stdio_mesh.py   # Unified Claude Desktop launcher
└── loom_dashboard.py    # Web dashboard launcher
```

## Tech Stack

Python 3.12 · FastMCP 3.x · FastAPI · Pydantic v2 · httpx · Click · SQLite · Ollama

## License

MIT
