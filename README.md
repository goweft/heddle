# LOOM — The WEFT Agent & MCP Mesh Runtime

LOOM turns YAML config files into MCP servers. Define an agent in YAML, point it at a REST API, and LOOM auto-generates a Model Context Protocol server that Claude Desktop (or any MCP client) can use. No Python handlers, no boilerplate — just config.

```yaml
# agents/prometheus-bridge.yaml
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
    trust_tier: 1
```

That's a working MCP server. `loom run agents/prometheus-bridge.yaml` and Claude can query your Prometheus metrics in natural language.

## What LOOM Does

**Config-driven agents.** Agents are YAML, not code. The runtime interprets the config, generates typed MCP tools, and handles HTTP bridging with template rendering (`{{param}}`).

**AI agent generator.** Describe an agent in English → local LLM (Ollama) generates valid YAML → schema validation → save. `loom generate "agent that wraps the Gitea API"` produces a working config in 20 seconds.

**Security architecture.** Trust tiers (T1–T4) enforce what each agent can do. Credential broker keeps secrets out of YAML. Hash-chained audit log records every tool call. Input validation catches injection attempts. Config signing detects tampering. All mapped to OWASP Agentic Top 10, NIST AI RMF, and MAESTRO.

**Agent mesh.** Multiple agents share a single MCP connection to Claude Desktop. Cross-agent tool calls. Multi-agent runner with auto-port assignment.

**Advanced orchestration.** Agents can have their own LLM brain. The `daily-ops` agent queries Prometheus, weft-intel, and Ollama in parallel, then uses a local model to synthesize a daily briefing.

## Current Deployment

Running on a self-hosted Linux server (93GB RAM, AMD RX 7900 XTX GPU):

| Agent | Tools | What It Does |
|-------|-------|-------------|
| weft-intel-bridge | 8 | RAG queries, trending entities, patterns, daily briefs |
| prometheus-bridge | 5 | PromQL queries, target health, alerts, 638 metrics |
| nexus-bridge | 8 | AI platform health, routing stats/costs, app management |
| grafana-bridge | 5 | Dashboards, datasources, alert rules |
| ollama-bridge | 4 | List/run models, generate text, VRAM monitoring |
| gitea-api-bridge | 2 | List repos, list issues |
| rsshub-bridge | 4 | HN, GitHub trending, arXiv, Reuters |
| daily-ops | 3 | LLM-synthesized briefing, health check, threat landscape |

**39 tools** served through a single Claude Desktop MCP connection.

## Security Model

See [docs/threat-model.md](docs/threat-model.md) for the full analysis.

| Control | Status | Framework |
|---------|--------|-----------|
| Trust tier enforcement (T1–T4) | Implemented | OWASP Agentic #3 |
| Credential broker + per-agent policy | Implemented | OWASP Agentic #7 |
| Hash-chained audit log | Implemented | OWASP Agentic #9 |
| Input validation + injection detection | Implemented | OWASP Agentic #1 |
| Config signing (HMAC-SHA256) | Implemented | OWASP Agentic #8 |
| AI-generated agent quarantine | Implemented | OWASP Agentic #8 |
| Rate limiting (per-agent, per-tool) | Implemented | OWASP Agentic #4 |
| Docker sandbox framework | Implemented | OWASP Agentic #6 |

## Quick Start

```bash
# Clone and install
git clone <repo-url> && cd loom
python -m venv venv && source venv/bin/activate
pip install -e .

# Validate an agent config
loom validate agents/prometheus-bridge.yaml

# Run a single agent
loom run agents/prometheus-bridge.yaml --port 8200

# Generate a new agent from natural language
loom generate "agent that wraps the weather API at localhost:5000"

# Start all agents as a mesh
loom mesh agents/

# Security operations
loom audit show -n 20
loom audit verify
loom sign all agents/
loom sign verify agents/
loom secrets list
loom secrets policy
loom sandbox agents/weft-intel-bridge.yaml
loom quarantine list
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `loom run` | Run a single agent from YAML config |
| `loom validate` | Validate an agent config without running |
| `loom generate` | Generate agent config from natural language |
| `loom mesh` | Start all agents from a directory |
| `loom list` | List registered agents |
| `loom registry` | Show all registered tools |
| `loom info` | Detailed agent info |
| `loom probe` | Discover tools on a running MCP server |
| `loom discovery` | Dump discovery manifest as JSON |
| `loom audit show` | View audit log entries |
| `loom audit verify` | Verify audit chain integrity |
| `loom secrets list/set/grant/revoke/policy` | Credential management |
| `loom sign all/verify/config` | Config signing operations |
| `loom quarantine list/promote/reject` | AI-generated agent staging |
| `loom sandbox` | Show Docker sandbox config for an agent |

## Architecture

```
Claude Desktop
    │ MCP (stdio)
    ▼
LOOM Runtime
├── YAML Config → FastMCP Server (auto-generated)
├── HTTP Bridge ({{template}} rendering)
├── Security Layer
│   ├── Trust Enforcer (T1–T4)
│   ├── Credential Broker ({{secret:key}})
│   ├── Input Validator (type/injection/rate)
│   ├── Audit Logger (hash-chained JSON Lines)
│   └── Config Signer (HMAC-SHA256)
├── Agent Mesh (cross-agent tool calls)
└── AI Generator (Ollama → YAML → validate)
    │ HTTP
    ▼
Backend Services (Prometheus, Grafana, Ollama, etc.)
```

## Tech Stack

- **Python 3.12** — FastAPI, FastMCP 3.x, Pydantic v2, httpx, Click
- **MCP Protocol** — stdio transport for Claude Desktop
- **Ollama** — local LLM inference for agent generation and orchestration
- **SQLite** — agent/tool registry
- **YAML** — agent configuration with JSON Schema validation

## Project Structure

```
loom/
├── agents/          # YAML agent configs (10 configs, 44 tools)
├── docs/            # Threat model, security controls reference
├── src/loom/
│   ├── cli.py       # 14-command Click CLI
│   ├── config/      # Pydantic schema, YAML loader
│   ├── mcp/         # MCP server builder, client, registry
│   ├── runtime/     # Agent runner, multi-agent mesh
│   ├── generator/   # AI agent generator, API discovery
│   ├── security/    # Trust, credentials, audit, validation, signing, sandbox
│   ├── agents/      # Custom handler agents (daily-ops)
│   └── evolve/      # Passive research, coverage gap analysis
├── tests/           # 102 tests across 7 test files
└── loom_stdio_mesh.py  # Unified Claude Desktop launcher (39 tools)
```

## License

MIT
