<h1 align="center">LOOM</h1>
<p align="center"><strong>A secure, declarative MCP runtime.</strong></p>
<p align="center">
  LOOM turns declarative configs into <a href="https://modelcontextprotocol.io/">Model Context Protocol</a> servers<br>
  with trust enforcement, credential brokering, and tamper-evident audit logging built in.
</p>
<p align="center">
  <a href="#proof">See It Work</a> ·
  <a href="#why-loom">Why LOOM</a> ·
  <a href="#security">Security</a> ·
  <a href="docs/threat-model.md">Threat Model</a> ·
  <a href="#quick-start">Quick Start</a>
</p>

---

<h2 id="proof">See It Work</h2>

<p align="center">
  <img src="docs/assets/demo.svg" alt="LOOM CLI demo" width="750">
</p>

**One config, one MCP server.** This YAML is a complete tool server — no Python, no boilerplate:

```yaml
agent:
  name: prometheus-bridge
  version: "1.0.0"
  description: "Bridges Prometheus for natural language metric queries"
  exposes:
    - name: query_prometheus
      description: "Run a PromQL query"
      parameters:
        query: { type: string, required: true }
    - name: get_alerts
      description: "List active Prometheus alerts"
  http_bridge:
    - tool_name: query_prometheus
      method: GET
      url: "http://localhost:9092/api/v1/query"
      query_params: { query: query }
    - tool_name: get_alerts
      method: GET
      url: "http://localhost:9092/api/v1/alerts"
  runtime:
    trust_tier: 1  # enforced: GET/HEAD only, no writes, no cross-agent calls
```

**`loom run agents/prometheus-bridge.yaml`** — Claude can now query Prometheus in natural language.

**Currently running: 46 tools from 9 agents through a single MCP connection:**

```
  daily-ops        (T3): daily_briefing, system_health_check, threat_landscape
  gitea-api-bridge (T1): list_user_repos, list_repo_issues
  grafana-bridge   (T1): list_dashboards, get_dashboard, list_datasources, get_alert_rules, grafana_health
  ai-platform      (T1): health, ai_status, routing_stats, routing_costs, list_apps, detect_drift, ...
  ollama-bridge    (T2): list_models, list_running, generate, show_model
  prometheus-bridge(T1): query_prometheus, query_range, get_targets, get_alerts, get_metric_names
  rsshub-bridge    (T1): get_hacker_news, get_github_trending, search_arxiv, get_reuters_news
  vram-orchestrator(T3): vram_status, smart_load, smart_generate, optimize_vram, unload_model, model_library
  intel-rag-bridge  (T2): ask_intel, get_dossier, get_trending, get_patterns, get_communities, get_stats, ...
```

**Security is always on.** Every tool call passes through trust enforcement, credential brokering, and audit logging. Here's a real event from the audit trail — a T1 (read-only) agent attempted a POST and was blocked:

```json
{
  "event": "trust_violation",
  "agent": "reader",
  "trust_tier": 1,
  "action": "http_POST",
  "detail": "T1 agent cannot use POST. Allowed: ['GET', 'HEAD', 'OPTIONS']",
  "severity": "high",
  "chain_hash": "92c189e3..."
}
```

The violation was logged, the request was rejected, and the hash chain links this entry to every event before and after it. Tampering with any entry breaks the chain.

---

<h2 id="why-loom">Why LOOM Instead Of...</h2>

| | **LOOM** | Hand-written FastMCP | OpenAPI wrapper gen | n8n / workflow tools |
|---|---|---|---|---|
| **New tool** | Write YAML, done | Write Python handler per tool | Generate stubs, then customize | Drag nodes, wire connections |
| **Security** | Trust tiers, credential broker, audit log, input validation, config signing — all built in | You build it yourself | None | Platform-level auth only |
| **AI-generatable** | `loom generate "wrap the Gitea API"` → valid config in 20s | LLM can write code but can't validate it | Not designed for LLM generation | Visual-only, not scriptable |
| **Credential handling** | `{{secret:key}}` — resolved at runtime, never in config | Hardcoded or env vars | Hardcoded or env vars | Platform credential store |
| **Audit trail** | Hash-chained, tamper-evident, every call logged | You build it yourself | None | Platform logs only |
| **Composability** | Configs become MCP tools, mesh them together | Manual wiring | Separate services | Workflow-scoped |

LOOM is for the case where you have REST APIs that you want to expose as MCP tools with real security controls, not just connectivity. If you only need one tool with no security requirements, hand-written FastMCP is simpler. If you need a visual workflow builder, use n8n. LOOM sits in between: declarative like a workflow tool, programmable like a framework, secure by default.

---

## How It Works

<p align="center">
  <img src="docs/assets/architecture.svg" alt="LOOM runtime pipeline" width="720">
</p>

## Core Features

### Declarative Tool Configs
Tools are defined in YAML. The runtime validates the config with Pydantic, generates typed MCP tools, and bridges HTTP with `{{param}}` template rendering. Cross-field validation catches bad configs before they run.

### AI Config Generator
Describe what you need in English → a local LLM (Ollama) generates valid YAML → schema validation with self-correcting retry → save.

```bash
$ loom generate "agent that wraps the Gitea API" --model qwen3:14b
✓ Generated gitea-api-bridge.yaml (2 tools) in 20.3s
```

### Security Architecture
See the full [threat model](docs/threat-model.md) and [security controls reference](docs/security-controls.md). Every control maps to OWASP Agentic Top 10, NIST AI RMF, or MAESTRO.

| Control | What It Does | Framework |
|---------|-------------|-----------|
| **Trust tiers** | 4 levels (observer → privileged), runtime-enforced, violations blocked and logged | OWASP Agentic #3 |
| **Credential broker** | Per-config secret access policy, `{{secret:key}}` resolved at runtime, never stored in YAML | OWASP Agentic #7 |
| **Audit log** | Hash-chained JSON Lines, tamper-evident, 5 event types, secret redaction | OWASP Agentic #9 |
| **Input validation** | Type checking, length limits, injection pattern detection (shell, SQL, LLM prompt) | OWASP Agentic #1 |
| **Config signing** | HMAC-SHA256 on all agent configs, tamper detection | OWASP Agentic #8 |
| **Config quarantine** | AI-generated configs staged for review before promotion | OWASP Agentic #8 |
| **Rate limiting** | Sliding window per-agent per-tool | OWASP Agentic #4 |
| **Sandbox framework** | Docker container config generation, network policies, resource limits by tier | OWASP Agentic #6 |

---

---

## Starter Packs

Ready-made configs for common services. Copy to `agents/`, update the URL, run. See [packs/](packs/) for full docs.

| Pack | Tools | Trust | Description |
|------|-------|-------|-------------|
| [prometheus](packs/prometheus.yaml) | 5 | T1 read-only | PromQL queries, targets, alerts, metric discovery |
| [grafana](packs/grafana.yaml) | 5 | T1 read-only | Dashboards, datasources, alert rules |
| [git-forge](packs/git-forge.yaml) | 3 | T1 read-only | Repos, issues (Gitea/GitHub/Forgejo) |
| [ollama](packs/ollama.yaml) | 4 | T2 worker | Model listing, text generation, VRAM status |

```bash
cp packs/prometheus.yaml agents/
loom validate agents/prometheus.yaml
loom run agents/prometheus.yaml --port 8200
```

## Advanced Examples

These are built on top of the core runtime and demonstrate what LOOM can do beyond simple API bridging.

### Tool Mesh
Multiple configs share a single MCP connection to Claude Desktop. The unified mesh launcher loads all configs, merges tools, and serves them through one stdio transport. Currently serving 46 tools from 9 configs.

### VRAM Orchestrator
An advanced agent that manages GPU memory across Ollama and a 30-model GGUF library. Smart model loading with automatic eviction — when VRAM is full, it unloads the least-needed model to make room.

### Daily Ops Orchestrator
An agent with its own LLM brain. Queries Prometheus, an intelligence API, and Ollama in parallel, feeds all data to a local model, and synthesizes a daily operations briefing.

### Web Dashboard
FastAPI backend + React frontend showing mesh topology, agent status, live audit stream, credential policy, and config signatures. Runs at port 8300.

### Evolve System
Passive research that scans GitHub trending repos and HuggingFace MCP spaces, cross-references with running agents, identifies coverage gaps, and generates agent briefs for `loom generate`.

---

<h2 id="quick-start">Quick Start</h2>

```bash
# Clone and install
git clone https://github.com/goweft/loom.git && cd loom
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Validate an agent config
loom validate agents/prometheus-bridge.yaml

# Run a single agent
loom run agents/prometheus-bridge.yaml --port 8200

# Generate a new agent from natural language (requires Ollama)
loom generate "agent that wraps the weather API at localhost:5000"

# Start all agents as a unified mesh
loom mesh agents/

# Security operations
loom audit show -n 20
loom audit verify
loom sign all agents/
loom sign verify agents/
loom secrets policy
loom sandbox agents/my-agent.yaml
```

### Claude Desktop Integration

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
| `loom audit show/verify` | Audit log inspection and chain verification |
| `loom secrets` | Credential broker management |
| `loom sign` | Config signing and verification |
| `loom quarantine` | AI-generated agent staging |
| `loom sandbox <config>` | Show Docker sandbox configuration |

## Project Structure

```
loom/
├── agents/              # YAML agent configs (11 configs, 46 tools)
├── docs/
│   ├── threat-model.md  # 8 threat categories, framework-mapped
│   └── security-controls.md
├── src/loom/
│   ├── cli.py           # 14-command Click CLI
│   ├── config/          # Pydantic v2 schema, YAML loader
│   ├── mcp/             # MCP server builder, client, SQLite registry
│   ├── runtime/         # Agent runner, multi-agent mesh
│   ├── generator/       # AI agent generator, API discovery
│   ├── security/        # 6 modules: trust, credentials, audit,
│   │                    #   validation, signing, sandbox
│   ├── agents/          # Custom handlers (daily-ops, vram-orchestrator)
│   ├── evolve/          # Passive research, coverage gap analysis
│   └── web/             # Dashboard (FastAPI + React)
├── tests/               # 102 tests across 7 files
├── loom_stdio_mesh.py   # Unified Claude Desktop launcher
└── loom_dashboard.py    # Web dashboard launcher
```

## Tech Stack

Python 3.12 · FastMCP 3.x · FastAPI · Pydantic v2 · httpx · Click · SQLite · Ollama

## License

MIT
