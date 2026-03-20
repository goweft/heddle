# LOOM Security Controls Reference

Quick reference for all implemented and planned security controls. For full threat analysis, see [threat-model.md](threat-model.md).

## Implemented Controls

### Trust Tier Enforcement (`security/trust.py`)

| Tier | Name | HTTP Methods | Write | Cross-Agent | HITL |
|------|------|-------------|-------|-------------|------|
| T1 | Observer | GET, HEAD, OPTIONS | No | No | No |
| T2 | Worker | + POST, PUT, PATCH | Scoped | No | No |
| T3 | Operator | + DELETE | Full | Yes | No |
| T4 | Privileged | + DELETE | Full | Yes | Yes |

Violations are **blocked** (not warned) and logged to the audit trail.

### Credential Broker (`security/credentials.py`)

- Secrets stored in `~/.loom/secrets.json` (chmod 600)
- Per-agent access policy in `~/.loom/credential_policy.json`
- Agent configs use `{{secret:key}}` — resolved at runtime, never stored in YAML
- Unauthorized access: denied, logged, returns `***CREDENTIAL_DENIED***`
- CLI: `loom secrets list`, `loom secrets set`, `loom secrets grant`, `loom secrets revoke`, `loom secrets policy`

### Audit Logging (`security/audit.py`)

- Structured JSON Lines at `~/.loom/audit/audit.jsonl`
- SHA-256 hash-chained entries (tamper-evident)
- Events: `tool_call`, `http_bridge`, `trust_violation`, `credential_access`, `agent_lifecycle`
- Secret values redacted automatically
- CLI: `loom audit show [-n N] [--event TYPE]`, `loom audit verify`

### Schema Validation (`config/schema.py`, `config/loader.py`)

- Pydantic v2 models with strict typing
- Cross-field validation (http_bridge references must match exposes)
- Agent names: kebab-case. Tool names: snake_case
- `loom validate <config>` for pre-deployment checks

## Planned Controls

| Control | Phase | OWASP # | Description |
|---------|-------|---------|-------------|
| Docker sandboxing | 3a | #6 | Container per agent, network/filesystem isolation |
| Input validation | 3e | #1, #2 | Type/length/pattern checks on tool parameters |
| Config signing | 3f | #8 | Cryptographic signatures on YAML configs |
| Agent quarantine | 3f | #8 | Staging directory for AI-generated configs |
| Rate limiting | 3e | #4 | Per-agent, per-tool request throttling |
| Network isolation | 3a | #6 | Agents can only reach declared services |

## Framework Mapping

Every control maps to at least one industry framework:

- **OWASP Agentic Security Top 10** — agentic-specific threats
- **OWASP LLM Top 10** — LLM-specific vulnerabilities
- **NIST AI Risk Management Framework (AI RMF 1.0)** — governance and risk
- **MAESTRO** — multi-agent security layers

See the [threat model](threat-model.md) Section 4 for the complete cross-reference tables.
