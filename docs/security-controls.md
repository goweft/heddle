# LOOM Security Controls Reference

Quick reference for all security controls. For full threat analysis, see [threat-model.md](threat-model.md).

## Implemented Controls (15 of 16)

### Trust Tier Enforcement (`security/trust.py`)

| Tier | Name | HTTP Methods | Write Tools | Cross-Agent | HITL |
|------|------|-------------|-------------|-------------|------|
| T1 | Observer | GET, HEAD, OPTIONS | Blocked | No | No |
| T2 | Worker | + POST, PUT, PATCH | Allowed | No | No |
| T3 | Operator | + DELETE | Allowed | Yes | No |
| T4 | Privileged | + DELETE | Allowed | Yes | Yes |

Violations are **blocked** (not warned) and logged to the audit trail.

### Access Mode Annotations (`config/schema.py`, `security/trust.py`)

- Every tool declares `access: read` or `access: write` (default: read)
- T1 configs with write tools are **rejected at load time** (config validation)
- T1 agents calling write tools are **blocked at runtime** (trust enforcement)
- Write tools: state-modifying operations (model loading, data mutation)
- Read tools: queries, listings, status checks — safe to call anytime
- CLI: `loom validate` checks access/tier compatibility before deployment

### Credential Broker (`security/credentials.py`)

- Secrets stored in `~/.loom/secrets.json` (chmod 600)
- Per-config access policy in `~/.loom/credential_policy.json`
- Configs use `{{secret:key}}` — resolved at runtime, never stored in YAML
- Unauthorized access: denied, logged, returns `***CREDENTIAL_DENIED***`
- CLI: `loom secrets list`, `set`, `grant`, `revoke`, `policy`

### Audit Logging (`security/audit.py`)

- Structured JSON Lines at `~/.loom/audit/audit.jsonl`
- SHA-256 hash-chained entries (tamper-evident)
- Events: `tool_call`, `http_bridge`, `trust_violation`, `credential_access`, `agent_lifecycle`
- Secret values redacted automatically
- CLI: `loom audit show [-n N] [--event TYPE]`, `loom audit verify`

### Input Validation (`security/validation.py`)

- Type checking and coercion (string, integer, number, boolean, array, object)
- Length limits per type (string max 10,000 chars)
- Injection pattern detection: shell, SQL, path traversal, LLM prompt injection
- Strict mode blocks, non-strict mode passes through with logging
- Wired into MCP server HTTP bridge dispatch pipeline

### Rate Limiting (`security/validation.py`)

- Sliding window counter per config per tool
- Default: 120 requests per minute
- Configurable per-tool RPM
- Exceeding limit: blocked, logged as trust violation

### Config Signing (`security/signing.py`)

- HMAC-SHA256 signing of YAML configs
- Auto-generated signing key at `~/.loom/signing.key` (chmod 600)
- Tamper detection: modified configs fail verification
- CLI: `loom sign all`, `loom sign verify`, `loom sign config`

### Config Quarantine (`security/signing.py`)

- Staging directory at `~/.loom/quarantine/`
- AI-generated configs quarantined before going live
- Promote/reject workflow with manifest tracking
- CLI: `loom quarantine list`, `promote`, `reject`

### Sandbox Framework (`security/sandbox.py`)

- Docker container config generation from agent YAML
- Resource limits scaled by trust tier (T1=256MB, T3=1GB)
- Network policy: configs can only reach declared http_bridge hosts
- Read-only root filesystem, scoped writable volumes
- CLI: `loom sandbox <config>`

### Schema Validation (`config/schema.py`, `config/loader.py`)

- Pydantic v2 models with strict typing
- Cross-field validation: http_bridge refs match exposes, access modes match trust tiers
- Config names: kebab-case. Tool names: snake_case
- `loom validate <config>` for pre-deployment checks

### Escalation Rules (`security/escalation.py`)

- Declarative rules in YAML that hold tool calls for review when conditions match
- Condition types: tool name globs, numeric thresholds (`param_gt`), exact match (`param_eq`), substring (`param_contains`), access mode
- Matched calls raise `EscalationHold` — execution stops, audit trail records the hold
- Rules loaded from config `escalation_rules` field, checked in the dispatch pipeline
- Example: `smart_load` with "27b" model → held (17GB+ VRAM consumption)

## Remaining

| Control | Status | Description |
|---------|--------|-------------|
| Network isolation (iptables) | Planned | Container-level network enforcement |

## Framework Mapping

Every control maps to at least one industry framework:

- **OWASP Agentic Security Top 10** — agentic-specific threats
- **NIST AI Risk Management Framework (AI RMF 1.0)** — governance and risk
- **MAESTRO** — multi-agent security layers

See the [threat model](threat-model.md) Section 4 for complete cross-reference tables.
