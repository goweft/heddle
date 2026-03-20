# LOOM Threat Model

> **Purpose:** This document identifies threats specific to agentic AI systems and maps LOOM's security controls to industry frameworks. It serves as both an operational security reference and a portfolio demonstration of applied AI security architecture.
>
> **Last updated:** March 2026  
> **Author:** Steve Gostev  
> **System:** LOOM v0.1.0 — 10 agents, 44 tools, 292+ audit entries

---

## 1. System Overview

LOOM is a self-hosted runtime that turns declarative YAML configurations into MCP (Model Context Protocol) servers. Each agent wraps existing APIs (Prometheus, Grafana, Ollama, etc.) or orchestrates across multiple data sources using a local LLM. Claude Desktop consumes LOOM agents as MCP tools, enabling natural language access to infrastructure, intelligence feeds, and AI models.

### Architecture

```
Claude Desktop / MCP Client
        │
        ▼ (MCP over stdio)
┌─────────────────────────────┐
│       LOOM RUNTIME          │
│                             │
│  ┌─────┐ ┌─────┐ ┌──────┐  │
│  │Agent│ │Agent│ │Agent │  │
│  │ A   │ │ B   │ │ C    │  │
│  └──┬──┘ └──┬──┘ └──┬───┘  │
│     │       │       │       │
│  ┌──▼───────▼───────▼───┐  │
│  │  Security Layer       │  │
│  │  - Trust enforcer     │  │
│  │  - Credential broker  │  │
│  │  - Audit logger       │  │
│  └──────────┬────────────┘  │
│             │               │
│  ┌──────────▼────────────┐  │
│  │  HTTP Bridge          │  │
│  │  Template rendering   │  │
│  │  Response parsing     │  │
│  └──────────┬────────────┘  │
└─────────────┼───────────────┘
              │ (HTTP)
    ┌─────────▼──────────┐
    │ Backend Services   │
    │ Prometheus, Ollama  │
    │ Grafana, weft-intel │
    │ Gitea, NEXUS, etc.  │
    └────────────────────┘
```

### Trust Boundaries

1. **MCP Client → LOOM Runtime** — Claude Desktop sends tool calls via stdio. LOOM trusts that the MCP protocol framing is valid but does not trust the content of parameters.
2. **LOOM Runtime → Security Layer** — Every tool call passes through trust enforcement, credential resolution, and audit logging before execution.
3. **Security Layer → HTTP Bridge** — The bridge renders templates and makes HTTP calls to backend services. Credentials are injected here, never stored in agent configs.
4. **HTTP Bridge → Backend Services** — LOOM acts as a proxy. Backend services authenticate LOOM via tokens/credentials, not the end user.
5. **Agent → Agent** (mesh) — Cross-agent invocations require Trust Tier 3+. Lower-tier agents cannot call other agents' tools.

---

## 2. Threat Catalog

### T1: Prompt Injection via Tool Parameters

**Risk:** An attacker crafts a tool parameter (e.g., a search query or entity name) that, when forwarded to a backend LLM, causes it to ignore its system prompt and execute arbitrary instructions.

**Attack vector:** The `ask_intel` tool accepts a free-text `question` parameter and forwards it to weft-intel's RAG pipeline, which uses an LLM. A malicious question could inject instructions into that LLM's context.

**LOOM controls:**
- **Template rendering is string-only.** The HTTP bridge uses `{{param}}` substitution, not code execution. Parameters are interpolated as literal strings into URLs, headers, and JSON bodies.
- **No prompt construction in bridge agents.** Bridge agents don't build prompts — they forward parameters to backend APIs. The prompt security boundary is at the backend, not LOOM.
- **Orchestrating agents separate system/user context.** The `daily-ops` agent constructs LLM prompts with data in a structured format, not by concatenating user input into the system prompt.

**Residual risk:** Backend services (weft-intel) that use LLMs are responsible for their own prompt injection defenses. LOOM cannot sanitize what it doesn't interpret.

**Framework mapping:**
| Control | OWASP Agentic | OWASP LLM | NIST AI RMF | MAESTRO |
|---------|---------------|-----------|-------------|---------|
| String-only templating | #1 Prompt Injection | #1 Prompt Injection | MS-2.7 | Prompt layer |
| Structured data in orchestrator prompts | #1 Prompt Injection | #1 Prompt Injection | MS-2.7 | Prompt layer |

---

### T2: Excessive Agency / Privilege Escalation

**Risk:** An agent performs actions beyond its intended scope — a read-only monitoring agent writes data, or a worker agent invokes destructive operations.

**Attack vector:** A misconfigured agent YAML declares `trust_tier: 1` (observer) but includes an `http_bridge` entry that uses POST. Or an agent attempts to call another agent's tools without authorization.

**LOOM controls (implemented):**
- **Trust tier enforcement at runtime.** Every HTTP bridge call passes through `TrustEnforcer.check_http_method()` before the request is sent. A T1 agent attempting POST is blocked with a `TrustViolation` exception.
  - **T1 (Observer):** GET, HEAD, OPTIONS only.
  - **T2 (Worker):** Adds POST, PUT, PATCH.
  - **T3 (Operator):** Adds DELETE and cross-agent invocation.
  - **T4 (Privileged):** Same as T3, but `requires_human_approval()` returns True (enforcement is a flag for future HITL gating).
- **Violations are blocked and logged.** Trust violations are never warnings — the operation fails, and the violation is recorded in the audit log with agent name, tier, action, and target URL.
- **Real-world validation.** During development, the trust enforcer caught that `weft-intel-bridge` was declared T1 but used POST for `ask_intel`. The system correctly blocked the call, forcing a config fix (upgrade to T2).

**Evidence from production:**
```
[trust_violation] weft-intel-bridge T1: http_POST — T1 agent cannot use POST.
    Allowed: ['GET', 'HEAD', 'OPTIONS'] target=http://localhost:9090/api/query
```

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Trust tier enforcement | #3 Excessive Agency | GV-1.3, MP-4.1 | Authorization layer |
| Method-level access control | #3 Excessive Agency | GV-1.3 | Authorization layer |
| Violation logging | #3 Excessive Agency | MS-2.6 | Observability layer |

---

### T3: Unsafe Credential Management

**Risk:** API tokens, passwords, or other secrets are exposed in agent configuration files, logs, or error messages. A compromised or malicious agent accesses credentials it shouldn't have.

**Attack vector:** A developer hardcodes a Bearer token in a YAML config and commits it to Git. Or an AI-generated agent config includes a credential in plaintext. Or one agent accesses another agent's API token.

**LOOM controls (implemented):**
- **Credential broker with per-agent access policy.** Secrets are stored in `~/.loom/secrets.json` (chmod 600, owner-only read). Each agent has an explicit allow-list in `credential_policy.json` defining which secrets it can access.
- **Runtime-only resolution.** Agent configs use `{{secret:key}}` placeholders. The broker resolves these at HTTP execution time — raw secrets never appear in YAML files, the registry, or MCP tool schemas.
- **Denied access is logged and blocked.** If an agent requests a secret it's not authorized for, the broker raises `CredentialDenied`, logs the attempt, and returns `***CREDENTIAL_DENIED***` (not the secret).
- **Secret redaction in audit logs.** The audit logger scans parameters for keys matching patterns like "token", "password", "secret", "authorization" and replaces their values with `***REDACTED***`.

**Current production state:**
```
Credential Policy:
  grafana-bridge     → grafana-basic-auth
  weft-intel-bridge  → weft-intel-token
  gitea-api-bridge   → (none)
  ollama-bridge      → (none)
  prometheus-bridge   → (none)
```

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Credential broker | #7 Unsafe Credential Mgmt | MAP-3.4 | Secrets management |
| Per-agent access policy | #7 Unsafe Credential Mgmt | MAP-3.4 | Authorization layer |
| Audit log redaction | #9 Insufficient Logging | MS-2.6 | Observability layer |

---

### T4: Insufficient Logging and Monitoring

**Risk:** Security-relevant events (tool calls, credential access, trust violations) go unrecorded, making it impossible to detect attacks, debug failures, or audit agent behavior.

**LOOM controls (implemented):**
- **Structured JSON Lines audit log.** Every event is a JSON object with: `event`, `agent`, `tool`, `parameters` (redacted), `status`, `duration_ms`, `timestamp`, and `chain_hash`.
- **Hash-chained entries for tamper evidence.** Each entry's `chain_hash` is the SHA-256 of the previous entry's JSON. If any entry is modified, deleted, or reordered, `verify_chain()` detects the break. The chain starts with a `GENESIS` hash.
- **Five event types logged:**
  - `tool_call` — every MCP tool invocation with timing and status.
  - `http_bridge` — every HTTP request with method, URL, status code, and timing.
  - `trust_violation` — every blocked action with severity "high".
  - `credential_access` — every secret request with granted/denied status.
  - `agent_lifecycle` — agent start, stop, build, error events.
- **CLI for log inspection.** `loom audit show` displays recent entries with rich formatting. `loom audit verify` checks chain integrity. Both support event-type filtering.

**Production metrics (as of this writing):**
- 292+ audit entries
- Chain integrity: verified valid
- Trust violations captured: 5+ (including the T1/POST real bug)
- Credential access events: 12+ granted, 8+ denied

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Structured audit log | #9 Insufficient Logging | MS-2.6 | Observability layer |
| Hash-chained entries | #9 Insufficient Logging | MS-2.6 | Integrity layer |
| Event-type coverage | #9 Insufficient Logging | MS-2.6 | Observability layer |

---

### T5: Unsafe Tool Orchestration

**Risk:** When agents can call other agents' tools (the "mesh"), a compromised or malfunctioning agent could chain tool calls to achieve effects that no single tool permits — e.g., reading intelligence data and exfiltrating it via an external API call.

**LOOM controls (implemented):**
- **Cross-agent invocation requires T3+.** The `TrustEnforcer.check_agent_invocation()` method blocks any agent below Tier 3 from calling another agent's tools. Currently only `daily-ops` (T3) has this capability.
- **All cross-agent calls are audited.** The MCP client logs every remote tool call with the calling agent's name, the target tool, parameters, and timing.
- **Declared consumption in config.** The `consumes` field in agent YAML explicitly lists which remote tools an agent intends to use. This is currently informational (not enforced), but provides a manifest for audit and review.

**Residual risk:** A T3 agent has broad access by design. The `daily-ops` agent can read from Prometheus, weft-intel, and Ollama. If the daily-ops agent were compromised, it could access all three. Mitigation: the daily-ops orchestrator code is hand-written (not AI-generated) and reviewed.

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Tier-gated invocation | #2 Unsafe Tool Orchestration | MS-2.5 | Authorization layer |
| Cross-agent audit trail | #2 Unsafe Tool Orchestration | MS-2.6 | Observability layer |

---

### T6: Supply Chain — AI-Generated Agent Configs

**Risk:** The Phase 2 generator uses a local LLM (Ollama) to produce agent YAML from natural language descriptions. A malicious or confused LLM could generate configs that: point to attacker-controlled URLs, request excessive trust tiers, or include hidden parameters.

**LOOM controls (implemented):**
- **Pydantic schema validation.** Every generated config is validated against the full `AgentConfig` schema. Invalid agent names, unknown fields, missing required parameters, and type mismatches are rejected.
- **Cross-field validation.** The loader checks that every `http_bridge` entry references a tool that exists in `exposes`, and that URL templates reference parameters that are defined.
- **Self-correcting retry.** If validation fails, the generator feeds the errors back to the LLM and retries. This catches structural issues but does not catch semantic attacks (e.g., a valid-but-malicious URL).
- **Dry-run mode.** `loom generate --dry-run` validates without saving, allowing human review before the config is written to disk.

**Residual risk:** A structurally valid config that points to a malicious URL would pass schema validation. The current system does not verify that URLs point to known, trusted services. This is planned for Phase 3f (config signing and generated agent quarantine).

**Planned controls (not yet implemented):**
- **Generated agent quarantine.** AI-generated configs land in a staging directory and require explicit promotion before they can be registered or run.
- **Config signing.** YAML configs can be cryptographically signed; the runtime verifies signatures before loading.
- **URL allowlist.** Bridge URLs are checked against a set of known weftbox service endpoints.

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Schema validation | #8 Supply Chain | GV-6.1 | Validation layer |
| Dry-run / human review | #8 Supply Chain | GV-6.1, MP-2.3 | Staging gate |
| Config signing (planned) | #8 Supply Chain | GV-6.1 | Integrity layer |
| Quarantine (planned) | #8 Supply Chain | MP-2.3 | Staging gate |

---

### T7: Inadequate Sandboxing

**Risk:** An agent runs with the same OS-level permissions as the LOOM runtime itself. A compromised agent could access the filesystem, network, or other processes beyond its intended scope.

**Current state:** Agents run in-process (no sandboxing). All agents share the same Python process, filesystem, and network access. This is the primary security gap in the current implementation.

**Planned controls (Phase 3a):**
- **Docker container per agent.** Each agent runs in its own container with: read-only root filesystem, scoped writable volume, network limited to declared `consumes` targets, CPU/memory/time limits.
- **gVisor upgrade path.** For stronger kernel-level isolation, containers can be run with gVisor's `runsc` runtime.

**Compensating controls (currently active):**
- **Trust tier enforcement** limits what HTTP methods an agent can use, even without OS-level sandboxing.
- **Credential broker** prevents agents from accessing secrets they're not authorized for, even if they share a process.
- **Audit logging** provides detection capability — if an agent behaves unexpectedly, the audit trail captures it.

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Docker sandboxing (planned) | #6 Inadequate Sandboxing | MS-2.3 | Isolation layer |
| Trust tiers (compensating) | #3 Excessive Agency | GV-1.3 | Authorization layer |
| Audit logging (detection) | #9 Insufficient Logging | MS-2.6 | Observability layer |

---

### T8: Denial of Wallet / Resource Exhaustion

**Risk:** An agent makes excessive API calls (to paid LLM endpoints, metered APIs, or internal services), either through misconfiguration, a feedback loop, or malicious intent.

**Current state:** No per-agent rate limiting is implemented.

**Compensating controls:**
- **`max_execution_time` in agent config.** Each agent declares a timeout (e.g., 30s, 120s). The HTTP client enforces this at the request level.
- **Trust tiers limit scope.** T1 agents can only read; they cannot trigger expensive write operations or chain calls.
- **Ollama is local.** The most expensive LLM operation (text generation via the `ollama-bridge`) runs on local hardware — no API costs.

**Planned controls:**
- Rate limiting per agent per tool (Phase 3e).
- Cost tracking for cloud LLM calls via NEXUS routing stats.

**Framework mapping:**
| Control | OWASP Agentic | NIST AI RMF | MAESTRO |
|---------|---------------|-------------|---------|
| Execution timeout | #4 Denial of Wallet | MS-2.8 | Throttling layer |
| Rate limiting (planned) | #4 Denial of Wallet | MS-2.8 | Throttling layer |

---

## 3. Security Controls Summary

| # | Control | Status | Code Location | Evidence |
|---|---------|--------|---------------|----------|
| 1 | Trust tier enforcement | **Implemented** | `security/trust.py` | Real T1/POST violation caught and blocked |
| 2 | Credential broker | **Implemented** | `security/credentials.py` | 2 secrets, per-agent policy for 8 agents |
| 3 | Hash-chained audit log | **Implemented** | `security/audit.py` | 292+ entries, chain verified valid |
| 4 | Secret redaction | **Implemented** | `security/audit.py` | Tokens replaced with `***REDACTED***` in logs |
| 5 | Schema validation | **Implemented** | `config/schema.py`, `config/loader.py` | Pydantic v2, cross-field checks |
| 6 | Dry-run validation | **Implemented** | `cli.py`, `generator/agent_gen.py` | `loom validate`, `loom generate --dry-run` |
| 7 | Self-correcting generation | **Implemented** | `generator/agent_gen.py` | Retry with error feedback |
| 8 | Execution timeout | **Implemented** | Agent YAML `max_execution_time` | Per-agent, enforced by HTTP client |
| 9 | Docker sandboxing | **Planned** | Phase 3a | — |
| 10 | Input validation | **Planned** | Phase 3e | — |
| 11 | Config signing | **Planned** | Phase 3f | — |
| 12 | Generated agent quarantine | **Planned** | Phase 3f | — |
| 13 | Rate limiting | **Planned** | Phase 3e | — |
| 14 | Network isolation | **Planned** | Phase 3a | — |

---

## 4. Framework Cross-Reference

### OWASP Agentic Security Top 10 (2025)

| OWASP # | Threat | LOOM Control | Status |
|---------|--------|------|--------|
| 1 | Prompt Injection | String-only templating, structured orchestrator prompts | Implemented |
| 2 | Unsafe Tool Orchestration | Tier-gated cross-agent calls, audit trail | Implemented |
| 3 | Excessive Agency | Trust tier enforcement with 4 levels | Implemented |
| 4 | Denial of Wallet | Execution timeouts, local LLM preference | Partial |
| 5 | Insecure Output Handling | (Delegated to MCP client) | N/A |
| 6 | Inadequate Sandboxing | Docker containers planned; trust tiers compensate | Planned |
| 7 | Unsafe Credential Management | Credential broker, per-agent policy, redaction | Implemented |
| 8 | Supply Chain Vulnerabilities | Schema validation, dry-run; signing planned | Partial |
| 9 | Insufficient Logging | Hash-chained audit log, 5 event types | Implemented |
| 10 | Uncontrolled Autonomy | T4 human-in-the-loop flag | Partial |

### NIST AI Risk Management Framework (AI RMF 1.0)

| NIST Function | Subcategory | LOOM Control |
|---------------|-------------|------|
| GOVERN (GV) | GV-1.3 Risk tolerance | Trust tiers define acceptable actions per agent |
| GOVERN (GV) | GV-6.1 Supply chain | Schema validation, planned config signing |
| MAP (MP) | MP-2.3 Staged deployment | Dry-run validation, planned quarantine |
| MAP (MP) | MP-4.1 Risk controls | Trust enforcement, credential broker |
| MEASURE (MS) | MS-2.3 Isolation | Planned Docker sandboxing |
| MEASURE (MS) | MS-2.5 Validation | Pydantic schema, cross-field checks |
| MEASURE (MS) | MS-2.6 Monitoring | Hash-chained audit log |
| MEASURE (MS) | MS-2.7 Prompt security | String-only templating |
| MEASURE (MS) | MS-2.8 Resource limits | Execution timeouts |

### MAESTRO (Multi-Agent Security Threat and Risk Operations)

| MAESTRO Layer | LOOM Implementation |
|---------------|---------------------|
| Prompt layer | `{{param}}` string substitution, no code execution |
| Authorization layer | TrustEnforcer with 4 tiers, per-agent credential policy |
| Secrets management | CredentialBroker with file-based store and access policy |
| Observability layer | AuditLogger with hash chaining and 5 event types |
| Validation layer | Pydantic schema, cross-field checks, dry-run mode |
| Isolation layer | Planned Docker/gVisor sandboxing |
| Integrity layer | Planned config signing and generated agent quarantine |
| Staging gate | Dry-run validation, planned quarantine directory |
| Throttling layer | Execution timeouts, planned per-agent rate limiting |
| Network layer | Planned container network policies |

---

## 5. Residual Risks and Mitigations

| Risk | Severity | Mitigation | Timeline |
|------|----------|------------|----------|
| In-process agents share memory | High | Docker sandboxing (Phase 3a) | Next |
| No input validation on tool parameters | Medium | Type/length validation (Phase 3e) | Next |
| AI-generated configs not quarantined | Medium | Staging directory + signing (Phase 3f) | Planned |
| No rate limiting per agent | Medium | Per-agent throttle (Phase 3e) | Planned |
| Backend LLMs vulnerable to injection | Low | Out of LOOM scope; backend responsibility | N/A |
| Audit log on local filesystem | Low | Remote log shipping (future) | Future |

---

## 6. Incident Response

**Detection:** The audit log provides real-time visibility into all agent operations. Trust violations are logged with severity "high" and are queryable via `loom audit show --event trust_violation`.

**Investigation:** The hash chain ensures that audit entries cannot be tampered with after the fact. `loom audit verify` confirms chain integrity. Each entry includes agent name, action, target, parameters (redacted), timing, and timestamp.

**Containment:** An agent exhibiting unexpected behavior can be stopped by removing its YAML config from the agents directory and restarting the mesh. The credential broker can have its access revoked immediately via `loom secrets revoke <agent> <key>`.

**Recovery:** All agent configs are stored in Git (Gitea). The registry can be rebuilt by re-registering agents. Audit logs are append-only and hash-chained, providing a forensic record.

---

## 7. Design Decisions

| Decision | Rationale | Security Impact |
|----------|-----------|-----------------|
| YAML over Python for agent definitions | AI-generatable, human-reviewable, schema-validatable | Configs are data, not code — reduces arbitrary code execution risk |
| Per-agent credential policy | Least privilege — agents only access secrets they need | Limits blast radius of a compromised agent |
| Hash-chained audit log | Tamper evidence without external infrastructure | Enables forensic integrity verification |
| Trust tiers in config | Declarative, reviewable, enforced at runtime | Security posture is visible in the config, not hidden in code |
| Local LLM (Ollama) preference | No data leaves the machine | Eliminates cloud API data exposure risk |
| String-only template rendering | No code execution in parameter substitution | Prevents injection via template engine |

---

*This threat model is a living document. It will be updated as LOOM progresses through Phase 3 hardening (Docker sandboxing, input validation, config signing) and as new threat patterns emerge in the agentic AI landscape.*
