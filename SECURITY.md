# Security

Heddle is a security-focused MCP runtime. If you find a vulnerability in the security controls (trust enforcement, credential broker, audit logging, input validation, config signing, escalation rules), please report it.

## Reporting

Open a GitHub issue with the label `security`. If the issue involves credential exposure or a bypass of trust enforcement, please email instead of posting publicly.

## Scope

The following are in scope:
- Trust tier bypass (a T1 agent executing a write operation)
- Credential broker leaking secrets in logs, configs, or error messages
- Audit chain bypass or hash collision
- Input validation bypass allowing injection
- Escalation rule bypass
- Config signing bypass allowing unsigned configs to load

The following are out of scope:
- Vulnerabilities in backend services that Heddle bridges to (Prometheus, Grafana, Ollama, etc.)
- LLM prompt injection in backend RAG pipelines (Heddle forwards parameters as strings, not prompts)
- Issues requiring physical access to the server

## Design

See [docs/threat-model.md](docs/threat-model.md) for the full threat analysis with controls mapped to OWASP Agentic Top 10, NIST AI RMF, and MAESTRO.
