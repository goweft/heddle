# ADR-001: YAML for Agent Definitions

**Status:** Accepted
**Date:** 2026-03-19 (original decision); documented retroactively 2026-04-15
**Deciders:** Steve Gonzalez

## Context

Heddle (then named LOOM) needed a way to define MCP tool servers — what tools they expose, what they consume, what trust tier they run at, what HTTP APIs they bridge to. Two shapes were viable:

1. **Python-first:** Each agent is a Python module with decorated functions, subclassing a base runtime class. The tool schema is inferred from type hints. The runtime imports and instantiates it.
2. **Config-first:** Each agent is a declarative YAML file. The runtime interprets the file and spins up an MCP server from it. Custom logic, when genuinely needed, lives in separate Python modules referenced by the config.

The core tension: Python-first is more expressive and lets you "just write code." Config-first trades expressiveness for a structural property — the agent surface is machine-readable without executing anything.

Three things made the machine-readability property decisive:

- **AI generation.** A major premise of the project is that Claude should be able to scaffold new agents from natural language. Generating validated YAML against a JSON Schema is meaningfully easier — and meaningfully safer — than generating Python that has to import correctly, pass type checks, and not contain arbitrary side effects at import time.
- **Security review.** A reviewer (human or automated) can inspect a YAML file and see the entire agent surface: every tool, every external host it talks to, every secret it requests, its declared trust tier. A Python module hides those behind imports, decorators, and conditional branches. "What does this agent actually do" is answerable by reading a YAML file in a way it isn't for arbitrary code.
- **Schema as the contract.** Access-mode annotations (`access: read` / `access: write`) and trust-tier declarations need to be validated *at load time*, before any code runs. That's much cleaner to enforce against a schema than against a Python module.

## Decision

Agents are defined as YAML files validated against a Pydantic/JSON Schema model. The runtime loads the YAML, validates it, and constructs the MCP server from the config. When an agent genuinely needs custom logic that can't be expressed declaratively — computed tool outputs, non-HTTP backends, composite behaviour — that logic lives in a separate Python module registered via a named handler in the config, not inline in the YAML.

Custom-logic agents live in `src/heddle/agents/` and are registered by name. The YAML still declares the tool surface, trust tier, access modes, and secret references; the Python module only provides the handler function.

## Consequences

**Positive:**
- The agent surface is fully inspectable without executing code.
- AI-generated configs can be schema-validated and dry-run tested before being allowed to register. Generated configs that parse as valid YAML but violate the schema are rejected mechanically, not by review.
- Trust tier and access-mode enforcement happen at load time: a T1 config with a write-annotated tool is rejected before the server starts, which is the earliest possible failure point.
- Config signing (HMAC-SHA256) is meaningful because the signed artifact is the complete agent definition — not a reference to code that could change independently.

**Negative:**
- Genuinely novel agent behaviour requires both a YAML file and a Python module. Contributors have to learn both shapes.
- The declarative schema has to grow when a new kind of behaviour becomes common (e.g., adding `http_bridge` was a schema change). There is a real risk of the schema becoming a poor-man's programming language over time.
- Debugging is less immediate than "set a breakpoint in the module" — the runtime's interpretation of the config is what executes, not the config itself.

**Mitigated by:**
- Keeping the schema intentionally small and pushing anything that feels like programming (conditionals, loops) into registered handler modules.
- Shipping starter packs (`packs/`) as worked examples so contributors have reference shapes to copy.

## Alternatives considered

- **Python decorators on top of FastMCP directly.** Rejected because it hides the agent surface behind imports and decorator side effects, and because AI-generating Python that imports cleanly is harder than AI-generating schema-validated YAML.
- **TOML or JSON instead of YAML.** YAML won on human-readability of nested structures (tool parameter definitions, HTTP bridge mappings). TOML is fine for flat config, awkward for nested. JSON is machine-friendly but punishing to hand-edit.
