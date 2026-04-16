# ADR-002: FastMCP over Raw MCP SDK

**Status:** Accepted
**Date:** 2026-03-19 (original decision); documented retroactively 2026-04-15
**Deciders:** Steve Gonzalez

## Context

Heddle auto-generates MCP servers from YAML configs. The core question was whether the runtime should target the low-level MCP SDK (building JSON-RPC message handlers, transport plumbing, capability negotiation by hand) or FastMCP (a higher-level decorator-driven framework that wraps the SDK).

The project had a prior data point. An existing weftbox-ssh MCP server was written in FastMCP, had shipped, and was running reliably in production against Claude Desktop. That was concrete evidence FastMCP handled the protocol surface Heddle would depend on (tool discovery, tool invocation, stdio transport).

Arguments for raw SDK:
- Full control over protocol details, including capabilities and transports that FastMCP might not expose yet.
- No dependency on an abstraction that could lag behind the spec.
- Fewer moving parts for a security-focused project that values surface minimisation.

Arguments for FastMCP:
- Substantially less boilerplate per tool. A tool is a decorated function; parameter schemas are inferred from type hints.
- Heddle *auto-generates* servers from config. The less code per generated server, the less surface to get wrong.
- Proven path via the weftbox-ssh precedent.
- The abstraction is transparent enough that if it later lags the spec, escape hatches to the raw SDK are practical rather than requiring a rewrite.

## Decision

Use FastMCP for the MCP server layer. The Heddle runtime translates each validated YAML config into a FastMCP server instance, registering declared tools as FastMCP `@tool`-decorated handlers. The handlers are not user-facing — they are internal shims that route calls through Heddle's dispatch pipeline (rate limiting → access mode check → escalation rules → trust tier enforcement → input validation → handler execution).

When FastMCP doesn't expose something Heddle needs (e.g., a specific transport detail), drop to the raw SDK for that single piece rather than rewriting the whole layer.

## Consequences

**Positive:**
- Every generated MCP server is small and consistent in shape. There is one code path for translating a YAML config into a running server, and it exercises FastMCP's public API, not bespoke JSON-RPC handling.
- Onboarding cost for reading the runtime is lower — contributors familiar with FastMCP patterns from any other project can navigate Heddle's MCP layer immediately.
- The dispatch pipeline (the actual security work) is cleanly separated from the protocol layer. FastMCP handles "how does MCP work"; Heddle handles "should this call be allowed, logged, and rate-limited."

**Negative:**
- Heddle inherits whatever assumptions FastMCP makes. If the MCP spec evolves in a way FastMCP is slow to follow, Heddle is blocked until either FastMCP catches up or Heddle implements the new piece against the raw SDK.
- FastMCP's error handling, logging format, and transport selection are less visible than if Heddle owned the full stack. The audit log explicitly re-captures information that crosses the FastMCP boundary so that the hash-chained log is the canonical record of what happened, not FastMCP's internal logs.

**Mitigated by:**
- The auto-generation architecture means the cost of switching to raw SDK later is bounded: one translator module would need replacing, not every agent. YAML configs are SDK-agnostic.
- The test suite exercises the full dispatch pipeline against real FastMCP server instances, so FastMCP-layer regressions surface in CI.

## Alternatives considered

- **Raw MCP SDK.** Rejected because per-server boilerplate in an auto-generation context multiplies: every YAML config produces a server, and each server with raw-SDK boilerplate is more lines that have to be generated correctly.
- **A custom JSON-RPC layer targeting the MCP spec.** Rejected outright. Writing a from-scratch implementation of a protocol that other people already maintain a working Python library for is the textbook definition of avoidable work for a solo-maintained project. This option was never seriously on the table, but is listed for completeness.
