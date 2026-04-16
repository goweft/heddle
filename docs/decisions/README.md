# Architecture Decision Records

This directory contains Heddle's Architecture Decision Records (ADRs). Each ADR documents one significant design decision: the context that prompted it, the decision itself, and the consequences that followed.

The format is Michael Nygard's lightweight ADR template:

- **Status** — accepted, superseded, deprecated, etc.
- **Context** — what problem or force drove the decision
- **Decision** — what was chosen
- **Consequences** — what happens as a result (positive, negative, mitigations)
- **Alternatives considered** — what else was on the table and why it lost

ADRs are additive. A superseded decision keeps its ADR; a new ADR supersedes it and links back. Decisions are never silently changed; if the codebase diverges from an ADR, the ADR is updated or a new one is added.

## Index

| # | Title | Status |
|---|-------|--------|
| [001](001-yaml-for-agent-definitions.md) | YAML for Agent Definitions | Accepted |
| [002](002-fastmcp-over-raw-mcp-sdk.md) | FastMCP over Raw MCP SDK | Accepted |
| [003](003-sqlite-for-registry.md) | SQLite for the Agent Registry | Accepted |

## Why these three first

Heddle's v0.2 milestone (see `docs/MILESTONE-v0.2.md`) Pillar 3 explicitly called out that `docs/decisions/` was empty despite the project's CLAUDE.md having planned ADRs since inception. The first three documented here are retroactive — they describe decisions that were made early in the project, have held up, and are load-bearing for everything built on top. They are documented now so that subsequent decisions have a precedent to link back to.
