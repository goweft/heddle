# ADR-003: SQLite for the Agent Registry

**Status:** Accepted
**Date:** 2026-03-19 (original decision); documented retroactively 2026-04-15
**Deciders:** Steve Gonzalez

## Context

Heddle maintains a registry of all loaded agents and their exposed tools: which configs are active, what tools each one provides, their trust tiers, and metadata used for discovery by MCP clients. This state has to persist across restarts, support concurrent reads from the runtime and from CLI commands (`heddle list`, `heddle registry …`), and remain consistent under append-mostly workloads.

Options considered:

1. **SQLite** — single-file embedded database, ACID, full SQL, no daemon, ships in the Python stdlib.
2. **Postgres** (or similar external RDBMS) — more capable, requires a running server, needs connection pooling, brings an additional operational surface.
3. **Filesystem-as-database** — one JSON or YAML file per agent in a directory, filesystem semantics as the concurrency model.
4. **A NoSQL/document store** — overkill for the access patterns involved.

Two facts made the decision straightforward.

First, Heddle is self-hosted and local-first by design (see the project's core principles). Every additional daemon is additional operational cost for every single user — setup docs, port conflicts, backup stories, version compatibility. An embedded database avoids all of that.

Second, other WEFT-ecosystem projects (idea-hub, journal-app) had already settled on SQLite for similar local-first reasons, and that precedent had held up. Picking SQLite kept the project consistent with its neighbours without requiring new operational knowledge.

The filesystem-as-database option was briefly attractive for its simplicity but was rejected because registry integrity is a security property Heddle cares about (see MILESTONE-v0.2 Pillar 2: per-row HMAC and `heddle registry verify`). Enforcing integrity across loose files requires reinventing transaction semantics and atomic writes. SQLite already provides those primitives.

## Decision

Use SQLite as the backing store for the agent registry. The database file lives at `~/.heddle/registry.db`. Access goes through a single broker module; direct database access from elsewhere in the codebase is discouraged. Writes are transactional; reads can be concurrent (SQLite WAL mode).

Schema is managed via migrations — each schema change lands as a numbered migration script that the runtime applies idempotently on startup. No ORM; queries are parameterised SQL strings against a thin wrapper, consistent with how the rest of the codebase treats I/O.

## Consequences

**Positive:**
- Zero additional setup for users. `pip install` (or clone + venv) is the full install; no database server to configure, no schema bootstrapping to explain.
- ACID semantics come for free. The registry integrity work (HMAC per row, `heddle registry verify`) can rely on transaction boundaries rather than reinventing them.
- Backups are `cp ~/.heddle/registry.db backup.db` with the runtime stopped, or the SQLite online-backup API with it running. No pg_dump equivalent to learn.
- The file is inspectable from any machine: `sqlite3 ~/.heddle/registry.db` in a pinch, no credentials required.

**Negative:**
- Single-writer model. If Heddle's use cases ever include heavy concurrent writes across processes (not the current design), SQLite will become a bottleneck before Postgres would.
- SQL feature ceiling is lower than Postgres. Window functions and JSON operators exist but with fewer capabilities.
- No network access. If Heddle ever wants a shared registry across machines, the embedded model has to be replaced wholesale. That is an explicit non-goal as of v0.2.

**Mitigated by:**
- The broker module abstraction means replacing SQLite later (if ever warranted) is a bounded change. Code elsewhere calls the broker, not `sqlite3` directly.
- The access patterns (startup reads, occasional writes when agents register/deregister, audit query reads) are nowhere near SQLite's concurrency limits in practice.

## Alternatives considered

- **Postgres.** Rejected because it imposes operational cost on every user for a capability (multi-writer network DB) Heddle doesn't need. Heddle is not a multi-tenant service; it's a single-user runtime.
- **Flat files per agent.** Rejected because integrity guarantees would have to be reinvented, and because registry-wide queries (e.g., "list all tools across all agents at trust tier ≥ 2") are natural in SQL and awkward in filesystem traversal.
- **In-memory only, rebuild from YAML on startup.** Tempting — the YAML configs are already the source of truth for what agents exist. Rejected because (a) audit metadata accumulates over time and doesn't live in the YAML, (b) cross-session state (last successful load, last seen tool version, registry row HMAC) needs durable storage, and (c) startup scans over N configs don't scale beyond a handful.
