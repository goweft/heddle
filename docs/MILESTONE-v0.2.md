# Heddle v0.2 — Milestone Scope

**Declared:** 2026-04-15
**Target:** TBD (not date-bound; scope-bound)
**Predecessor:** v0.1.0 (shipped 2026-03; 137 tests, 15 security controls, blog post live, 6 starter packs)

## Why this milestone exists

v0.1 shipped without a declared finish line; v0.2 is being declared up front so scope stays bounded and "Phase 3" stops being used as a catch-all label for whatever security work happens to land. The original LOOM-era CLAUDE.md described a six-part Phase 3 (3a–3f) of which 3b/3c/3e plus most of 3d/3f are already shipped. v0.2 closes the remaining 3a/3d/3f gaps and clears the loom→heddle naming sediment that's accumulated since the rename.

**Out of scope for v0.2** (parking lot, not commitments): Phase 4 mesh/orchestration, PyPI publish, web UI, gVisor upgrade, CAS integration, evolve system promotion to public repo.

---

## Pillar 1 — Sandboxed execution (Phase 3a)

The biggest unshipped Phase 3 control. Today every Heddle config runs in the same process as the runtime; trust tiers gate behaviour but not blast radius. v0.2 makes the trust tier a real isolation boundary.

**Definition of done:**
- Each agent config can opt into Docker-based execution via `runtime.sandbox: docker` in YAML (default remains `none` for backward compat).
- Sandboxed agents run in a per-config container with: read-only root filesystem, scoped writable volume at `/var/heddle/agent`, network access restricted to hosts declared in the config's `consumes` / `http_bridge` URLs (egress allowlist), CPU and memory limits enforced via Docker `--cpus` / `--memory`.
- Container image is pinned by digest, not tag, in the runtime config.
- Tier 4 (privileged) configs cannot opt out of sandboxing.
- Tests cover: egress to a non-allowlisted host is blocked; write to `/` is denied; OOM kill is captured and surfaced as a structured audit event.
- Documented in `docs/sandboxing.md` with a worked example.

**Explicit non-goals:** gVisor, Firecracker, rootless Docker rework. Stock Docker is the v0.2 floor.

---

## Pillar 2 — Phase 3d/3f leftovers (close the story)

Four small items that finish the audit and supply-chain narrative the blog post already implies is complete.

**Definition of done:**
- **Anomaly flags (3d):** runtime emits a typed `AuditAnomaly` event when (a) a config calls a tool it has never previously called within a configurable window, (b) tool call rate exceeds the per-config rate-limit threshold, (c) a credential is requested that was previously denied for that config. Flags are written to the same hash-chained audit log with `event_type: anomaly`.
- **Audit query CLI (3d):** `heddle audit show` (filter by config, tool, time range, event type) and `heddle audit verify` (walks the hash chain, reports break point if any). Both render via Rich tables. No new dependencies.
- **Dependency pinning (3f):** `pyproject.toml` pins all runtime dependencies to exact versions; CI (or a `make` target) runs `pip-audit` against the lock and fails on known CVEs.
- **Registry integrity (3f):** the SQLite registry has a per-row HMAC computed from row contents + a runtime key; `heddle registry verify` recomputes and reports tampering. Registry writes go through a single broker that signs new rows; direct INSERTs from outside the broker fail verification.

---

## Pillar 3 — Loom→Heddle cleanup

Naming sediment from the rename. Each item is small individually; together they remove the "wait, is this still LOOM?" friction for any new contributor or reviewer.

**Definition of done:**
- Project directory renamed `/mnt/workspace/projects/loom/` → `/mnt/workspace/projects/heddle/`. All local tooling (Claude Desktop MCP entry, weft-dev paths, session-log conventions, `.reality-check` if affected) updated. Gitea remote URL updated. Git history preserved.
- `loom-dashboard.service` and `loom-intel-bridge.service` either renamed to `heddle-*` or deleted if unused. Confirm against `systemctl list-units` before deletion.
- `heddle_dashboard.py` moved from project root into `src/heddle/` (with import-path updates and the systemd unit pointing at the new location).
- `heddle_stdio_mesh.py` reviewed for the same — likely also belongs in `src/heddle/`.
- `docs/decisions/` populated with at least three ADRs covering: (1) YAML over Python for agent definitions, (2) FastMCP over raw MCP SDK, (3) SQLite over external DB. These are decisions already made; this is documentation debt, not new design work. After v0.2 the directory should never be empty again.
- Blog post and README updated to reflect actual current test count (whatever it is at v0.2 ship), not the stale 126 figure.

---

## Definition of "v0.2 shipped"

All three pillars complete, `pytest -q` green, `heddle audit verify` returns clean on a freshly populated chain, demo GIF re-recorded if the CLI surface changed enough to warrant it, and a tagged release `v0.2.0` pushed to `origin` (github.com/goweft/heddle). Optional: short follow-up dev.to post — only if there's something genuinely new to say to the audience the v0.1 post reached, otherwise the changelog is enough.

## What this doc explicitly is NOT

- A timeline. There is no v0.2 ship date. Pillars complete in whatever order makes sense. If burling needs attention, burling gets it.
- A feature wishlist. Anything not above is parking-lot. New ideas during v0.2 work go into a `SCOPE-CREEP-PARKING-LOT.md` (to create on first use), not into this doc.
- A reason to slow down community engagement on v0.1. Reddit/blog/selfh.st response work continues in parallel and outranks v0.2 implementation when both compete for time.
