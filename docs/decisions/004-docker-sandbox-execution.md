# ADR-004: Docker-based Sandbox Execution for Pillar 1

**Status:** Accepted
**Date:** 2026-05-06 (proposed); accepted 2026-05-16
**Deciders:** Steve Gonzalez
**Supersedes:** none
**Related:** MILESTONE-v0.2.md Pillar 1; OWASP Agentic #6 (Inadequate Sandboxing); NIST AI RMF MS-2.3

## Context

Today every Heddle agent runs in the same process as the runtime. Trust tiers gate *behaviour* (which HTTP methods are allowed, which credentials can be requested) but not *blast radius* — a compromised T1 prometheus-bridge has the same filesystem and network reach as the broker itself. Pillar 1 of v0.2 makes the trust tier a real isolation boundary by running each opt-in agent inside a Docker container.

The existing `src/heddle/security/sandbox.py` is a config *generator*: it reads agent YAML and produces a `docker run` arg list and a network-policy dict. Nothing in the runtime ever execs those args. A 2026-05-05 assessment (logged to helm session 37) catalogued the gaps in detail. This ADR fixes the three load-bearing decisions that were left ambiguous in the original 213-line module:

1. **How sandboxed agents actually execute** — the seam between the broker and `docker run`.
2. **How egress allowlists are enforced** — currently the generator emits a policy dict that nothing reads.
3. **What "resource caps" includes** — the current `--cpus` / `--memory` are necessary but not sufficient.

Two host-side concerns are coupled to those decisions: how `heddle-dashboard.service` itself stays trustworthy when it now mints containers, and how Claude Desktop's stdio child (`heddle-mesh`) interacts with a containerised execution model.

The milestone explicitly rules gVisor, Firecracker, and rootless Docker out of scope for v0.2. Stock Docker is the floor.

## Decision

### 1. Docker execution pattern: broker-spawned subprocess with a Python-side watchdog

The broker process (`heddle-mesh` or the dashboard, depending on entry point) keeps running on the host. Per-agent containers are spawned by `subprocess.Popen(["docker", "run", ...])` from a new module `src/heddle/runtime/sandboxed_runner.py`. The runner returns a `SandboxedAgent` handle that exposes the same call surface as today's in-process agents (the `MCPClient` interface), but each tool call is forwarded over a stdio pipe to the agent process inside the container.

A Python-side watchdog (`asyncio.wait_for` around the call, plus a `docker container kill --signal=KILL <name>` on timeout) enforces wall-clock execution caps. `--stop-timeout` is **not** used as a runtime cap — that flag is the SIGTERM→SIGKILL grace period during `docker stop`, not a max-execution-time, and the current code's use of it is wrong.

The Docker CLI is invoked rather than the `docker` Python SDK because (a) it keeps the dependency surface unchanged (no `docker-py`, which pulls in `requests` + `websocket-client`), (b) the arg list is already the source-of-truth artefact in `SandboxManager.generate_docker_run_args`, and (c) failure modes are easier to debug from `docker logs <name>` when the args are exactly what we'd type.

Compose / Swarm / Kubernetes are not used. v0.2 is single-host by design (see ADR-003); container orchestration on top of Docker is unnecessary complexity for "one short-lived container per agent invocation".

### 2. Egress allowlist: `--network=none` + per-agent user-defined bridge with explicit DNS, iptables enforced inside the container

The current generator's behaviour — `network=bridge` whenever `allowed_hosts` is non-empty — gives the agent **full bridge-net egress**, including 172.17.0.1 (the Docker host gateway) and any other container on the default bridge. The "allowlist" is fictional. This is the most over-claimed control in the codebase today.

The replacement, in priority order:

1. **No declared hosts → `--network=none`.** Confirmed working in the assessment: DNS dies, no outbound. This is the default for any T1 agent without `http_bridge` or `consumes` entries.
2. **Declared hosts → per-agent user-defined network.** A bridge network named `heddle-<agent>` is created on first run (`docker network create --driver=bridge --internal heddle-<agent>`) — the `--internal` flag prevents the bridge from reaching the default route, so the only reachable hosts are ones the broker explicitly attaches to that network or exposes via DNS aliases.
3. **Localhost-on-host services** (the prometheus-bridge case: `localhost:9090`) are reached via `--add-host=host.docker.internal:host-gateway` and the agent rewrites `localhost` → `host.docker.internal` at config-load time. The broker also sets per-host firewall rules on the host side (nftables `inet heddle` table, populated from the agent's allowlist) to drop outbound from the container's IP range to anything outside the declared host:port set. Falling back to host-side enforcement is necessary because Docker's per-container egress policy is anaemic.
4. **DNS** is set to `--dns=127.0.0.11` (Docker's embedded resolver on the user-defined bridge) and the broker writes a per-agent `--dns-search` such that only declared hostnames resolve. Any non-declared lookup returns NXDOMAIN.

The `generate_network_policy()` dict that's currently advisory becomes the input to (a) the `docker network create` call, (b) the nftables ruleset writer, and (c) an audit event emitted at sandbox start. Egress denial events from nftables logs are tailed by the broker and surfaced as `event_type: egress_denied` in the audit log.

This is more moving parts than "just use Docker network policies" because Docker doesn't have per-container egress rules — the platform forces the choice between iptables/nftables on the host or a sidecar proxy. The sidecar option (per-container Envoy or tinyproxy) was rejected; see Alternatives.

### 3. Resource caps: full hardening flag set, trust-tier matrix, image digest pinning

The current generator emits `--cpus`, `--memory`, `--read-only`, `--tmpfs`, and a writable volume. The assessment confirmed all four work as intended on this host. Six flags must be added before claiming Pillar 1 done:

| Flag | Value | Reason |
|---|---|---|
| `--cap-drop=ALL` | always | Default container has ~14 capabilities including `setuid`, `net_raw`, `mknod`. None are needed by an HTTP-bridge agent. |
| `--security-opt=no-new-privileges:true` | always | Prevents setuid escalation inside the container. Currently `NoNewPrivs: 0`. |
| `--pids-limit=N` | T1: 64, T2: 128, T3: 256, T4: 512 | Prevents fork bombs. Currently `pids.max = 115345` (host default). |
| `--user=65534:65534` | always (T1–T3) | Run as `nobody:nogroup`. T4 may opt into a different uid via `runtime.user` (e.g. for agents that need to write to a host-uid-owned volume). |
| `--security-opt=seccomp=…` | default profile (T1–T2), custom narrow profile (T3+) | The default Docker seccomp profile already blocks ~44 syscalls; T3+ ships a stricter custom profile dropping `ptrace`, `keyctl`, `clone3` flags we don't need. |
| Image pinned by digest | `python:3.12-slim@sha256:46cb…` | Milestone DoD requirement. The hardcoded `python:3.12-slim` tag is reproducibility theatre; an upstream tag-overwrite compromises every agent. |

Image digest pinning lives in a new file `src/heddle/runtime/images.yaml`, not in agent configs. Each entry maps a logical name (`python-3.12-slim`) to a digest plus a refresh date. A `heddle images refresh` CLI re-pulls and updates the digest; refreshes are committed and reviewed.

The trust-tier resource matrix (memory / cpu / pids / image) lives in `src/heddle/security/sandbox_policy.py` and is the single source of truth. `SandboxConfig` reads from it rather than carrying defaults inline (the current dict literal at sandbox.py:97 is replaced).

The container's writable volume moves from `/data` (in-container) + a legacy `/tmp`-based path (host) to `/var/heddle/agent` (in-container, per milestone DoD) + `~/.heddle/sandbox/<agent>/data` (host, mode 0700). The host temp path is removed: `/tmp` is world-readable on shared systems. T1 agents get **no** writable volume by default — the bug at sandbox.py:107 where it's set unconditionally is fixed; the `validate_sandbox` warning becomes load-bearing.

### 4. heddle-dashboard.service implementation strategy

The dashboard process is the trust root: it holds the registry HMAC signing key, writes the audit chain, and now mints containers. Sandboxing the dashboard *itself* in Docker is rejected — it would need the Docker socket bind-mounted in (handing it back the keys to the kingdom) and would block access to `~/.heddle/registry.db`, `~/.heddle/audit/audit.jsonl`, `~/.heddle/secrets.json`, and `~/.heddle/registry.key`, which are the broker's reason for existing.

Instead, host-side hardening via systemd directives. The `heddle-dashboard.service` unit gains:

```
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.heddle
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SupplementaryGroups=docker
```

`SupplementaryGroups=docker` (rather than running as root) gives the service Docker socket access via the docker group. The service does not run as root; it runs as the user that owns `~/.heddle`. `ProtectHome=read-only` + `ReadWritePaths=%h/.heddle` confines write access to the heddle state directory only — the rest of the user's home is invisible-or-read-only to the broker.

The unit file is committed to the repo at `packs/systemd/heddle-dashboard.service` (template; the user's installed unit at `/etc/systemd/system/` is generated from it via `heddle install --systemd`). Any stale prior-name service unit, if present, is removed.

### 5. Claude Desktop configuration strategy

Claude Desktop launches `heddle-mesh` as a stdio child via the user's `claude_desktop_config.json`. With sandboxed execution, the picture is:

- `heddle-mesh` runs **on the host** (not inside a container). It needs Docker socket access to spawn agent containers, host-side nftables capability for egress enforcement, and access to `~/.heddle/*` for credentials and registry.
- The Claude Desktop config does **not** change. It still points at `heddle-mesh` on the user's PATH:
  ```json
  {"mcpServers": {"heddle": {"command": "/path/to/venv/bin/heddle-mesh"}}}
  ```
- Per-agent containers are children of the mesh process. The mesh adopts a launch-on-first-call pattern: containers are spawned lazily when the first tool call routes to that agent, and reaped after a configurable idle timeout (default 5 minutes). This avoids paying container-startup latency on every tool call while keeping the steady-state footprint small.
- For agents that opt out of sandboxing (`runtime.sandbox: none`, the default), behaviour is unchanged from today — they execute in-process. Claude Desktop sees no difference. This preserves backwards compatibility for v0.1.x configs.
- Tier 4 configs cannot opt out: the loader rejects `sandbox: none` for `trust_tier: 4` with a clear error, in line with the milestone DoD.
- Latency budget: container cold start for `python:3.12-slim` is ~250–600 ms on this host; the lazy-spawn-and-keep-warm policy means only the first tool call per agent per 5-minute window pays it. Claude Desktop's tool-use timeout (default 60s) is comfortably above that.

## Consequences

**Positive:**
- Trust tier becomes a real isolation boundary, not just a behavioural policy. A compromised T1 agent cannot read `~/.ssh/`, cannot reach hosts outside its allowlist, cannot fork-bomb the host, cannot escalate via setuid binaries.
- The sandbox config generator, currently advisory, becomes load-bearing — every flag it emits is exercised by the runtime.
- Image-digest pinning closes the supply-chain gap that complements Pillar 2's dependency pinning. Docker Hub tag-overwrite no longer compromises every agent silently.
- Audit visibility improves: container start/exit, egress-denied, OOM-killed are all distinct event types in the chain. `audit_sandbox_config()`, currently dead code at sandbox.py:158, is wired into the runner.
- The dashboard's own attack surface shrinks via systemd hardening — it can lose Docker-socket access to a compromise but the rest of the host filesystem is out of reach.

**Negative:**
- Docker becomes a hard runtime dependency for any sandboxed agent. The "Docker not available — sandboxing disabled" warning at sandbox.py:68 becomes a clear error when an agent declares `sandbox: docker`.
- nftables / iptables capability requirement on the broker's user is new operational surface. Documented in `docs/sandboxing.md`.
- Container cold-start latency (250–600 ms first call) is visible in tool-use traces. The lazy-keep-warm policy mitigates steady-state but the first call after idle is slower.
- More moving parts in the broker: process supervisor for warm containers, idle reaper, nftables ruleset writer, Docker network lifecycle. Each is a small piece of code but together they're a non-trivial complexity bump.
- Per-agent user-defined networks accumulate over time if not cleaned up. The broker has to garbage-collect `heddle-<agent>` networks for agents that have been removed from configs.

**Mitigated by:**
- The opt-in via `runtime.sandbox: docker` means existing v0.1 deployments are unaffected. Sandboxing rolls out one agent at a time.
- Failure to acquire Docker / nftables / network-create capability fails *closed*: the agent does not start. There is no "sandbox attempted but couldn't enforce so we ran in-process anyway" path.
- The image refresh CLI (`heddle images refresh`) is a manual step, not automatic — digest changes require a human review, which is the trade-off for reproducibility.

## Alternatives considered

- **Sidecar proxy (per-container Envoy or tinyproxy) for egress enforcement.** Rejected. Each agent container would need a co-process; the operational story is heavier than nftables-on-host, and the proxy itself becomes a trust-sensitive component (TLS interception, cert handling). nftables rules driven by the same allowlist data are simpler and don't add a long-lived proxy process per agent.
- **Bind-mount Docker socket into a sandboxed broker.** Rejected emphatically. Mounting `/var/run/docker.sock` into a container gives that container full root on the host (it can `docker run --privileged -v /:/host`). Sandboxing the broker by handing it the keys defeats the purpose.
- **`docker-py` SDK instead of subprocess.** Rejected. Adds two dependencies (`requests`, `websocket-client`), neither pinned today; doesn't change the arg list which is the artefact under test; and the failure modes (timeouts, daemon-down) are harder to reason about than `subprocess.Popen` + watchdog.
- **gVisor / Firecracker / Kata.** Out of scope per milestone. Worth revisiting in a v0.3 ADR if the threat model expands beyond "compromised agent on a single-user host".
- **Rootless Docker.** Out of scope per milestone. Reduces host blast radius further but reworks the install story; v0.2 keeps stock Docker as the floor and lets users opt into rootless on their own.
- **One long-lived container per agent (vs. one per invocation).** Selected via the lazy-spawn-and-keep-warm policy: per-invocation cold-start would dominate latency; per-process-lifetime would hold resources for idle agents. Five-minute idle reap is the compromise; it's tunable via `runtime.sandbox_idle_timeout`.
- **Compose / Swarm / Kubernetes.** Rejected. Single-host design. ADR-003 already commits to local-first; layering an orchestrator on Docker is operational cost without a benefit.
- **Sandboxing the dashboard inside a container.** Rejected as discussed in §4 — it is the trust root and needs host paths; systemd hardening achieves the same defence-in-depth without the chicken-and-egg problem.
