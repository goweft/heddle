# Heddle Sandboxing

Container-based agent isolation. Each opt-in agent runs in its own
short-lived Docker container with a read-only root, capped resources,
a dropped capability set, and (in v0.2) a `--network=none` baseline.

For the design rationale see
[ADR-004](decisions/004-docker-sandbox-execution.md). For the
milestone DoD see [MILESTONE-v0.2.md §Pillar 1](MILESTONE-v0.2.md).

## What sandboxing protects against

| Threat | Without sandboxing | With sandboxing |
|---|---|---|
| Compromised agent reads `~/.ssh/` | Same uid as broker | `/` is read-only, host paths invisible |
| Agent escalates via setuid binary | Possible | `--security-opt=no-new-privileges`, `--cap-drop=ALL` |
| Fork bomb / runaway process | Eats host PIDs | `--pids-limit` per tier |
| Memory leak takes down the host | Possible | `--memory` cap, OOM kill at the boundary |
| Agent reaches arbitrary internet hosts | Possible | `--network=none` baseline (T2+ with declared hosts uses `bridge` today; per-host nftables enforcement is v0.3) |
| Upstream image tag overwritten | Silent compromise of every agent | Pinned `image@sha256:...` |
| Privileged tier opts out by accident | Silent — depends on author | Loader rejects `sandbox: none` for `trust_tier: 4` |

## Quick start

Add `sandbox: docker` to the agent's `runtime` block:

```yaml
agent:
  name: my-bridge
  runtime:
    sandbox: docker      # opt in
    trust_tier: 2
    max_execution_time: 30s
```

Inspect what the runtime would spawn:

```
$ heddle sandbox agents/my-bridge.yaml
Sandbox: my-bridge
  Image: python:3.12-slim@sha256:401f6e1a67dad…
  Memory: 512m  |  CPU: 0.5
  Network: none  |  Read-only: True
  Timeout: 30s
  Docker: available

  Docker run args:
    --rm
    --name=heddle-my-bridge
    --memory=512m
    --cpus=0.5
    --pids-limit=128
    --user=65534:65534
    --cap-drop=ALL
    --security-opt=no-new-privileges:true
    --read-only
    --network=none
    --tmpfs=/tmp:rw,noexec,nosuid,size=64m
    --stop-timeout=30
```

The default (`sandbox: none`) keeps existing agents in-process — no
behavior change for v0.1.x configs.

## Trust-tier policy matrix

Resource caps and the hardening profile come from
[`sandbox_policy.py`](../src/heddle/security/sandbox_policy.py) — one
source of truth, indexed by `trust_tier`.

| Tier | Memory | CPU | PIDs | User | Seccomp | Writable volume |
|------|-------:|----:|----:|------|---------|-----------------|
| **T1** Observer   | 256m | 0.5 | 64  | `65534:65534` | default | **none** |
| **T2** Worker     | 512m | 0.5 | 128 | `65534:65534` | default | `~/.heddle/sandbox/<agent>/data` |
| **T3** Operator   | 1g   | 1.0 | 256 | `65534:65534` | strict  | `~/.heddle/sandbox/<agent>/data` |
| **T4** Privileged | 2g   | 1.0 | 512 | `65534:65534` | strict  | `~/.heddle/sandbox/<agent>/data` |

Notes:
- T1 has no writable volume by default — agents that need scratch
  space should be T2+. The loader emits a warning if a T1 config
  declares one explicitly.
- The writable mount inside the container is always
  `/var/heddle/agent`. Host-side path is mode 0700, owned by the
  broker user.
- `strict` seccomp ships a custom narrower profile dropping `ptrace`,
  `keyctl`, and unused `clone3` flags. `default` uses Docker's
  built-in profile (already drops ~44 syscalls).
- T4 may override `user` via `runtime.user` (e.g. to write to a
  host-uid-owned volume). T1–T3 always run as `nobody:nogroup`.

## Hardening flags

| Flag | Value | What it prevents |
|---|---|---|
| `--cap-drop=ALL` | always | The default Linux capabilities (`setuid`, `net_raw`, `mknod`, etc.) — none are needed by an HTTP-bridge agent |
| `--security-opt=no-new-privileges:true` | always | setuid escalation inside the container |
| `--read-only` | always | Writes to `/`, `/etc`, `/usr` — anywhere except the explicit `/tmp` tmpfs and `/var/heddle/agent` volume |
| `--pids-limit=N` | tiered (64–512) | Fork bombs |
| `--user=65534:65534` | always (T1–T3) | Running as root inside the container; even a bind-mount mistake exposes only `nobody`-readable host files |
| `--tmpfs=/tmp:rw,noexec,nosuid,size=64m` | always | Executable temp files, setuid temp files, unbounded `/tmp` growth |
| `--memory=N` | tiered | One agent exhausting host RAM |
| `--cpus=N` | tiered (0.5 / 1.0) | One agent consuming all cores |
| `--security-opt=seccomp=…` | T3+ | A narrower syscall surface for higher-privilege agents |
| `--network=none` / `bridge` | derived from `http_bridge` declarations | Arbitrary egress (none-baseline only in v0.2) |
| `--stop-timeout=N` | always | **Not** the execution cap — this is the SIGTERM→SIGKILL grace period for `docker stop`. The wall-clock cap is enforced by the runner's `asyncio.wait_for` watchdog. |
| Image pinned by digest | always | Silent supply-chain compromise via tag overwrite |

## Image digest pinning

The runtime never spawns containers with bare tags. Every image
reference is resolved through
[`runtime/images.yaml`](../src/heddle/runtime/images.yaml):

```yaml
python-3.12-slim:
  image: python:3.12-slim
  digest: sha256:401f6e1a67dad31a1bd78e9ad22d0ee0a3b52154e6bd30e90be696bb6a3d7461
  refreshed: 2026-05-16
```

To update a digest:

```bash
docker pull python:3.12-slim          # fetches the current digest
docker images --digests python:3.12-slim
# Edit src/heddle/runtime/images.yaml with the new digest + today's date
git diff src/heddle/runtime/images.yaml     # review what changed
git commit -m "images: refresh python-3.12-slim digest"
```

The refresh is intentionally manual — a digest change is a real
supply-chain decision that should be reviewed, not automated.

Logical names that are not in the registry pass through unchanged for
dev/test (`resolve("custom:latest")` returns `"custom:latest"`).

## Network model

### v0.2 (shipped)

| `http_bridge` / `consumes` declared? | Network mode | Egress |
|---|---|---|
| No | `--network=none` | DNS dies, no outbound. Full isolation. |
| Yes | `--network=bridge` | Full bridge-net egress — *the allowlist is not yet enforced*. |

The `validate_sandbox` report surfaces this with a warning when
localhost-on-host services are declared (the `host.docker.internal`
rewrite is still manual).

### v0.3 (planned, deferred)

Per-agent `--internal` user-defined bridge + host-side nftables rules
populated from the agent's `http_bridge` allowlist. Egress to any
non-declared host gets dropped at the kernel and surfaced as
`event=egress_denied` in the audit log. Requires `CAP_NET_ADMIN` on
the broker user. See [ADR-004 §2](decisions/004-docker-sandbox-execution.md#2-egress-allowlist--network-none--per-agent-user-defined-bridge-with-explicit-dns-iptables-enforced-inside-the-container).

## Audit events

Sandbox lifecycle events flow into the same hash-chained log as tool
calls (`event: sandbox_lifecycle`):

| Action | When | Detail field |
|---|---|---|
| `spawn` | After `docker run` succeeds | `image=python:3.12-slim@sha256:…` |
| `stop` | After `docker stop` returns | `graceful` \| `idle_timeout` \| `shutdown` |
| `timeout` | Watchdog fires (`asyncio.wait_for`) | `tool=<name> cap=<N>s` |
| `crash` | Container EOF or stdin BrokenPipe | `eof tool=<name>` \| `stdin_closed tool=<name>` |

The anomaly detector's existing observer sees these automatically — a
spike in `crash` events for one agent would surface as a novel-event
pattern.

Query examples:

```bash
heddle audit show -n 20 --event sandbox_lifecycle
heddle audit show --agent prometheus-bridge --event sandbox_lifecycle
heddle audit verify       # walks the chain, reports any break
```

## Worked example

A T2 Prometheus bridge that opts into sandboxing:

```yaml
# agents/prometheus-bridge.yaml
agent:
  name: prometheus-bridge
  version: "1.0.0"
  description: "Read-only Prometheus query bridge"
  model:
    provider: none
  exposes:
    - name: query
      description: "Run a PromQL query"
      access: read
      parameters:
        q: { type: string, required: true }
  http_bridge:
    - tool_name: query
      method: GET
      url: "http://localhost:9090/api/v1/query"
      query_params: { query: "{{q}}" }
  runtime:
    sandbox: docker
    trust_tier: 2
    max_execution_time: 30s
  triggers:
    - type: on_demand
```

What `heddle sandbox` shows:

```
Sandbox: prometheus-bridge
  Image: python:3.12-slim@sha256:401f6e1a67dad31a1bd78e9ad22d0ee0a3b52154e6bd30e90be696bb6a3d7461
  Memory: 512m  |  CPU: 0.5
  Network: bridge  |  Read-only: True
  Timeout: 30s
  Docker: available
  Allowed hosts: localhost:9090
  Warning: Agent accesses localhost services: ['localhost:9090']. In Docker,
  these need host network or explicit port mapping.

  Docker run args:
    --rm
    --name=heddle-prometheus-bridge
    --memory=512m
    --cpus=0.5
    --pids-limit=128
    --user=65534:65534
    --cap-drop=ALL
    --security-opt=no-new-privileges:true
    --read-only
    --network=bridge
    --tmpfs=/tmp:rw,noexec,nosuid,size=64m
    -v=/home/<user>/.heddle/sandbox/prometheus-bridge/data:/var/heddle/agent:rw
    --stop-timeout=30
```

The first time a client calls `query`, the runner (`SandboxedRunner`)
spawns the container lazily, forwards the tool call over stdio, and
keeps the container warm for follow-up calls. After 5 minutes of
idleness the reaper stops it. Audit log gets one `spawn` and (later)
one `stop` event.

## Operational notes

- **Fails closed.** If `runtime.sandbox: docker` is declared but
  Docker isn't reachable, the agent does not start. There is no
  silent fallback to in-process execution.
- **T4 cannot opt out.** The loader rejects `sandbox: none` with
  `trust_tier: 4` at validation time. Backward compat is preserved
  for T1–T3.
- **The broker is the trust root.** It holds the registry HMAC key,
  writes the audit chain, and mints containers — sandboxing the
  broker itself is rejected (ADR-004 §4). Host-side hardening via the
  `heddle-dashboard.service` systemd unit is the planned mitigation.
- **`--stop-timeout` is not the execution cap.** Don't confuse them.
  Wall-clock enforcement lives in the runner's `asyncio.wait_for`
  watchdog; on timeout, the runner issues
  `docker container kill --signal=KILL heddle-<agent>`.

## v0.2 limitations — what is *not* yet wired

This is intentional, deferred, or framed for follow-up work. Be
explicit about it so the docs don't over-promise:

- **`stdio_mesh.py` does not yet route sandboxed agents through
  `SandboxedRunner`.** The runner is built and tested in isolation;
  flipping the integration switch is a per-agent migration.
- **`container_agent.py` only ships `__ping__` / `__echo__` /
  `__sleep__`.** Real HTTP-bridge dispatch from inside the container
  (and the credential-injection model that needs) is a separate
  slice.
- **No nftables egress writer.** v0.2 ships the `--network=none`
  baseline only; per-host enforcement is v0.3.
- **No `heddle-dashboard.service` systemd unit in `packs/`.** The
  dashboard-hardening directives in ADR-004 §4 are documented but not
  shipped as a unit file.
- **No `heddle images refresh` CLI.** Refreshes are the manual
  `docker pull` + edit-and-commit flow described above.

## Test coverage by DoD line

| DoD requirement | Covered by |
|---|---|
| `runtime.sandbox: docker` opt-in | `test_hardening.py::test_sandbox_config_from_agent` |
| Read-only root filesystem | `test_integration.py::test_integration_write_to_root_denied` |
| Scoped writable volume at `/var/heddle/agent` | `test_hardening.py::test_sandbox_writable_volume_mounts_at_var_heddle_agent` |
| Egress allowlist (baseline) | `test_integration.py::test_integration_egress_blocked_with_network_none` |
| CPU / memory limits via `--cpus` / `--memory` | `test_hardening.py::test_sandbox_docker_run_args`; OOM trigger: `test_integration.py::test_integration_oom_kill_captured` |
| Image pinned by digest | `test_hardening.py::test_generated_sandbox_uses_digest_pinned_image` |
| T4 cannot opt out | `test_hardening.py::test_t4_cannot_opt_out_of_sandbox` |
| OOM kill captured | `test_integration.py::test_integration_oom_kill_captured` (exit 137) |
| OOM surfaced as audit event | `test_sandboxed_runner.py::test_audit_logs_crash_on_eof` (surfaces as `crash`) |
| Documented with worked example | this file |

## References

- [ADR-004: Docker-based Sandbox Execution](decisions/004-docker-sandbox-execution.md)
- [MILESTONE-v0.2.md §Pillar 1](MILESTONE-v0.2.md)
- [`src/heddle/security/sandbox.py`](../src/heddle/security/sandbox.py) — config generator
- [`src/heddle/security/sandbox_policy.py`](../src/heddle/security/sandbox_policy.py) — trust-tier matrix
- [`src/heddle/runtime/sandboxed_runner.py`](../src/heddle/runtime/sandboxed_runner.py) — runtime
- [`src/heddle/runtime/container_agent.py`](../src/heddle/runtime/container_agent.py) — container-side stdio handler
- [`src/heddle/runtime/images.yaml`](../src/heddle/runtime/images.yaml) — pinned image digests
- OWASP Top 10 for Agentic Applications ASI05 — Unexpected Code Execution (sandbox containment)
- NIST AI RMF — MS-2.3 (Risk Treatment)
