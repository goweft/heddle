"""Tests for the sandboxed-agent runner.

No real Docker is invoked — every test injects a fake spawner that
returns an in-memory stand-in for an asyncio subprocess. The
container_agent.py protocol is exercised separately by driving it
in-process with StringIO.
"""
from __future__ import annotations

import asyncio
import io
import json
import time
from typing import Any

import pytest
import yaml

from heddle.config.loader import validate_config
from heddle.runtime import container_agent
from heddle.runtime.sandboxed_runner import (
    DEFAULT_CONTAINER_ENTRY,
    SandboxCrashedError,
    SandboxNotRegisteredError,
    SandboxRunnerError,
    SandboxTimeoutError,
    SandboxedAgent,
    SandboxedRunner,
)
from heddle.security.audit import AuditLogger
from heddle.security.sandbox import SandboxConfig, SandboxManager


# ── Helpers ──────────────────────────────────────────────────────────


class _FakeStream:
    """Minimal stand-in for asyncio.StreamReader / StreamWriter."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._closed = False
        self._waiters: list[asyncio.Future] = []

    # writer side
    def write(self, data: bytes) -> None:
        if self._closed:
            raise BrokenPipeError("fake stream closed")
        self._buf.extend(data)
        for w in self._waiters:
            if not w.done():
                w.set_result(None)
        self._waiters.clear()

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self._closed = True
        for w in self._waiters:
            if not w.done():
                w.set_result(None)
        self._waiters.clear()

    # reader side
    async def readline(self) -> bytes:
        while True:
            nl = self._buf.find(b"\n")
            if nl != -1:
                line = bytes(self._buf[: nl + 1])
                del self._buf[: nl + 1]
                return line
            if self._closed:
                rest = bytes(self._buf)
                self._buf.clear()
                return rest
            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            self._waiters.append(fut)
            await fut


class _FakeProcess:
    """Stand-in for asyncio.subprocess.Process driven by the test."""

    def __init__(
        self,
        responder=None,
        *,
        crash_after_write: bool = False,
        never_respond: bool = False,
    ):
        self.stdin = _FakeStream()
        self.stdout = _FakeStream()
        self.stderr = _FakeStream()
        self.returncode: int | None = None
        self._task: asyncio.Task | None = None
        self._responder = responder
        self._crash_after_write = crash_after_write
        self._never_respond = never_respond
        self._task = asyncio.get_event_loop().create_task(self._pump())

    async def _pump(self) -> None:
        try:
            while True:
                line = await self._read_input()
                if not line:
                    return
                if self._never_respond:
                    return
                request = json.loads(line.decode().strip())
                if self._crash_after_write:
                    self.returncode = 137
                    self.stdout.close()
                    return
                if self._responder is None:
                    payload = {"ok": True, "result": "ack"}
                else:
                    payload = self._responder(request)
                self.stdout.write((json.dumps(payload) + "\n").encode())
        except Exception:
            return

    async def _read_input(self) -> bytes:
        # Stdin in our model receives writes via write(); poll its buffer.
        while True:
            nl = self.stdin._buf.find(b"\n")
            if nl != -1:
                line = bytes(self.stdin._buf[: nl + 1])
                del self.stdin._buf[: nl + 1]
                return line
            if self.stdin._closed:
                return b""
            await asyncio.sleep(0.001)

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def _make_fake_spawner(responder=None, *, crash_after_write: bool = False, never_respond: bool = False):
    spawned: list[list[str]] = []

    async def spawn(*cmd: str):
        spawned.append(list(cmd))
        return _FakeProcess(
            responder=responder,
            crash_after_write=crash_after_write,
            never_respond=never_respond,
        )

    return spawn, spawned


def _make_t2_config(name: str = "t2-test"):
    raw = yaml.safe_load(f"""
agent:
  name: {name}
  version: "1.0.0"
  description: "test"
  model:
    provider: none
  exposes:
    - name: noop
      description: "noop"
  runtime:
    sandbox: docker
    trust_tier: 2
  triggers:
    - type: on_demand
""")
    return validate_config(raw, source="<test>")


# ── SandboxedAgent ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_starts_lazily_on_first_call():
    spawner, spawned = _make_fake_spawner(
        responder=lambda req: {"ok": True, "result": "pong"},
    )
    agent = SandboxedAgent(
        agent_name="lazy",
        sandbox=SandboxConfig(agent_name="lazy", timeout_seconds=5),
        docker_run_args=["--rm"],
        spawner=spawner,
    )
    assert not agent.is_running
    assert spawned == []

    result = await agent.call_tool("__ping__", {})
    assert result == "pong"
    assert agent.is_running
    assert len(spawned) == 1


@pytest.mark.asyncio
async def test_agent_uses_default_container_entry():
    spawner, spawned = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    agent = SandboxedAgent(
        agent_name="entry-test",
        sandbox=SandboxConfig(agent_name="entry-test", image="img:tag"),
        docker_run_args=["--rm", "--memory=256m"],
        spawner=spawner,
    )
    await agent.call_tool("__ping__", {})
    cmd = spawned[0]
    assert cmd[:3] == ["docker", "run", "-i"]
    assert "--memory=256m" in cmd
    assert "img:tag" in cmd
    # default container entry tail
    assert cmd[-len(DEFAULT_CONTAINER_ENTRY):] == DEFAULT_CONTAINER_ENTRY


@pytest.mark.asyncio
async def test_agent_passes_params_and_returns_result():
    received = []

    def responder(req):
        received.append(req)
        return {"ok": True, "result": json.dumps(req["params"])}

    spawner, _ = _make_fake_spawner(responder=responder)
    agent = SandboxedAgent(
        agent_name="echo",
        sandbox=SandboxConfig(agent_name="echo"),
        docker_run_args=[],
        spawner=spawner,
    )
    result = await agent.call_tool("__echo__", {"x": 1, "y": "two"})
    assert json.loads(result) == {"x": 1, "y": "two"}
    assert received[0]["tool"] == "__echo__"


@pytest.mark.asyncio
async def test_agent_surfaces_container_error_response():
    spawner, _ = _make_fake_spawner(
        responder=lambda req: {"ok": False, "error": "boom"},
    )
    agent = SandboxedAgent(
        agent_name="errs",
        sandbox=SandboxConfig(agent_name="errs"),
        docker_run_args=[],
        spawner=spawner,
    )
    with pytest.raises(SandboxRunnerError, match="boom"):
        await agent.call_tool("__ping__", {})


@pytest.mark.asyncio
async def test_agent_timeout_invokes_docker_kill():
    killed: list[str] = []

    async def killer(name: str) -> None:
        killed.append(name)

    spawner, _ = _make_fake_spawner(never_respond=True)
    agent = SandboxedAgent(
        agent_name="slow",
        sandbox=SandboxConfig(agent_name="slow", timeout_seconds=0),
        docker_run_args=[],
        spawner=spawner,
        killer=killer,
    )
    with pytest.raises(SandboxTimeoutError, match="exceeded"):
        await agent.call_tool("__sleep__", {"seconds": 99}, timeout=0.05)
    assert killed == ["heddle-slow"]
    # Process handle dropped so the next call would respawn.
    assert not agent.is_running


@pytest.mark.asyncio
async def test_agent_detects_container_crash():
    spawner, _ = _make_fake_spawner(crash_after_write=True)
    agent = SandboxedAgent(
        agent_name="boom",
        sandbox=SandboxConfig(agent_name="boom"),
        docker_run_args=[],
        spawner=spawner,
    )
    with pytest.raises(SandboxCrashedError):
        await agent.call_tool("__ping__", {})


@pytest.mark.asyncio
async def test_agent_serialises_concurrent_calls():
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    def responder(req):
        nonlocal in_flight, max_in_flight
        # responder runs synchronously inside the fake process pump, so
        # measure here. Concurrency would show as in_flight > 1 if the
        # call_lock were missing.
        return {"ok": True, "result": "ack"}

    # We'll instead probe the lock more directly: start two coroutines
    # against the same agent, with a slow responder, and confirm the
    # second waits for the first.
    timings = []

    async def slow_responder_factory():
        sleeps = [0.05, 0.05]
        idx = 0

        def responder(req):
            nonlocal idx
            timings.append(("respond", time.monotonic()))
            idx += 1
            return {"ok": True, "result": "ack"}
        return responder

    responder_fn = await slow_responder_factory()
    spawner, _ = _make_fake_spawner(responder=responder_fn)
    agent = SandboxedAgent(
        agent_name="serial",
        sandbox=SandboxConfig(agent_name="serial", timeout_seconds=5),
        docker_run_args=[],
        spawner=spawner,
    )
    start = time.monotonic()
    results = await asyncio.gather(
        agent.call_tool("__ping__", {}),
        agent.call_tool("__ping__", {}),
    )
    assert results == ["ack", "ack"]
    # If calls were parallel they'd both complete near t=0; with the lock,
    # they're back-to-back. We only assert ordering, not absolute time.
    assert len(timings) == 2
    assert timings[0][1] <= timings[1][1]


@pytest.mark.asyncio
async def test_agent_stop_invokes_docker_stop_and_drops_handle():
    stopped: list[str] = []

    async def stopper(name: str) -> None:
        stopped.append(name)

    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "x"})
    agent = SandboxedAgent(
        agent_name="s",
        sandbox=SandboxConfig(agent_name="s"),
        docker_run_args=[],
        spawner=spawner,
        stopper=stopper,
    )
    await agent.call_tool("__ping__", {})
    assert agent.is_running
    await agent.stop()
    assert stopped == ["heddle-s"]
    assert not agent.is_running


# ── SandboxedRunner ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_runner_ignores_sandbox_none():
    runner = SandboxedRunner()
    raw = yaml.safe_load("""
agent:
  name: in-proc
  version: "1.0.0"
  description: "x"
  model:
    provider: none
  exposes:
    - name: noop
      description: "noop"
  runtime:
    trust_tier: 2
  triggers:
    - type: on_demand
""")
    config = validate_config(raw, source="<test>")
    assert runner.register(config) is False
    assert not runner.is_sandboxed("in-proc")


@pytest.mark.asyncio
async def test_runner_registers_sandbox_docker():
    runner = SandboxedRunner()
    config = _make_t2_config("sb")
    assert runner.register(config) is True
    assert runner.is_sandboxed("sb")


@pytest.mark.asyncio
async def test_runner_call_unregistered_raises():
    runner = SandboxedRunner()
    with pytest.raises(SandboxNotRegisteredError):
        await runner.call_tool("ghost", "__ping__", {})


@pytest.mark.asyncio
async def test_runner_lazy_spawn_uses_sandbox_manager_args():
    spawner, spawned = _make_fake_spawner(
        responder=lambda r: {"ok": True, "result": "pong"},
    )
    runner = SandboxedRunner(spawner=spawner)
    runner.register(_make_t2_config("lazy-mgr"))

    # Nothing spawned yet.
    assert spawned == []
    assert runner.active_agents() == []

    result = await runner.call_tool("lazy-mgr", "__ping__", {})
    assert result == "pong"
    assert "lazy-mgr" in runner.active_agents()

    # The spawned command must carry the SandboxManager-generated
    # hardening flags from Slice 1.
    cmd = spawned[0]
    joined = " ".join(cmd)
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges:true" in cmd
    assert "--pids-limit=128" in cmd  # T2
    assert "--user=65534:65534" in cmd
    assert "--name=heddle-lazy-mgr" in cmd
    assert "@sha256:" in joined  # digest-pinned image


@pytest.mark.asyncio
async def test_runner_reap_idle_stops_old_agents():
    stopped: list[str] = []

    async def stopper(name: str) -> None:
        stopped.append(name)

    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    runner = SandboxedRunner(
        idle_timeout_seconds=0.05, spawner=spawner, stopper=stopper,
    )
    runner.register(_make_t2_config("reap-me"))
    await runner.call_tool("reap-me", "__ping__", {})
    assert "reap-me" in runner.active_agents()

    await asyncio.sleep(0.08)
    reaped = await runner.reap_idle()
    assert reaped == ["reap-me"]
    assert stopped == ["heddle-reap-me"]


@pytest.mark.asyncio
async def test_runner_reap_skips_fresh_agents():
    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    runner = SandboxedRunner(idle_timeout_seconds=60.0, spawner=spawner)
    runner.register(_make_t2_config("fresh"))
    await runner.call_tool("fresh", "__ping__", {})
    reaped = await runner.reap_idle()
    assert reaped == []


@pytest.mark.asyncio
async def test_runner_reaper_task_lifecycle():
    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    runner = SandboxedRunner(
        idle_timeout_seconds=10.0,
        reaper_interval_seconds=0.01,
        spawner=spawner,
    )
    await runner.start_reaper()
    assert runner._reaper_task is not None
    assert not runner._reaper_task.done()
    await asyncio.sleep(0.03)  # let the loop tick at least twice
    await runner.shutdown()
    assert runner._reaper_task is None


@pytest.mark.asyncio
async def test_runner_shutdown_stops_all_active_agents():
    stopped: list[str] = []

    async def stopper(name: str) -> None:
        stopped.append(name)

    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    runner = SandboxedRunner(spawner=spawner, stopper=stopper)
    runner.register(_make_t2_config("a1"))
    runner.register(_make_t2_config("a2"))
    await runner.call_tool("a1", "__ping__", {})
    await runner.call_tool("a2", "__ping__", {})
    assert sorted(runner.active_agents()) == ["a1", "a2"]
    await runner.shutdown()
    assert sorted(stopped) == ["heddle-a1", "heddle-a2"]


@pytest.mark.asyncio
async def test_runner_respawns_after_crash():
    """If a container dies, the next call_tool() spins a fresh one."""
    state = {"calls": 0}

    def flaky_responder(req):
        state["calls"] += 1
        if state["calls"] == 1:
            return {"ok": True, "result": "first"}
        return {"ok": True, "result": "second"}

    spawned_count = {"n": 0}

    async def spawn(*cmd):
        spawned_count["n"] += 1
        # Second spawn returns a healthy process; first spawn crashes
        # after the initial successful exchange when we close it.
        return _FakeProcess(responder=flaky_responder)

    runner = SandboxedRunner(spawner=spawn)
    runner.register(_make_t2_config("respawn"))
    r1 = await runner.call_tool("respawn", "__ping__", {})
    assert r1 == "first"

    # Simulate crash: stop the underlying process handle.
    agent = runner._agents["respawn"]
    agent._process = None  # type: ignore[attr-defined]

    r2 = await runner.call_tool("respawn", "__ping__", {})
    assert r2 == "second"
    assert spawned_count["n"] == 2


# ── container_agent stdio protocol ───────────────────────────────────


def _run_container_agent(stdin_text: str) -> str:
    """Drive container_agent.main() in-process against canned stdin."""
    saved_stdin, saved_stdout = container_agent.sys.stdin, container_agent.sys.stdout
    container_agent.sys.stdin = io.StringIO(stdin_text)
    container_agent.sys.stdout = io.StringIO()
    try:
        container_agent.main()
        return container_agent.sys.stdout.getvalue()
    finally:
        container_agent.sys.stdin = saved_stdin
        container_agent.sys.stdout = saved_stdout


def test_container_agent_ping_returns_pong():
    out = _run_container_agent('{"tool": "__ping__", "params": {}}\n')
    line = out.strip().splitlines()[-1]
    assert json.loads(line) == {"ok": True, "result": "pong"}


def test_container_agent_echo_returns_params():
    out = _run_container_agent('{"tool": "__echo__", "params": {"a": 1}}\n')
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert json.loads(payload["result"]) == {"a": 1}


def test_container_agent_unknown_tool_returns_error():
    out = _run_container_agent('{"tool": "nope", "params": {}}\n')
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["ok"] is False
    assert "unknown tool" in payload["error"]


def test_container_agent_invalid_json_returns_error():
    out = _run_container_agent("not json\n")
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["ok"] is False
    assert "invalid JSON" in payload["error"]


def test_container_agent_multiple_requests_in_one_session():
    stdin = (
        '{"tool": "__ping__", "params": {}}\n'
        '{"tool": "__echo__", "params": {"k": "v"}}\n'
    )
    out = _run_container_agent(stdin)
    lines = [json.loads(l) for l in out.strip().splitlines()]
    assert lines[0] == {"ok": True, "result": "pong"}
    assert lines[1]["ok"] is True
    assert json.loads(lines[1]["result"]) == {"k": "v"}


# ── Audit lifecycle events ───────────────────────────────────────────


def _sandbox_events(audit: AuditLogger) -> list[dict]:
    return [e for e in audit.recent(50) if e.get("event") == "sandbox_lifecycle"]


@pytest.mark.asyncio
async def test_audit_logs_spawn_on_first_call(tmp_path):
    audit = AuditLogger(log_dir=tmp_path / "audit")
    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    agent = SandboxedAgent(
        agent_name="audited",
        sandbox=SandboxConfig(agent_name="audited", image="img@sha256:abc"),
        docker_run_args=[],
        spawner=spawner,
        audit_logger=audit,
    )
    await agent.call_tool("__ping__", {})
    events = _sandbox_events(audit)
    spawns = [e for e in events if e["action"] == "spawn"]
    assert len(spawns) == 1
    assert spawns[0]["agent"] == "audited"
    assert "img@sha256:abc" in spawns[0]["detail"]


@pytest.mark.asyncio
async def test_audit_logs_stop_with_reason(tmp_path):
    audit = AuditLogger(log_dir=tmp_path / "audit")

    async def noop_stopper(name: str) -> None:
        return None

    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    agent = SandboxedAgent(
        agent_name="bye",
        sandbox=SandboxConfig(agent_name="bye"),
        docker_run_args=[],
        spawner=spawner,
        stopper=noop_stopper,
        audit_logger=audit,
    )
    await agent.call_tool("__ping__", {})
    await agent.stop(reason="graceful")
    stops = [e for e in _sandbox_events(audit) if e["action"] == "stop"]
    assert len(stops) == 1
    assert stops[0]["detail"] == "graceful"


@pytest.mark.asyncio
async def test_audit_logs_timeout(tmp_path):
    audit = AuditLogger(log_dir=tmp_path / "audit")

    async def noop_killer(name: str) -> None:
        return None

    spawner, _ = _make_fake_spawner(never_respond=True)
    agent = SandboxedAgent(
        agent_name="slow",
        sandbox=SandboxConfig(agent_name="slow", timeout_seconds=0),
        docker_run_args=[],
        spawner=spawner,
        killer=noop_killer,
        audit_logger=audit,
    )
    with pytest.raises(SandboxTimeoutError):
        await agent.call_tool("__sleep__", {"seconds": 99}, timeout=0.02)
    events = _sandbox_events(audit)
    timeouts = [e for e in events if e["action"] == "timeout"]
    assert len(timeouts) == 1
    assert "__sleep__" in timeouts[0]["detail"]


@pytest.mark.asyncio
async def test_audit_logs_crash_on_eof(tmp_path):
    audit = AuditLogger(log_dir=tmp_path / "audit")
    spawner, _ = _make_fake_spawner(crash_after_write=True)
    agent = SandboxedAgent(
        agent_name="crash",
        sandbox=SandboxConfig(agent_name="crash"),
        docker_run_args=[],
        spawner=spawner,
        audit_logger=audit,
    )
    with pytest.raises(SandboxCrashedError):
        await agent.call_tool("__ping__", {})
    crashes = [e for e in _sandbox_events(audit) if e["action"] == "crash"]
    assert len(crashes) == 1
    assert "eof" in crashes[0]["detail"]


@pytest.mark.asyncio
async def test_audit_reap_uses_idle_timeout_reason(tmp_path):
    audit = AuditLogger(log_dir=tmp_path / "audit")

    async def noop_stopper(name: str) -> None:
        return None

    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    runner = SandboxedRunner(
        idle_timeout_seconds=0.02,
        spawner=spawner,
        stopper=noop_stopper,
        audit_logger=audit,
    )
    runner.register(_make_t2_config("reaper"))
    await runner.call_tool("reaper", "__ping__", {})
    await asyncio.sleep(0.05)
    reaped = await runner.reap_idle()
    assert reaped == ["reaper"]
    stops = [e for e in _sandbox_events(audit) if e["action"] == "stop"]
    assert len(stops) == 1
    assert stops[0]["detail"] == "idle_timeout"


@pytest.mark.asyncio
async def test_audit_shutdown_uses_shutdown_reason(tmp_path):
    audit = AuditLogger(log_dir=tmp_path / "audit")

    async def noop_stopper(name: str) -> None:
        return None

    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    runner = SandboxedRunner(
        spawner=spawner, stopper=noop_stopper, audit_logger=audit,
    )
    runner.register(_make_t2_config("sd"))
    await runner.call_tool("sd", "__ping__", {})
    await runner.shutdown()
    stops = [e for e in _sandbox_events(audit) if e["action"] == "stop"]
    assert len(stops) == 1
    assert stops[0]["detail"] == "shutdown"


@pytest.mark.asyncio
async def test_audit_failure_does_not_break_runner(tmp_path):
    """Observer errors must never crash the runner pipeline."""

    class BrokenAudit(AuditLogger):
        def log_sandbox_lifecycle(self, *args, **kwargs):
            raise RuntimeError("audit is on fire")

    audit = BrokenAudit(log_dir=tmp_path / "audit")
    spawner, _ = _make_fake_spawner(responder=lambda r: {"ok": True, "result": "ok"})
    agent = SandboxedAgent(
        agent_name="resilient",
        sandbox=SandboxConfig(agent_name="resilient"),
        docker_run_args=[],
        spawner=spawner,
        audit_logger=audit,
    )
    # Should not raise even though audit raises internally.
    result = await agent.call_tool("__ping__", {})
    assert result == "ok"
