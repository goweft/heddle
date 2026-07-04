"""Sandboxed agent runner — broker-spawned containers with a watchdog.

Bridges SandboxManager (which generates docker run args) and MCP tool
dispatch. Per-agent containers are spawned lazily on first tool call,
each invocation is wall-clock-capped by an asyncio watchdog, and idle
containers are reaped after a configurable timeout.

ADR-004 §1 (execution pattern) and §5 (lazy-spawn / idle reap).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from heddle.config.schema import AgentConfig
from heddle.security.audit import AuditLogger
from heddle.security.sandbox import SandboxManager, SandboxConfig

logger = logging.getLogger(__name__)


# Default command run inside the container. The runner module ships a
# minimal stdio protocol handler at heddle.runtime.container_agent; an
# agent image with heddle installed can invoke it directly. Custom
# agents may override this via SandboxedRunner.register(..., entry_cmd=).
DEFAULT_CONTAINER_ENTRY = ["python", "-m", "heddle.runtime.container_agent"]

DEFAULT_IDLE_TIMEOUT_SECONDS = 300.0
DEFAULT_REAPER_INTERVAL_SECONDS = 30.0


# ── Errors ───────────────────────────────────────────────────────────


class SandboxRunnerError(Exception):
    """Base class for runner-level errors."""


class SandboxTimeoutError(SandboxRunnerError):
    """Tool call exceeded the wall-clock cap; container was killed."""


class SandboxCrashedError(SandboxRunnerError):
    """Container exited unexpectedly mid-call."""


class SandboxNotRegisteredError(SandboxRunnerError):
    """Agent name has no sandbox registration."""


# ── Spawner abstraction (lets tests inject fake subprocesses) ────────


Spawner = Callable[..., Awaitable[asyncio.subprocess.Process]]
Reaper = Callable[[str], Awaitable[None]]


async def _default_spawner(*cmd: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _default_docker_kill(container_name: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        "docker", "container", "kill", "--signal=KILL", container_name,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()


async def _default_docker_stop(container_name: str, grace_seconds: int = 5) -> None:
    proc = await asyncio.create_subprocess_exec(
        "docker", "stop", "-t", str(grace_seconds), container_name,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()


# ── SandboxedAgent ───────────────────────────────────────────────────


class SandboxedAgent:
    """A single sandboxed agent container.

    Owns the lifecycle of one `docker run` subprocess and the stdio
    protocol used to forward tool calls into it.
    """

    def __init__(
        self,
        agent_name: str,
        sandbox: SandboxConfig,
        docker_run_args: list[str],
        entry_cmd: list[str] | None = None,
        spawner: Spawner | None = None,
        killer: Callable[[str], Awaitable[None]] | None = None,
        stopper: Callable[[str], Awaitable[None]] | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.agent_name = agent_name
        self.sandbox = sandbox
        self._docker_run_args = docker_run_args
        self._entry_cmd = entry_cmd or DEFAULT_CONTAINER_ENTRY
        self._spawner = spawner or _default_spawner
        self._killer = killer or _default_docker_kill
        self._stopper = stopper or _default_docker_stop
        self._audit = audit_logger
        self._process: asyncio.subprocess.Process | None = None
        self._call_lock = asyncio.Lock()
        self._last_activity = time.monotonic()

    def _log(self, action: str, detail: str = "") -> None:
        if self._audit is not None:
            try:
                self._audit.log_sandbox_lifecycle(self.agent_name, action, detail)
            except Exception as exc:
                logger.warning("audit log failed for %s/%s: %s", self.agent_name, action, exc)

    @property
    def container_name(self) -> str:
        return f"heddle-{self.agent_name}"

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self._last_activity

    async def start(self) -> None:
        if self.is_running:
            return
        # `-i` keeps stdin open; the container_agent reads JSON request lines.
        cmd = [
            "docker", "run", "-i", *self._docker_run_args,
            self.sandbox.image, *self._entry_cmd,
        ]
        logger.info("starting sandboxed agent %s", self.agent_name)
        self._process = await self._spawner(*cmd)
        self._last_activity = time.monotonic()
        self._log("spawn", f"image={self.sandbox.image}")

    async def call_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
        timeout: float | None = None,
    ) -> str:
        """Forward a single tool call into the container with a watchdog.

        Serialised per-agent — concurrent calls to the same agent are
        queued behind an asyncio.Lock since the stdio protocol is
        request/response on a single pipe.
        """
        if timeout is None:
            timeout = float(self.sandbox.timeout_seconds)

        if not self.is_running:
            await self.start()

        async with self._call_lock:
            self._last_activity = time.monotonic()
            assert self._process is not None
            assert self._process.stdin is not None
            assert self._process.stdout is not None

            request = json.dumps({"tool": tool_name, "params": params}) + "\n"
            try:
                self._process.stdin.write(request.encode())
                await self._process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                self._process = None
                self._log("crash", f"stdin_closed tool={tool_name}")
                raise SandboxCrashedError(
                    f"{self.agent_name}: container stdin closed: {exc}"
                ) from exc

            try:
                line = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=timeout,
                )
            except asyncio.TimeoutError as exc:
                # Watchdog fired: hard-kill the container, drop the
                # process handle so the next call will respawn.
                await self._killer(self.container_name)
                self._process = None
                self._log("timeout", f"tool={tool_name} cap={timeout}s")
                raise SandboxTimeoutError(
                    f"{self.agent_name}.{tool_name} exceeded {timeout}s"
                ) from exc

            if not line:
                # EOF before a response — container died mid-call.
                self._process = None
                self._log("crash", f"eof tool={tool_name}")
                raise SandboxCrashedError(
                    f"{self.agent_name}: container exited before responding"
                )

            try:
                response = json.loads(line.decode().strip())
            except json.JSONDecodeError as exc:
                raise SandboxRunnerError(
                    f"{self.agent_name}: malformed response from container: {exc}"
                ) from exc

            self._last_activity = time.monotonic()

            if response.get("ok"):
                return str(response.get("result", ""))
            raise SandboxRunnerError(
                f"{self.agent_name}.{tool_name}: {response.get('error', 'unknown error')}"
            )

    async def stop(self, reason: str = "graceful") -> None:
        """Stop the container gracefully (docker stop with grace period).

        `reason` is logged with the audit event so callers can
        distinguish reaper-driven stops ("idle_timeout"), shutdown
        sweeps ("shutdown"), and explicit user stops ("graceful").
        """
        if not self.is_running:
            self._process = None
            return
        proc = self._process
        self._process = None
        if proc is not None and proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass
        try:
            await self._stopper(self.container_name)
        except Exception as exc:
            logger.warning("docker stop failed for %s: %s", self.container_name, exc)
        if proc is not None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                logger.warning("subprocess for %s did not exit after stop", self.container_name)
        self._log("stop", reason)


# ── SandboxedRunner registry ─────────────────────────────────────────


@dataclass
class _Registration:
    config: AgentConfig
    entry_cmd: list[str] | None


class SandboxedRunner:
    """Manages the lifecycle of sandboxed agents.

    Registration is cheap (records the config). The first tool call to
    an agent spawns the container; an idle reaper stops containers that
    haven't been used within `idle_timeout_seconds`.

    Agents whose `runtime.sandbox != "docker"` are ignored — the
    existing in-process dispatch handles them, unchanged.
    """

    def __init__(
        self,
        sandbox_manager: SandboxManager | None = None,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        reaper_interval_seconds: float = DEFAULT_REAPER_INTERVAL_SECONDS,
        spawner: Spawner | None = None,
        killer: Callable[[str], Awaitable[None]] | None = None,
        stopper: Callable[[str], Awaitable[None]] | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self._sandbox_manager = sandbox_manager or SandboxManager()
        self._idle_timeout = idle_timeout_seconds
        self._reaper_interval = reaper_interval_seconds
        self._spawner = spawner
        self._killer = killer
        self._stopper = stopper
        self._audit = audit_logger
        self._registrations: dict[str, _Registration] = {}
        self._agents: dict[str, SandboxedAgent] = {}
        self._spawn_lock = asyncio.Lock()
        self._reaper_task: asyncio.Task | None = None

    def register(
        self, config: AgentConfig, entry_cmd: list[str] | None = None,
    ) -> bool:
        """Register an agent for sandboxed execution.

        Returns True if the agent will be sandboxed (runtime.sandbox ==
        "docker"), False otherwise. Non-sandboxed agents are silently
        ignored so callers can register every config uniformly.
        """
        if config.agent.runtime.sandbox != "docker":
            return False
        self._registrations[config.agent.name] = _Registration(
            config=config, entry_cmd=entry_cmd,
        )
        return True

    def is_sandboxed(self, agent_name: str) -> bool:
        return agent_name in self._registrations

    def active_agents(self) -> list[str]:
        return [n for n, a in self._agents.items() if a.is_running]

    async def call_tool(
        self, agent_name: str, tool_name: str, params: dict[str, Any],
    ) -> str:
        agent = await self._ensure_agent(agent_name)
        return await agent.call_tool(tool_name, params)

    async def _ensure_agent(self, agent_name: str) -> SandboxedAgent:
        if agent_name not in self._registrations:
            raise SandboxNotRegisteredError(
                f"agent '{agent_name}' is not registered as sandboxed"
            )
        async with self._spawn_lock:
            if agent_name not in self._agents:
                reg = self._registrations[agent_name]
                sandbox_config = self._sandbox_manager.generate_sandbox_config(reg.config)
                args = self._sandbox_manager.generate_docker_run_args(sandbox_config)
                self._agents[agent_name] = SandboxedAgent(
                    agent_name=agent_name,
                    sandbox=sandbox_config,
                    docker_run_args=args,
                    entry_cmd=reg.entry_cmd,
                    spawner=self._spawner,
                    killer=self._killer,
                    stopper=self._stopper,
                    audit_logger=self._audit,
                )
        return self._agents[agent_name]

    async def start_reaper(self) -> None:
        """Start the background idle-reaper task."""
        if self._reaper_task is None or self._reaper_task.done():
            self._reaper_task = asyncio.create_task(self._reaper_loop())

    async def _reaper_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._reaper_interval)
                await self.reap_idle()
        except asyncio.CancelledError:
            pass

    async def reap_idle(self) -> list[str]:
        """Stop containers that have been idle longer than the timeout.

        Returns the list of agent names that were reaped.
        """
        reaped: list[str] = []
        for name, agent in list(self._agents.items()):
            if agent.is_running and agent.idle_seconds > self._idle_timeout:
                try:
                    await agent.stop(reason="idle_timeout")
                    reaped.append(name)
                except Exception as exc:
                    logger.warning("reap failed for %s: %s", name, exc)
        return reaped

    async def shutdown(self) -> None:
        """Stop the reaper and tear down every running agent."""
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except (asyncio.CancelledError, Exception):
                pass
            self._reaper_task = None
        for agent in list(self._agents.values()):
            try:
                await agent.stop(reason="shutdown")
            except Exception as exc:
                logger.warning("shutdown stop failed for %s: %s", agent.agent_name, exc)
