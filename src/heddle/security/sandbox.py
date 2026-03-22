"""Heddle sandboxing — container-based agent isolation.

Each agent can run in its own Docker container with:
- Read-only root filesystem
- Scoped writable volume
- Network limited to declared services
- CPU, memory, and execution time limits

Frameworks: OWASP Agentic #6 (Inadequate Sandboxing), NIST AI RMF
MS-2.3, MAESTRO Isolation layer
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from heddle.config.schema import AgentConfig
from heddle.security.audit import get_audit_logger

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Container sandbox configuration derived from agent config."""
    agent_name: str
    image: str = "python:3.12-slim"
    read_only_root: bool = True
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    network_mode: str = "none"
    allowed_hosts: list[str] = field(default_factory=list)
    writable_volume: str = ""
    timeout_seconds: int = 30
    env: dict[str, str] = field(default_factory=dict)


class SandboxManager:
    """Manages Docker-based sandboxing for Heddle agents.

    Generates container configurations from agent YAML, checks Docker
    availability, and provides the interface for running agents in
    isolated containers.
    """

    def __init__(self):
        self._audit = get_audit_logger()
        self._docker_available: bool | None = None

    def is_docker_available(self) -> bool:
        """Check if Docker daemon is running and accessible."""
        if self._docker_available is not None:
            return self._docker_available

        import subprocess
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, timeout=5,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False

        if not self._docker_available:
            logger.warning("Docker not available — sandboxing disabled")
        return self._docker_available

    def generate_sandbox_config(self, config: AgentConfig) -> SandboxConfig:
        """Generate a SandboxConfig from an agent's YAML configuration.

        Extracts network permissions from http_bridge URLs, resource
        limits from runtime config, and sets up isolation parameters.
        """
        spec = config.agent

        # Parse allowed hosts from http_bridge URLs
        allowed_hosts = set()
        for ep in spec.http_bridge:
            from urllib.parse import urlparse
            parsed = urlparse(ep.url)
            if parsed.hostname:
                host_port = f"{parsed.hostname}:{parsed.port or 80}"
                allowed_hosts.add(host_port)

        # Parse timeout from runtime config
        timeout_str = spec.runtime.max_execution_time
        timeout = 30
        if timeout_str.endswith("s"):
            timeout = int(timeout_str[:-1])
        elif timeout_str.endswith("m"):
            timeout = int(timeout_str[:-1]) * 60

        # Memory limit based on trust tier
        memory_limits = {1: "256m", 2: "512m", 3: "1g", 4: "2g"}
        memory = memory_limits.get(spec.runtime.trust_tier, "512m")

        sandbox = SandboxConfig(
            agent_name=spec.name,
            allowed_hosts=sorted(allowed_hosts),
            timeout_seconds=timeout,
            memory_limit=memory,
            cpu_limit=0.5 if spec.runtime.trust_tier <= 2 else 1.0,
            network_mode="bridge" if allowed_hosts else "none",
            writable_volume=f"/tmp/loom-{spec.name}",
            env=spec.runtime.env,
        )

        return sandbox

    def generate_docker_run_args(self, sandbox: SandboxConfig) -> list[str]:
        """Generate docker run command arguments from sandbox config.

        Returns the argument list (without 'docker run' prefix).
        """
        args = [
            "--rm",
            f"--name=loom-{sandbox.agent_name}",
            f"--memory={sandbox.memory_limit}",
            f"--cpus={sandbox.cpu_limit}",
            f"--read-only" if sandbox.read_only_root else "",
            f"--network={sandbox.network_mode}",
            f"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
        ]

        # Add writable volume
        if sandbox.writable_volume:
            args.append(f"-v={sandbox.writable_volume}:/data:rw")

        # Add environment variables
        for k, v in sandbox.env.items():
            args.append(f"-e={k}={v}")

        # Add timeout via --stop-timeout
        args.append(f"--stop-timeout={sandbox.timeout_seconds}")

        # Filter empty strings
        return [a for a in args if a]

    def generate_network_policy(self, sandbox: SandboxConfig) -> dict[str, Any]:
        """Generate a network policy document for the sandbox.

        In a full implementation, this would configure iptables rules
        inside the container to restrict outbound connections to only
        the declared hosts.
        """
        return {
            "agent": sandbox.agent_name,
            "network_mode": sandbox.network_mode,
            "allowed_outbound": sandbox.allowed_hosts,
            "allowed_inbound": [],
            "dns": "none" if sandbox.network_mode == "none" else "host",
            "policy": "deny_all_except_declared",
        }

    def audit_sandbox_config(self, sandbox: SandboxConfig) -> None:
        """Log the sandbox configuration for audit purposes."""
        self._audit.log_agent_lifecycle(
            sandbox.agent_name, "sandbox_config",
            (
                f"image={sandbox.image} memory={sandbox.memory_limit} "
                f"cpu={sandbox.cpu_limit} network={sandbox.network_mode} "
                f"hosts={sandbox.allowed_hosts} readonly={sandbox.read_only_root}"
            ),
        )

    def validate_sandbox(self, config: AgentConfig) -> dict[str, Any]:
        """Validate that an agent's sandbox configuration is safe.

        Returns a report with any issues found.
        """
        spec = config.agent
        sandbox = self.generate_sandbox_config(config)
        issues: list[str] = []
        warnings: list[str] = []

        # T1 agents should have no network or very limited
        if spec.runtime.trust_tier == 1 and len(sandbox.allowed_hosts) > 3:
            warnings.append(
                f"T1 agent connects to {len(sandbox.allowed_hosts)} hosts — consider reducing scope"
            )

        # Check for localhost access
        localhost_hosts = [h for h in sandbox.allowed_hosts if "localhost" in h or "127.0.0.1" in h]
        if localhost_hosts:
            warnings.append(
                f"Agent accesses localhost services: {localhost_hosts}. "
                "In Docker, these need host network or explicit port mapping."
            )

        # T1 should not have writable volumes
        if spec.runtime.trust_tier == 1 and sandbox.writable_volume:
            warnings.append("T1 agent has writable volume — consider read-only only")

        return {
            "agent": spec.name,
            "sandbox": {
                "image": sandbox.image,
                "memory": sandbox.memory_limit,
                "cpu": sandbox.cpu_limit,
                "network": sandbox.network_mode,
                "hosts": sandbox.allowed_hosts,
                "readonly": sandbox.read_only_root,
                "timeout": sandbox.timeout_seconds,
            },
            "docker_available": self.is_docker_available(),
            "issues": issues,
            "warnings": warnings,
            "docker_run_args": self.generate_docker_run_args(sandbox),
            "network_policy": self.generate_network_policy(sandbox),
        }
