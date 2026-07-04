"""Integration tests — these spawn real Docker containers.

Run with `pytest -m integration`. Skipped automatically when the docker
CLI is not on PATH so CI environments without Docker stay green.

The three tests here exercise the v0.2 Pillar 1 DoD baseline:
write-to-root denied, OOM kill captured, egress blocked. The egress
test uses --network=none only; fine-grained nftables enforcement is
deferred to v0.3 per the slice-3 brief.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from heddle.runtime.images import resolve as resolve_image


# Resolve once at import time so every test uses the same digest-pinned
# reference that production sandboxing would use.
IMAGE = resolve_image("python-3.12-slim")


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker CLI not available",
    ),
]


def _docker_run(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run `docker run` with the given args; capture stdout/stderr."""
    return subprocess.run(
        ["docker", "run", "--rm", *args],
        capture_output=True,
        timeout=timeout,
    )


def test_integration_write_to_root_denied():
    """--read-only must block writes to / inside the container."""
    result = _docker_run(
        "--read-only", IMAGE, "touch", "/nope",
    )
    assert result.returncode != 0, (
        f"expected non-zero exit; got 0 with stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    assert b"Read-only file system" in result.stderr, (
        f"expected read-only fs error in stderr; got {result.stderr!r}"
    )


def test_integration_oom_kill_captured():
    """--memory limit must trigger OOM kill (exit 137) on overshoot."""
    # bytearray(n) zero-initializes, but kernels with aggressive
    # overcommit (e.g. GitHub Actions runners) use copy-on-write zero
    # pages without committing real RAM — the OOM killer never fires.
    # Fix: allocate b'x' * 10MB in a loop. The bytes literal is
    # non-zero, so every page is dirty and the kernel must commit
    # physical memory. The loop runs until OOM kills the process.
    oom_script = (
        "data = []\n"
        "while True:\n"
        "    data.append(b'x' * 10_000_000)\n"
    )
    result = _docker_run(
        "--memory=64m", IMAGE,
        "python3", "-c", oom_script,
        timeout=30,
    )
    assert result.returncode == 137, (
        f"expected OOM exit code 137 (SIGKILL); got {result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_integration_egress_blocked_with_network_none():
    """--network=none must block all outbound traffic from the container.

    nftables-based per-host egress is deferred to v0.3; this test
    verifies the Docker-level baseline only.
    """
    result = _docker_run(
        "--network=none", IMAGE,
        "python", "-c",
        "import urllib.request, sys; "
        "urllib.request.urlopen('http://1.1.1.1', timeout=5); "
        "sys.exit(0)",
        timeout=30,
    )
    assert result.returncode != 0, (
        f"expected non-zero exit; got 0 (network was reachable). "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    stderr = result.stderr.decode("utf-8", errors="replace").lower()
    expected_signals = (
        "network is unreachable",
        "name or service not known",
        "temporary failure in name resolution",
        "no route to host",
        "urlerror",
    )
    assert any(sig in stderr for sig in expected_signals), (
        f"expected a network-isolation error in stderr; got {result.stderr!r}"
    )
