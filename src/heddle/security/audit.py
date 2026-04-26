"""Heddle audit logging — structured, hash-chained, tamper-evident.

Every tool call, HTTP bridge request, credential access, and trust
violation is recorded as a JSON Lines entry with a chain hash linking
each entry to its predecessor. This makes tampering detectable.

Frameworks: OWASP Agentic #9, NIST AI RMF MS-2.6, MAESTRO observability
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False  # Windows

logger = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path.home() / ".heddle" / "audit"


class AuditLogger:
    """Append-only, hash-chained audit log.

    Each entry is a JSON object on its own line. The 'chain_hash' field
    is a SHA-256 of the previous entry's JSON, creating a tamper-evident
    chain. If any entry is modified or deleted, the chain breaks.
    """

    def __init__(self, log_dir: str | Path | None = None):
        self._log_dir = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "audit.jsonl"
        self._prev_hash = self._compute_last_hash()

    def _compute_last_hash(self) -> str:
        """Read the last line of the log to get the chain hash."""
        if not self._log_file.exists():
            return "GENESIS"
        try:
            with open(self._log_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return "GENESIS"
                # Read last 4KB to find the final line
                f.seek(max(0, size - 4096))
                lines = f.read().decode("utf-8", errors="replace").strip().split("\n")
                last_line = lines[-1].strip()
                if last_line:
                    return hashlib.sha256(last_line.encode()).hexdigest()
        except Exception:
            pass
        return "GENESIS"

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Write a single audit entry, updating the chain hash.

        Uses file locking to prevent chain breaks when multiple
        processes (e.g. dashboard + test suite) write concurrently.
        """
        with open(self._log_file, "a") as f:
            if _HAS_FCNTL:
                fcntl.flock(f, fcntl.LOCK_EX)
            try:
                # Re-read last hash under lock in case another process
                # appended since we last computed it.
                self._prev_hash = self._compute_last_hash()

                entry["chain_hash"] = self._prev_hash
                entry["timestamp"] = datetime.now(timezone.utc).isoformat()

                line = json.dumps(entry, default=str, separators=(",", ":"))
                self._prev_hash = hashlib.sha256(line.encode()).hexdigest()

                f.write(line + "\n")
                f.flush()
            finally:
                if _HAS_FCNTL:
                    fcntl.flock(f, fcntl.LOCK_UN)

    # ── Public logging methods ───────────────────────────────────────

    def log_tool_call(
        self,
        agent_name: str,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        result_status: str = "success",
        error: str | None = None,
        duration_ms: float | None = None,
    ) -> None:
        """Log an MCP tool invocation."""
        self._write_entry({
            "event": "tool_call",
            "agent": agent_name,
            "tool": tool_name,
            "parameters": _redact_secrets(parameters or {}),
            "status": result_status,
            "error": error,
            "duration_ms": duration_ms,
        })

    def log_http_bridge(
        self,
        agent_name: str,
        tool_name: str,
        method: str,
        url: str,
        status_code: int | None = None,
        duration_ms: float | None = None,
        error: str | None = None,
    ) -> None:
        """Log an HTTP bridge request."""
        self._write_entry({
            "event": "http_bridge",
            "agent": agent_name,
            "tool": tool_name,
            "method": method,
            "url": _redact_url(url),
            "status_code": status_code,
            "duration_ms": duration_ms,
            "error": error,
        })

    def log_trust_violation(
        self,
        agent_name: str,
        trust_tier: int,
        action: str,
        detail: str,
    ) -> None:
        """Log a trust tier violation (blocked action)."""
        self._write_entry({
            "event": "trust_violation",
            "agent": agent_name,
            "trust_tier": trust_tier,
            "action": action,
            "detail": detail,
            "severity": "high",
        })

    def log_credential_access(
        self,
        agent_name: str,
        credential_key: str,
        granted: bool,
    ) -> None:
        """Log a credential request from an agent."""
        self._write_entry({
            "event": "credential_access",
            "agent": agent_name,
            "credential_key": credential_key,
            "granted": granted,
        })

    def log_agent_lifecycle(
        self,
        agent_name: str,
        action: str,
        detail: str = "",
    ) -> None:
        """Log agent start/stop/register/error events."""
        self._write_entry({
            "event": "agent_lifecycle",
            "agent": agent_name,
            "action": action,
            "detail": detail,
        })

    # ── Chain verification ───────────────────────────────────────────

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the hash chain integrity.

        Returns (is_valid, entries_checked, message).
        """
        if not self._log_file.exists():
            return True, 0, "No audit log yet"

        prev_hash = "GENESIS"
        count = 0

        with open(self._log_file) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count, f"Line {line_num}: invalid JSON"

                if entry.get("chain_hash") != prev_hash:
                    return False, count, (
                        f"Line {line_num}: chain broken. "
                        f"Expected {prev_hash[:16]}..., got {entry.get('chain_hash', '?')[:16]}..."
                    )

                prev_hash = hashlib.sha256(line.encode()).hexdigest()
                count += 1

        return True, count, f"Chain valid: {count} entries"

    def recent(
        self,
        n: int = 20,
        event_type: str | None = None,
        agent: str | None = None,
        tool: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        """Read the most recent N entries with optional filters.

        Args:
            n: Maximum entries to return.
            event_type: Filter by event type (tool_call, http_bridge, etc.).
            agent: Filter by agent (config) name.
            tool: Filter by tool name.
            since: ISO timestamp — only entries at or after this time.
            until: ISO timestamp — only entries at or before this time.
        """
        if not self._log_file.exists():
            return []

        entries: list[dict] = []
        with open(self._log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event_type is not None and entry.get("event") != event_type:
                    continue
                if agent is not None and entry.get("agent") != agent:
                    continue
                if tool is not None and entry.get("tool") != tool:
                    continue
                ts = entry.get("timestamp", "")
                if since is not None and ts < since:
                    continue
                if until is not None and ts > until:
                    continue

                entries.append(entry)

        return entries[-n:]


# ── Helpers ──────────────────────────────────────────────────────────

_SECRET_PATTERNS = {"token", "password", "secret", "key", "authorization", "bearer"}


def _redact_secrets(params: dict[str, Any]) -> dict[str, Any]:
    """Redact values that look like secrets."""
    redacted = {}
    for k, v in params.items():
        if any(p in k.lower() for p in _SECRET_PATTERNS):
            redacted[k] = "***REDACTED***"
        elif isinstance(v, str) and len(v) > 40 and v.isalnum():
            redacted[k] = f"{v[:4]}...{v[-4:]}"
        else:
            redacted[k] = v
    return redacted


def _redact_url(url: str) -> str:
    """Redact tokens from URLs."""
    import re
    return re.sub(
        r"(token=|Bearer%20|key=)[A-Za-z0-9]+",
        r"\1***REDACTED***",
        url,
    )


# ── Singleton for global access ──────────────────────────────────────

_global_audit: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _global_audit
    if _global_audit is None:
        _global_audit = AuditLogger()
    return _global_audit
