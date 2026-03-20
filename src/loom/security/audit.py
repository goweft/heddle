"""LOOM audit logging — structured, hash-chained, tamper-evident.

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

logger = logging.getLogger(__name__)

DEFAULT_LOG_DIR = Path.home() / ".loom" / "audit"


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
        """Write a single audit entry, updating the chain hash."""
        entry["chain_hash"] = self._prev_hash
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()

        line = json.dumps(entry, default=str, separators=(",", ":"))
        self._prev_hash = hashlib.sha256(line.encode()).hexdigest()

        with open(self._log_file, "a") as f:
            f.write(line + "\n")

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

    def recent(self, n: int = 20, event_type: str | None = None) -> list[dict]:
        """Read the most recent N entries, optionally filtered by event type."""
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
                    if event_type is None or entry.get("event") == event_type:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue

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
