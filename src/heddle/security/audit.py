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
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

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
        self._observers: list = []

    def add_observer(self, callback) -> None:
        """Register a callback invoked after each audit entry is written.

        Callback receives the entry dict. Observers that write their own
        audit entries (e.g. anomaly detector) must guard against recursion
        by checking entry['event'] != 'anomaly'.
        """
        self._observers.append(callback)

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

        # Notify observers (skip anomaly events to prevent recursion)
        if entry.get("event") != "anomaly":
            for obs in self._observers:
                try:
                    obs(entry)
                except Exception:
                    pass  # observers must not break the audit pipeline

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

    def log_sandbox_lifecycle(
        self,
        agent_name: str,
        action: str,
        detail: str = "",
    ) -> None:
        """Log a sandbox container lifecycle event.

        Action is one of: spawn, stop, crash, timeout. Wired by
        SandboxedAgent so spawn/kill/reap events flow into the same
        hash-chained log as tool calls. The anomaly detector's
        observer sees these automatically.
        """
        self._write_entry({
            "event": "sandbox_lifecycle",
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

_SECRET_PATTERNS = {
    "token", "password", "passwd", "secret", "key",
    "authorization", "bearer", "signature",
}

_MAX_REDACT_DEPTH = 8

# Long opaque strings (hex, base64, base64url, JWT-shaped) that may be
# secrets even under innocuous key names. Values with whitespace never
# match; path- and URL-like values are screened out in _looks_opaque.
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9._+/=-]{40,}$")


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    return any(p in k for p in _SECRET_PATTERNS)


def _looks_opaque(value: str) -> bool:
    if value.startswith(("/", "./", "~/")) or "://" in value:
        return False  # path- or URL-like; URLs are handled by _redact_url
    return bool(_OPAQUE_RE.match(value))


def _redact_secrets(params: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact values that look like secrets.

    Sensitive key names are matched case-insensitively at every nesting
    level (dicts within dicts, dicts within lists). Long opaque string
    values (hex/base64/JWT-shaped) are partially masked even under
    non-sensitive key names.
    """
    return {k: _redact_value(k, v) for k, v in params.items()}


def _redact_value(key: str, value: Any, _depth: int = 0) -> Any:
    if _is_sensitive_key(key):
        return "***REDACTED***"
    if _depth >= _MAX_REDACT_DEPTH:
        return "***REDACTED_DEPTH***"
    if isinstance(value, dict):
        return {k: _redact_value(k, v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(key, item, _depth + 1) for item in value]
    if isinstance(value, str):
        if value.lower().startswith("bearer "):
            return "***REDACTED***"
        if len(value) > 40 and _looks_opaque(value):
            return f"{value[:4]}...{value[-4:]}"
    return value


def _redact_url(url: str) -> str:
    """Redact secrets from URLs: userinfo, query params, and fragments.

    Query and fragment pairs are parsed properly, so tokens containing
    punctuation (JWT dots, base64 padding, PAT underscores) are redacted
    in full rather than only up to the first non-alphanumeric character.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "***REDACTED_URL***"

    netloc = parts.netloc
    if "@" in netloc:
        netloc = "***REDACTED***@" + netloc.rsplit("@", 1)[1]

    query = _redact_pairs(parts.query) if parts.query else parts.query
    fragment = (
        _redact_pairs(parts.fragment)
        if parts.fragment and "=" in parts.fragment
        else parts.fragment
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, fragment))


def _redact_pairs(qs: str) -> str:
    """Redact sensitive keys in a query-string-shaped set of pairs."""
    pairs = parse_qsl(qs, keep_blank_values=True)
    if not pairs:
        return qs
    out = []
    for k, v in pairs:
        if _is_sensitive_key(k) or v.lower().startswith("bearer "):
            v = "***REDACTED***"
        out.append((k, v))
    return urlencode(out, quote_via=_quote_keep_marker)


def _quote_keep_marker(value: str, safe: str = "", encoding=None, errors=None) -> str:
    """urlencode quote hook that leaves the *** redaction marker readable."""
    return quote(value, safe="*", encoding=encoding, errors=errors)


# ── Singleton for global access ──────────────────────────────────────

_global_audit: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _global_audit
    if _global_audit is None:
        _global_audit = AuditLogger()
        # Attach anomaly detector as observer
        try:
            from heddle.security.anomaly import AnomalyDetector
            detector = AnomalyDetector(audit_logger=_global_audit)
            _global_audit.add_observer(detector.observe)
        except Exception:
            pass  # anomaly detection is optional
    return _global_audit
