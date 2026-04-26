"""Heddle anomaly detection — flags unusual patterns in tool calls and credential access.

Monitors the audit stream for:
  (a) Novel tool calls — a config calls a tool it has never previously called.
  (b) Rate-limit breaches — tool call rate exceeds the per-config threshold.
  (c) Repeated credential denials — a credential is repeatedly denied for a config.

Anomalies are written to the audit log as event_type='anomaly' entries.

Frameworks: OWASP Agentic #9, NIST AI RMF MS-2.6
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detects anomalous patterns across tool calls and credential access.

    Maintains in-memory state tracking which tools each agent has called
    and which credentials have been denied. State resets on process restart
    — this is a runtime detector, not a persistent baseline.

    The warm-up phase (configurable via `warmup_calls`) suppresses novel-tool
    anomalies during startup, when every first call would otherwise trigger.
    """

    def __init__(
        self,
        audit_logger: Any = None,
        warmup_calls: int = 50,
        denial_threshold: int = 3,
    ):
        """
        Args:
            audit_logger: AuditLogger instance for writing anomaly events.
            warmup_calls: Suppress novel-tool anomalies until this many
                total calls have been observed (avoids startup noise).
            denial_threshold: Number of consecutive denials for the same
                agent+credential before flagging an anomaly.
        """
        if audit_logger is None:
            from heddle.security.audit import get_audit_logger
            audit_logger = get_audit_logger()
        self._audit = audit_logger
        self._warmup_calls = warmup_calls
        self._denial_threshold = denial_threshold

        # Tracking state
        self._total_calls = 0
        self._seen_tools: dict[str, set[str]] = defaultdict(set)
        self._denial_counts: dict[str, int] = defaultdict(int)

    def on_tool_call(self, agent_name: str, tool_name: str) -> str | None:
        """Record a tool call. Returns anomaly reason if flagged, else None."""
        self._total_calls += 1
        key = agent_name
        seen = self._seen_tools[key]

        if tool_name not in seen:
            seen.add(tool_name)
            if self._total_calls > self._warmup_calls:
                reason = (
                    f"Novel tool call: {agent_name} called '{tool_name}' "
                    f"for the first time (previously seen: {sorted(seen - {tool_name})})"
                )
                self._emit_anomaly(agent_name, "novel_tool_call", reason, tool=tool_name)
                return reason

        return None

    def on_rate_limit(self, agent_name: str, tool_name: str, calls: int, limit: int) -> str:
        """Record a rate-limit breach. Always flags as anomaly."""
        reason = f"Rate limit exceeded: {agent_name}/{tool_name} at {calls}/{limit} calls/min"
        self._emit_anomaly(agent_name, "rate_limit_breach", reason, tool=tool_name)
        return reason

    def on_credential_denial(self, agent_name: str, credential_key: str) -> str | None:
        """Record a credential denial. Flags after threshold consecutive denials."""
        key = f"{agent_name}:{credential_key}"
        self._denial_counts[key] += 1
        count = self._denial_counts[key]

        if count >= self._denial_threshold:
            reason = (
                f"Repeated credential denial: {agent_name} denied "
                f"'{credential_key}' {count} times"
            )
            self._emit_anomaly(
                agent_name, "repeated_credential_denial", reason,
                credential_key=credential_key, denial_count=count,
            )
            return reason

        return None

    def on_credential_grant(self, agent_name: str, credential_key: str) -> None:
        """Record a credential grant. Resets the denial counter for this pair."""
        key = f"{agent_name}:{credential_key}"
        self._denial_counts[key] = 0

    def observe(self, entry: dict[str, Any]) -> None:
        """Called by AuditLogger for each non-anomaly entry.

        Dispatches to the appropriate detection method based on event type.
        """
        event = entry.get("event", "")
        agent = entry.get("agent", "")

        if event == "tool_call":
            tool = entry.get("tool", "")
            if tool:
                self.on_tool_call(agent, tool)

        elif event == "credential_access":
            key = entry.get("credential_key", "")
            if entry.get("granted"):
                self.on_credential_grant(agent, key)
            else:
                self.on_credential_denial(agent, key)

        elif event == "trust_violation":
            action = entry.get("action", "")
            if action == "rate_limit":
                # Parse tool name from detail: "tool=X ..."
                detail = entry.get("detail", "")
                tool = ""
                if "tool=" in detail:
                    tool = detail.split("tool=")[1].split()[0]
                self.on_rate_limit(agent, tool, 0, 0)

    def _emit_anomaly(self, agent_name: str, anomaly_type: str, reason: str, **extra: Any) -> None:
        """Write an anomaly event to the audit log."""
        self._audit._write_entry({
            "event": "anomaly",
            "agent": agent_name,
            "anomaly_type": anomaly_type,
            "detail": reason,
            **extra,
        })
        logger.warning("Anomaly detected: %s", reason)


# ── Singleton ────────────────────────────────────────────────────────

_global_detector: AnomalyDetector | None = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get or create the global anomaly detector."""
    global _global_detector
    if _global_detector is None:
        _global_detector = AnomalyDetector()
    return _global_detector
