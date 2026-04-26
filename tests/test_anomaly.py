"""Tests for Heddle anomaly detection."""
import json
import pytest
from pathlib import Path

from heddle.security.audit import AuditLogger
from heddle.security.anomaly import AnomalyDetector


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(log_dir=tmp_path / "audit")


@pytest.fixture
def detector(audit):
    d = AnomalyDetector(audit_logger=audit, warmup_calls=3, denial_threshold=2)
    return d


# ── Novel tool call ──────────────────────────────────────────────────

def test_novel_tool_no_anomaly_during_warmup(audit, detector):
    """No anomaly flagged during warmup period."""
    result = detector.on_tool_call("agent-a", "tool-1")
    assert result is None
    result = detector.on_tool_call("agent-a", "tool-2")
    assert result is None
    # Still in warmup (3 calls needed)
    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 0


def test_novel_tool_anomaly_after_warmup(audit, detector):
    """Novel tool call flagged after warmup period."""
    # Warmup: 3 calls
    detector.on_tool_call("agent-a", "tool-1")
    detector.on_tool_call("agent-a", "tool-1")
    detector.on_tool_call("agent-a", "tool-1")

    # 4th call with a new tool -> should flag
    result = detector.on_tool_call("agent-a", "tool-NEW")
    assert result is not None
    assert "Novel tool call" in result

    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 1
    assert entries[0]["anomaly_type"] == "novel_tool_call"
    assert entries[0]["agent"] == "agent-a"


def test_novel_tool_not_flagged_twice(audit, detector):
    """Same tool called again after flagging doesn't re-flag."""
    for _ in range(4):
        detector.on_tool_call("agent-a", "tool-1")

    # First call to tool-NEW -> flags
    detector.on_tool_call("agent-a", "tool-NEW")
    # Second call to tool-NEW -> no flag
    result = detector.on_tool_call("agent-a", "tool-NEW")
    assert result is None

    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 1  # only one anomaly


def test_novel_tool_per_agent(audit, detector):
    """Novel tool detection is per-agent."""
    for _ in range(4):
        detector.on_tool_call("agent-a", "shared-tool")

    # agent-b calling same tool is novel for agent-b
    result = detector.on_tool_call("agent-b", "shared-tool")
    # But agent-b hasn't exceeded warmup yet (only 5 total calls)
    assert result is not None or detector._total_calls <= detector._warmup_calls


# ── Rate limit breach ────────────────────────────────────────────────

def test_rate_limit_breach(audit, detector):
    """Rate limit breach always emits anomaly."""
    result = detector.on_rate_limit("agent-x", "heavy-tool", 150, 120)
    assert "Rate limit" in result

    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 1
    assert entries[0]["anomaly_type"] == "rate_limit_breach"


# ── Repeated credential denial ──────────────────────────────────────

def test_credential_denial_below_threshold(audit, detector):
    """Single denial doesn't flag anomaly."""
    result = detector.on_credential_denial("agent-a", "secret-key")
    assert result is None

    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 0


def test_credential_denial_at_threshold(audit, detector):
    """Reaching threshold flags anomaly."""
    detector.on_credential_denial("agent-a", "secret-key")
    result = detector.on_credential_denial("agent-a", "secret-key")
    assert result is not None
    assert "Repeated credential denial" in result

    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 1
    assert entries[0]["anomaly_type"] == "repeated_credential_denial"
    assert entries[0]["denial_count"] == 2


def test_credential_grant_resets_counter(audit, detector):
    """Grant resets the denial counter."""
    detector.on_credential_denial("agent-a", "secret-key")
    detector.on_credential_grant("agent-a", "secret-key")
    result = detector.on_credential_denial("agent-a", "secret-key")
    assert result is None  # counter was reset, only 1 denial now


def test_credential_denial_per_agent(audit, detector):
    """Denial counting is per agent+credential pair."""
    detector.on_credential_denial("agent-a", "key-1")
    detector.on_credential_denial("agent-b", "key-1")

    # Neither has hit threshold (2) for their respective pairs
    entries = audit.recent(10, event_type="anomaly")
    assert len(entries) == 0


# ── Observer integration ─────────────────────────────────────────────

def test_observer_integration(audit):
    """Anomaly detector works as audit logger observer."""
    detector = AnomalyDetector(audit_logger=audit, warmup_calls=2, denial_threshold=2)
    audit.add_observer(detector.observe)

    # Warmup
    audit.log_tool_call("agent-a", "tool-1", {}, "success")
    audit.log_tool_call("agent-a", "tool-1", {}, "success")

    # Novel tool via observer
    audit.log_tool_call("agent-a", "tool-NEW", {}, "success")

    entries = audit.recent(20, event_type="anomaly")
    assert len(entries) == 1
    assert entries[0]["anomaly_type"] == "novel_tool_call"


def test_observer_credential_denial(audit):
    """Observer picks up credential denials and flags after threshold."""
    detector = AnomalyDetector(audit_logger=audit, warmup_calls=0, denial_threshold=2)
    audit.add_observer(detector.observe)

    audit.log_credential_access("agent-x", "api-key", granted=False)
    audit.log_credential_access("agent-x", "api-key", granted=False)

    entries = audit.recent(20, event_type="anomaly")
    assert len(entries) == 1
    assert entries[0]["anomaly_type"] == "repeated_credential_denial"


def test_observer_no_recursion(audit):
    """Anomaly events don't trigger the observer (no infinite loop)."""
    detector = AnomalyDetector(audit_logger=audit, warmup_calls=0, denial_threshold=1)
    audit.add_observer(detector.observe)

    # This triggers an anomaly, which writes to audit, which should NOT
    # re-trigger the observer (event="anomaly" is filtered out)
    audit.log_credential_access("agent-x", "key", granted=False)

    # Should have exactly: 1 credential_access + 1 anomaly
    all_entries = audit.recent(20)
    anomalies = [e for e in all_entries if e["event"] == "anomaly"]
    assert len(anomalies) == 1  # not infinite
