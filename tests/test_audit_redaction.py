"""Regression tests for audit log secret redaction.

Covers the externally reported v0.2.0 finding: parameter redaction was
shallow (top-level keys only) and URL token matching stopped at the first
non-alphanumeric character, so nested secrets and punctuated tokens
(JWTs, base64, PAT-style) could be written to the hash-chained audit log
-- where they can never be scrubbed without breaking chain verification.
"""
import pytest

from heddle.security.audit import (
    AuditLogger,
    _redact_secrets,
    _redact_url,
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
)
B64_PADDED = "dGhpcy1pcy1hLXNlY3JldC12YWx1ZS1mb3ItdGVzdHM+Pz8="


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(log_dir=tmp_path / "audit")


# ── Recursive parameter redaction ────────────────────────────────────

def test_nested_dict_secret_redacted():
    out = _redact_secrets({"config": {"auth": {"api_token": "abc123"}}})
    assert out["config"]["auth"]["api_token"] == "***REDACTED***"


def test_secret_inside_list_of_dicts_redacted():
    out = _redact_secrets({"headers": [{"Authorization": "Bearer xyz"}, {"Accept": "json"}]})
    assert out["headers"][0]["Authorization"] == "***REDACTED***"
    assert out["headers"][1]["Accept"] == "json"


def test_sensitive_key_holding_structure_fully_redacted():
    out = _redact_secrets({"secrets": {"a": 1, "b": 2}, "tokens": ["t1", "t2"]})
    assert out["secrets"] == "***REDACTED***"
    assert out["tokens"] == "***REDACTED***"


def test_jwt_under_innocuous_key_is_masked():
    out = _redact_secrets({"payload": JWT})
    assert JWT not in str(out)
    assert out["payload"].startswith(JWT[:4])
    assert out["payload"].endswith(JWT[-4:])


def test_bearer_value_redacted_regardless_of_key():
    out = _redact_secrets({"note": "Bearer abc123xyz"})
    assert out["note"] == "***REDACTED***"


def test_non_sensitive_nested_values_preserved():
    params = {"query": "up", "opts": {"limit": 10, "fields": ["a", "b"]}}
    assert _redact_secrets(params) == params


def test_path_like_long_values_not_masked():
    p = "/mnt/workspace/projects/heddle/src/heddle/security/audit_module.py"
    out = _redact_secrets({"file": p})
    assert out["file"] == p


def test_depth_bomb_does_not_crash():
    inner: dict = {"v": "leaf"}
    for _ in range(50):
        inner = {"nest": inner}
    out = _redact_secrets({"root": inner})
    assert "***REDACTED_DEPTH***" in str(out)


def test_chain_verifies_after_nested_secret_entries(audit):
    audit.log_tool_call("a", "t1", {"config": {"api_key": "sk-live-1234"}}, "success")
    audit.log_tool_call("a", "t2", {"body": {"auth": {"token": JWT}}}, "success")
    valid, count, msg = audit.verify_chain()
    assert valid, msg
    assert count == 2
    raw = str(audit.recent(2))
    assert "sk-live-1234" not in raw
    assert JWT not in raw


# ── URL redaction ────────────────────────────────────────────────────

def test_url_jwt_token_fully_redacted():
    url = f"http://localhost:9090/api/v1/query?token={JWT}&query=up"
    out = _redact_url(url)
    assert JWT not in out
    assert "eyJzdWIi" not in out  # middle JWT segment must not survive
    assert "query=up" in out


def test_url_base64_padded_key_fully_redacted():
    url = f"http://api.local/v1?api_key={B64_PADDED}"
    out = _redact_url(url)
    assert "c3Vi" not in out
    assert B64_PADDED not in out
    assert "***REDACTED***" in out


def test_url_underscored_pat_fully_redacted():
    url = "https://git.local/api?token=ghp_Abc123_def456_XYZ"
    out = _redact_url(url)
    assert "def456" not in out
    assert "_XYZ" not in out


def test_url_userinfo_redacted():
    out = _redact_url("https://admin:hunter2@git.local/repo.git")
    assert "hunter2" not in out
    assert "git.local" in out


def test_url_fragment_access_token_redacted():
    out = _redact_url("https://app.local/cb#access_token=abc.def-ghi&state=ok")
    assert "abc.def-ghi" not in out
    assert "state=ok" in out


def test_url_without_query_unchanged():
    assert _redact_url("http://localhost:9090/api/v1/alerts") == "http://localhost:9090/api/v1/alerts"


def test_url_non_sensitive_params_preserved():
    out = _redact_url("http://x/api?query=up&limit=5")
    assert "query=up" in out
    assert "limit=5" in out
