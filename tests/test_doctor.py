"""Tests for heddle doctor (ADR 005 reconciliation)."""
import json
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from click.testing import CliRunner

from heddle.cli import cli
from heddle.doctor import run_doctor
from heddle.mcp.registry import Registry
from heddle.security.audit import AuditLogger
from heddle.security.credentials import CredentialBroker
from heddle.security.signing import AgentQuarantine


def _write_agent(agents_dir, name, exposes=("ping",), rules=(), headers=None):
    spec = {
        "name": name, "version": "1.0.0", "description": "t",
        "exposes": [{"name": t, "description": "d"} for t in exposes],
        "http_bridge": [{"tool_name": t, "method": "GET", "url": "http://x/" + t,
                         **({"headers": headers} if headers else {})} for t in exposes],
        "escalation_rules": list(rules),
    }
    (agents_dir / f"{name}.yaml").write_text(yaml.safe_dump({"agent": spec}))


@pytest.fixture
def env(tmp_path):
    agents = tmp_path / "agents"
    agents.mkdir()
    broker = CredentialBroker(secrets_file=tmp_path / "s.json", policy_file=tmp_path / "p.json")
    registry = Registry(db_path=tmp_path / "r.db")
    quarantine = AgentQuarantine(quarantine_dir=tmp_path / "q")
    audit = AuditLogger(log_dir=tmp_path / "audit")
    return dict(agents=agents, broker=broker, registry=registry, quarantine=quarantine, audit=audit)


def _run(env, **kw):
    return run_doctor(env["agents"], broker=env["broker"], registry=env["registry"],
                      quarantine=env["quarantine"], audit=env["audit"], **kw)


def _kinds(report):
    return sorted(f.kind for f in report.findings)


def test_clean_run(env):
    _write_agent(env["agents"], "a")
    r = _run(env)
    assert r.clean and r.configs_loaded == 1


def test_config_invalid_is_a_finding(env):
    (env["agents"] / "bad.yaml").write_text("agent:\n  name: bad\n  trust_teir: 1\n")
    r = _run(env)
    assert _kinds(r) == ["config_invalid"]


def test_orphaned_grant(env):
    env["broker"].set_secret("k", "v")
    env["broker"].grant_access("ghost", "k")
    _write_agent(env["agents"], "a", headers={"Authorization": "{{secret:k}}"})
    r = _run(env)
    assert _kinds(r) == ["orphaned_grant"]
    assert r.findings[0].subject == "ghost"


def test_grant_known_via_registry_is_not_orphaned(env):
    env["broker"].set_secret("k", "v")
    env["broker"].grant_access("reg-only", "k")
    env["registry"].register_agent("reg-only", "1.0.0")
    _write_agent(env["agents"], "reg-only", headers={"Authorization": "{{secret:k}}"})
    r = _run(env)
    assert r.clean


def test_grant_missing_secret(env):
    _write_agent(env["agents"], "a")
    env["broker"].grant_access("a", "vanished")
    r = _run(env)
    assert _kinds(r) == ["grant_missing_secret"]
    assert r.findings[0].subject == "a:vanished"


def test_registry_missing_source(env):
    env["registry"].register_agent("stale", "1.0.0")
    r = _run(env)
    assert _kinds(r) == ["registry_missing_source"]


def test_escalation_rule_no_match(env):
    rules = [{"name": "dangerous", "tool": "delete_*", "reason": "x"},
             {"name": "ok", "tool": "pi*", "reason": "y"},
             {"name": "mode-only", "access": "write", "reason": "z"}]
    _write_agent(env["agents"], "a", exposes=("ping",), rules=rules)
    r = _run(env)
    assert _kinds(r) == ["escalation_rule_no_match"]
    assert r.findings[0].subject == "a:dangerous"


def test_unreferenced_secret(env):
    env["broker"].set_secret("used", "1")
    env["broker"].set_secret("dangling", "2")
    env["broker"].grant_access("a", "used")
    _write_agent(env["agents"], "a", headers={"Authorization": "{{secret:used}}"})
    r = _run(env)
    assert _kinds(r) == ["unreferenced_secret"]
    assert r.findings[0].subject == "dangling"


def test_stale_quarantine(env, tmp_path):
    src = tmp_path / "gen.yaml"
    src.write_text("agent:\n  name: gen\n")
    env["quarantine"].quarantine(src)
    now = datetime.now(timezone.utc)
    assert _run(env, now=now).clean
    r = _run(env, now=now + timedelta(days=31))
    assert _kinds(r) == ["stale_quarantine"]
    assert _run(env, now=now + timedelta(days=31), stale_days=60).clean


def test_findings_reach_audit_chain(env):
    env["registry"].register_agent("stale", "1.0.0")
    _run(env)
    entries = env["audit"].recent(10)
    orphaned = [e for e in entries if e["event"] == "exception_orphaned"]
    assert len(orphaned) == 1
    assert orphaned[0]["kind"] == "registry_missing_source"
    valid, _, _ = env["audit"].verify_chain()
    assert valid


def test_no_audit_suppresses_events(env):
    env["registry"].register_agent("stale", "1.0.0")
    _run(env, emit_audit=False)
    assert not [e for e in env["audit"].recent(10) if e["event"] == "exception_orphaned"]


def test_cli_exit_codes_and_json(env, monkeypatch):
    monkeypatch.setattr("heddle.security.credentials.CredentialBroker", lambda: env["broker"])
    monkeypatch.setattr("heddle.mcp.registry.Registry", lambda: env["registry"])
    monkeypatch.setattr("heddle.security.signing.AgentQuarantine", lambda: env["quarantine"])
    _write_agent(env["agents"], "a")
    res = CliRunner().invoke(cli, ["doctor", "--agents-dir", str(env["agents"]), "--no-audit"])
    assert res.exit_code == 0 and "CLEAN" in res.output

    env["registry"].register_agent("stale", "1.0.0")
    res = CliRunner().invoke(cli, ["doctor", "--agents-dir", str(env["agents"]), "--no-audit", "--json"])
    assert res.exit_code == 1
    data = json.loads(res.output)
    assert data["clean"] is False
    assert data["findings"][0]["kind"] == "registry_missing_source"
