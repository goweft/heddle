"""Reconciliation: find policy exceptions that have outlived the thing they
were granted for.

ADR 005 names the invariant -- every exception carries exactly one
collector. ``heddle doctor`` is the read-only half of that: it walks the
places where Heddle stores exceptions (credential grants, registry rows,
escalation rules, quarantine entries) and reports any that no longer
point at anything. Each finding is written to the audit chain as an
``exception_orphaned`` event so the report itself is tamper-evident.

Nothing here mutates state. ``--fix`` is deliberately absent in v0.3.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from heddle.config.loader import ConfigError, load_agent_config
from heddle.config.schema import AgentConfig

SECRET_REF = re.compile(r"\{\{secret:(\S+?)\}\}")

KINDS = (
    "config_invalid",
    "orphaned_grant",
    "grant_missing_secret",
    "registry_missing_source",
    "escalation_rule_no_match",
    "unreferenced_secret",
    "stale_quarantine",
)


@dataclass(frozen=True)
class Finding:
    kind: str
    subject: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "subject": self.subject, "detail": self.detail}


@dataclass
class DoctorReport:
    findings: list[Finding] = field(default_factory=list)
    configs_loaded: int = 0
    agents_dir: str = ""

    @property
    def clean(self) -> bool:
        return not self.findings

    def by_kind(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {k: [] for k in KINDS}
        for f in self.findings:
            out.setdefault(f.kind, []).append(f)
        return {k: v for k, v in out.items() if v}

    def as_dict(self) -> dict[str, Any]:
        return {
            "agents_dir": self.agents_dir,
            "configs_loaded": self.configs_loaded,
            "clean": self.clean,
            "findings": [f.as_dict() for f in self.findings],
        }


# -- Loading ------------------------------------------------------------------

def _load_configs(agents_dir: Path, findings: list[Finding]) -> dict[str, tuple[AgentConfig, str]]:
    """Return {agent_name: (config, raw_text)}; unparseable files become findings.

    A YAML that fails validation is itself an exception with no collector:
    it is excluded from every other check below, so it is reported first
    rather than silently narrowing the audit.
    """
    loaded: dict[str, tuple[AgentConfig, str]] = {}
    for path in sorted(agents_dir.glob("*.yaml")):
        try:
            cfg = load_agent_config(path)
        except (ConfigError, Exception) as exc:  # noqa: BLE001 - report, don't crash
            findings.append(Finding("config_invalid", path.name, str(exc).splitlines()[0][:200]))
            continue
        loaded[cfg.agent.name] = (cfg, path.read_text())
    return loaded


# -- Checks -------------------------------------------------------------------

def _check_grants(policy: dict[str, list[str]], secrets: set[str],
                  config_names: set[str], registry_names: set[str],
                  findings: list[Finding]) -> None:
    known = config_names | registry_names
    for agent, keys in sorted(policy.items()):
        if agent not in known:
            findings.append(Finding(
                "orphaned_grant", agent,
                f"policy grants {sorted(keys)} but no config or registry entry exists"))
        for key in keys:
            if key not in secrets:
                findings.append(Finding(
                    "grant_missing_secret", f"{agent}:{key}",
                    "grant references a secret that is not in the store"))


def _check_registry(registry_names: set[str], config_names: set[str],
                    findings: list[Finding]) -> None:
    for name in sorted(registry_names - config_names):
        findings.append(Finding(
            "registry_missing_source", name,
            "registry row has no source YAML in the agents directory"))


def _check_escalation_rules(configs: dict[str, tuple[AgentConfig, str]],
                            findings: list[Finding]) -> None:
    for name, (cfg, _) in sorted(configs.items()):
        exposed = [t.name for t in cfg.agent.exposes]
        for rule in cfg.agent.escalation_rules:
            if rule.tool is None:
                continue  # access-only rules match by mode, not name
            if not any(fnmatch.fnmatchcase(t, rule.tool) for t in exposed):
                findings.append(Finding(
                    "escalation_rule_no_match", f"{name}:{rule.name}",
                    f"tool glob {rule.tool!r} matches none of {exposed}"))


def _check_unreferenced_secrets(secrets: set[str],
                                configs: dict[str, tuple[AgentConfig, str]],
                                findings: list[Finding]) -> None:
    referenced: set[str] = set()
    for _, raw in configs.values():
        referenced.update(SECRET_REF.findall(raw))
    for key in sorted(secrets - referenced):
        findings.append(Finding(
            "unreferenced_secret", key,
            "secret exists but no agent config references it"))


def _check_quarantine(entries: list[dict[str, Any]], stale_days: int,
                      now: datetime, findings: list[Finding]) -> None:
    cutoff = now - timedelta(days=stale_days)
    for e in entries:
        if e.get("status") != "pending":
            continue
        raw = e.get("quarantined_at")
        if not raw:
            findings.append(Finding("stale_quarantine", e.get("file", "?"),
                                    "pending entry has no quarantined_at timestamp"))
            continue
        try:
            ts = datetime.fromisoformat(raw)
        except ValueError:
            findings.append(Finding("stale_quarantine", e.get("file", "?"),
                                    f"unparseable quarantined_at {raw!r}"))
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            age = (now - ts).days
            findings.append(Finding(
                "stale_quarantine", e.get("file", "?"),
                f"pending for {age} days (threshold {stale_days})"))


# -- Entry point --------------------------------------------------------------

def run_doctor(
    agents_dir: str | Path = "agents",
    *,
    broker: Any | None = None,
    registry: Any | None = None,
    quarantine: Any | None = None,
    audit: Any | None = None,
    stale_days: int = 30,
    emit_audit: bool = True,
    now: datetime | None = None,
) -> DoctorReport:
    """Run every reconciliation check and return the report.

    Dependencies default to the live ``~/.heddle`` stores; tests inject
    temp-backed instances. ``emit_audit=False`` suppresses the
    ``exception_orphaned`` events (used by ``--no-audit``).
    """
    agents_dir = Path(agents_dir)
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    if broker is None:
        from heddle.security.credentials import CredentialBroker
        broker = CredentialBroker()
    if registry is None:
        from heddle.mcp.registry import Registry
        registry = Registry()
    if quarantine is None:
        from heddle.security.signing import AgentQuarantine
        quarantine = AgentQuarantine()

    configs = _load_configs(agents_dir, findings)
    config_names = set(configs)
    registry_names = {a["name"] for a in registry.list_agents()}
    secrets = set(broker.list_secrets())
    policy: dict[str, list[str]] = dict(getattr(broker, "_policy", {}))

    _check_grants(policy, secrets, config_names, registry_names, findings)
    _check_registry(registry_names, config_names, findings)
    _check_escalation_rules(configs, findings)
    _check_unreferenced_secrets(secrets, configs, findings)
    _check_quarantine(quarantine.list_all(), stale_days, now, findings)

    report = DoctorReport(findings=findings, configs_loaded=len(configs),
                          agents_dir=str(agents_dir))

    if emit_audit and findings:
        if audit is None:
            from heddle.security.audit import get_audit_logger
            audit = get_audit_logger()
        for f in findings:
            audit.log_exception_orphaned(f.kind, f.subject, f.detail)

    return report
