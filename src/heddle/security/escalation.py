"""Heddle escalation rules — conditional hold-for-review on tool calls.

When a tool call matches an escalation rule (parameter exceeds a
threshold, tool name matches a pattern, or a specific value is
detected), the call is held instead of executed. The hold is logged
to the audit trail with the rule that triggered it.

This extends T4's binary human-in-the-loop flag into conditional,
per-tool, parameter-aware escalation.

Frameworks: OWASP Agentic #3 (Excessive Agency), NIST AI RMF GV-1.3
(risk tolerance), MAESTRO Authorization layer
"""

from __future__ import annotations

import fnmatch
import logging
import re
from typing import Any

from heddle.security.audit import get_audit_logger

logger = logging.getLogger(__name__)


class EscalationHold(Exception):
    """Raised when a tool call triggers an escalation rule.

    The call is not executed. The hold is logged and the caller
    receives the rule details so they can request approval.
    """

    def __init__(self, agent_name: str, tool_name: str, rule_name: str, reason: str):
        self.agent_name = agent_name
        self.tool_name = tool_name
        self.rule_name = rule_name
        self.reason = reason
        super().__init__(
            f"Escalation hold [{agent_name}.{tool_name}]: "
            f"rule '{rule_name}' — {reason}"
        )


class EscalationRule:
    """A single escalation rule that can match against tool call parameters.

    Supports these condition types:
    - tool: glob pattern matching tool names (e.g. "delete_*", "smart_*")
    - param_gt: parameter value exceeds a numeric threshold
    - param_eq: parameter value equals a specific string
    - param_contains: parameter value contains a substring
    - access: matches tools with a specific access mode ("write")
    """

    def __init__(
        self,
        name: str,
        reason: str,
        tool: str | None = None,
        param_gt: dict[str, float] | None = None,
        param_eq: dict[str, str] | None = None,
        param_contains: dict[str, str] | None = None,
        access: str | None = None,
    ):
        self.name = name
        self.reason = reason
        self.tool = tool
        self.param_gt = param_gt or {}
        self.param_eq = param_eq or {}
        self.param_contains = param_contains or {}
        self.access = access

    def matches(
        self,
        tool_name: str,
        params: dict[str, Any],
        tool_access: str = "read",
    ) -> str | None:
        """Check if this rule matches the given tool call.

        Returns the reason string if matched, None otherwise.
        """
        # Tool name pattern
        if self.tool and not fnmatch.fnmatch(tool_name, self.tool):
            return None

        # Access mode
        if self.access and tool_access != self.access:
            return None

        # Parameter > threshold
        for param, threshold in self.param_gt.items():
            value = params.get(param)
            if value is None:
                continue
            try:
                if float(value) > threshold:
                    return f"{self.reason} ({param}={value} > {threshold})"
            except (ValueError, TypeError):
                continue

        # Parameter == value
        for param, expected in self.param_eq.items():
            value = params.get(param)
            if value is not None and str(value).lower() == expected.lower():
                return f"{self.reason} ({param}={value})"

        # Parameter contains substring
        for param, substring in self.param_contains.items():
            value = params.get(param)
            if value is not None and substring.lower() in str(value).lower():
                return f"{self.reason} ({param} contains '{substring}')"

        # If we had conditions but none matched, no escalation
        if self.param_gt or self.param_eq or self.param_contains:
            return None

        # If only tool/access matched with no param conditions, that's a match
        if self.tool or self.access:
            return self.reason

        return None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "reason": self.reason}
        if self.tool:
            d["tool"] = self.tool
        if self.param_gt:
            d["param_gt"] = self.param_gt
        if self.param_eq:
            d["param_eq"] = self.param_eq
        if self.param_contains:
            d["param_contains"] = self.param_contains
        if self.access:
            d["access"] = self.access
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EscalationRule":
        return cls(
            name=data["name"],
            reason=data.get("reason", ""),
            tool=data.get("tool"),
            param_gt=data.get("param_gt"),
            param_eq=data.get("param_eq"),
            param_contains=data.get("param_contains"),
            access=data.get("access"),
        )


class EscalationEngine:
    """Evaluates escalation rules against tool calls.

    Loaded from an agent config's escalation_rules field.
    Checks every tool call before execution. If a rule matches,
    raises EscalationHold instead of executing.
    """

    def __init__(self, agent_name: str, rules: list[EscalationRule] | None = None):
        self.agent_name = agent_name
        self.rules = rules or []
        self._audit = get_audit_logger()

    def check(
        self,
        tool_name: str,
        params: dict[str, Any],
        tool_access: str = "read",
    ) -> None:
        """Check all rules against this tool call.

        Raises EscalationHold if any rule matches.
        """
        for rule in self.rules:
            reason = rule.matches(tool_name, params, tool_access)
            if reason:
                self._audit.log_trust_violation(
                    self.agent_name,
                    trust_tier=0,
                    action="escalation_hold",
                    detail=f"rule={rule.name} tool={tool_name} reason={reason}",
                )
                raise EscalationHold(
                    self.agent_name, tool_name, rule.name, reason,
                )

    def add_rule(self, rule: EscalationRule) -> None:
        self.rules.append(rule)

    def list_rules(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.rules]

    @classmethod
    def from_config(cls, agent_name: str, rules_data: list[dict]) -> "EscalationEngine":
        """Build an engine from the YAML config's escalation_rules list."""
        rules = [EscalationRule.from_dict(r) for r in rules_data]
        return cls(agent_name, rules)
