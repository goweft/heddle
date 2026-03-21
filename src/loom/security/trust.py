"""LOOM trust tier enforcement — least privilege for agents.

Trust tiers control what actions an agent can perform. The runtime
checks every operation against the agent's declared tier and blocks
violations before they execute.

Tier 1 (Observer):  Read-only. GET requests only. No outbound to undeclared services.
Tier 2 (Worker):    Scoped write. Can POST/PUT to declared endpoints.
Tier 3 (Operator):  Full scope within declared services. Can invoke other agents.
Tier 4 (Privileged): Same as T3 but requires human-in-the-loop approval.

Frameworks: OWASP Agentic #3 (Excessive Agency), NIST AI RMF GV-1.3, Zero Trust
"""

from __future__ import annotations

import logging
from typing import Any

from loom.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

# Methods allowed per trust tier
_TIER_ALLOWED_METHODS: dict[int, set[str]] = {
    1: {"GET", "HEAD", "OPTIONS"},           # observer: read-only
    2: {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"},  # worker: scoped write
    3: {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},  # operator: full scope
    4: {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"},  # privileged: same + HITL
}


class TrustViolation(Exception):
    """Raised when an agent tries to exceed its trust tier."""

    def __init__(self, agent_name: str, tier: int, action: str, detail: str):
        self.agent_name = agent_name
        self.tier = tier
        self.action = action
        self.detail = detail
        super().__init__(f"Trust violation [{agent_name} T{tier}]: {action} — {detail}")


class TrustEnforcer:
    """Enforces trust tier restrictions on agent operations.

    Attached to an agent at runtime. Every HTTP bridge call and
    cross-agent invocation passes through here before executing.
    """

    def __init__(self, agent_name: str, trust_tier: int):
        self.agent_name = agent_name
        self.trust_tier = trust_tier
        self._audit = get_audit_logger()
        self._allowed_methods = _TIER_ALLOWED_METHODS.get(trust_tier, set())

    def check_http_method(self, method: str, url: str) -> None:
        """Check if the agent's tier allows this HTTP method.

        Raises TrustViolation if the method is not permitted.
        """
        method = method.upper()
        if method not in self._allowed_methods:
            detail = (
                f"T{self.trust_tier} agent cannot use {method}. "
                f"Allowed: {sorted(self._allowed_methods)}"
            )
            self._audit.log_trust_violation(
                self.agent_name, self.trust_tier,
                action=f"http_{method}",
                detail=f"{detail} target={url}",
            )
            raise TrustViolation(self.agent_name, self.trust_tier, f"HTTP {method}", detail)

    def check_write_operation(self, operation: str, target: str = "") -> None:
        """Check if the agent can perform a write operation.

        Used for non-HTTP operations like file writes, DB updates, etc.
        """
        if self.trust_tier < 2:
            detail = f"T{self.trust_tier} agents are read-only, cannot {operation}"
            self._audit.log_trust_violation(
                self.agent_name, self.trust_tier,
                action=operation, detail=f"{detail} target={target}",
            )
            raise TrustViolation(self.agent_name, self.trust_tier, operation, detail)

    def check_agent_invocation(self, target_agent: str) -> None:
        """Check if this agent can invoke another agent's tools.

        Only Tier 3+ can do cross-agent invocations (Phase 4 mesh).
        """
        if self.trust_tier < 3:
            detail = f"T{self.trust_tier} agents cannot invoke other agents (requires T3+)"
            self._audit.log_trust_violation(
                self.agent_name, self.trust_tier,
                action="agent_invoke",
                detail=f"{detail} target={target_agent}",
            )
            raise TrustViolation(
                self.agent_name, self.trust_tier,
                "agent_invoke", detail,
            )

    def check_delete(self, target: str = "") -> None:
        """Check if the agent can perform destructive operations.

        Only Tier 3+ can DELETE. Tier 4 would additionally need HITL
        approval (future implementation).
        """
        if self.trust_tier < 3:
            detail = f"T{self.trust_tier} agents cannot delete (requires T3+)"
            self._audit.log_trust_violation(
                self.agent_name, self.trust_tier,
                action="delete", detail=f"{detail} target={target}",
            )
            raise TrustViolation(self.agent_name, self.trust_tier, "delete", detail)

    def check_access_mode(self, tool_name: str, access: str) -> None:
        """Check if the agent's tier allows this access mode.

        T1 agents can only use 'read' tools.
        T2+ agents can use both 'read' and 'write' tools.
        """
        if access == "write" and self.trust_tier < 2:
            detail = (
                f"T{self.trust_tier} agents cannot call write tools. "
                f"Tool '{tool_name}' requires write access."
            )
            self._audit.log_trust_violation(
                self.agent_name, self.trust_tier,
                action="write_tool",
                detail=detail,
            )
            raise TrustViolation(
                self.agent_name, self.trust_tier,
                f"write_tool:{tool_name}", detail,
            )

    def requires_human_approval(self) -> bool:
        """Whether this agent requires human-in-the-loop approval."""
        return self.trust_tier >= 4
