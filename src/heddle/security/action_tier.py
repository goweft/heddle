"""Per-action tier classification: GREEN / YELLOW / RED / BLACK.

Classifies individual tool invocations by inspecting their arguments,
not just the tool name. The same binary can carry different blast
radii (git commit vs git push), so classification is per-action.

Design rules (executor agent spec, agents/executor.yaml):
- Fail closed: anything unclassifiable is BLACK.
- Deny beats allow: deny lists are checked before allowlists.
- Transitive: a chain of actions takes the worst tier anywhere in it.
- Symlinks resolve before jail checks.

Distinct from sandbox_policy.TierPolicy (numeric trust tiers = resource
budgets per agent). This module classifies *actions*; that one budgets
*agents*.

Integration: RED decisions should be routed to EscalationEngine by the
caller; BLACK decisions are never executed. All decisions are audit-
loggable via Decision.as_audit_fields().
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class ActionTier(IntEnum):
    """Ordered so worst-wins reduction is just max()."""

    GREEN = 0   # harmless, auto-execute
    YELLOW = 1  # mutating but reversible, auto-execute + diff log
    RED = 2     # risky, requires human approval (EscalationHold)
    BLACK = 3   # forbidden, never executes


@dataclass(frozen=True)
class Decision:
    tier: ActionTier
    tool: str
    reason: str

    def as_audit_fields(self) -> dict[str, str]:
        return {"tool": self.tool, "tier": self.tier.name, "reason": self.reason}


def worst(*decisions: Decision) -> Decision:
    """Transitive reduction: the worst tier anywhere in a chain wins."""
    if not decisions:
        raise ValueError("worst() requires at least one decision")
    return max(decisions, key=lambda d: d.tier)


# Git subcommands that imply network egress. Egress is BLACK in v1,
# so these are denied at classification time, not at execution time.
_GIT_NETWORK = {"push", "pull", "fetch", "remote", "clone", "submodule"}
# Destructive history operations: not network, still forbidden.
_GIT_DESTRUCTIVE = {"clean", "filter-branch", "reflog"}


class ActionClassifier:
    """Classifies tool invocations against the executor policy.

    Parameters mirror the ``tools:`` block of an agent YAML. Globs are
    matched against paths relative to the jail root after symlink
    resolution.
    """

    def __init__(
        self,
        jail_root: str,
        deny_globs: list[str] | None = None,
        git_allowlist: list[str] | None = None,
        shell_allowlist: list[str] | None = None,
        shell_deny: list[str] | None = None,
    ):
        self.jail_root = os.path.realpath(jail_root)
        self.deny_globs = deny_globs or []
        self.git_allowlist = git_allowlist or []
        self.shell_allowlist = shell_allowlist or []
        self.shell_deny = shell_deny or []

    # -- public API --------------------------------------------------

    def classify(self, tool: str, params: dict[str, Any]) -> Decision:
        """Classify one tool invocation. Unknown tools are BLACK."""
        handler = {
            "read_file": self._classify_read,
            "write_file": self._classify_write,
            "git_ops": self._classify_git,
            "shell_exec": self._classify_shell,
            "network": self._classify_network,
        }.get(tool)
        if handler is None:
            return Decision(ActionTier.BLACK, tool, "unclassifiable tool: fail closed")
        return handler(params)

    # -- path jail ---------------------------------------------------

    def _jail_check(self, tool: str, raw_path: str) -> Decision | None:
        """Return a BLACK decision on violation, None if the path is clean.

        realpath() first: symlink escapes must be caught before any
        prefix or glob comparison.
        """
        # Relative paths resolve against the JAIL ROOT, not the process
        # cwd — otherwise a bare filename like "DONE.md" would anchor to
        # wherever the process happens to run and falsely read as an escape.
        # realpath still runs (on the joined path) so symlink escapes are
        # caught: a symlink inside the jail pointing outward resolves to its
        # external target and fails the prefix check below.
        if os.path.isabs(raw_path):
            resolved = os.path.realpath(raw_path)
        else:
            resolved = os.path.realpath(os.path.join(self.jail_root, raw_path))
        if resolved != self.jail_root and not (resolved + os.sep).startswith(self.jail_root + os.sep):
            return Decision(
                ActionTier.BLACK, tool, f"path escapes jail: {raw_path} -> {resolved}"
            )
        rel = os.path.relpath(resolved, self.jail_root)
        for pattern in self.deny_globs:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(
                os.path.basename(rel), pattern
            ):
                return Decision(
                    ActionTier.BLACK, tool, f"path matches deny glob '{pattern}': {rel}"
                )
        return None

    # -- per-tool handlers --------------------------------------------

    def _classify_read(self, params: dict[str, Any]) -> Decision:
        path = params.get("path")
        if not path:
            return Decision(ActionTier.BLACK, "read_file", "missing path: fail closed")
        violation = self._jail_check("read_file", path)
        if violation:
            return violation
        return Decision(ActionTier.GREEN, "read_file", "read inside jail")

    def _classify_write(self, params: dict[str, Any]) -> Decision:
        path = params.get("path")
        if not path:
            return Decision(ActionTier.BLACK, "write_file", "missing path: fail closed")
        violation = self._jail_check("write_file", path)
        if violation:
            return violation
        if params.get("delete"):
            if params.get("untracked", True):  # unknown tracking state -> assume worst
                return Decision(
                    ActionTier.RED, "write_file", "untracked delete: not git-recoverable"
                )
            return Decision(
                ActionTier.YELLOW, "write_file", "tracked delete: git-recoverable"
            )
        return Decision(ActionTier.YELLOW, "write_file", "write inside jail")

    def _classify_git(self, params: dict[str, Any]) -> Decision:
        argv = list(params.get("argv") or [])
        sub = next((a for a in argv if not a.startswith("-")), None)
        if sub is None:
            return Decision(ActionTier.BLACK, "git_ops", "no subcommand: fail closed")
        if sub in _GIT_NETWORK:
            return Decision(
                ActionTier.BLACK, "git_ops", f"git {sub} implies network egress"
            )
        if sub in _GIT_DESTRUCTIVE:
            return Decision(ActionTier.BLACK, "git_ops", f"git {sub} is destructive")
        if sub == "reset" and "--hard" in argv:
            return Decision(ActionTier.BLACK, "git_ops", "git reset --hard discards work")
        for entry in self.git_allowlist:
            tokens = entry.split()
            if tokens[0] == sub and all(t in argv for t in tokens[1:]):
                return Decision(
                    ActionTier.YELLOW, "git_ops", f"allowlisted: git {entry}"
                )
        return Decision(
            ActionTier.BLACK, "git_ops", f"git {sub} not on allowlist: fail closed"
        )

    def _classify_shell(self, params: dict[str, Any]) -> Decision:
        argv = list(params.get("argv") or [])
        if not argv:
            return Decision(ActionTier.BLACK, "shell_exec", "empty argv: fail closed")
        binary = os.path.basename(argv[0])
        if binary in self.shell_deny:
            return Decision(
                ActionTier.BLACK, "shell_exec", f"denied binary: {binary}"
            )
        # Shell metacharacters could smuggle a second command past the
        # binary check. Classifying them is harder than refusing them.
        joined = " ".join(argv)
        for meta in (";", "&&", "||", "|", "`", "$("):
            if meta in joined:
                return Decision(
                    ActionTier.BLACK, "shell_exec", f"shell metacharacter '{meta}'"
                )
        if binary in self.shell_allowlist:
            return Decision(
                ActionTier.RED, "shell_exec", f"allowlisted binary {binary}: needs approval"
            )
        return Decision(
            ActionTier.BLACK, "shell_exec", f"{binary} not on allowlist: fail closed"
        )

    def _classify_network(self, params: dict[str, Any]) -> Decision:
        return Decision(ActionTier.BLACK, "network", "network egress denied in v1")
