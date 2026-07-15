"""Unified policy dispatch pipeline.

Every Heddle tool invocation — HTTP-bridged, zero-parameter, or custom
Python handler — routes through :meth:`ToolPolicy.dispatch`. This is the
single enforcement path for:

    rate limiting -> access mode -> escalation rules -> input validation
    -> execution -> audit

Prior to v0.2.1 these checks lived inside per-handler closures in
``mcp/server.py``. That meant zero-parameter tools and custom mesh
handlers bypassed most of the pipeline, and the escalation engine was
dropped between ``_register_http_tool()`` and ``_build_typed_handler()``.
Centralizing dispatch here makes "every tool goes through the same
pipeline" a property of the code rather than the documentation.

Trust-tier HTTP *method* enforcement stays inside the HTTP bridge
(``_execute_http_bridge``) because it needs the rendered URL. Access-mode
enforcement happens here so non-HTTP handlers are covered too.
"""
from __future__ import annotations

import functools
import inspect
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from heddle.security.escalation import EscalationEngine
from heddle.security.trust import TrustEnforcer
from heddle.security.validation import InputValidator, RateLimiter

Executor = Callable[[dict[str, Any]], Awaitable[str]]


@dataclass
class ToolPolicy:
    """Enforcement context for a single exposed tool.

    Any component left as ``None`` is skipped, so callers only pay for
    the controls their agent config declares. The pipeline itself never
    fails open: a raising layer aborts the call before execution.
    """

    agent_name: str
    tool_name: str
    access: str = "read"
    trust: TrustEnforcer | None = None
    audit: Any = None
    validator: InputValidator | None = None
    rate_limiter: RateLimiter | None = None
    escalation: EscalationEngine | None = None
    tool_schema: dict[str, dict[str, Any]] | None = None

    async def dispatch(self, params: dict[str, Any], executor: Executor) -> str:
        """Run the full policy pipeline, then the executor.

        Layer order is cheapest-first, matching the documented dispatch
        pipeline: rate limit -> access mode -> escalation -> validation
        -> execute. Any layer may raise (RateLimit via ValidationError,
        TrustViolation, EscalationHold, ValidationError); failures are
        audited and re-raised so the MCP client sees the policy error.
        """
        start = time.monotonic()
        try:
            if self.rate_limiter is not None:
                self.rate_limiter.check(self.agent_name, self.tool_name)
            if self.trust is not None:
                self.trust.check_access_mode(self.tool_name, self.access)
            if self.escalation is not None:
                self.escalation.check(self.tool_name, params, self.access)
            if self.validator is not None and self.tool_schema:
                params = self.validator.validate_params(
                    self.tool_name, params, self.tool_schema
                )
            result = await executor(params)
            duration = (time.monotonic() - start) * 1000
            if self.audit is not None:
                self.audit.log_tool_call(
                    self.agent_name, self.tool_name, params, "success",
                    duration_ms=duration,
                )
            return result
        except Exception as exc:
            duration = (time.monotonic() - start) * 1000
            if self.audit is not None:
                self.audit.log_tool_call(
                    self.agent_name, self.tool_name, params, "error",
                    error=str(exc), duration_ms=duration,
                )
            raise


def schema_for(tool: Any) -> dict[str, dict[str, Any]]:
    """Build the validator schema dict from an ExposedTool's parameters."""
    return {
        pname: {"type": pdef.type, "required": pdef.required, "default": pdef.default}
        for pname, pdef in tool.parameters.items()
    }


def guard(
    policy: ToolPolicy, fn: Callable[..., Awaitable[str]]
) -> Callable[..., Awaitable[str]]:
    """Wrap an arbitrary async handler so it dispatches through ``policy``.

    Preserves the original signature (``functools.wraps``) so FastMCP
    still derives the correct tool schema. Used by the stdio mesh to put
    custom Python handlers (daily-ops, vram-orchestrator, weft-dev) on
    the same pipeline as HTTP-bridged tools.
    """
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        params = dict(bound.arguments)

        async def _exec(validated: dict[str, Any]) -> str:
            return await fn(**validated)

        return await policy.dispatch(params, _exec)

    return wrapper
