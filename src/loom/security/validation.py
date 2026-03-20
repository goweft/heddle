"""LOOM input validation — sanitize tool parameters before execution.

Validates tool parameters against their declared types, enforces
length limits, and checks for injection patterns. Every validation
failure is logged to the audit trail.

Frameworks: OWASP Agentic #1 (Prompt Injection), #2 (Unsafe Tool
Orchestration), OWASP LLM #2 (Insecure Output), NIST AI RMF MS-2.5,
MAESTRO Validation layer
"""

from __future__ import annotations

import logging
import re
from typing import Any

from loom.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

# Maximum parameter lengths by type
MAX_LENGTHS = {
    "string": 10_000,
    "integer": 20,
    "number": 30,
    "boolean": 5,
    "array": 50_000,
    "object": 50_000,
}

# Patterns that suggest injection attempts
INJECTION_PATTERNS = [
    # Shell injection
    re.compile(r"[;&|`$]\s*(rm|curl|wget|nc|bash|sh|python|exec|eval)\b", re.IGNORECASE),
    # Path traversal
    re.compile(r"\.\./\.\./"),
    # SQL injection basics
    re.compile(r"('\s*(OR|AND|UNION|SELECT|DROP|DELETE|INSERT|UPDATE)\s)", re.IGNORECASE),
    # Template injection (Jinja, Mako, etc.)
    re.compile(r"\{\{.*\}\}|\{%.*%\}|<%.*%>"),
    # Common LLM prompt injection markers
    re.compile(r"(ignore previous|disregard|forget your|new instructions|system prompt)", re.IGNORECASE),
]


class ValidationError(Exception):
    """Raised when a parameter fails validation."""

    def __init__(self, agent_name: str, tool_name: str, param_name: str, detail: str):
        self.agent_name = agent_name
        self.tool_name = tool_name
        self.param_name = param_name
        self.detail = detail
        super().__init__(f"Validation error [{agent_name}.{tool_name}]: {param_name} — {detail}")


class InputValidator:
    """Validates tool parameters against declared schemas.

    Attached to an agent at build time. Runs before the HTTP bridge
    on every tool call.
    """

    def __init__(self, agent_name: str, strict: bool = False):
        self.agent_name = agent_name
        self.strict = strict  # strict mode blocks injection patterns
        self._audit = get_audit_logger()

    def validate_params(
        self,
        tool_name: str,
        params: dict[str, Any],
        schema: dict[str, dict],
    ) -> dict[str, Any]:
        """Validate and sanitize all parameters for a tool call.

        Args:
            tool_name: Name of the tool being called.
            params: Raw parameters from the MCP client.
            schema: Parameter schema from the agent config
                    (e.g. {"query": {"type": "string", "required": True}}).

        Returns:
            Sanitized parameters (types coerced, strings trimmed).

        Raises:
            ValidationError if a parameter is invalid.
        """
        sanitized = {}

        for pname, pdef in schema.items():
            ptype = pdef.get("type", "string")
            required = pdef.get("required", False)
            default = pdef.get("default")

            value = params.get(pname)

            # Check required
            if value is None:
                if required:
                    self._fail(tool_name, pname, f"Required parameter missing")
                sanitized[pname] = default
                continue

            # Type validation and coercion
            value = self._validate_type(tool_name, pname, value, ptype)

            # Length check for strings
            if isinstance(value, str):
                max_len = MAX_LENGTHS.get(ptype, MAX_LENGTHS["string"])
                if len(value) > max_len:
                    self._fail(tool_name, pname,
                               f"String too long: {len(value)} > {max_len} chars")

            # Injection pattern check (strict mode)
            if self.strict and isinstance(value, str):
                self._check_injection(tool_name, pname, value)

            sanitized[pname] = value

        # Check for unexpected parameters
        extra = set(params.keys()) - set(schema.keys())
        if extra:
            self._audit.log_tool_call(
                self.agent_name, tool_name,
                parameters={"_extra_params": list(extra)},
                result_status="warning",
                error=f"Unexpected parameters ignored: {extra}",
            )

        return sanitized

    def _validate_type(
        self, tool_name: str, pname: str, value: Any, expected_type: str,
    ) -> Any:
        """Validate and coerce a parameter value to its declared type."""
        if expected_type in ("string", "str"):
            if not isinstance(value, str):
                try:
                    return str(value)
                except Exception:
                    self._fail(tool_name, pname, f"Cannot convert {type(value).__name__} to string")
            return value

        if expected_type in ("integer", "int"):
            if isinstance(value, int) and not isinstance(value, bool):
                return value
            try:
                return int(value)
            except (ValueError, TypeError):
                self._fail(tool_name, pname, f"Expected integer, got {type(value).__name__}: {value!r}")

        if expected_type in ("number", "float"):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
            try:
                return float(value)
            except (ValueError, TypeError):
                self._fail(tool_name, pname, f"Expected number, got {type(value).__name__}: {value!r}")

        if expected_type in ("boolean", "bool"):
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                if value.lower() in ("true", "1", "yes"):
                    return True
                if value.lower() in ("false", "0", "no"):
                    return False
            self._fail(tool_name, pname, f"Expected boolean, got {value!r}")

        if expected_type == "array":
            if isinstance(value, list):
                return value
            self._fail(tool_name, pname, f"Expected array, got {type(value).__name__}")

        if expected_type == "object":
            if isinstance(value, dict):
                return value
            self._fail(tool_name, pname, f"Expected object, got {type(value).__name__}")

        # Unknown type — pass through
        return value

    def _check_injection(self, tool_name: str, pname: str, value: str) -> None:
        """Check for common injection patterns."""
        for pattern in INJECTION_PATTERNS:
            match = pattern.search(value)
            if match:
                self._audit.log_trust_violation(
                    self.agent_name,
                    trust_tier=0,
                    action="injection_attempt",
                    detail=f"tool={tool_name} param={pname} pattern={pattern.pattern[:50]}",
                )
                self._fail(tool_name, pname,
                           f"Potential injection detected: matched pattern near '{match.group()[:30]}'")

    def _fail(self, tool_name: str, pname: str, detail: str) -> None:
        """Log and raise a validation error."""
        self._audit.log_tool_call(
            self.agent_name, tool_name,
            parameters={pname: "***VALIDATION_FAILED***"},
            result_status="validation_error",
            error=detail,
        )
        raise ValidationError(self.agent_name, tool_name, pname, detail)


class RateLimiter:
    """Simple per-agent, per-tool rate limiter.

    Uses a sliding window counter. When the limit is exceeded,
    the call is blocked and logged.
    """

    def __init__(self, default_rpm: int = 60):
        self.default_rpm = default_rpm
        self._windows: dict[str, list[float]] = {}

    def check(self, agent_name: str, tool_name: str, rpm: int | None = None) -> bool:
        """Check if a tool call is within rate limits.

        Returns True if allowed, raises ValidationError if blocked.
        """
        import time
        limit = rpm or self.default_rpm
        key = f"{agent_name}:{tool_name}"
        now = time.monotonic()
        window = self._windows.setdefault(key, [])

        # Purge entries older than 60 seconds
        window[:] = [t for t in window if now - t < 60.0]

        if len(window) >= limit:
            audit = get_audit_logger()
            audit.log_trust_violation(
                agent_name, trust_tier=0,
                action="rate_limit",
                detail=f"tool={tool_name} {len(window)} calls in 60s (limit={limit})",
            )
            raise ValidationError(
                agent_name, tool_name, "_rate_limit",
                f"Rate limit exceeded: {len(window)}/{limit} calls per minute",
            )

        window.append(now)
        return True
