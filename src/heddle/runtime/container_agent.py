"""Container-side stdio protocol handler for sandboxed agents.

Reads JSON request lines from stdin, writes JSON response lines to
stdout. Stays stdlib-only so it runs inside python:3.12-slim with no
heddle install needed.

Wire protocol (one JSON object per line, both directions):

    request : {"tool": "<name>", "params": {...}}
    response: {"ok": true,  "result": "<string>"}
              {"ok": false, "error":  "<message>"}

Built-in tools (Slice 2 minimum; production dispatch is a separate
slice):

    __ping__              -> "pong"
    __echo__   params     -> JSON dump of params
    __sleep__  {"seconds": N} -> sleeps N seconds, returns "slept N"

The runner uses __ping__ for health checks and __sleep__ for watchdog
behavior under test. Real agent tools are registered by extending
HANDLERS.
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any, Callable


def _ping(_: dict[str, Any]) -> str:
    return "pong"


def _echo(params: dict[str, Any]) -> str:
    return json.dumps(params)


def _sleep(params: dict[str, Any]) -> str:
    seconds = float(params.get("seconds", 0))
    time.sleep(seconds)
    return f"slept {seconds}"


HANDLERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "__ping__": _ping,
    "__echo__": _echo,
    "__sleep__": _sleep,
}


def _respond(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def main() -> int:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _respond({"ok": False, "error": f"invalid JSON: {exc}"})
            continue

        tool_name = request.get("tool")
        params = request.get("params") or {}
        handler = HANDLERS.get(tool_name)
        if handler is None:
            _respond({"ok": False, "error": f"unknown tool: {tool_name!r}"})
            continue

        try:
            result = handler(params)
        except Exception as exc:
            _respond({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            continue
        _respond({"ok": True, "result": result})

    return 0


if __name__ == "__main__":
    sys.exit(main())
