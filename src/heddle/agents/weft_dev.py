"""Heddle weft-dev agent — development build and test operations.

Provides tools for building, testing, and interactively testing goweft
projects on weftbox. TUI applications are tested via tmux: spawn the binary
in a detached session, send keystrokes, capture the rendered terminal output.

Tools:
    build(project, flags)       — go build, returns stdout/stderr + exit code
    run_tests(project, pattern) — go test, returns full output
    git_status(project)         — branch, dirty files, last commit
    read_file(path)             — read any file from the filesystem
    run_tui(binary, session)    — spawn a binary in a tmux session
    send_keys(session, keys)    — send keystrokes to a running tmux session
    capture_screen(session)     — capture current tmux pane content as text
    kill_session(session)       — kill a tmux session
    list_sessions()             — list active tmux sessions

Trust tier: T2 (worker) — can execute commands, restricted to known projects.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Known project roots — only these paths are allowed for build/test/git ops
_HOME = Path.home()
_PROJECTS = {
    "cas":     _HOME / "projects" / "cas",
    "cas-go":  _HOME / "projects" / "cas",  # legacy alias
    "heddle":  _HOME / "projects" / "loom",
    "loom":    _HOME / "projects" / "loom",
}

# Tmux session prefix to namespace weft-dev sessions
_SESSION_PREFIX = "weft-dev-"
_MAX_OUTPUT = 32_000   # truncate large outputs
_BUILD_TIMEOUT = 120   # seconds
_TEST_TIMEOUT  = 180
_CMD_TIMEOUT   = 30


# ── Helpers ──────────────────────────────────────────────────────────


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = _CMD_TIMEOUT, env: dict | None = None) -> dict:
    """Run a command and return structured result."""
    try:
        merge_env = {**os.environ, **(env or {})}
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merge_env,
        )
        stdout = result.stdout[-_MAX_OUTPUT:] if len(result.stdout) > _MAX_OUTPUT else result.stdout
        stderr = result.stderr[-_MAX_OUTPUT:] if len(result.stderr) > _MAX_OUTPUT else result.stderr
        return {
            "exit_code": result.returncode,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "ok": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s", "ok": False}
    except FileNotFoundError as exc:
        return {"exit_code": -1, "stdout": "", "stderr": str(exc), "ok": False}
    except Exception as exc:
        logger.exception("Unexpected error running %s", cmd)
        return {"exit_code": -1, "stdout": "", "stderr": str(exc), "ok": False}


def _resolve_project(project: str) -> Path | None:
    """Resolve a project name or path to an absolute Path."""
    if project in _PROJECTS:
        return _PROJECTS[project]
    p = Path(project).expanduser()
    if p.is_dir():
        return p
    return None


def _session_name(name: str) -> str:
    """Ensure session name has the weft-dev prefix."""
    if not name.startswith(_SESSION_PREFIX):
        return _SESSION_PREFIX + name
    return name


# ── Tool implementations ──────────────────────────────────────────────


async def build(project: str, flags: str = "") -> str:
    """Build a Go project. Returns exit code, stdout, and stderr.

    project: project name (cas, heddle, loom) or absolute path
    flags:   extra flags passed to go build, e.g. "-race -v"
    """
    root = _resolve_project(project)
    if root is None:
        return json.dumps({"ok": False, "error": f"Unknown project: {project}. Known: {list(_PROJECTS.keys())}"})

    cmd = ["go", "build"]
    if flags:
        cmd.extend(shlex.split(flags))
    cmd.append("./...")

    logger.info("weft-dev: build %s in %s", cmd, root)
    result = _run(cmd, cwd=root, timeout=_BUILD_TIMEOUT)
    result["project"] = project
    result["command"] = " ".join(cmd)
    return json.dumps(result, indent=2)


async def run_tests(project: str, pattern: str = "./...") -> str:
    """Run Go tests. Returns full test output.

    project: project name or path
    pattern: test pattern, default ./... (all packages)
             e.g. "./internal/intent/..." or "-run TestDetect ./internal/intent/"
    """
    root = _resolve_project(project)
    if root is None:
        return json.dumps({"ok": False, "error": f"Unknown project: {project}"})

    # Build command — split pattern in case it includes -run flags
    cmd = ["go", "test", "-v"] + shlex.split(pattern)

    logger.info("weft-dev: test %s in %s", cmd, root)
    result = _run(cmd, cwd=root, timeout=_TEST_TIMEOUT)

    # Parse pass/fail summary from output
    lines = result["stdout"].split("\n")
    passed = sum(1 for l in lines if l.startswith("--- PASS"))
    failed = sum(1 for l in lines if l.startswith("--- FAIL"))
    result["passed"] = passed
    result["failed"] = failed
    result["project"] = project
    result["pattern"] = pattern
    return json.dumps(result, indent=2)


async def git_status(project: str) -> str:
    """Get git status for a project: branch, dirty files, last 5 commits."""
    root = _resolve_project(project)
    if root is None:
        return json.dumps({"ok": False, "error": f"Unknown project: {project}"})

    branch   = _run(["git", "branch", "--show-current"], cwd=root)
    status   = _run(["git", "status", "--short"], cwd=root)
    log      = _run(["git", "log", "--oneline", "-5"], cwd=root)
    remotes  = _run(["git", "remote", "-v"], cwd=root)

    return json.dumps({
        "project": project,
        "branch":  branch["stdout"],
        "dirty":   status["stdout"] or "(clean)",
        "recent_commits": log["stdout"],
        "remotes": remotes["stdout"],
        "ok": True,
    }, indent=2)


async def read_file(path: str) -> str:
    """Read a file from the filesystem. Path can use ~ for home directory."""
    p = Path(path).expanduser()
    try:
        content = p.read_text(errors="replace")
        if len(content) > _MAX_OUTPUT:
            content = content[:_MAX_OUTPUT] + f"\n\n[truncated — {len(content)} chars total]"
        return json.dumps({"path": str(p), "content": content, "ok": True}, indent=2)
    except FileNotFoundError:
        return json.dumps({"ok": False, "error": f"File not found: {p}"})
    except PermissionError:
        return json.dumps({"ok": False, "error": f"Permission denied: {p}"})
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)})


async def run_tui(binary: str, session: str, args: str = "") -> str:
    """Spawn a TUI binary in a detached tmux session for interactive testing.

    binary:  path to the binary (e.g. ~/projects/cas/cas)
    session: short session name (weft-dev- prefix added automatically)
    args:    extra arguments passed to the binary (e.g. "--memory")

    The session stays alive until kill_session() is called.
    Use send_keys() to interact and capture_screen() to observe output.
    """
    bin_path = Path(binary).expanduser()
    if not bin_path.exists():
        return json.dumps({"ok": False, "error": f"Binary not found: {bin_path}"})

    sname = _session_name(session)

    # Kill any existing session with this name
    _run(["tmux", "kill-session", "-t", sname])

    cmd = [str(bin_path)]
    if args:
        cmd.extend(shlex.split(args))

    result = _run(["tmux", "new-session", "-d", "-s", sname, "-x", "220", "-y", "50"] + cmd)
    if not result["ok"] and result["exit_code"] != 0:
        return json.dumps({"ok": False, "error": result["stderr"], "session": sname})

    # Brief wait for the TUI to initialise
    time.sleep(1.5)

    # Capture initial screen
    cap = _run(["tmux", "capture-pane", "-t", sname, "-p"])
    return json.dumps({
        "ok": True,
        "session": sname,
        "binary": str(bin_path),
        "args": args,
        "initial_screen": cap["stdout"],
    }, indent=2)


async def send_keys(session: str, keys: str) -> str:
    """Send keystrokes to a running tmux session.

    session: session name (weft-dev- prefix added if missing)
    keys:    key string in tmux format, e.g.:
               "hello world" — literal text
               "Enter"       — Enter key
               "Tab"         — Tab key
               "C-c"         — Ctrl+C
               "Escape"      — Escape key
               "hello Enter" — type text then press Enter

    After sending keys, waits briefly then returns the screen contents.
    """
    sname = _session_name(session)

    result = _run(["tmux", "send-keys", "-t", sname, keys, ""])
    if not result["ok"]:
        return json.dumps({"ok": False, "error": result["stderr"], "session": sname})

    # Wait for the TUI to react (longer for operations that trigger LLM)
    time.sleep(0.5)

    cap = _run(["tmux", "capture-pane", "-t", sname, "-p"])
    return json.dumps({
        "ok": True,
        "session": sname,
        "keys_sent": keys,
        "screen": cap["stdout"],
    }, indent=2)


async def capture_screen(session: str) -> str:
    """Capture the current terminal contents of a tmux session.

    Returns the rendered text of whatever is displayed in the pane,
    including any TUI elements (borders, tab bars, content, status bar).
    """
    sname = _session_name(session)
    cap = _run(["tmux", "capture-pane", "-t", sname, "-p"])
    if not cap["ok"] and not cap["stdout"]:
        return json.dumps({"ok": False, "error": f"Session not found or empty: {sname}"})
    return json.dumps({
        "ok": True,
        "session": sname,
        "screen": cap["stdout"],
    }, indent=2)


async def kill_session(session: str) -> str:
    """Kill a tmux session created by run_tui()."""
    sname = _session_name(session)
    result = _run(["tmux", "kill-session", "-t", sname])
    return json.dumps({
        "ok": result["ok"],
        "session": sname,
        "message": "killed" if result["ok"] else result["stderr"],
    }, indent=2)


async def list_sessions() -> str:
    """List all active weft-dev tmux sessions."""
    result = _run(["tmux", "list-sessions", "-F", "#{session_name}: #{session_windows} windows, created #{session_created_string}"])
    if not result["ok"]:
        return json.dumps({"ok": True, "sessions": [], "message": "No active sessions"})

    sessions = [
        line for line in result["stdout"].split("\n")
        if line.startswith(_SESSION_PREFIX)
    ]
    return json.dumps({
        "ok": True,
        "sessions": sessions,
        "count": len(sessions),
    }, indent=2)
