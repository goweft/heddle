"""Heddle credential broker — runtime secret injection.

Agents never see raw credentials in their YAML configs. Instead, they
reference credential keys like {{secret:intel-rag-token}}, and the
broker resolves them at runtime from an encrypted secrets store.

Secrets are stored in a JSON file (encrypted at rest in Phase 3+) at
~/.heddle/secrets.json. Agents can only access secrets that are explicitly
granted to them in the broker's access policy.

Memory hardening (OWASP Agentic #7, NIST AI RMF MAP-3.4):
  - Secrets are stored as mlock'd bytearrays (SecretBuffer), not plain str.
    mlock pins the pages in RAM so the kernel cannot swap them to disk.
  - Buffers are explicitly zeroed when a secret is removed or the broker
    is closed, shrinking the window during which secrets exist in memory.
  - Python str values returned to callers are transient (can't be zeroed —
    str is immutable). Use use_credential() where you need minimal lifetime.
  - mlock failure is non-fatal: logged as a warning, broker continues without
    swap protection. This handles unprivileged environments gracefully.

Frameworks: OWASP Agentic #7 (Unsafe Credential Management), NIST AI RMF MAP-3.4
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import logging
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from heddle.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

DEFAULT_SECRETS_FILE = Path.home() / ".heddle" / "secrets.json"
DEFAULT_POLICY_FILE = Path.home() / ".heddle" / "credential_policy.json"

# ── mlock helpers ────────────────────────────────────────────────────

_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL | None:
    global _libc
    if _libc is None:
        lib = ctypes.util.find_library("c")
        if lib:
            try:
                _libc = ctypes.CDLL(lib, use_errno=True)
            except OSError:
                pass
    return _libc


def _try_mlock(buf: bytearray) -> bool:
    """Pin *buf* in RAM so the kernel won't swap it to disk.

    Returns True if mlock succeeded, False if it failed or is unavailable.
    Failure is non-fatal — the broker logs a warning and continues.
    """
    libc = _get_libc()
    if libc is None or not buf:
        return False
    try:
        arr = (ctypes.c_char * len(buf)).from_buffer(buf)
        ret = libc.mlock(arr, len(buf))
        if ret != 0:
            errno = ctypes.get_errno()
            logger.warning("mlock failed (errno %d) — secrets not swap-pinned", errno)
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("mlock unavailable: %s — secrets not swap-pinned", exc)
        return False


def _try_munlock(buf: bytearray) -> None:
    """Release an mlock on *buf*. Errors are silently ignored."""
    libc = _get_libc()
    if libc is None or not buf:
        return
    try:
        arr = (ctypes.c_char * len(buf)).from_buffer(buf)
        libc.munlock(arr, len(buf))
    except Exception:  # noqa: BLE001
        pass


# ── SecretBuffer ─────────────────────────────────────────────────────


class SecretBuffer:
    """A mutable, mlock-pinned buffer for a single secret value.

    Stores the secret as a bytearray so it can be explicitly zeroed when
    it is no longer needed.  The buffer is mlocked on construction to
    prevent the kernel from swapping it to disk.

    Usage as a context manager (preferred — minimises secret lifetime):

        with broker.use_credential(agent, key) as secret:
            headers["Authorization"] = f"Bearer {secret}"
        # secret str goes out of scope; buffer is NOT zeroed here —
        # the broker controls buffer lifetime, not individual calls.

    The buffer is zeroed only when the broker calls .zero() explicitly
    (on remove_secret / close).  This is intentional: mlock is the
    primary protection; zeroing is a defence-in-depth measure for
    when the broker shuts down or a secret is rotated out.
    """

    __slots__ = ("_buf", "_locked")

    def __init__(self, value: str) -> None:
        encoded = value.encode("utf-8")
        self._buf: bytearray = bytearray(encoded)
        self._locked: bool = _try_mlock(self._buf)

    def decode(self) -> str:
        """Return a plain str copy of the secret for use in API calls.

        The returned str is a transient Python object; it cannot be zeroed
        (str is immutable). Use it, let it go out of scope, and rely on
        the GC to collect it. The canonical secret lives in _buf.
        """
        return self._buf.decode("utf-8")

    def zero(self) -> None:
        """Overwrite the buffer with zeros and release the mlock."""
        for i in range(len(self._buf)):
            self._buf[i] = 0
        if self._locked:
            _try_munlock(self._buf)
            self._locked = False

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:
        return f"<SecretBuffer len={len(self._buf)} locked={self._locked}>"


# ── Exceptions ───────────────────────────────────────────────────────


class CredentialDenied(Exception):
    """Raised when an agent requests a credential it doesn't have access to."""

    def __init__(self, agent_name: str, key: str, reason: str):
        self.agent_name = agent_name
        self.key = key
        super().__init__(f"Credential denied [{agent_name}]: {key} — {reason}")


# ── CredentialBroker ─────────────────────────────────────────────────


class CredentialBroker:
    """Manages secrets and controls agent access to them.

    Secrets file format (~/.heddle/secrets.json):
    {
        "intel-rag-token": "a6e60bd2...",
        "gitea-api-token": "abc123...",
        "service-webhook": "https://..."
    }

    Policy file format (~/.heddle/credential_policy.json):
    {
        "intel-rag-bridge": ["intel-rag-token"],
        "gitea-api-bridge": ["gitea-api-token"],
        "webhook-poster": ["service-webhook", "intel-rag-token"]
    }

    Secrets are held as SecretBuffer instances (mlock'd bytearrays).
    Call close() when the broker is no longer needed to zero all buffers.
    """

    def __init__(
        self,
        secrets_file: str | Path | None = None,
        policy_file: str | Path | None = None,
    ):
        self._secrets_file = Path(secrets_file) if secrets_file else DEFAULT_SECRETS_FILE
        self._policy_file = Path(policy_file) if policy_file else DEFAULT_POLICY_FILE
        self._audit = get_audit_logger()
        self._secrets: dict[str, SecretBuffer] = {}
        self._policy: dict[str, list[str]] = {}
        self._load()

    # ── Loading ──────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load secrets and policy from disk."""
        if self._secrets_file.exists():
            try:
                raw: dict[str, str] = json.loads(self._secrets_file.read_text())
                self._secrets = {k: SecretBuffer(v) for k, v in raw.items()}
                logger.info("Loaded %d secrets from %s", len(self._secrets), self._secrets_file)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to load secrets: %s", exc)

        if self._policy_file.exists():
            try:
                self._policy = json.loads(self._policy_file.read_text())
                logger.info("Loaded credential policy for %d agents", len(self._policy))
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to load credential policy: %s", exc)

    # ── Policy checks ────────────────────────────────────────────────

    def _check_policy(self, agent_name: str, key: str) -> None:
        """Raise CredentialDenied if the agent is not allowed the key."""
        allowed_keys = self._policy.get(agent_name, [])
        if key not in allowed_keys:
            self._audit.log_credential_access(agent_name, key, granted=False)
            raise CredentialDenied(
                agent_name,
                key,
                f"Not in agent's allowed credentials: {allowed_keys}",
            )
        if key not in self._secrets:
            self._audit.log_credential_access(agent_name, key, granted=False)
            raise CredentialDenied(
                agent_name,
                key,
                "Secret key not found in secrets store",
            )

    # ── Public API ───────────────────────────────────────────────────

    def get_credential(self, agent_name: str, key: str) -> str:
        """Retrieve a credential for an agent as a plain str.

        The returned str is a transient copy decoded from the SecretBuffer.
        It cannot be zeroed (Python str is immutable). For tighter lifetime
        control, prefer use_credential() as a context manager.

        Raises CredentialDenied if the agent doesn't have access.
        """
        self._check_policy(agent_name, key)
        self._audit.log_credential_access(agent_name, key, granted=True)
        return self._secrets[key].decode()

    @contextmanager
    def use_credential(self, agent_name: str, key: str) -> Iterator[str]:
        """Context manager that yields the secret str for the duration of the block.

        Preferred over get_credential() where the secret is only needed for
        a single operation (e.g. constructing an HTTP header). The str is a
        transient copy that goes out of scope when the block exits.

        Example:
            with broker.use_credential("my-agent", "api-token") as token:
                headers["Authorization"] = f"Bearer {token}"
            # token is no longer referenced after this point
        """
        self._check_policy(agent_name, key)
        self._audit.log_credential_access(agent_name, key, granted=True)
        secret = self._secrets[key].decode()
        try:
            yield secret
        finally:
            del secret

    def resolve_template(self, agent_name: str, text: str) -> str:
        """Replace {{secret:key}} placeholders in a string.

        Used by the HTTP bridge to inject credentials into headers and URLs
        at runtime instead of storing them in the YAML config.
        """
        def replacer(match: re.Match) -> str:
            key = match.group(1).strip()
            try:
                return self.get_credential(agent_name, key)
            except CredentialDenied:
                logger.warning("Credential %s denied for agent %s", key, agent_name)
                return "***CREDENTIAL_DENIED***"

        return re.sub(r"\{\{secret:(\S+?)\}\}", replacer, text)

    def resolve_headers(self, agent_name: str, headers: dict[str, str]) -> dict[str, str]:
        """Resolve {{secret:key}} in all header values."""
        return {k: self.resolve_template(agent_name, v) for k, v in headers.items()}

    # ── Management ───────────────────────────────────────────────────

    def set_secret(self, key: str, value: str) -> None:
        """Store a secret (admin operation).

        If a buffer already exists for this key, it is zeroed before being
        replaced so the old value doesn't linger alongside the new one.
        """
        if key in self._secrets:
            self._secrets[key].zero()
        self._secrets[key] = SecretBuffer(value)
        self._save_secrets()
        logger.info("Secret stored: %s", key)

    def remove_secret(self, key: str) -> bool:
        """Remove a secret, zeroing its buffer immediately."""
        if key in self._secrets:
            self._secrets[key].zero()
            del self._secrets[key]
            self._save_secrets()
            return True
        return False

    def grant_access(self, agent_name: str, key: str) -> None:
        """Grant an agent access to a credential key."""
        if agent_name not in self._policy:
            self._policy[agent_name] = []
        if key not in self._policy[agent_name]:
            self._policy[agent_name].append(key)
            self._save_policy()
            logger.info("Granted %s access to %s", agent_name, key)

    def revoke_access(self, agent_name: str, key: str) -> bool:
        """Revoke an agent's access to a credential key."""
        if agent_name in self._policy and key in self._policy[agent_name]:
            self._policy[agent_name].remove(key)
            self._save_policy()
            return True
        return False

    def list_secrets(self) -> list[str]:
        """List secret keys (not values)."""
        return list(self._secrets.keys())

    def list_agent_grants(self, agent_name: str) -> list[str]:
        """List which credential keys an agent can access."""
        return self._policy.get(agent_name, [])

    def close(self) -> None:
        """Zero all secret buffers and release mlocks.

        Call this when the broker is being shut down (e.g. on SIGTERM/SIGINT)
        to minimise how long secrets remain in process memory.
        """
        for key, buf in self._secrets.items():
            buf.zero()
            logger.debug("Zeroed secret buffer: %s", key)
        self._secrets.clear()
        logger.info("CredentialBroker closed — all buffers zeroed")

    def __del__(self) -> None:
        """Best-effort cleanup if close() was not called explicitly."""
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    # ── Persistence ──────────────────────────────────────────────────

    def _save_secrets(self) -> None:
        self._secrets_file.parent.mkdir(parents=True, exist_ok=True)
        # Decode each buffer only for serialisation; the file is protected
        # by 0600 permissions (managed storage, not in-memory hardening).
        payload = {k: v.decode() for k, v in self._secrets.items()}
        self._secrets_file.write_text(json.dumps(payload, indent=2))
        os.chmod(self._secrets_file, 0o600)

    def _save_policy(self) -> None:
        self._policy_file.parent.mkdir(parents=True, exist_ok=True)
        self._policy_file.write_text(json.dumps(self._policy, indent=2))


# ── Singleton ────────────────────────────────────────────────────────

_global_broker: CredentialBroker | None = None


def get_credential_broker() -> CredentialBroker:
    global _global_broker
    if _global_broker is None:
        _global_broker = CredentialBroker()
    return _global_broker
