"""LOOM credential broker — runtime secret injection.

Agents never see raw credentials in their YAML configs. Instead, they
reference credential keys like {{secret:weft-intel-token}}, and the
broker resolves them at runtime from an encrypted secrets store.

Secrets are stored in a JSON file (encrypted at rest in Phase 3+) at
~/.loom/secrets.json. Agents can only access secrets that are explicitly
granted to them in the broker's access policy.

Frameworks: OWASP Agentic #7 (Unsafe Credential Management), NIST AI RMF MAP-3.4
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from loom.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

DEFAULT_SECRETS_FILE = Path.home() / ".loom" / "secrets.json"
DEFAULT_POLICY_FILE = Path.home() / ".loom" / "credential_policy.json"


class CredentialDenied(Exception):
    """Raised when an agent requests a credential it doesn't have access to."""

    def __init__(self, agent_name: str, key: str, reason: str):
        self.agent_name = agent_name
        self.key = key
        super().__init__(f"Credential denied [{agent_name}]: {key} — {reason}")


class CredentialBroker:
    """Manages secrets and controls agent access to them.

    Secrets file format (~/.loom/secrets.json):
    {
        "weft-intel-token": "a6e60bd2...",
        "gitea-api-token": "abc123...",
        "rocketchat-webhook": "https://..."
    }

    Policy file format (~/.loom/credential_policy.json):
    {
        "weft-intel-bridge": ["weft-intel-token"],
        "gitea-api-bridge": ["gitea-api-token"],
        "rc-poster": ["rocketchat-webhook", "weft-intel-token"]
    }
    """

    def __init__(
        self,
        secrets_file: str | Path | None = None,
        policy_file: str | Path | None = None,
    ):
        self._secrets_file = Path(secrets_file) if secrets_file else DEFAULT_SECRETS_FILE
        self._policy_file = Path(policy_file) if policy_file else DEFAULT_POLICY_FILE
        self._audit = get_audit_logger()
        self._secrets: dict[str, str] = {}
        self._policy: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        """Load secrets and policy from disk."""
        if self._secrets_file.exists():
            try:
                self._secrets = json.loads(self._secrets_file.read_text())
                logger.info("Loaded %d secrets from %s", len(self._secrets), self._secrets_file)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to load secrets: %s", exc)

        if self._policy_file.exists():
            try:
                self._policy = json.loads(self._policy_file.read_text())
                logger.info("Loaded credential policy for %d agents", len(self._policy))
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to load credential policy: %s", exc)

    def get_credential(self, agent_name: str, key: str) -> str:
        """Retrieve a credential for an agent.

        Checks the policy to ensure the agent has access, logs the
        request, and returns the secret value.

        Raises CredentialDenied if the agent doesn't have access.
        """
        # Check policy
        allowed_keys = self._policy.get(agent_name, [])
        if key not in allowed_keys:
            self._audit.log_credential_access(agent_name, key, granted=False)
            raise CredentialDenied(
                agent_name, key,
                f"Not in agent's allowed credentials: {allowed_keys}",
            )

        # Check if secret exists
        if key not in self._secrets:
            self._audit.log_credential_access(agent_name, key, granted=False)
            raise CredentialDenied(
                agent_name, key,
                "Secret key not found in secrets store",
            )

        self._audit.log_credential_access(agent_name, key, granted=True)
        return self._secrets[key]

    def resolve_template(self, agent_name: str, text: str) -> str:
        """Replace {{secret:key}} placeholders in a string.

        Used by the HTTP bridge to inject credentials into headers and URLs
        at runtime instead of storing them in the YAML config.
        """
        import re

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
        """Store a secret (admin operation)."""
        self._secrets[key] = value
        self._save_secrets()
        logger.info("Secret stored: %s", key)

    def remove_secret(self, key: str) -> bool:
        """Remove a secret."""
        if key in self._secrets:
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

    def _save_secrets(self) -> None:
        self._secrets_file.parent.mkdir(parents=True, exist_ok=True)
        self._secrets_file.write_text(json.dumps(self._secrets, indent=2))
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
