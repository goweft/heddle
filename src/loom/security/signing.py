"""LOOM config signing and agent quarantine.

Config signing: YAML configs can be cryptographically signed using
HMAC-SHA256. The runtime verifies signatures before loading, ensuring
configs haven't been tampered with since they were approved.

Agent quarantine: AI-generated configs land in a staging directory
(~/.loom/quarantine/) and require explicit promotion before they
can be registered or run. This prevents auto-generated agents from
going live without review.

Frameworks: OWASP Agentic #8 (Supply Chain), NIST AI RMF GV-6.1,
MAESTRO Integrity layer / Staging gate
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loom.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

DEFAULT_KEY_FILE = Path.home() / ".loom" / "signing.key"
DEFAULT_QUARANTINE_DIR = Path.home() / ".loom" / "quarantine"
SIGNATURES_FILE = Path.home() / ".loom" / "signatures.json"


class SignatureError(Exception):
    """Raised when config signature verification fails."""


class ConfigSigner:
    """Sign and verify agent YAML configs using HMAC-SHA256.

    The signing key is stored in ~/.loom/signing.key (generated on
    first use). Signatures are stored in ~/.loom/signatures.json
    as a mapping of filename -> signature.
    """

    def __init__(self, key_file: str | Path | None = None):
        self._key_file = Path(key_file) if key_file else DEFAULT_KEY_FILE
        self._audit = get_audit_logger()
        self._key = self._load_or_create_key()
        self._signatures = self._load_signatures()

    def _load_or_create_key(self) -> bytes:
        """Load existing key or generate a new one."""
        if self._key_file.exists():
            return self._key_file.read_bytes()

        import os
        key = os.urandom(32)
        self._key_file.parent.mkdir(parents=True, exist_ok=True)
        self._key_file.write_bytes(key)
        self._key_file.chmod(0o600)
        logger.info("Generated new signing key: %s", self._key_file)
        return key

    def _load_signatures(self) -> dict[str, str]:
        if SIGNATURES_FILE.exists():
            try:
                return json.loads(SIGNATURES_FILE.read_text())
            except Exception:
                pass
        return {}

    def _save_signatures(self) -> None:
        SIGNATURES_FILE.parent.mkdir(parents=True, exist_ok=True)
        SIGNATURES_FILE.write_text(json.dumps(self._signatures, indent=2))

    def sign(self, config_path: str | Path) -> str:
        """Sign a config file and store the signature.

        Returns the HMAC-SHA256 hex digest.
        """
        path = Path(config_path)
        content = path.read_bytes()
        sig = hmac.new(self._key, content, hashlib.sha256).hexdigest()

        self._signatures[path.name] = sig
        self._save_signatures()

        self._audit.log_agent_lifecycle(
            path.stem, "signed",
            f"HMAC-SHA256 signature: {sig[:16]}...",
        )
        logger.info("Signed config: %s -> %s", path.name, sig[:16])
        return sig

    def verify(self, config_path: str | Path) -> bool:
        """Verify a config file's signature.

        Returns True if valid, raises SignatureError if invalid or missing.
        """
        path = Path(config_path)
        content = path.read_bytes()
        expected = self._signatures.get(path.name)

        if expected is None:
            self._audit.log_trust_violation(
                path.stem, 0,
                action="unsigned_config",
                detail=f"No signature found for {path.name}",
            )
            raise SignatureError(f"No signature for {path.name}. Sign it first with `loom sign`.")

        actual = hmac.new(self._key, content, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(actual, expected):
            self._audit.log_trust_violation(
                path.stem, 0,
                action="signature_mismatch",
                detail=f"Config {path.name} has been modified since signing",
            )
            raise SignatureError(
                f"Signature mismatch for {path.name}. "
                f"Config modified since last signing. Re-sign after review."
            )

        return True

    def sign_all(self, agents_dir: str | Path) -> int:
        """Sign all YAML configs in a directory."""
        agents_dir = Path(agents_dir)
        count = 0
        for path in sorted(agents_dir.glob("*.yaml")):
            self.sign(path)
            count += 1
        return count

    def verify_all(self, agents_dir: str | Path) -> list[dict]:
        """Verify all configs and return results."""
        agents_dir = Path(agents_dir)
        results = []
        for path in sorted(agents_dir.glob("*.yaml")):
            try:
                self.verify(path)
                results.append({"file": path.name, "status": "valid"})
            except SignatureError as exc:
                results.append({"file": path.name, "status": "invalid", "error": str(exc)})
        return results

    def list_signatures(self) -> dict[str, str]:
        """List all stored signatures."""
        return dict(self._signatures)


class AgentQuarantine:
    """Quarantine zone for AI-generated agent configs.

    Generated configs land here instead of the live agents/ directory.
    A human (or automated pipeline) must explicitly promote them
    before they can be run.
    """

    def __init__(self, quarantine_dir: str | Path | None = None):
        self._dir = Path(quarantine_dir) if quarantine_dir else DEFAULT_QUARANTINE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._audit = get_audit_logger()
        self._manifest_file = self._dir / "manifest.json"
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> list[dict]:
        if self._manifest_file.exists():
            try:
                return json.loads(self._manifest_file.read_text())
            except Exception:
                pass
        return []

    def _save_manifest(self) -> None:
        self._manifest_file.write_text(json.dumps(self._manifest, indent=2))

    def quarantine(self, config_path: str | Path, source: str = "ai-generated") -> Path:
        """Move a config file into quarantine.

        Returns the path to the quarantined file.
        """
        src = Path(config_path)
        dest = self._dir / src.name

        shutil.copy2(src, dest)

        entry = {
            "file": src.name,
            "source": source,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
            "promoted": False,
        }
        self._manifest.append(entry)
        self._save_manifest()

        self._audit.log_agent_lifecycle(
            src.stem, "quarantined",
            f"Source: {source}. Awaiting review.",
        )
        logger.info("Quarantined: %s (source: %s)", src.name, source)
        return dest

    def promote(self, filename: str, agents_dir: str | Path) -> Path:
        """Promote a quarantined config to the live agents directory.

        Copies the file from quarantine to agents/ and updates the manifest.
        """
        src = self._dir / filename
        if not src.exists():
            raise FileNotFoundError(f"Quarantined config not found: {filename}")

        dest = Path(agents_dir) / filename
        shutil.copy2(src, dest)

        # Update manifest
        for entry in self._manifest:
            if entry["file"] == filename and not entry["promoted"]:
                entry["status"] = "promoted"
                entry["promoted"] = True
                entry["promoted_at"] = datetime.now(timezone.utc).isoformat()
                break
        self._save_manifest()

        self._audit.log_agent_lifecycle(
            filename.replace(".yaml", ""), "promoted",
            f"Moved from quarantine to {agents_dir}",
        )
        logger.info("Promoted: %s -> %s", filename, dest)
        return dest

    def reject(self, filename: str, reason: str = "") -> None:
        """Reject a quarantined config."""
        for entry in self._manifest:
            if entry["file"] == filename and entry["status"] == "pending":
                entry["status"] = "rejected"
                entry["rejected_reason"] = reason
                entry["rejected_at"] = datetime.now(timezone.utc).isoformat()
                break
        self._save_manifest()

        # Optionally remove the file
        quarantined = self._dir / filename
        if quarantined.exists():
            quarantined.unlink()

        self._audit.log_agent_lifecycle(
            filename.replace(".yaml", ""), "rejected",
            f"Reason: {reason}",
        )

    def list_pending(self) -> list[dict]:
        """List all pending quarantined configs."""
        return [e for e in self._manifest if e["status"] == "pending"]

    def list_all(self) -> list[dict]:
        """List all quarantine entries."""
        return list(self._manifest)
