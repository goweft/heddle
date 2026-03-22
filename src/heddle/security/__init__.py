"""Heddle security — complete security architecture for agentic AI.

Phase 3 controls mapped to industry frameworks:
- 3a Sandboxing:  OWASP Agentic #6, NIST MS-2.3, MAESTRO Isolation
- 3b Trust:       OWASP Agentic #3, NIST GV-1.3, MAESTRO Authorization
- 3c Credentials: OWASP Agentic #7, NIST MAP-3.4, MAESTRO Secrets
- 3d Audit:       OWASP Agentic #9, NIST MS-2.6, MAESTRO Observability
- 3e Validation:  OWASP Agentic #1/#2, NIST MS-2.5, MAESTRO Validation
- 3f Signing:     OWASP Agentic #8, NIST GV-6.1, MAESTRO Integrity
"""

from heddle.security.audit import AuditLogger, get_audit_logger
from heddle.security.trust import TrustEnforcer, TrustViolation
from heddle.security.credentials import CredentialBroker, CredentialDenied, get_credential_broker
from heddle.security.validation import InputValidator, RateLimiter, ValidationError
from heddle.security.signing import ConfigSigner, AgentQuarantine, SignatureError
from heddle.security.sandbox import SandboxManager, SandboxConfig
from heddle.security.escalation import EscalationEngine, EscalationRule, EscalationHold

__all__ = [
    "AuditLogger", "get_audit_logger",
    "TrustEnforcer", "TrustViolation",
    "CredentialBroker", "CredentialDenied", "get_credential_broker",
    "InputValidator", "RateLimiter", "ValidationError",
    "ConfigSigner", "AgentQuarantine", "SignatureError",
    "SandboxManager", "SandboxConfig",
    "EscalationEngine", "EscalationRule", "EscalationHold",
]
