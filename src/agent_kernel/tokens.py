"""HMAC-SHA256 token provider for capability authorization."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from .errors import TokenExpired, TokenInvalid, TokenRevoked, TokenScopeError

logger = logging.getLogger(__name__)

_DEV_SECRET: str | None = None
_DEV_SECRET_LOCK = threading.Lock()


def _get_secret() -> str:
    """Return the HMAC secret from the environment or generate a dev fallback.

    Thread-safe: a :data:`threading.Lock` ensures only one thread generates
    the fallback secret.
    """
    global _DEV_SECRET
    secret = os.environ.get("AGENT_KERNEL_SECRET")
    if secret:
        return secret
    with _DEV_SECRET_LOCK:
        if _DEV_SECRET is None:
            _DEV_SECRET = secrets.token_hex(32)
            logger.warning(
                "AGENT_KERNEL_SECRET is not set. "
                "Using a random development secret — tokens will not survive restarts. "
                "Set AGENT_KERNEL_SECRET in production."
            )
    return _DEV_SECRET


# ── Token dataclass ───────────────────────────────────────────────────────────


@dataclass(slots=True)
class CapabilityToken:
    """A signed, time-bounded, principal-scoped authorization token.

    Warning:
        Tokens are tamper-evident (HMAC-SHA256) but **not encrypted**.
        Do not put sensitive data in token fields.
    """

    token_id: str
    capability_id: str
    principal_id: str
    issued_at: datetime.datetime
    expires_at: datetime.datetime
    constraints: dict[str, Any] = field(default_factory=dict)
    audit_id: str = ""
    signature: str = ""

    # ── Serialization ─────────────────────────────────────────────────────────

    def _signable_payload(self) -> str:
        """Return the canonical JSON string used as the HMAC message."""
        payload = {
            "token_id": self.token_id,
            "capability_id": self.capability_id,
            "principal_id": self.principal_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "constraints": self.constraints,
            "audit_id": self.audit_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict[str, Any]:
        """Serialise the token to a plain dict (suitable for JSON transport)."""
        return {
            "token_id": self.token_id,
            "capability_id": self.capability_id,
            "principal_id": self.principal_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "constraints": self.constraints,
            "audit_id": self.audit_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityToken:
        """Reconstruct a token from a plain dict."""
        return cls(
            token_id=data["token_id"],
            capability_id=data["capability_id"],
            principal_id=data["principal_id"],
            issued_at=datetime.datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.datetime.fromisoformat(data["expires_at"]),
            constraints=data.get("constraints", {}),
            audit_id=data.get("audit_id", ""),
            signature=data.get("signature", ""),
        )


# ── Protocol ──────────────────────────────────────────────────────────────────


class TokenProvider(Protocol):
    """Interface for token issuance and verification."""

    def issue(
        self,
        capability_id: str,
        principal_id: str,
        *,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 3600,
        audit_id: str = "",
    ) -> CapabilityToken:
        """Issue a new token.

        Args:
            capability_id: The capability this token authorises.
            principal_id: The principal this token is issued to.
            constraints: Optional execution constraints.
            ttl_seconds: How long the token is valid (default 1 hour).
            audit_id: Audit trail ID to embed in the token.

        Returns:
            A freshly signed :class:`CapabilityToken`.
        """
        ...

    def verify(
        self,
        token: CapabilityToken,
        *,
        expected_principal_id: str,
        expected_capability_id: str,
    ) -> None:
        """Verify a token.

        Args:
            token: The token to verify.
            expected_principal_id: The principal that should own this token.
            expected_capability_id: The capability this token should authorize.

        Raises:
            TokenRevoked: If the token has been revoked.
            TokenExpired: If the token has expired.
            TokenInvalid: If the signature does not verify.
            TokenScopeError: If the principal or capability do not match.
        """
        ...

    def revoke(self, token_id: str) -> None:
        """Revoke a single token by ID.

        Args:
            token_id: The ID of the token to revoke.
        """
        ...

    def revoke_all(self, principal_id: str) -> int:
        """Revoke all tokens issued to a principal.

        Args:
            principal_id: The principal whose tokens should be revoked.

        Returns:
            The number of tokens newly revoked by this call (excluding tokens
            that were already revoked).
        """
        ...


# ── Implementation ────────────────────────────────────────────────────────────


class HMACTokenProvider:
    """Issues and verifies HMAC-SHA256 capability tokens.

    The signing secret is read from the ``AGENT_KERNEL_SECRET`` environment
    variable.  If the variable is absent a random development secret is
    generated and a warning is logged.
    """

    def __init__(self, secret: str | None = None) -> None:
        self._secret = secret  # None → use env / dev fallback at call time
        self._revoked: set[str] = set()
        # TODO: consider TTL-based cleanup to bound growth over long-lived instances
        self._principal_tokens: dict[str, set[str]] = {}
        self._revocation_lock = threading.Lock()

    def _secret_bytes(self) -> bytes:
        return (self._secret or _get_secret()).encode()

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret_bytes(), payload.encode(), hashlib.sha256).hexdigest()

    def issue(
        self,
        capability_id: str,
        principal_id: str,
        *,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 3600,
        audit_id: str = "",
    ) -> CapabilityToken:
        """Issue a new signed token.

        Args:
            capability_id: The capability this token authorises.
            principal_id: The principal this token is issued to.
            constraints: Optional execution constraints.
            ttl_seconds: How long the token is valid (default 1 hour).
            audit_id: Audit trail ID to embed in the token.

        Returns:
            A freshly signed :class:`CapabilityToken`.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        token = CapabilityToken(
            token_id=str(uuid.uuid4()),
            capability_id=capability_id,
            principal_id=principal_id,
            issued_at=now,
            expires_at=now + datetime.timedelta(seconds=ttl_seconds),
            constraints=constraints or {},
            audit_id=audit_id,
        )
        token.signature = self._sign(token._signable_payload())
        with self._revocation_lock:
            self._principal_tokens.setdefault(principal_id, set()).add(token.token_id)
        return token

    def revoke(self, token_id: str) -> None:
        """Revoke a single token by ID.

        Idempotent — revoking an already-revoked or unknown token is a no-op.

        Args:
            token_id: The ID of the token to revoke.
        """
        with self._revocation_lock:
            self._revoked.add(token_id)

    def revoke_all(self, principal_id: str) -> int:
        """Revoke all tokens issued to a principal.

        Args:
            principal_id: The principal whose tokens should be revoked.

        Returns:
            The number of tokens newly revoked by this call (excluding tokens
            that were already revoked).
        """
        with self._revocation_lock:
            token_ids = self._principal_tokens.get(principal_id, set())
            newly_revoked = token_ids - self._revoked
            self._revoked |= newly_revoked
            # Drop the index entry; new tokens for this principal will start fresh
            self._principal_tokens.pop(principal_id, None)
            return len(newly_revoked)

    def verify(
        self,
        token: CapabilityToken,
        *,
        expected_principal_id: str,
        expected_capability_id: str,
    ) -> None:
        """Verify a token's signature, expiry, and scope bindings.

        Args:
            token: The token to verify.
            expected_principal_id: The principal that should own this token.
            expected_capability_id: The capability this token should authorize.

        Raises:
            TokenRevoked: If the token has been revoked.
            TokenExpired: If ``token.expires_at`` is in the past.
            TokenInvalid: If the HMAC signature does not verify.
            TokenScopeError: If principal or capability do not match.
        """
        # 0. Revocation (fast set lookup before any crypto)
        with self._revocation_lock:
            is_revoked = token.token_id in self._revoked
        if is_revoked:
            raise TokenRevoked(f"Token '{token.token_id}' has been revoked.")

        # 1. Expiry
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if token.expires_at <= now:
            raise TokenExpired(
                f"Token '{token.token_id}' expired at {token.expires_at.isoformat()}."
            )

        # 2. Signature
        expected_sig = self._sign(token._signable_payload())
        if not hmac.compare_digest(expected_sig, token.signature):
            raise TokenInvalid(
                f"Token '{token.token_id}' has an invalid signature. "
                "The token may have been tampered with."
            )

        # 3. Principal binding (confused-deputy prevention)
        if token.principal_id != expected_principal_id:
            raise TokenScopeError(
                f"Token '{token.token_id}' was issued for principal "
                f"'{token.principal_id}', not '{expected_principal_id}'."
            )

        # 4. Capability binding
        if token.capability_id != expected_capability_id:
            raise TokenScopeError(
                f"Token '{token.token_id}' was issued for capability "
                f"'{token.capability_id}', not '{expected_capability_id}'."
            )
