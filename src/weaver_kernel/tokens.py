"""Capability tokens: the :class:`CapabilityToken` dataclass and the
:class:`TokenProvider` Protocol.

The concrete :class:`HMACTokenProvider` lives in
:mod:`weaver_kernel._hmac_provider` (extracted to honour the AGENTS.md
300-line module budget). Import it from :mod:`weaver_kernel` (public) or
:mod:`weaver_kernel._hmac_provider`. It is intentionally *not* re-exported here:
``_hmac_provider`` imports this module, so re-exporting would create an import
cycle (flagged by CodeQL).
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from ._token_signing import parse_token_fields

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
    key_id: str = ""

    # ── Serialization ─────────────────────────────────────────────────────────

    def _signable_payload(self) -> str:
        """Return the canonical JSON string used as the HMAC message.

        The signing ``key_id`` is included so a token cannot be re-labelled to
        verify against a different rotation key (#185).
        """
        payload = {
            "token_id": self.token_id,
            "capability_id": self.capability_id,
            "principal_id": self.principal_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "constraints": self.constraints,
            "audit_id": self.audit_id,
            "key_id": self.key_id,
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
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityToken:
        """Reconstruct a token from a plain dict.

        Args:
            data: A serialized token, e.g. from :meth:`to_dict` or an untrusted
                transport source.

        Returns:
            The reconstructed :class:`CapabilityToken`.

        Raises:
            TokenInvalid: If *data* is missing a required field, has a field of
                the wrong type, or carries a malformed timestamp (#200).
        """
        return cls(**parse_token_fields(data))


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


__all__ = ["CapabilityToken", "TokenProvider"]
