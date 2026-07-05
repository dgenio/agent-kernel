"""HMAC-SHA256 token provider for capability authorization."""

from __future__ import annotations

import datetime
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from ._token_signing import KeyRing, parse_token_dict, sign_token, verify_token
from .stores import InMemoryRevocationStore, RevocationStoreProtocol

logger = logging.getLogger(__name__)


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
    """Which signing key this token was signed with (#185).

    Opaque to callers; used only by :class:`HMACTokenProvider` to select the
    right secret out of its :class:`~weaver_kernel._token_signing.KeyRing`
    during verification. ``""`` for a single-key (non-rotating) provider.
    """

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

        Raises:
            TokenInvalid: If a required field is missing or malformed. See
                :func:`~weaver_kernel._token_signing.parse_token_dict`.
        """
        return parse_token_dict(data)


# ── Protocol ──────────────────────────────────────────────────────────────────


class TokenProvider(Protocol):
    """Interface for token issuance and verification."""

    def issue(
        self,
        capability_id: str,
        principal_id: str,
        *,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: float = 3600,
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

    By default, the signing secret is read from the ``WEAVER_KERNEL_SECRET``
    environment variable; if absent, a random development secret is generated
    and a warning is logged. Pass *secrets* + *active_key_id* to enable
    signing-key rotation (#185): tokens carry the id of the key that signed
    them, so verification can accept a set of keys — including ones retired
    from active issuance — while new tokens are always signed with the
    active key.
    """

    def __init__(
        self,
        secret: str | None = None,
        *,
        revocation_store: RevocationStoreProtocol | None = None,
        secrets: dict[str, str] | None = None,
        active_key_id: str | None = None,
    ) -> None:
        """Construct a provider.

        Args:
            secret: A single legacy secret (no rotation). Mutually exclusive
                with *secrets* in practice — when *secrets* is given, *secret*
                is ignored. ``None`` resolves from the environment.
            revocation_store: Where revoked/tracked token state lives.
                Defaults to an in-memory store.
            secrets: A ``{key_id: secret}`` map for key rotation. When given,
                *active_key_id* selects which key new tokens are signed with.
            active_key_id: The key id new tokens are signed under. Required
                when *secrets* has more than one entry; defaults to the sole
                key otherwise.
        """
        self._key_ring = KeyRing(secrets, active_key_id=active_key_id, legacy_secret=secret)
        # Revocation state lives behind a protocol so it can be made durable
        # (e.g. SQLiteRevocationStore) without weakening verify-before-invoke.
        self._revocation: RevocationStoreProtocol = revocation_store or InMemoryRevocationStore()

    def issue(
        self,
        capability_id: str,
        principal_id: str,
        *,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: float = 3600,
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
            A freshly signed :class:`CapabilityToken`, signed with the
            provider's active signing key.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        key_id = self._key_ring.active_key_id
        token = CapabilityToken(
            token_id=str(uuid.uuid4()),
            capability_id=capability_id,
            principal_id=principal_id,
            issued_at=now,
            expires_at=now + datetime.timedelta(seconds=ttl_seconds),
            constraints=constraints or {},
            audit_id=audit_id,
            key_id=key_id,
        )
        token.signature = sign_token(token, key_ring=self._key_ring, key_id=key_id)
        self._revocation.track(principal_id, token.token_id, token.expires_at)
        logger.debug(
            "token_issued",
            extra={
                "token_id": token.token_id,
                "capability_id": capability_id,
                "principal_id": principal_id,
                "audit_id": audit_id,
                "expires_at": token.expires_at.isoformat(),
            },
        )
        return token

    def revoke(self, token_id: str) -> None:
        """Revoke a single token by ID.

        Idempotent — revoking an already-revoked or unknown token is a no-op.

        Args:
            token_id: The ID of the token to revoke.
        """
        self._revocation.revoke(token_id)

    def revoke_all(self, principal_id: str) -> int:
        """Revoke all tokens issued to a principal.

        Args:
            principal_id: The principal whose tokens should be revoked.

        Returns:
            The number of tokens newly revoked by this call (excluding tokens
            that were already revoked).
        """
        return self._revocation.revoke_principal(principal_id)

    def sweep_revocations(self, now: datetime.datetime | None = None) -> int:
        """Drop revocation bookkeeping for tokens that have already expired.

        Bounds revocation-state growth in long-lived processes (#182). Safe to
        call at any time: an expired token fails the verifier's expiry check
        regardless, so sweeping its entry never un-revokes a live token. The
        in-memory store also sweeps itself lazily; durable backends expose this
        for an operator to call on a schedule.

        Args:
            now: Reference time; defaults to the current UTC time.

        Returns:
            The number of tracked tokens whose state was removed.
        """
        when = now or datetime.datetime.now(tz=datetime.timezone.utc)
        return self._revocation.sweep_expired(when)

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
            TokenInvalid: If the token's ``key_id`` is unknown, or the HMAC
                signature does not verify.
            TokenScopeError: If principal or capability do not match.
        """
        verify_token(
            token,
            key_ring=self._key_ring,
            revocation=self._revocation,
            expected_principal_id=expected_principal_id,
            expected_capability_id=expected_capability_id,
        )
