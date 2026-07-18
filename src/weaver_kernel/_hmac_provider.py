"""The :class:`HMACTokenProvider` implementation.

Extracted from :mod:`weaver_kernel.tokens` to keep that module within the
AGENTS.md 300-line budget. :class:`~weaver_kernel.tokens.CapabilityToken` and
the :class:`~weaver_kernel.tokens.TokenProvider` Protocol remain in
:mod:`weaver_kernel.tokens`. This module imports from ``tokens`` (a one-way
dependency), so ``tokens`` does *not* re-export this class — that would form an
import cycle. Import it from :mod:`weaver_kernel` (public) instead.
"""

from __future__ import annotations

import datetime
import hmac
import logging
import uuid
from typing import Any

from ._secrets import resolve_keyring
from ._token_signing import KeyRing, sign
from .errors import AgentKernelError, TokenExpired, TokenInvalid, TokenRevoked, TokenScopeError
from .stores import InMemoryRevocationStore, RevocationStoreProtocol
from .tokens import CapabilityToken

# Keep the logger name stable across the tokens.py → _hmac_provider.py split so
# operators (and tests) filtering on "weaver_kernel.tokens" still see these records.
logger = logging.getLogger("weaver_kernel.tokens")


class HMACTokenProvider:
    """Issues and verifies HMAC-SHA256 capability tokens.

    Supports signing-key rotation (#185): pass a ``secrets`` map of
    ``{key_id: secret}`` plus an ``active_key_id`` to sign new tokens under one
    key while still verifying tokens signed under others during an overlap
    window. A single ``secret`` (or the ``WEAVER_KERNEL_SECRET`` env var) is
    filed under the ``"default"`` key id. When nothing is configured the
    ``WEAVER_KERNEL_SECRETS`` / ``WEAVER_KERNEL_SECRET`` env vars are consulted,
    falling back to a random development secret with a one-time warning.

    Args:
        secret: A single signing secret. Mutually exclusive with *secrets*.
        secrets: A ``{key_id: secret}`` key-ring for rotation.
        active_key_id: Which *secrets* key to sign new tokens with. Required when
            *secrets* holds more than one key; inferred when it holds exactly one.
        revocation_store: Backing store for revocation state; defaults to an
            in-memory store.

    Raises:
        AgentKernelError: If both *secret* and *secrets* are given, or an
            explicit key-ring is empty, malformed, or names an unknown
            *active_key_id*.
    """

    def __init__(
        self,
        secret: str | None = None,
        *,
        secrets: dict[str, str] | None = None,
        active_key_id: str | None = None,
        revocation_store: RevocationStoreProtocol | None = None,
    ) -> None:
        if secret is not None and secrets is not None:
            raise AgentKernelError(
                "HMACTokenProvider: pass either 'secret' or 'secrets', not both."
            )
        self._secret = secret
        self._secrets = secrets
        self._active_key_id_arg = active_key_id
        # Explicit config is validated eagerly; the env/dev-fallback path stays
        # lazy so the dev-secret warning fires only on first use, not import.
        self._keyring: KeyRing | None = None
        self._active_key_id: str = ""
        if secret is not None or secrets is not None:
            self._keyring, self._active_key_id = resolve_keyring(secret, secrets, active_key_id)
        # Revocation state lives behind a protocol so it can be made durable
        # (e.g. SQLiteRevocationStore) without weakening verify-before-invoke.
        self._revocation: RevocationStoreProtocol = revocation_store or InMemoryRevocationStore()

    @staticmethod
    def _log_verify_failure(token_id: str, reason: str, **extra: Any) -> None:
        """Log a token verification failure at WARNING."""
        logger.warning(
            "token_verify_failed",
            extra={"token_id": token_id, "reason": reason, **extra},
        )

    def _resolve_keyring(self) -> tuple[KeyRing, str]:
        """Return the ``(keyring, active_key_id)`` pair, resolving env/dev lazily."""
        if self._keyring is None:
            self._keyring, self._active_key_id = resolve_keyring(
                self._secret, self._secrets, self._active_key_id_arg
            )
        return self._keyring, self._active_key_id

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
        keyring, active_key_id = self._resolve_keyring()
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        token = CapabilityToken(
            token_id=str(uuid.uuid4()),
            capability_id=capability_id,
            principal_id=principal_id,
            issued_at=now,
            expires_at=now + datetime.timedelta(seconds=ttl_seconds),
            constraints=constraints or {},
            audit_id=audit_id,
            key_id=active_key_id,
        )
        token.signature = sign(keyring[active_key_id], token._signable_payload())
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
            TokenInvalid: If the HMAC signature does not verify, or the token
                declares an unknown signing key id.
            TokenScopeError: If principal or capability do not match.
        """
        # 0. Revocation (fast lookup before any crypto)
        if self._revocation.is_revoked(token.token_id):
            self._log_verify_failure(token.token_id, "revoked")
            raise TokenRevoked(f"Token '{token.token_id}' has been revoked.")

        # 1. Expiry
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if token.expires_at <= now:
            self._log_verify_failure(
                token.token_id, "expired", expires_at=token.expires_at.isoformat()
            )
            raise TokenExpired(
                f"Token '{token.token_id}' expired at {token.expires_at.isoformat()}."
            )

        # 2. Signature (rotation-aware): select the secret for the token's
        # declared key id. An unknown key id fails closed — never fall through
        # to another key.
        keyring, active_key_id = self._resolve_keyring()
        secret = keyring.get(token.key_id)
        if secret is None:
            self._log_verify_failure(token.token_id, "unknown_key_id", key_id=token.key_id)
            raise TokenInvalid(
                f"Token '{token.token_id}' was signed with unknown key id '{token.key_id}'."
            )
        expected_sig = sign(secret, token._signable_payload())
        if not hmac.compare_digest(expected_sig, token.signature):
            self._log_verify_failure(token.token_id, "invalid_signature")
            raise TokenInvalid(
                f"Token '{token.token_id}' has an invalid signature. "
                "The token may have been tampered with."
            )
        if token.key_id != active_key_id:
            # Never logs the secret — only the key id — so operators can tell
            # when the previous key is safe to retire (#185).
            logger.info(
                "token_verified_non_active_key",
                extra={"token_id": token.token_id, "key_id": token.key_id},
            )

        # 3. Principal binding (confused-deputy prevention)
        if token.principal_id != expected_principal_id:
            self._log_verify_failure(token.token_id, "principal_mismatch")
            raise TokenScopeError(
                f"Token '{token.token_id}' was issued for principal "
                f"'{token.principal_id}', not '{expected_principal_id}'."
            )

        # 4. Capability binding
        if token.capability_id != expected_capability_id:
            self._log_verify_failure(token.token_id, "capability_mismatch")
            raise TokenScopeError(
                f"Token '{token.token_id}' was issued for capability "
                f"'{token.capability_id}', not '{expected_capability_id}'."
            )


__all__ = ["HMACTokenProvider"]
