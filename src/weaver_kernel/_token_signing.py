"""Multi-key HMAC signing and typed-error token deserialization.

Split out of :mod:`tokens` to keep it within its ratchet ceiling
(AGENTS.md). :class:`KeyRing` backs
:class:`~weaver_kernel.tokens.HMACTokenProvider`'s key-rotation support
(#185); :func:`parse_token_dict` is the typed-error
:meth:`~weaver_kernel.tokens.CapabilityToken.from_dict` body (#200).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
from typing import TYPE_CHECKING, Any

from ._secrets import resolve_hmac_secrets_map
from .errors import AgentKernelError, TokenExpired, TokenInvalid, TokenRevoked, TokenScopeError
from .stores import RevocationStoreProtocol

if TYPE_CHECKING:  # pragma: no cover
    from .tokens import CapabilityToken

logger = logging.getLogger("weaver_kernel.tokens")


class KeyRing:
    """A set of named HMAC secrets, one of which is active for new issuance.

    Verification resolves a token's declared ``key_id`` against the full
    set — including keys retired from active issuance — so a token signed
    under a previous key still verifies during a rotation's overlap window.
    An unknown ``key_id`` fails closed (:class:`~weaver_kernel.TokenInvalid`
    via :meth:`secret_for`), never silently falling back to another secret.
    """

    def __init__(
        self,
        secrets: dict[str, str] | None = None,
        *,
        active_key_id: str | None = None,
        legacy_secret: str | None = None,
    ) -> None:
        """Build a key ring.

        Args:
            secrets: Mapping of ``key_id`` to HMAC secret, for multi-key
                rotation. When omitted, falls back to *legacy_secret*.
            active_key_id: The key id new tokens are signed with. Must be a
                key in *secrets*. Defaults to the sole key when exactly one
                is configured; required when more than one is configured.
            legacy_secret: Single-secret convenience for the pre-rotation
                ``HMACTokenProvider(secret=...)`` shape — used only when
                *secrets* is not given. ``None`` resolves from the
                environment (``WEAVER_KERNEL_SECRETS``, then
                ``WEAVER_KERNEL_SECRET``, then a dev fallback).

        Raises:
            AgentKernelError: If *active_key_id* is not a key in the
                resolved secrets, or more than one secret is configured and
                *active_key_id* was not given.
        """
        if secrets:
            self._secrets: dict[str, str] = dict(secrets)
        elif legacy_secret is not None:
            self._secrets = {"": legacy_secret}
        else:
            self._secrets = resolve_hmac_secrets_map()

        if active_key_id is not None:
            if active_key_id not in self._secrets:
                raise AgentKernelError(
                    f"active_key_id {active_key_id!r} is not a key in the configured secrets."
                )
            self._active_key_id = active_key_id
        elif len(self._secrets) == 1:
            self._active_key_id = next(iter(self._secrets))
        else:
            raise AgentKernelError(
                "active_key_id is required when more than one secret is configured."
            )

    @property
    def active_key_id(self) -> str:
        """The key id new tokens are signed under."""
        return self._active_key_id

    def is_active(self, key_id: str) -> bool:
        """Return whether *key_id* is the current active signing key."""
        return key_id == self._active_key_id

    def secret_for(self, key_id: str) -> bytes:
        """Resolve the signing secret bytes for *key_id*.

        Raises:
            TokenInvalid: If *key_id* is not a known key in this ring —
                fails closed rather than falling back to another secret.
        """
        secret = self._secrets.get(key_id)
        if secret is None:
            raise TokenInvalid(f"Unknown signing key id {key_id!r}.")
        return secret.encode()


def parse_token_dict(data: dict[str, Any]) -> CapabilityToken:
    """Reconstruct a :class:`~weaver_kernel.tokens.CapabilityToken` from a dict.

    Tokens cross process boundaries by design, so a malformed dict is an
    expected input class, not a programming error — every failure mode below
    raises :class:`TokenInvalid` instead of a bare ``KeyError``/``ValueError``.

    Args:
        data: The token's serialized form, as produced by
            :meth:`~weaver_kernel.tokens.CapabilityToken.to_dict`.

    Raises:
        TokenInvalid: If a required field is missing, a required field has
            the wrong type, a timestamp field is not a valid ISO-8601
            string, or ``constraints`` is present but not an object.
    """
    from .tokens import CapabilityToken  # lazy: avoid tokens<->_token_signing cycle

    try:
        token_id = data["token_id"]
        capability_id = data["capability_id"]
        principal_id = data["principal_id"]
        issued_at_raw = data["issued_at"]
        expires_at_raw = data["expires_at"]
    except KeyError as exc:
        raise TokenInvalid(f"malformed token payload: missing field {exc.args[0]!r}") from exc

    for field_name, value in (
        ("token_id", token_id),
        ("capability_id", capability_id),
        ("principal_id", principal_id),
    ):
        if not isinstance(value, str):
            raise TokenInvalid(f"malformed token payload: field {field_name!r} must be a string")

    try:
        issued_at = datetime.datetime.fromisoformat(issued_at_raw)
    except (TypeError, ValueError) as exc:
        raise TokenInvalid(
            "malformed token payload: invalid timestamp in field 'issued_at'"
        ) from exc
    try:
        expires_at = datetime.datetime.fromisoformat(expires_at_raw)
    except (TypeError, ValueError) as exc:
        raise TokenInvalid(
            "malformed token payload: invalid timestamp in field 'expires_at'"
        ) from exc

    constraints = data.get("constraints", {})
    if not isinstance(constraints, dict):
        raise TokenInvalid("malformed token payload: field 'constraints' must be an object")

    key_id = data.get("key_id", "")
    if not isinstance(key_id, str):
        raise TokenInvalid("malformed token payload: field 'key_id' must be a string")

    return CapabilityToken(
        token_id=token_id,
        capability_id=capability_id,
        principal_id=principal_id,
        issued_at=issued_at,
        expires_at=expires_at,
        constraints=constraints,
        audit_id=data.get("audit_id", ""),
        signature=data.get("signature", ""),
        key_id=key_id,
    )


def _log_verify_failure(token_id: str, reason: str, **extra: Any) -> None:
    """Log a token verification failure at WARNING."""
    logger.warning("token_verify_failed", extra={"token_id": token_id, "reason": reason, **extra})


def _sign(payload: str, *, key_ring: KeyRing, key_id: str) -> str:
    return hmac.new(key_ring.secret_for(key_id), payload.encode(), hashlib.sha256).hexdigest()


def sign_token(token: CapabilityToken, *, key_ring: KeyRing, key_id: str) -> str:
    """Return the HMAC-SHA256 signature for *token* under *key_id*."""
    return _sign(token._signable_payload(), key_ring=key_ring, key_id=key_id)


def verify_token(
    token: CapabilityToken,
    *,
    key_ring: KeyRing,
    revocation: RevocationStoreProtocol,
    expected_principal_id: str,
    expected_capability_id: str,
) -> None:
    """Verify a token's revocation state, expiry, signature, and scope bindings.

    The full :meth:`~weaver_kernel.tokens.TokenProvider.verify` contract,
    factored out of :class:`~weaver_kernel.tokens.HMACTokenProvider` to keep
    that module within its line budget (AGENTS.md).

    Raises:
        TokenRevoked: If the token has been revoked.
        TokenExpired: If ``token.expires_at`` is in the past.
        TokenInvalid: If the token's ``key_id`` is unknown to *key_ring*, or
            the HMAC signature does not verify.
        TokenScopeError: If principal or capability do not match.
    """
    # 0. Revocation (fast lookup before any crypto)
    if revocation.is_revoked(token.token_id):
        _log_verify_failure(token.token_id, "revoked")
        raise TokenRevoked(f"Token '{token.token_id}' has been revoked.")

    # 1. Expiry
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if token.expires_at <= now:
        _log_verify_failure(token.token_id, "expired", expires_at=token.expires_at.isoformat())
        raise TokenExpired(f"Token '{token.token_id}' expired at {token.expires_at.isoformat()}.")

    # 2. Signature (also resolves the signing key by the token's declared
    # key_id — an id outside the configured KeyRing fails closed here as
    # TokenInvalid rather than falling back to another secret).
    try:
        expected_sig = sign_token(token, key_ring=key_ring, key_id=token.key_id)
    except TokenInvalid:
        _log_verify_failure(token.token_id, "unknown_key_id", key_id=token.key_id)
        raise
    if not hmac.compare_digest(expected_sig, token.signature):
        _log_verify_failure(token.token_id, "invalid_signature")
        raise TokenInvalid(
            f"Token '{token.token_id}' has an invalid signature. "
            "The token may have been tampered with."
        )
    if not key_ring.is_active(token.key_id):
        # Never logs the secret itself — only the (non-secret) key id — so
        # operators can tell when an overlap-window key is still in use and
        # it's safe to retire (#185).
        logger.info(
            "token_verified_non_active_key",
            extra={"token_id": token.token_id, "key_id": token.key_id},
        )

    # 3. Principal binding (confused-deputy prevention)
    if token.principal_id != expected_principal_id:
        _log_verify_failure(token.token_id, "principal_mismatch")
        raise TokenScopeError(
            f"Token '{token.token_id}' was issued for principal "
            f"'{token.principal_id}', not '{expected_principal_id}'."
        )

    # 4. Capability binding
    if token.capability_id != expected_capability_id:
        _log_verify_failure(token.token_id, "capability_mismatch")
        raise TokenScopeError(
            f"Token '{token.token_id}' was issued for capability "
            f"'{token.capability_id}', not '{expected_capability_id}'."
        )


__all__ = ["KeyRing", "parse_token_dict", "sign_token", "verify_token"]
