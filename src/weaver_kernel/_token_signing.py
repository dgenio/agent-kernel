"""HMAC signing and token-parsing helpers.

Extracted from :mod:`weaver_kernel.tokens` to keep that module within the
AGENTS.md 300-line budget and to isolate the crypto/deserialization concern:
HMAC signing, and parsing an untrusted serialized token into validated
constructor kwargs — raising :class:`TokenInvalid` rather than leaking a bare
``KeyError``/``ValueError`` (#200).

This module is a leaf: it imports nothing from :mod:`weaver_kernel.tokens` (not
even under ``TYPE_CHECKING``), so the ``tokens`` → ``_token_signing`` dependency
stays acyclic. Canonical payload building lives on
:meth:`CapabilityToken._signable_payload` in ``tokens.py``.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from typing import Any

from .errors import TokenInvalid

KeyRing = dict[str, str]
"""Mapping of key id → HMAC secret used for signing-key rotation (#185)."""


def sign(secret: str, payload: str) -> str:
    """Return the hex HMAC-SHA256 of *payload* under *secret*.

    Args:
        secret: The signing secret (never logged).
        payload: The canonical signable payload string.

    Returns:
        The hex-encoded signature.
    """
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _require_str(data: dict[str, Any], field: str) -> str:
    """Return a required string field, raising :class:`TokenInvalid` otherwise."""
    if field not in data:
        raise TokenInvalid(f"malformed token payload: missing field '{field}'.")
    value = data[field]
    if not isinstance(value, str):
        raise TokenInvalid(
            f"malformed token payload: field '{field}' must be a string, "
            f"got {type(value).__name__}."
        )
    return value


def _optional_str(data: dict[str, Any], field: str) -> str:
    """Return an optional string field (default ``""``), validating its type."""
    value = data.get(field, "")
    if not isinstance(value, str):
        raise TokenInvalid(
            f"malformed token payload: field '{field}' must be a string, "
            f"got {type(value).__name__}."
        )
    return value


def _require_timestamp(data: dict[str, Any], field: str) -> datetime.datetime:
    """Return a required ISO-8601 timestamp field, raising :class:`TokenInvalid`.

    A naive (timezone-less) timestamp is treated as UTC — matching how the
    revocation stores handle naive datetimes — so a malformed/untrusted token can
    never turn into a naive-vs-aware ``TypeError`` at ``verify()`` time.
    """
    if field not in data:
        raise TokenInvalid(f"malformed token payload: missing field '{field}'.")
    raw = data[field]
    if not isinstance(raw, str):
        raise TokenInvalid(
            f"malformed token payload: field '{field}' must be an ISO-8601 string, "
            f"got {type(raw).__name__}."
        )
    try:
        parsed = datetime.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise TokenInvalid(
            f"malformed token payload: invalid timestamp in field '{field}': {raw!r}."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def parse_token_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Validate a serialized token dict into constructor kwargs (#200).

    Tokens cross process boundaries by design, so a malformed dict is an
    expected input class, not a programming error. Every failure raises
    :class:`TokenInvalid` with a stable, descriptive message. Unknown extra
    keys are tolerated; ``constraints`` defaults to ``{}`` and must be an object.

    Args:
        data: The plain dict produced by :meth:`CapabilityToken.to_dict` (or an
            untrusted equivalent).

    Returns:
        Keyword arguments suitable for the :class:`CapabilityToken` constructor.

    Raises:
        TokenInvalid: If any field is missing, of the wrong type, or a
            malformed timestamp.
    """
    constraints = data.get("constraints", {})
    if not isinstance(constraints, dict):
        raise TokenInvalid(
            f"malformed token payload: field 'constraints' must be an object, "
            f"got {type(constraints).__name__}."
        )
    return {
        "token_id": _require_str(data, "token_id"),
        "capability_id": _require_str(data, "capability_id"),
        "principal_id": _require_str(data, "principal_id"),
        "issued_at": _require_timestamp(data, "issued_at"),
        "expires_at": _require_timestamp(data, "expires_at"),
        "constraints": constraints,
        "audit_id": _optional_str(data, "audit_id"),
        "signature": _optional_str(data, "signature"),
        "key_id": _optional_str(data, "key_id"),
    }


__all__ = ["KeyRing", "sign", "parse_token_fields"]
