"""HMAC secret loading, shared by token signing and audit-log hashing.

Kept in its own module so both :mod:`weaver_kernel.tokens` and
:mod:`weaver_kernel.stores.audit_chain` can resolve the signing secret the same
way without importing one another (which would create an import cycle).

Security: the resolved secret is never logged. Only the *absence* of an
explicit secret is reported, via a one-time warning when the dev fallback is
generated.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from typing import Any

from .errors import AgentKernelError

logger = logging.getLogger(__name__)

SECRET_ENV_VAR = "WEAVER_KERNEL_SECRET"
"""Environment variable holding the HMAC secret used for tokens and audit chains."""

SECRETS_ENV_VAR = "WEAVER_KERNEL_SECRETS"
"""Environment variable holding a JSON object of ``{key_id: secret}`` for
signing-key rotation (#185). Takes precedence over :data:`SECRET_ENV_VAR`
when set. A rotation adds the new key alongside the old one, switches which
key new tokens are issued under (see
:class:`~weaver_kernel.tokens.HMACTokenProvider`'s ``active_key_id``), and
retires the old key only after the longest outstanding token's TTL elapses.
"""

_DEV_SECRET: str | None = None
_DEV_SECRET_LOCK = threading.Lock()


def _get_secret() -> str:
    """Return the HMAC secret from the environment or a generated dev fallback.

    Thread-safe: a :class:`threading.Lock` ensures only one thread generates the
    fallback secret, and the warning is emitted once.
    """
    global _DEV_SECRET
    secret = os.environ.get(SECRET_ENV_VAR)
    if secret:
        return secret
    with _DEV_SECRET_LOCK:
        if _DEV_SECRET is None:
            _DEV_SECRET = secrets.token_hex(32)
            logger.warning(
                "%s is not set. Using a random development secret — tokens and "
                "audit-chain signatures will not survive restarts. Set %s in production.",
                SECRET_ENV_VAR,
                SECRET_ENV_VAR,
            )
    return _DEV_SECRET


def resolve_hmac_secret(explicit: str | None = None) -> str:
    """Resolve the HMAC secret to use.

    Args:
        explicit: A secret supplied directly by the caller. When non-empty it
            takes precedence over the environment and dev fallback.

    Returns:
        The explicit secret if given, else ``WEAVER_KERNEL_SECRET`` from the
        environment, else a process-lived random development secret (with a
        one-time warning).
    """
    if explicit:
        return explicit
    return _get_secret()


def resolve_hmac_secrets_map() -> dict[str, str]:
    """Resolve a ``key_id -> secret`` map for multi-key signing/rotation.

    Precedence:

    1. :data:`SECRETS_ENV_VAR` (``WEAVER_KERNEL_SECRETS``) — a JSON object
       mapping each ``key_id`` to its secret, e.g. ``{"2026-a": "...",
       "2026-b": "..."}``.
    2. A single legacy key under ``key_id=""``, resolved the same way as
       :func:`resolve_hmac_secret` (``WEAVER_KERNEL_SECRET``, else a
       process-lived dev fallback with a one-time warning).

    Returns:
        A non-empty ``{key_id: secret}`` mapping.

    Raises:
        AgentKernelError: If :data:`SECRETS_ENV_VAR` is set but is not a JSON
            object of string keys to string values.
    """
    raw = os.environ.get(SECRETS_ENV_VAR)
    if not raw:
        return {"": _get_secret()}
    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AgentKernelError(f"{SECRETS_ENV_VAR} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
    ):
        raise AgentKernelError(
            f"{SECRETS_ENV_VAR} must be a JSON object mapping string key ids to "
            f"string secrets, got {raw!r}."
        )
    if not parsed:
        raise AgentKernelError(f"{SECRETS_ENV_VAR} must not be an empty object.")
    return parsed
