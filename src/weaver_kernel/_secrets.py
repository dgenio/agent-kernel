"""HMAC secret loading, shared by token signing and audit-log hashing.

Kept in its own module so both :mod:`weaver_kernel.tokens` and
:mod:`weaver_kernel.stores.audit_chain` can resolve the signing secret the same
way without importing one another (which would create an import cycle).

Security: the resolved secret is never logged. Only the *absence* of an
explicit secret is reported, via a one-time warning when the dev fallback is
generated.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading

logger = logging.getLogger(__name__)

SECRET_ENV_VAR = "WEAVER_KERNEL_SECRET"
"""Environment variable holding the HMAC secret used for tokens and audit chains."""

PRODUCTION_CHECKLIST_URL = (
    "https://github.com/dgenio/agent-kernel/blob/main/docs/production-checklist.md"
)
"""Stable operator guidance linked from the development-secret warning."""

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
                "%s is not set. Using a process-local random development secret; "
                "tokens and audit-chain signatures will be invalid after restart and "
                "will not share signing state with another process. Set %s before "
                "production. Production checklist: %s",
                SECRET_ENV_VAR,
                SECRET_ENV_VAR,
                PRODUCTION_CHECKLIST_URL,
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
