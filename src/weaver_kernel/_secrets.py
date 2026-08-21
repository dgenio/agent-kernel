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

from .errors import AgentKernelError

logger = logging.getLogger(__name__)

SECRET_ENV_VAR = "WEAVER_KERNEL_SECRET"
"""Environment variable holding the HMAC secret used for tokens and audit chains."""

PRODUCTION_CHECKLIST_PATH = "docs/production-checklist.md"
"""Repository-relative operator guidance referenced by the development warning."""

SECRETS_ENV_VAR = "WEAVER_KERNEL_SECRETS"
"""Environment variable holding a JSON ``{key_id: secret}`` map for key rotation (#185)."""

ACTIVE_KEY_ENV_VAR = "WEAVER_KERNEL_ACTIVE_KEY"
"""Environment variable naming which :data:`SECRETS_ENV_VAR` key to sign new tokens with."""

LEGACY_KEY_ID = "default"
"""Key id assigned to a single-secret configuration (``secret=`` or ``WEAVER_KERNEL_SECRET``)."""

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
                PRODUCTION_CHECKLIST_PATH,
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


def _assemble_keyring(
    secrets_map: dict[str, str],
    active_key_id: str | None,
    *,
    source: str,
) -> tuple[dict[str, str], str]:
    """Validate a key id → secret map and resolve which key is active.

    Args:
        secrets_map: Candidate ``{key_id: secret}`` mapping.
        active_key_id: The key id new tokens should be signed with, or ``None``
            to infer it (only possible when the map holds exactly one key).
        source: Human-readable origin used in error messages.

    Returns:
        A ``(keyring, active_key_id)`` pair with a validated, non-empty keyring.

    Raises:
        AgentKernelError: If the map is empty, holds non-string keys/values, has
            multiple keys without an explicit active key, or names an active key
            id absent from the map.
    """
    if not secrets_map:
        raise AgentKernelError(f"{source} keyring is empty; at least one key is required.")
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in secrets_map.items()):
        raise AgentKernelError(f"{source} keyring must map string key ids to string secrets.")
    keyring = dict(secrets_map)
    if active_key_id is None:
        if len(keyring) == 1:
            active_key_id = next(iter(keyring))
        else:
            raise AgentKernelError(
                f"{source} has multiple keys; an active key id must be specified "
                f"(via active_key_id or {ACTIVE_KEY_ENV_VAR})."
            )
    if active_key_id not in keyring:
        raise AgentKernelError(
            f"active key id {active_key_id!r} is not present in the {source} keyring."
        )
    return keyring, active_key_id


def resolve_keyring(
    explicit_secret: str | None,
    explicit_secrets: dict[str, str] | None,
    explicit_active_key_id: str | None,
) -> tuple[dict[str, str], str]:
    """Resolve the signing key-ring and active key id for token rotation (#185).

    Precedence: an explicit ``secrets`` map, then an explicit single ``secret``,
    then :data:`SECRETS_ENV_VAR` (JSON ``{key_id: secret}``), then the legacy
    single :data:`SECRET_ENV_VAR`, then a generated dev secret (with a one-time
    warning). A single secret is filed under :data:`LEGACY_KEY_ID`.

    Args:
        explicit_secret: A single secret passed to the provider, or ``None``.
        explicit_secrets: A ``{key_id: secret}`` map passed to the provider, or
            ``None``.
        explicit_active_key_id: The active key id passed to the provider, or
            ``None`` to infer it.

    Returns:
        A ``(keyring, active_key_id)`` pair.

    Raises:
        AgentKernelError: If the resolved configuration is empty, malformed, or
            names an unknown active key id.
    """
    if explicit_secrets is not None:
        return _assemble_keyring(explicit_secrets, explicit_active_key_id, source="secrets=")
    if explicit_secret is not None:
        return {LEGACY_KEY_ID: explicit_secret}, LEGACY_KEY_ID
    env_secrets = os.environ.get(SECRETS_ENV_VAR)
    if env_secrets:
        try:
            parsed = json.loads(env_secrets)
        except json.JSONDecodeError as exc:
            raise AgentKernelError(f"{SECRETS_ENV_VAR} is not valid JSON: {exc}.") from exc
        if not isinstance(parsed, dict):
            raise AgentKernelError(
                f"{SECRETS_ENV_VAR} must be a JSON object of {{key_id: secret}} strings."
            )
        active = explicit_active_key_id or os.environ.get(ACTIVE_KEY_ENV_VAR)
        return _assemble_keyring(parsed, active, source=SECRETS_ENV_VAR)
    single = os.environ.get(SECRET_ENV_VAR)
    if single:
        return {LEGACY_KEY_ID: single}, LEGACY_KEY_ID
    return {LEGACY_KEY_ID: _get_secret()}, LEGACY_KEY_ID
