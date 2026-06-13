"""In-memory revocation store — the default backend for :class:`HMACTokenProvider`.

This is the behaviour previously inlined in ``HMACTokenProvider`` (a revoked-id
set plus a principal→token-ids index, guarded by a lock), extracted behind
:class:`~weaver_kernel.stores.RevocationStoreProtocol` so a durable backend can
be swapped in. Semantics are unchanged.
"""

from __future__ import annotations

import threading


class InMemoryRevocationStore:
    """Process-local revocation list. State is lost on restart.

    For revocation that survives restarts and is shared across processes, use
    :class:`~weaver_kernel.stores.SQLiteRevocationStore`.
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._principal_tokens: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def is_revoked(self, token_id: str) -> bool:
        """Return whether *token_id* has been revoked."""
        with self._lock:
            return token_id in self._revoked

    def revoke(self, token_id: str) -> None:
        """Revoke a single token. Idempotent."""
        with self._lock:
            self._revoked.add(token_id)

    def track(self, principal_id: str, token_id: str) -> None:
        """Record that *token_id* was issued to *principal_id*."""
        with self._lock:
            self._principal_tokens.setdefault(principal_id, set()).add(token_id)

    def revoke_principal(self, principal_id: str) -> int:
        """Revoke every tracked token for *principal_id*.

        Returns:
            The count of tokens newly revoked by this call.
        """
        with self._lock:
            token_ids = self._principal_tokens.get(principal_id, set())
            newly_revoked = token_ids - self._revoked
            self._revoked |= newly_revoked
            # Drop the index entry; new tokens for this principal start fresh.
            self._principal_tokens.pop(principal_id, None)
            return len(newly_revoked)
