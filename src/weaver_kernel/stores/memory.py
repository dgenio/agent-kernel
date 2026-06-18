"""In-memory revocation store — the default backend for :class:`HMACTokenProvider`.

This is the behaviour previously inlined in ``HMACTokenProvider`` (a revoked-id
set plus a principal→token-ids index, guarded by a lock), extracted behind
:class:`~weaver_kernel.stores.RevocationStoreProtocol` so a durable backend can
be swapped in.

Memory is bounded (#182): every tracked token carries its ``expires_at``, and
state for already-expired tokens is swept — lazily on an interval (mirroring the
``HandleStore`` eviction pattern) and explicitly via :meth:`sweep_expired`. A
sweep never un-revokes a *live* token: only entries whose token has already
expired (and therefore fails verification on the expiry check regardless) are
removed.
"""

from __future__ import annotations

import datetime
import threading

# Run a lazy expiry sweep once every this many ``track`` calls, amortising the
# cost across issuance the way ``HandleStore`` amortises handle eviction.
_SWEEP_INTERVAL = 256


class InMemoryRevocationStore:
    """Process-local revocation list. State is lost on restart.

    For revocation that survives restarts and is shared across processes, use
    :class:`~weaver_kernel.stores.SQLiteRevocationStore`.
    """

    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._principal_tokens: dict[str, set[str]] = {}
        self._expiry: dict[str, datetime.datetime] = {}
        self._track_count = 0
        self._lock = threading.Lock()

    def is_revoked(self, token_id: str) -> bool:
        """Return whether *token_id* has been revoked."""
        with self._lock:
            return token_id in self._revoked

    def revoke(self, token_id: str) -> None:
        """Revoke a single token. Idempotent."""
        with self._lock:
            self._revoked.add(token_id)

    def track(self, principal_id: str, token_id: str, expires_at: datetime.datetime) -> None:
        """Record that *token_id* was issued to *principal_id*.

        A naive *expires_at* is treated as UTC (consistent with
        :class:`~weaver_kernel.stores.SQLiteRevocationStore`) so the sweep never
        compares naive and aware datetimes.
        """
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        with self._lock:
            self._principal_tokens.setdefault(principal_id, set()).add(token_id)
            self._expiry[token_id] = expires_at
            self._track_count += 1
            if self._track_count % _SWEEP_INTERVAL == 0:
                self._sweep_locked(datetime.datetime.now(tz=datetime.timezone.utc))

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

    def sweep_expired(self, now: datetime.datetime) -> int:
        """Drop revocation/tracking state for tokens expired at *now*.

        A naive *now* is treated as UTC, matching ``track`` and the durable
        backends, so the comparison never mixes naive and aware datetimes.

        Returns:
            The number of tracked tokens whose state was removed.
        """
        if now.tzinfo is None:
            now = now.replace(tzinfo=datetime.timezone.utc)
        with self._lock:
            return self._sweep_locked(now)

    def _sweep_locked(self, now: datetime.datetime) -> int:
        """Remove expired tokens' state. Caller must hold ``self._lock``.

        Iterates in sorted ``token_id`` order so the sweep is deterministic.
        """
        expired = sorted(tid for tid, exp in self._expiry.items() if exp <= now)
        for token_id in expired:
            self._expiry.pop(token_id, None)
            self._revoked.discard(token_id)
        if expired:
            expired_set = set(expired)
            for principal_id in list(self._principal_tokens):
                self._principal_tokens[principal_id] -= expired_set
                if not self._principal_tokens[principal_id]:
                    del self._principal_tokens[principal_id]
        return len(expired)
