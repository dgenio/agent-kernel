"""Storage-backend protocols for the kernel's stateful stores.

These mirror the existing protocol-based seams in the codebase
(:class:`~weaver_kernel.drivers.base.Driver`,
:class:`~weaver_kernel.tokens.TokenProvider`): the in-memory implementations
remain the defaults, and any object satisfying these protocols can be injected
into the :class:`~weaver_kernel.Kernel` / :class:`~weaver_kernel.HMACTokenProvider`
via constructor injection.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import ActionTrace


@runtime_checkable
class TraceStoreProtocol(Protocol):
    """Interface for storing and retrieving :class:`ActionTrace` records.

    The in-memory :class:`~weaver_kernel.TraceStore` is the default
    implementation; :class:`~weaver_kernel.stores.SQLiteTraceStore` and
    :class:`~weaver_kernel.stores.JsonlTraceStore` add durability.
    """

    def record(self, trace: ActionTrace) -> None:
        """Persist an action trace."""
        ...

    def get(self, action_id: str) -> ActionTrace:
        """Return the trace for *action_id* or raise :class:`AgentKernelError`."""
        ...

    def list_all(self) -> list[ActionTrace]:
        """Return all recorded traces in insertion order."""
        ...


@runtime_checkable
class RevocationStoreProtocol(Protocol):
    """Interface for the token revocation list used by :class:`HMACTokenProvider`.

    Implementations must be safe to consult on the hot verification path
    (:meth:`is_revoked`) and must honour I-02: a token revoked before
    verification never validates afterwards.
    """

    def is_revoked(self, token_id: str) -> bool:
        """Return whether *token_id* has been revoked."""
        ...

    def revoke(self, token_id: str) -> None:
        """Revoke a single token. Idempotent."""
        ...

    def track(self, principal_id: str, token_id: str) -> None:
        """Record that *token_id* was issued to *principal_id* (for ``revoke_all``)."""
        ...

    def revoke_principal(self, principal_id: str) -> int:
        """Revoke every tracked token for *principal_id*.

        Returns:
            The count of tokens newly revoked by this call (excluding tokens
            already revoked).
        """
        ...


@runtime_checkable
class HandleStoreProtocol(Protocol):
    """Interface for the full-result handle store.

    Note:
        Only the in-memory :class:`~weaver_kernel.HandleStore` ships today. The
        protocol is defined so a durable backend can be added later without a
        breaking change; handles are short-lived, TTL-bounded result caches, so
        durability is lower priority than the audit-trail stores.
    """

    def evict_expired(self) -> int:
        """Drop all expired handles; return the number evicted."""
        ...
