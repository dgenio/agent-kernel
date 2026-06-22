"""HandleStore: in-memory storage for full capability results with TTL."""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from .errors import BudgetConfigError, HandleExpired, HandleNotFound, HandleTooLarge
from .firewall.size_estimate import estimated_size
from .handle_query import expand_handle
from .models import Frame, Handle, ResponseMode


class HandleStore:
    """Stores full capability results by handle ID with TTL-based expiry.

    Entries are evicted lazily (on access), periodically during :meth:`store`,
    or explicitly via :meth:`evict_expired`.  A *max_entries* cap prevents
    unbounded memory growth in long-lived processes — when the cap is exceeded
    the oldest entries are dropped after expired ones are cleared.

    Two optional **byte budgets** bound memory by size rather than entry count,
    since one deployment's 10k entries are kilobytes and another's are gigabytes
    (issue #211). Both default to ``None`` (disabled), leaving behaviour
    unchanged until configured:

    - ``max_entry_bytes`` rejects a single over-cap payload with
      :class:`~weaver_kernel.errors.HandleTooLarge` (the data is never stored).
    - ``max_total_bytes`` evicts oldest-first after each store until aggregate
      estimated residency is within budget.
    """

    _EVICT_INTERVAL: int = 128  # run evict_expired() every N store() calls

    def __init__(
        self,
        default_ttl_seconds: int = 3600,
        *,
        max_entries: int = 10_000,
        max_total_bytes: int | None = None,
        max_entry_bytes: int | None = None,
    ) -> None:
        if max_total_bytes is not None and max_total_bytes <= 0:
            raise BudgetConfigError("max_total_bytes must be positive when set")
        if max_entry_bytes is not None and max_entry_bytes <= 0:
            raise BudgetConfigError("max_entry_bytes must be positive when set")
        self._default_ttl = default_ttl_seconds
        self._max_entries = max_entries
        self._max_total_bytes = max_total_bytes
        self._max_entry_bytes = max_entry_bytes
        self._store_count = 0
        self._data: dict[str, Any] = {}
        self._meta: dict[str, Handle] = {}
        self._sizes: dict[str, int] = {}
        self._total_bytes = 0

    @property
    def current_bytes(self) -> int:
        """Estimated total bytes of data currently resident in the store."""
        return self._total_bytes

    # ── Storage ───────────────────────────────────────────────────────────────

    def store(
        self,
        capability_id: str,
        data: Any,
        *,
        ttl_seconds: int | None = None,
        principal_id: str = "",
        constraints: dict[str, Any] | None = None,
    ) -> Handle:
        """Store *data* and return a :class:`Handle`.

        Args:
            capability_id: The capability that produced *data*.
            data: The full dataset to store.
            ttl_seconds: Time-to-live in seconds (defaults to the store default).
            principal_id: Principal the original grant was issued to. When
                non-empty, :meth:`expand` rejects requests from other
                principals with :class:`HandleConstraintViolation`.
            constraints: Grant constraints to persist on the handle (typically
                ``token.constraints`` — e.g. ``max_rows``, ``allowed_fields``,
                ``scope``). :meth:`expand` rechecks these.

        Returns:
            A :class:`Handle` referencing the stored data.

        Raises:
            HandleTooLarge: If ``max_entry_bytes`` is set and the estimated size
                of *data* exceeds it.
        """
        size = estimated_size(data)
        if self._max_entry_bytes is not None and size > self._max_entry_bytes:
            raise HandleTooLarge(
                f"Handle data for '{capability_id}' is ~{size} bytes, exceeding the "
                f"per-entry cap of {self._max_entry_bytes} bytes; not stored."
            )

        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        handle = Handle(
            handle_id=str(uuid.uuid4()),
            capability_id=capability_id,
            created_at=now,
            expires_at=now + datetime.timedelta(seconds=ttl),
            total_rows=len(data) if isinstance(data, list) else 1,
            principal_id=principal_id,
            constraints=dict(constraints) if constraints else {},
        )
        self._data[handle.handle_id] = data
        self._meta[handle.handle_id] = handle
        self._sizes[handle.handle_id] = size
        self._total_bytes += size

        # Periodic eviction of expired entries
        self._store_count += 1
        if self._store_count % self._EVICT_INTERVAL == 0:
            self.evict_expired()

        # Cap enforcement: evict oldest entries when over the entry limit
        if len(self._meta) > self._max_entries:
            self.evict_expired()  # clear expired first
            overflow = len(self._meta) - self._max_entries
            if overflow > 0:
                for hid in self._oldest_ids()[:overflow]:
                    self._drop(hid)

        # Byte-budget enforcement: evict oldest until within the total budget,
        # never evicting the entry we just stored (the caller holds its handle).
        if self._max_total_bytes is not None and self._total_bytes > self._max_total_bytes:
            self.evict_expired()
            for hid in self._oldest_ids():
                if self._total_bytes <= self._max_total_bytes:
                    break
                if hid == handle.handle_id:
                    continue  # never evict the entry we just stored
                self._drop(hid)

        return handle

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def get(self, handle_id: str) -> Any:
        """Retrieve raw data by handle ID.

        Args:
            handle_id: The handle's unique identifier.

        Returns:
            The stored data.

        Raises:
            HandleNotFound: If the handle ID is unknown.
            HandleExpired: If the handle's TTL has elapsed.
        """
        handle = self._meta.get(handle_id)
        if handle is None:
            raise HandleNotFound(f"Handle '{handle_id}' not found. It may have been evicted.")
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if handle.expires_at <= now:
            # Lazy eviction
            self._drop(handle_id)
            raise HandleExpired(
                f"Handle '{handle_id}' expired at {handle.expires_at.isoformat()}."
            )
        return self._data[handle_id]

    def get_meta(self, handle_id: str) -> Handle:
        """Retrieve the :class:`Handle` metadata without fetching the data.

        Args:
            handle_id: The handle's unique identifier.

        Returns:
            The :class:`Handle` metadata.

        Raises:
            HandleNotFound: If the handle ID is unknown.
        """
        handle = self._meta.get(handle_id)
        if handle is None:
            raise HandleNotFound(f"Handle '{handle_id}' not found.")
        return handle

    # ── Expand ────────────────────────────────────────────────────────────────

    def expand(
        self,
        handle: Handle,
        *,
        query: dict[str, Any],
        action_id: str = "",
        response_mode: ResponseMode = "table",
        principal_id: str = "",
        max_depth: int | None = None,
    ) -> Frame:
        """Expand a handle with optional pagination, field selection, and filtering.

        Supported query keys:
            - ``offset`` (int): Skip this many rows.
            - ``limit`` (int): Return at most this many rows.
            - ``fields`` (list[str]): Only include these fields.
            - ``filter`` (dict[str, Any]): Basic equality filter (all conditions AND-ed).

        The query pipeline lives in :func:`weaver_kernel.handle_query.expand_handle`;
        this method binds it to the store's TTL-checked data fetch.

        Args:
            handle: The handle to expand.
            query: Query parameters controlling the expansion.
            action_id: Audit action ID to embed in the returned Frame.
            response_mode: Response mode for the returned Frame.
            principal_id: Principal performing the expansion. When the handle
                was created with a non-empty ``principal_id``, this must match.
            max_depth: Redaction recursion cap for the projected rows. When
                ``None`` the :func:`redact` default applies; the kernel passes
                the firewall's configured ``Budgets.max_depth`` so the
                expansion path redacts to the same depth as ``transform``.

        Returns:
            A :class:`Frame` containing the slice of data.

        Raises:
            HandleNotFound: If the handle ID is unknown.
            HandleExpired: If the handle's TTL has elapsed.
            HandleConstraintViolation: If the requested expansion exceeds the
                grant's persisted constraints (``max_rows``, ``allowed_fields``,
                ``scope``) or is requested by a different principal.
        """
        return expand_handle(
            handle,
            fetch_data=lambda: self.get(handle.handle_id),
            query=query,
            action_id=action_id,
            response_mode=response_mode,
            principal_id=principal_id,
            max_depth=max_depth,
        )

    # ── Maintenance ───────────────────────────────────────────────────────────

    def evict_expired(self) -> int:
        """Remove all expired handles from the store.

        Returns:
            The number of handles evicted.
        """
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        expired = [hid for hid, h in self._meta.items() if h.expires_at <= now]
        for hid in expired:
            self._drop(hid)
        return len(expired)

    def _oldest_ids(self) -> list[str]:
        """Handle IDs ordered oldest-first by creation time (deterministic)."""
        return sorted(self._meta, key=lambda hid: self._meta[hid].created_at)

    def _drop(self, handle_id: str) -> None:
        """Remove a handle's data, metadata, and size accounting."""
        self._data.pop(handle_id, None)
        self._meta.pop(handle_id, None)
        self._total_bytes -= self._sizes.pop(handle_id, 0)
