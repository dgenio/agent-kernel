"""HandleStore: in-memory storage for full capability results with TTL."""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from .errors import HandleExpired, HandleNotFound
from .models import Frame, Handle, Provenance, ResponseMode


class HandleStore:
    """Stores full capability results by handle ID with TTL-based expiry.

    Entries are evicted lazily (on access), periodically during :meth:`store`,
    or explicitly via :meth:`evict_expired`.  A *max_entries* cap prevents
    unbounded memory growth in long-lived processes — when the cap is exceeded
    the oldest entries are dropped after expired ones are cleared.
    """

    _EVICT_INTERVAL: int = 128  # run evict_expired() every N store() calls

    def __init__(
        self,
        default_ttl_seconds: int = 3600,
        *,
        max_entries: int = 10_000,
    ) -> None:
        self._default_ttl = default_ttl_seconds
        self._max_entries = max_entries
        self._store_count = 0
        self._data: dict[str, Any] = {}
        self._meta: dict[str, Handle] = {}

    # ── Storage ───────────────────────────────────────────────────────────────

    def store(
        self,
        capability_id: str,
        data: Any,
        *,
        ttl_seconds: int | None = None,
    ) -> Handle:
        """Store *data* and return a :class:`Handle`.

        Args:
            capability_id: The capability that produced *data*.
            data: The full dataset to store.
            ttl_seconds: Time-to-live in seconds (defaults to the store default).

        Returns:
            A :class:`Handle` referencing the stored data.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        handle = Handle(
            handle_id=str(uuid.uuid4()),
            capability_id=capability_id,
            created_at=now,
            expires_at=now + datetime.timedelta(seconds=ttl),
            total_rows=len(data) if isinstance(data, list) else 1,
        )
        self._data[handle.handle_id] = data
        self._meta[handle.handle_id] = handle

        # Periodic eviction of expired entries
        self._store_count += 1
        if self._store_count % self._EVICT_INTERVAL == 0:
            self.evict_expired()

        # Cap enforcement: evict oldest entries when over the limit
        if len(self._meta) > self._max_entries:
            self.evict_expired()  # clear expired first
            overflow = len(self._meta) - self._max_entries
            if overflow > 0:
                oldest = sorted(self._meta, key=lambda hid: self._meta[hid].created_at)
                for hid in oldest[:overflow]:
                    self._data.pop(hid, None)
                    self._meta.pop(hid, None)

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
            del self._data[handle_id]
            del self._meta[handle_id]
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
    ) -> Frame:
        """Expand a handle with optional pagination, field selection, and filtering.

        Supported query keys:
            - ``offset`` (int): Skip this many rows.
            - ``limit`` (int): Return at most this many rows.
            - ``fields`` (list[str]): Only include these fields.
            - ``filter`` (dict[str, Any]): Basic equality filter (all conditions AND-ed).

        Args:
            handle: The handle to expand.
            query: Query parameters controlling the expansion.
            action_id: Audit action ID to embed in the returned Frame.
            response_mode: Response mode for the returned Frame.

        Returns:
            A :class:`Frame` containing the slice of data.

        Raises:
            HandleNotFound: If the handle ID is unknown.
            HandleExpired: If the handle's TTL has elapsed.
        """
        data = self.get(handle.handle_id)
        rows: list[Any] = data if isinstance(data, list) else [data]

        # ── Filtering ──────────────────────────────────────────────────────────
        filter_spec: dict[str, Any] = query.get("filter", {})
        if filter_spec and isinstance(filter_spec, dict):
            rows = [
                r
                for r in rows
                if isinstance(r, dict) and all(r.get(k) == v for k, v in filter_spec.items())
            ]

        # ── Pagination ────────────────────────────────────────────────────────
        offset = int(query.get("offset", 0))
        limit = int(query.get("limit", len(rows)))
        rows = rows[offset : offset + limit]

        # ── Field selection ───────────────────────────────────────────────────
        fields: list[str] = list(query.get("fields", []))
        if fields:
            rows = [
                {k: v for k, v in r.items() if k in fields} if isinstance(r, dict) else r
                for r in rows
            ]

        if not rows:
            table_preview: list[Any] = []
        elif isinstance(rows[0], dict):
            table_preview = rows
        else:
            table_preview = [{"value": r} for r in rows]

        return Frame(
            action_id=action_id,
            capability_id=handle.capability_id,
            response_mode=response_mode,
            table_preview=table_preview,
            handle=handle,
            provenance=Provenance(
                capability_id=handle.capability_id,
                principal_id="",
                invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
                action_id=action_id,
            ),
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
            self._data.pop(hid, None)
            self._meta.pop(hid, None)
        return len(expired)
