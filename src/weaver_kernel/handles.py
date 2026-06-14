"""HandleStore: in-memory storage for full capability results with TTL."""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from .errors import HandleConstraintViolation, HandleExpired, HandleNotFound
from .firewall.redaction import redact
from .models import Frame, Handle, Provenance, ResponseMode
from .policy_reasons import DenialReason


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
        """
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
        principal_id: str = "",
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
            principal_id: Principal performing the expansion. When the handle
                was created with a non-empty ``principal_id``, this must match.

        Returns:
            A :class:`Frame` containing the slice of data.

        Raises:
            HandleNotFound: If the handle ID is unknown.
            HandleExpired: If the handle's TTL has elapsed.
            HandleConstraintViolation: If the requested expansion exceeds the
                grant's persisted constraints (``max_rows``, ``allowed_fields``,
                ``scope``) or is requested by a different principal.
        """
        # ── Principal binding ─────────────────────────────────────────────────
        # A handle bound to a principal is not a bearer credential. If the
        # handle has a non-empty principal_id, the caller MUST present a
        # matching principal_id — omitting it counts as a mismatch (otherwise
        # any caller in the same process could expand by passing "").
        if handle.principal_id and handle.principal_id != principal_id:
            raise HandleConstraintViolation(
                f"Handle '{handle.handle_id}' was granted to principal "
                f"'{handle.principal_id}' and cannot be expanded by "
                f"'{principal_id or '<unspecified>'}'.",
                reason_code=DenialReason.HANDLE_PRINCIPAL_MISMATCH,
            )

        # ── Query input validation ────────────────────────────────────────────
        # Validate user-supplied query types up front so callers see a stable
        # HandleConstraintViolation (with INVALID_CONSTRAINT) instead of a
        # bare TypeError/ValueError from inside the expansion logic. Public
        # interfaces must not leak stdlib exceptions (see AGENTS.md).
        raw_filter = query.get("filter")
        if raw_filter is not None and not isinstance(raw_filter, dict):
            raise HandleConstraintViolation(
                f"Handle expand 'filter' must be a dict, got {type(raw_filter).__name__}.",
                reason_code=DenialReason.INVALID_CONSTRAINT,
            )
        raw_fields = query.get("fields")
        if raw_fields is not None and not isinstance(raw_fields, list | tuple):
            raise HandleConstraintViolation(
                f"Handle expand 'fields' must be a list, got {type(raw_fields).__name__}.",
                reason_code=DenialReason.INVALID_CONSTRAINT,
            )

        # ── Grant-constraint rechecks ─────────────────────────────────────────
        granted_max_rows = handle.constraints.get("max_rows")
        granted_fields = handle.constraints.get("allowed_fields") or []
        granted_scope = handle.constraints.get("scope") or {}

        requested_fields: list[str] = list(raw_fields or [])
        if granted_fields and requested_fields:
            disallowed = [f for f in requested_fields if f not in granted_fields]
            if disallowed:
                raise HandleConstraintViolation(
                    f"Handle '{handle.handle_id}' grant restricts fields to "
                    f"{sorted(granted_fields)}; request asked for "
                    f"{sorted(disallowed)}.",
                    reason_code=DenialReason.HANDLE_CONSTRAINT_VIOLATION,
                )

        filter_in: dict[str, Any] = raw_filter or {}
        if granted_scope:
            for sk, sv in granted_scope.items():
                if sk in filter_in and filter_in[sk] != sv:
                    raise HandleConstraintViolation(
                        f"Handle '{handle.handle_id}' is scoped to "
                        f"{sk}={sv!r}; request filter "
                        f"{sk}={filter_in[sk]!r} is outside that scope.",
                        reason_code=DenialReason.HANDLE_CONSTRAINT_VIOLATION,
                    )

        data = self.get(handle.handle_id)
        rows: list[Any] = data if isinstance(data, list) else [data]

        # ── Filtering ──────────────────────────────────────────────────────────
        # Grant scope is AND-merged into the request filter so the caller
        # cannot bypass it by omitting the scope key.
        filter_spec: dict[str, Any] = dict(filter_in)
        for sk, sv in granted_scope.items():
            filter_spec.setdefault(sk, sv)
        if filter_spec:
            rows = [
                r
                for r in rows
                if isinstance(r, dict) and all(r.get(k) == v for k, v in filter_spec.items())
            ]

        # ── Pagination ────────────────────────────────────────────────────────
        try:
            offset = int(query.get("offset", 0))
        except (TypeError, ValueError) as exc:
            raise HandleConstraintViolation(
                f"Handle expand 'offset' must be an integer, got {query.get('offset')!r}.",
                reason_code=DenialReason.INVALID_CONSTRAINT,
            ) from exc
        if offset < 0:
            raise HandleConstraintViolation(
                f"Handle expand 'offset' must be non-negative, got {offset}.",
                reason_code=DenialReason.INVALID_CONSTRAINT,
            )
        requested_limit_raw = query.get("limit")
        requested_limit: int | None
        if requested_limit_raw is None:
            requested_limit = None
        else:
            try:
                requested_limit = int(requested_limit_raw)
            except (TypeError, ValueError) as exc:
                raise HandleConstraintViolation(
                    f"Handle expand 'limit' must be an integer, got {requested_limit_raw!r}.",
                    reason_code=DenialReason.INVALID_CONSTRAINT,
                ) from exc
            # A negative limit would slice as rows[offset:offset+limit] and could
            # return rows in excess of a (possibly zero) grant cap — reject it
            # rather than silently bypassing max_rows.
            if requested_limit < 0:
                raise HandleConstraintViolation(
                    f"Handle expand 'limit' must be non-negative, got {requested_limit}.",
                    reason_code=DenialReason.INVALID_CONSTRAINT,
                )
        limit = len(rows) if requested_limit is None else requested_limit

        if isinstance(granted_max_rows, int) and granted_max_rows >= 0:
            if requested_limit is not None and requested_limit > granted_max_rows:
                raise HandleConstraintViolation(
                    f"Handle '{handle.handle_id}' grant caps rows at "
                    f"{granted_max_rows}; request asked for "
                    f"limit={requested_limit}.",
                    reason_code=DenialReason.HANDLE_CONSTRAINT_VIOLATION,
                )
            limit = min(limit, granted_max_rows)

        rows = rows[offset : offset + limit]

        # ── Field selection ───────────────────────────────────────────────────
        # If the grant restricts fields and the caller did not ask for any,
        # apply the grant's allowed_fields as the default projection so
        # disallowed fields cannot leak through an unscoped expand call.
        effective_fields: list[str]
        if requested_fields:
            effective_fields = requested_fields
        elif granted_fields:
            effective_fields = list(granted_fields)
        else:
            effective_fields = []
        if effective_fields:
            rows = [
                {k: v for k, v in r.items() if k in effective_fields} if isinstance(r, dict) else r
                for r in rows
            ]

        if not rows:
            table_preview: list[Any] = []
        elif isinstance(rows[0], dict):
            table_preview = rows
        else:
            table_preview = [{"value": r} for r in rows]

        # ── Redaction ───────────────────────────────────────────────────────────
        # expand() builds its Frame directly from the raw stored dataset, which
        # is persisted pre-firewall. Field-level grant constraints
        # (allowed_fields / scope) are already enforced above, but a permitted
        # field can still carry inline secrets (e.g. a Bearer token in a `note`
        # value). Route the projected rows through the same redactor the
        # Firewall applies on first invocation so the I-01 boundary holds on the
        # expansion path too (see docs/agent-context/invariants.md).
        redacted_preview, warnings = redact(table_preview)

        return Frame(
            action_id=action_id,
            capability_id=handle.capability_id,
            response_mode=response_mode,
            table_preview=redacted_preview,
            warnings=warnings,
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
