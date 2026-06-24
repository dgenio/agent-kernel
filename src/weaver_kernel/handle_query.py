"""Handle expansion query logic, factored out of :mod:`weaver_kernel.handles`.

:func:`expand_handle` holds the pagination / field-selection / filtering /
redaction pipeline that turns a stored raw dataset into a bounded
:class:`~weaver_kernel.models.Frame`. It lives here (rather than as a method on
:class:`~weaver_kernel.handles.HandleStore`) so the store module stays within
the module-size budget while the query logic remains independently testable.

The data fetch is injected as a ``fetch_data`` callable so this module never
imports :class:`~weaver_kernel.handles.HandleStore` — the store stays the single
owner of TTL/eviction state and passes ``lambda: self.get(handle_id)``.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable
from typing import Any

from .errors import HandleConstraintViolation
from .firewall.redaction import redact
from .models import Frame, Handle, Provenance, ResponseMode
from .policy_reasons import DenialReason


def expand_handle(
    handle: Handle,
    *,
    fetch_data: Callable[[], Any],
    query: dict[str, Any],
    action_id: str = "",
    response_mode: ResponseMode = "table",
    principal_id: str = "",
    max_depth: int | None = None,
) -> Frame:
    """Expand *handle* with optional pagination, field selection, and filtering.

    Args:
        handle: The handle to expand.
        fetch_data: Zero-argument callable returning the stored dataset. Raising
            :class:`~weaver_kernel.errors.HandleExpired` /
            :class:`~weaver_kernel.errors.HandleNotFound` from here propagates
            unchanged.
        query: Query parameters controlling the expansion (``offset``, ``limit``,
            ``fields``, ``filter``).
        action_id: Audit action ID to embed in the returned Frame.
        response_mode: Response mode for the returned Frame.
        principal_id: Principal performing the expansion. When the handle was
            created with a non-empty ``principal_id``, this must match.
        max_depth: Redaction recursion cap for the projected rows.

    Returns:
        A :class:`Frame` containing the slice of data.

    Raises:
        HandleConstraintViolation: If the requested expansion exceeds the grant's
            persisted constraints or is requested by a different principal.
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

    data = fetch_data()
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
    # (allowed_fields / scope) are already enforced by the projection above,
    # so allowed_fields is intentionally not re-passed here; but a permitted
    # field can still carry inline secrets (e.g. a Bearer token in a `note`
    # value). Route the projected rows through the same redactor the
    # Firewall applies on first invocation — using the firewall's configured
    # max_depth when the caller threads it — so the I-01 boundary holds on
    # the expansion path too (see docs/agent-context/invariants.md).
    if max_depth is None:
        redacted_preview, warnings = redact(table_preview)
    else:
        redacted_preview, warnings = redact(table_preview, max_depth=max_depth)

    return Frame(
        action_id=action_id,
        capability_id=handle.capability_id,
        response_mode=response_mode,
        table_preview=redacted_preview,
        warnings=warnings,
        handle=handle,
        provenance=Provenance(
            capability_id=handle.capability_id,
            principal_id=principal_id,
            invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
            action_id=action_id,
        ),
    )
