"""Context firewall: transforms raw driver output into bounded Frames."""

from __future__ import annotations

import datetime
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any

from ..models import (
    Frame,
    Handle,
    Provenance,
    RawResult,
    ResponseMode,
)
from .budgets import Budgets
from .redaction import StreamRedactor, redact
from .size_estimate import estimated_size
from .summarize import summarize

logger = logging.getLogger(__name__)


class Firewall:
    """Transforms :class:`RawResult` objects into LLM-safe :class:`Frame` objects.

    The firewall enforces:
    - Row, field, character, and depth budgets.
    - PII/PCI redaction (when sensitivity constraints are set).
    - Four response modes: ``summary``, ``table``, ``handle_only``, ``raw``.
    """

    def __init__(self, budgets: Budgets | None = None) -> None:
        if budgets is None:
            self._budgets = Budgets()
        else:
            self._budgets = budgets

    @property
    def budgets(self) -> Budgets:
        """The configured row/field/character/depth budgets.

        Exposed so other egress paths (e.g. handle expansion) can redact with
        the *same* ``max_depth`` the single-shot ``transform`` path uses,
        keeping the I-01 boundary consistent across paths.
        """
        return self._budgets

    def transform(
        self,
        raw: RawResult,
        *,
        action_id: str,
        principal_id: str,
        principal_roles: list[str],
        response_mode: ResponseMode,
        constraints: dict[str, Any] | None = None,
        handle: Handle | None = None,
    ) -> Frame:
        """Transform a raw result into a Frame.

        Args:
            raw: The driver output to transform.
            action_id: The audit action ID.
            principal_id: Principal making the request.
            principal_roles: Principal's roles (used for ``raw`` mode gate).
            response_mode: How to present the data.
            constraints: Active execution constraints (may include ``max_rows``,
                ``allowed_fields``).
            handle: Pre-created handle for the full dataset.

        Returns:
            A bounded :class:`Frame`.

        Raises:
            FirewallError: If the raw result cannot be transformed.
        """
        constraints = constraints or {}
        max_rows = int(constraints.get("max_rows", self._budgets.max_rows))
        allowed_fields: list[str] = list(constraints.get("allowed_fields", []))

        provenance = Provenance(
            capability_id=raw.capability_id,
            principal_id=principal_id,
            invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
            action_id=action_id,
        )

        warnings: list[str] = []
        data = raw.data

        # ── Redaction ──────────────────────────────────────────────────────────
        needs_redaction = bool(allowed_fields)
        if needs_redaction:
            data, redact_warnings = redact(
                data,
                allowed_fields=allowed_fields,
                max_depth=self._budgets.max_depth,
            )
            warnings.extend(redact_warnings)
        else:
            # Always run redaction even without allowed_fields to catch inline PII
            data, redact_warnings = redact(data, max_depth=self._budgets.max_depth)
            warnings.extend(redact_warnings)

        logger.debug(
            "firewall_redaction",
            extra={
                "action_id": action_id,
                "capability_id": raw.capability_id,
                "principal_id": principal_id,
                "redaction_warnings": len(redact_warnings),
                "needs_redaction": needs_redaction,
            },
        )

        # ── Raw mode (admin only) ──────────────────────────────────────────────
        if response_mode == "raw":
            if "admin" not in principal_roles:
                warnings.append("raw mode requires admin role; falling back to summary.")
                response_mode = "summary"
                logger.debug(
                    "firewall_mode_fallback",
                    extra={
                        "action_id": action_id,
                        "capability_id": raw.capability_id,
                        "requested_mode": "raw",
                        "effective_mode": "summary",
                        "reason": "principal lacks admin role",
                    },
                )
            else:
                raw_size = estimated_size(data)
                if raw_size > self._budgets.max_chars:
                    warnings.append(
                        f"raw output ({raw_size} chars) exceeds budget "
                        f"({self._budgets.max_chars} chars); data returned untruncated."
                    )
                logger.debug(
                    "firewall_transform",
                    extra={
                        "action_id": action_id,
                        "capability_id": raw.capability_id,
                        "response_mode": "raw",
                        "raw_size_chars": raw_size,
                        "budget_chars": self._budgets.max_chars,
                    },
                )
                return Frame(
                    action_id=action_id,
                    capability_id=raw.capability_id,
                    response_mode="raw",
                    raw_data=data,
                    handle=handle,
                    warnings=warnings,
                    provenance=provenance,
                )

        # ── Handle only ───────────────────────────────────────────────────────
        if response_mode == "handle_only":
            logger.debug(
                "firewall_transform",
                extra={
                    "action_id": action_id,
                    "capability_id": raw.capability_id,
                    "response_mode": "handle_only",
                },
            )
            return Frame(
                action_id=action_id,
                capability_id=raw.capability_id,
                response_mode="handle_only",
                handle=handle,
                warnings=warnings,
                provenance=provenance,
            )

        # ── Table mode ────────────────────────────────────────────────────────
        if response_mode == "table":
            table_preview = self._make_table(data, max_rows=max_rows)
            logger.debug(
                "firewall_transform",
                extra={
                    "action_id": action_id,
                    "capability_id": raw.capability_id,
                    "response_mode": "table",
                    "rows_returned": len(table_preview),
                    "max_rows": max_rows,
                },
            )
            return Frame(
                action_id=action_id,
                capability_id=raw.capability_id,
                response_mode="table",
                table_preview=table_preview,
                handle=handle,
                warnings=warnings,
                provenance=provenance,
            )

        # ── Summary mode (default) ────────────────────────────────────────────
        facts = summarize(data, max_facts=20)
        # Enforce char budget across all facts
        facts = _cap_facts(facts, self._budgets.max_chars)
        logger.debug(
            "firewall_transform",
            extra={
                "action_id": action_id,
                "capability_id": raw.capability_id,
                "response_mode": "summary",
                "facts_count": len(facts),
                "budget_chars": self._budgets.max_chars,
            },
        )
        return Frame(
            action_id=action_id,
            capability_id=raw.capability_id,
            response_mode="summary",
            facts=facts,
            handle=handle,
            warnings=warnings,
            provenance=provenance,
        )

    async def apply_stream(
        self,
        response_chunks: AsyncIterator[dict[str, Any]],
        *,
        action_id: str,
        capability_id: str,
        principal_id: str,
        principal_roles: list[str],
        response_mode: ResponseMode,
        constraints: dict[str, Any] | None = None,
    ) -> AsyncIterator[Frame]:
        """Stream chunks through the firewall, applying redaction per chunk.

        Each chunk is wrapped in a synthetic :class:`RawResult` and passed
        through :meth:`transform`. The same admin gate, redaction, and
        budget caps that apply to a single-shot :meth:`transform` apply to
        *every* chunk — PII never leaks even when results stream in.

        Cross-chunk redaction safety: top-level string fields are routed
        through a per-field :class:`StreamRedactor`, which holds back a
        trailing overlap window so a secret whose characters span two chunks
        is reassembled and redacted before either half is emitted. Non-string
        and nested values are redacted per chunk by :meth:`transform`.

        Mode escalation across chunks (e.g. dropping from ``table`` to
        ``summary`` as budget drains) is the caller's responsibility — the
        Firewall itself does not escalate. ``Kernel.invoke_stream`` orchestrates
        escalation via :class:`BudgetManager.suggested_mode`.

        The synthetic key ``"__is_final__"`` on a chunk is stripped before
        firewall processing and re-applied to the yielded Frame's
        ``is_final`` attribute. If the iterator ends without ever
        producing an explicit final chunk, no extra sentinel is yielded
        here — that bookkeeping is left to higher layers.

        Args:
            response_chunks: Async iterator of raw chunks from the driver.
            action_id: The audit action ID for this stream.
            capability_id: Capability being executed.
            principal_id: Principal making the request.
            principal_roles: Principal's roles (used for admin gate).
            response_mode: Current response mode (may differ chunk-to-chunk
                if the caller passes pre-escalated modes).
            constraints: Active execution constraints.

        Yields:
            :class:`Frame` chunks with ``is_final`` set on the last one.
        """
        redactors: dict[str, StreamRedactor] = {}
        async for chunk in response_chunks:
            is_final = bool(chunk.get("__is_final__", False))
            raw_payload = {k: v for k, v in chunk.items() if k != "__is_final__"}
            payload, stream_warnings = _apply_stream_redactors(
                raw_payload, redactors, is_final=is_final
            )
            synthetic_raw = RawResult(
                capability_id=capability_id,
                data=payload,
                metadata={"action_id": action_id, "streaming": True},
            )
            frame = self.transform(
                synthetic_raw,
                action_id=action_id,
                principal_id=principal_id,
                principal_roles=principal_roles,
                response_mode=response_mode,
                constraints=constraints,
            )
            if stream_warnings:
                frame = replace(frame, warnings=[*frame.warnings, *stream_warnings])
            if is_final:
                frame = replace(frame, is_final=True)
            yield frame

    def _make_table(self, data: Any, *, max_rows: int) -> list[dict[str, Any]]:
        """Convert *data* to a list of dicts, capped at *max_rows*."""
        if isinstance(data, list):
            rows = data[:max_rows]
        elif isinstance(data, dict):
            rows = [data]
        else:
            rows = [{"value": data}]

        result: list[dict[str, Any]] = []
        for row in rows:
            if isinstance(row, dict):
                capped = dict(list(row.items())[: self._budgets.max_fields])
                result.append(capped)
            else:
                result.append({"value": row})
        return result


def _apply_stream_redactors(
    payload: dict[str, Any],
    redactors: dict[str, StreamRedactor],
    *,
    is_final: bool,
) -> tuple[dict[str, Any], list[str]]:
    """Route a chunk's top-level string fields through per-field redactors.

    String values are fed to a :class:`StreamRedactor` (created lazily per
    field) so patterns split across chunks are reassembled before emission.
    Non-string values are passed through unchanged — :meth:`Firewall.transform`
    still redacts them per chunk. On the final chunk every active redactor is
    flushed, including fields absent from the final payload (their held tail is
    re-attached under the original key) so no buffered text is dropped.

    Args:
        payload: The chunk payload (``__is_final__`` already stripped).
        redactors: Mutable per-field redactor state carried across chunks.
        is_final: Whether this is the last chunk (triggers flush).

    Returns:
        ``(redacted_payload, warnings)``.
    """
    out: dict[str, Any] = {}
    warnings: list[str] = []
    for key, value in payload.items():
        if isinstance(value, str):
            redactor = redactors.setdefault(key, StreamRedactor())
            committed, warns = redactor.feed(value)
            if is_final:
                tail, tail_warns = redactor.flush()
                committed += tail
                warns = [*warns, *tail_warns]
            out[key] = committed
            warnings.extend(warns)
        else:
            out[key] = value
    if is_final:
        for key, redactor in redactors.items():
            if key in out:
                continue
            tail, tail_warns = redactor.flush()
            if tail:
                out[key] = tail
                warnings.extend(tail_warns)
    return out, warnings


def _cap_facts(facts: list[str], max_chars: int) -> list[str]:
    """Return as many facts as fit within *max_chars* total."""
    total = 0
    result: list[str] = []
    for fact in facts:
        total += len(fact)
        if total > max_chars:
            break
        result.append(fact)
    return result
