"""Context firewall: transforms raw driver output into bounded Frames."""

from __future__ import annotations

import datetime
import json
import logging
from typing import Any

from ..models import (
    Frame,
    Handle,
    Provenance,
    RawResult,
    ResponseMode,
)
from .budgets import Budgets
from .redaction import redact
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
                raw_size = len(json.dumps(data, default=str))
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

    # ── Helpers ───────────────────────────────────────────────────────────────

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


def _truncate_str(s: str, max_chars: int) -> str:
    if len(s) <= max_chars:
        return s
    return s[:max_chars]


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
