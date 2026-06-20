"""weaver-spec conformance mapping tests (issue #225).

Builds real kernel objects, maps them through ``weaver_kernel.conformance``,
and asserts the results validate against the published ``weaver-contracts``
dataclasses (their ``__post_init__`` enforces the contract invariants — these
are real assertions, not an echo). Skipped when the optional ``conformance``
extra is not installed, so the gate is non-blocking until the extra is present.
"""

from __future__ import annotations

import datetime

import pytest

from weaver_kernel import CapabilityToken, Frame, SensitivityTag
from weaver_kernel.models import ActionTrace

wc = pytest.importorskip("weaver_contracts", reason="install the 'conformance' extra")

from weaver_kernel import conformance  # noqa: E402  (after importorskip by design)

_T = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)


def _frame() -> Frame:
    return Frame(
        action_id="act-1",
        capability_id="billing.list_invoices",
        response_mode="summary",
        facts=["2 invoices found", "total 100 USD"],
    )


def _trace(*, event_type: str = "invoke", error: str | None = None) -> ActionTrace:
    return ActionTrace(
        action_id="act-1",
        capability_id="billing.list_invoices",
        principal_id="alice",
        token_id="tok-1",
        invoked_at=_T,
        args={"operation": "billing.list_invoices"},
        response_mode="summary",
        driver_id="billing",
        sensitivity=SensitivityTag.PII,
        event_type=event_type,  # type: ignore[arg-type]
        error=error,
    )


def _token() -> CapabilityToken:
    return CapabilityToken(
        token_id="tok-1",
        capability_id="billing.list_invoices",
        principal_id="alice",
        issued_at=_T,
        expires_at=_T + datetime.timedelta(hours=1),
    )


def test_contract_version_is_reported() -> None:
    assert conformance.contract_version() == str(wc.CONTRACT_VERSION)


def test_frame_maps_to_valid_contract_frame() -> None:
    contract_frame = conformance.frame_to_contract(_frame(), created_at=_T)
    assert isinstance(contract_frame, wc.Frame)
    assert contract_frame.frame_id == "act-1"
    assert contract_frame.capability_id == "billing.list_invoices"
    assert contract_frame.summary  # contract requires a non-empty summary
    assert contract_frame.created_at == _T


def test_empty_frame_still_yields_non_empty_summary() -> None:
    # The contract rejects an empty summary; the adapter must always supply one.
    bare = Frame(action_id="a", capability_id="cap.x", response_mode="handle_only")
    contract_frame = conformance.frame_to_contract(bare, created_at=_T)
    assert contract_frame.summary


def test_invoke_trace_maps_to_executed_success() -> None:
    event = conformance.trace_to_contract(_trace())
    assert isinstance(event, wc.TraceEvent)
    assert event.event_type == "capability_executed"
    assert event.outcome == "success"
    assert event.principal == "alice"
    assert event.frame_id == "act-1"


def test_deny_trace_maps_to_denied_failure() -> None:
    event = conformance.trace_to_contract(_trace(event_type="deny", error="missing role"))
    assert event.event_type == "capability_denied"
    assert event.outcome == "failure"
    assert event.frame_id is None  # a denied request produced no frame


def test_failed_invoke_maps_to_failure() -> None:
    event = conformance.trace_to_contract(_trace(error="driver exploded"))
    assert event.outcome == "failure"
    assert event.error_message == "driver exploded"


def test_token_maps_to_valid_contract_token() -> None:
    token = conformance.token_to_contract(_token())
    assert isinstance(token, wc.CapabilityToken)
    assert token.principal == "alice"
    assert token.scope == ["billing.list_invoices"]
    assert token.expires_at == _T + datetime.timedelta(hours=1)
