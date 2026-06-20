"""Tests for TraceStore and the ActionTrace export contract (issue #94)."""

from __future__ import annotations

import datetime
import json

import pytest

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
    TraceStore,
    export_action_trace,
    export_action_traces,
)
from weaver_kernel.errors import AgentKernelError
from weaver_kernel.models import ActionTrace, CapabilityRequest


def _trace(action_id: str = "act-1") -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id="cap.x",
        principal_id="u1",
        token_id="tok-1",
        invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
        args={"a": 1},
        response_mode="summary",
        driver_id="memory",
    )


def test_record_and_get() -> None:
    store = TraceStore()
    t = _trace("act-1")
    store.record(t)
    result = store.get("act-1")
    assert result is t


def test_get_unknown_raises() -> None:
    store = TraceStore()
    with pytest.raises(AgentKernelError, match="act-missing"):
        store.get("act-missing")


def test_list_all() -> None:
    store = TraceStore()
    for i in range(3):
        store.record(_trace(f"act-{i}"))
    all_traces = store.list_all()
    assert len(all_traces) == 3
    assert [t.action_id for t in all_traces] == ["act-0", "act-1", "act-2"]


# ── Bounded memory / eviction (issue #182) ──────────────────────────────────


def test_store_evicts_oldest_when_capped() -> None:
    store = TraceStore(max_entries=2)
    for i in range(3):
        store.record(_trace(f"act-{i}"))
    # Oldest (act-0) was evicted; newest two retained in insertion order.
    assert [t.action_id for t in store.list_all()] == ["act-1", "act-2"]
    assert store.evicted_count == 1


def test_rerecording_existing_action_id_does_not_evict() -> None:
    store = TraceStore(max_entries=2)
    store.record(_trace("act-0"))
    store.record(_trace("act-1"))
    store.record(_trace("act-0"))  # overwrite in place — count unchanged
    assert [t.action_id for t in store.list_all()] == ["act-0", "act-1"]
    assert store.evicted_count == 0


def test_eviction_is_counted_across_many_records() -> None:
    store = TraceStore(max_entries=10)
    for i in range(25):
        store.record(_trace(f"act-{i}"))
    assert len(store.list_all()) == 10
    assert store.evicted_count == 15


def test_max_entries_must_be_positive() -> None:
    with pytest.raises(AgentKernelError, match="max_entries must be positive"):
        TraceStore(max_entries=0)


def test_explain_returns_consistent_data() -> None:
    store = TraceStore()
    t = _trace("act-explain")
    store.record(t)
    result = store.get("act-explain")
    assert result.capability_id == "cap.x"
    assert result.principal_id == "u1"
    assert result.driver_id == "memory"
    assert result.args == {"a": 1}


def test_result_summary_defaults_none() -> None:
    # Backward-compatible: traces built without an explicit result_summary
    # (e.g. failure traces, or callers constructing ActionTrace directly) keep
    # it unset rather than fabricating a summary.
    assert _trace("act-default").result_summary is None


def test_sensitivity_defaults_none() -> None:
    assert _trace("act-default").sensitivity is SensitivityTag.NONE


# ── Export contract (issue #94) ─────────────────────────────────────────────


def test_export_action_trace_success_shape() -> None:
    trace = ActionTrace(
        action_id="act-ok",
        capability_id="billing.list_invoices",
        principal_id="u1",
        token_id="tok-1",
        invoked_at=datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
        args={"operation": "billing.list_invoices"},
        response_mode="summary",
        driver_id="billing",
        sensitivity=SensitivityTag.PII,
        handle_id="h-1",
        result_summary={"row_count": 3, "fact_count": 1, "warning_count": 0, "has_handle": True},
    )
    exported = export_action_trace(trace)
    assert exported["action_id"] == "act-ok"
    assert exported["capability_id"] == "billing.list_invoices"
    assert exported["invoked_at"] == "2026-01-02T03:04:05+00:00"
    assert exported["sensitivity"] == "PII"
    assert exported["status"] == "succeeded"
    assert exported["error"] is None
    assert exported["result_summary"]["row_count"] == 3
    assert exported["correction"] is None


def test_export_includes_event_type_and_reason_code() -> None:
    trace = ActionTrace(
        action_id="act-deny",
        capability_id="billing.delete_invoice",
        principal_id="u1",
        token_id="",
        invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
        args={},
        response_mode="summary",
        driver_id="",
        event_type="deny",
        reason_code="missing_role",
        error="denied: missing role",
    )
    exported = export_action_trace(trace)
    assert exported["event_type"] == "deny"
    assert exported["reason_code"] == "missing_role"
    # Default invoke trace carries the defaults.
    plain = export_action_trace(_trace("act-plain"))
    assert plain["event_type"] == "invoke"
    assert plain["reason_code"] is None


def test_export_action_trace_failure_status() -> None:
    trace = ActionTrace(
        action_id="act-fail",
        capability_id="cap.x",
        principal_id="u1",
        token_id="tok-1",
        invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
        args={},
        response_mode="summary",
        driver_id="",
        error="All drivers failed",
    )
    exported = export_action_trace(trace)
    assert exported["status"] == "failed"
    assert exported["error"] == "All drivers failed"
    assert exported["result_summary"] is None


def test_export_action_trace_attaches_correction() -> None:
    correction = {"corrected_by": "reviewer", "note": "wrong customer"}
    exported = export_action_trace(_trace("act-corr"), correction=correction)
    assert exported["correction"] == correction


def test_export_envelope_version_and_corrections() -> None:
    traces = [_trace("act-0"), _trace("act-1")]
    envelope = export_action_traces(traces, corrections={"act-1": {"note": "flagged"}})
    assert envelope["schema"] == "weaver_kernel.action_trace_export"
    assert envelope["version"] == "1"
    assert [t["action_id"] for t in envelope["traces"]] == ["act-0", "act-1"]
    assert envelope["traces"][0]["correction"] is None
    assert envelope["traces"][1]["correction"] == {"note": "flagged"}
    # A correction for an unknown action_id is simply ignored.
    json.dumps(envelope)  # must be JSON-serialisable


@pytest.mark.asyncio
async def test_export_redacts_memory_payload_end_to_end() -> None:
    """A memory payload redacted at record time stays redacted in the export."""
    cap = Capability(
        capability_id="memory.read_notes",
        name="read notes",
        description="read durable notes",
        safety_class=SafetyClass.READ,
        sensitivity=SensitivityTag.MEMORY,
    )
    registry = CapabilityRegistry()
    registry.register(cap)
    driver = InMemoryDriver(driver_id="mem")
    driver.register_handler("memory.read_notes", lambda ctx: [{"note": "n1"}])
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=StaticRouter(routes={"memory.read_notes": ["mem"]}),
    )
    kernel.register_driver(driver)

    principal = Principal(principal_id="u1", roles=["reader"])
    req = CapabilityRequest(capability_id="memory.read_notes", goal="read notes")
    token = kernel.get_token(req, principal, justification="")
    secret = "topsecret-PAYLOAD-123"
    frame = await kernel.invoke(
        token,
        principal=principal,
        args={"operation": "memory.read_notes", "payload": secret},
    )

    trace = kernel.explain(frame.action_id)
    assert trace.sensitivity is SensitivityTag.MEMORY
    assert trace.args["payload"] == "[REDACTED]"

    envelope = export_action_traces(kernel.list_traces())
    exported = envelope["traces"][0]
    assert exported["sensitivity"] == "MEMORY"
    assert exported["status"] == "succeeded"
    assert secret not in json.dumps(envelope)
