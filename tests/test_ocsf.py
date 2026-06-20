"""Tests for the OCSF / AOS SIEM export mapping (issue #176)."""

from __future__ import annotations

import datetime
import json

from weaver_kernel import OCSF_VERSION, SensitivityTag, trace_to_ocsf, traces_to_ocsf
from weaver_kernel.models import ActionTrace

_T = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)


def _trace(
    *,
    action_id: str = "act-1",
    event_type: str = "invoke",
    error: str | None = None,
    reason_code: str | None = None,
    driver_id: str = "billing",
) -> ActionTrace:
    return ActionTrace(
        action_id=action_id,
        capability_id="billing.list_invoices",
        principal_id="alice",
        token_id="tok-1",
        invoked_at=_T,
        args={"operation": "billing.list_invoices"},
        response_mode="summary",
        driver_id=driver_id,
        sensitivity=SensitivityTag.PII,
        event_type=event_type,  # type: ignore[arg-type]
        error=error,
        reason_code=reason_code,
    )


def _assert_ocsf_valid(event: dict[str, object]) -> None:
    """Structural OCSF API Activity (class 6003) validation."""
    assert event["class_uid"] == 6003
    assert event["class_name"] == "API Activity"
    assert event["category_uid"] == 6
    assert isinstance(event["activity_id"], int)
    assert isinstance(event["activity_name"], str)
    assert event["type_uid"] == 6003 * 100 + event["activity_id"]
    assert event["status_id"] in (1, 2)
    assert event["status"] in ("Success", "Failure")
    assert isinstance(event["severity_id"], int)
    assert isinstance(event["time"], int)
    metadata = event["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["version"] == OCSF_VERSION
    assert metadata["product"]["name"] == "weaver-kernel"
    assert any(ext["name"] == "aos" for ext in metadata["extensions"])
    assert isinstance(event["actor"]["user"]["uid"], str)
    assert isinstance(event["api"]["operation"], str)
    json.dumps(event)  # must be JSON-serialisable


def test_invoke_success_maps_to_valid_ocsf() -> None:
    event = trace_to_ocsf(_trace())
    _assert_ocsf_valid(event)
    assert event["status"] == "Success"
    assert event["activity_id"] == 99  # invoke → Other
    assert event["actor"]["user"]["uid"] == "alice"
    assert event["api"]["operation"] == "billing.list_invoices"


def test_invoke_failure_maps_to_failure_status() -> None:
    event = trace_to_ocsf(_trace(error="All drivers failed", driver_id=""))
    _assert_ocsf_valid(event)
    assert event["status"] == "Failure"
    assert event["status_id"] == 2
    assert event["status_detail"] == "All drivers failed"
    assert event["api"]["service"]["name"] == "weaver-kernel"  # empty driver_id falls back


def test_deny_event_is_medium_severity_failure() -> None:
    event = trace_to_ocsf(
        _trace(
            event_type="deny",
            error="denied: missing role",
            reason_code="missing_role",
            driver_id="",
        )
    )
    _assert_ocsf_valid(event)
    assert event["severity_id"] == 3  # Medium
    assert event["status"] == "Failure"
    assert event["unmapped"]["reason_code"] == "missing_role"
    assert event["unmapped"]["event_type"] == "deny"


def test_expand_event_maps_to_read_activity() -> None:
    event = trace_to_ocsf(_trace(event_type="expand", driver_id=""))
    _assert_ocsf_valid(event)
    assert event["activity_id"] == 2  # Read
    assert event["activity_name"] == "Read"


def test_time_is_epoch_millis() -> None:
    event = trace_to_ocsf(_trace())
    assert event["time"] == int(_T.timestamp() * 1000)


def test_golden_mapping_is_deterministic() -> None:
    event = trace_to_ocsf(_trace())
    assert event == {
        "activity_id": 99,
        "activity_name": "Other",
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": 6003,
        "class_name": "API Activity",
        "type_uid": 600399,
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "status_detail": None,
        "time": int(_T.timestamp() * 1000),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "weaver-kernel", "vendor_name": "Weaver"},
            "extensions": [{"name": "aos", "uid": "aos", "version": "draft"}],
        },
        "actor": {"user": {"uid": "alice"}},
        "api": {
            "operation": "billing.list_invoices",
            "service": {"name": "billing"},
        },
        "unmapped": {
            "action_id": "act-1",
            "token_id": "tok-1",
            "event_type": "invoke",
            "response_mode": "summary",
            "sensitivity": "PII",
            "reason_code": None,
            "handle_id": None,
            "result_summary": None,
        },
    }


def test_traces_to_ocsf_preserves_order() -> None:
    traces = [_trace(action_id="a"), _trace(action_id="b"), _trace(action_id="c")]
    events = traces_to_ocsf(traces)
    assert [e["unmapped"]["action_id"] for e in events] == ["a", "b", "c"]


def test_no_secret_leaks_through_ocsf() -> None:
    # error text is already redaction-safe at record time; the mapping adds no
    # raw payload, so a canary placed only in args never reaches the event.
    canary = "ZZZ-CANARY-OCSF-SECRET"
    trace = _trace()
    trace.args["secret"] = canary
    assert canary not in json.dumps(trace_to_ocsf(trace))
