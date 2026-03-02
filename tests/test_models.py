"""Tests for core dataclasses and models."""

from __future__ import annotations

import datetime

from agent_kernel.enums import SafetyClass, SensitivityTag
from agent_kernel.models import (
    ActionTrace,
    Budgets,
    Capability,
    CapabilityRequest,
    Frame,
    Handle,
    ImplementationRef,
    PolicyDecision,
    Principal,
    RawResult,
    RoutePlan,
)
from agent_kernel.tokens import CapabilityToken


def test_capability_construction() -> None:
    cap = Capability(
        capability_id="test.cap",
        name="Test Cap",
        description="A test capability",
        safety_class=SafetyClass.READ,
    )
    assert cap.capability_id == "test.cap"
    assert cap.safety_class == SafetyClass.READ
    assert cap.sensitivity == SensitivityTag.NONE
    assert cap.allowed_fields == []
    assert cap.tags == []
    assert cap.impl is None


def test_capability_with_all_fields() -> None:
    impl = ImplementationRef(driver_id="memory", operation="op1")
    cap = Capability(
        capability_id="test.full",
        name="Full Cap",
        description="Full capability",
        safety_class=SafetyClass.WRITE,
        sensitivity=SensitivityTag.PII,
        allowed_fields=["id", "name"],
        tags=["tag1", "tag2"],
        impl=impl,
    )
    assert cap.impl is not None
    assert cap.impl.driver_id == "memory"
    assert cap.impl.operation == "op1"
    assert cap.tags == ["tag1", "tag2"]


def test_principal_defaults() -> None:
    p = Principal(principal_id="user-001")
    assert p.roles == []
    assert p.attributes == {}


def test_capability_request() -> None:
    req = CapabilityRequest(
        capability_id="test.cap",
        goal="I need to list things",
        constraints={"max_rows": 10},
    )
    assert req.capability_id == "test.cap"
    assert req.constraints["max_rows"] == 10


def test_policy_decision() -> None:
    dec = PolicyDecision(allowed=True, reason="OK", constraints={"max_rows": 50})
    assert dec.allowed is True
    assert dec.constraints["max_rows"] == 50


def test_raw_result() -> None:
    rr = RawResult(capability_id="cap.x", data=[1, 2, 3])
    assert rr.data == [1, 2, 3]
    assert rr.metadata == {}


def test_frame_defaults() -> None:
    frame = Frame(action_id="a1", capability_id="cap.x", response_mode="summary")
    assert frame.facts == []
    assert frame.table_preview == []
    assert frame.handle is None
    assert frame.warnings == []


def test_handle_construction() -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    h = Handle(
        handle_id="h1",
        capability_id="cap.x",
        created_at=now,
        expires_at=now + datetime.timedelta(hours=1),
        total_rows=100,
    )
    assert h.handle_id == "h1"
    assert h.total_rows == 100


def test_budgets_defaults() -> None:
    b = Budgets()
    assert b.max_rows == 50
    assert b.max_fields == 20
    assert b.max_chars == 4000
    assert b.max_depth == 3


def test_action_trace() -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    trace = ActionTrace(
        action_id="act-1",
        capability_id="cap.x",
        principal_id="user-1",
        token_id="tok-1",
        invoked_at=now,
        args={"a": 1},
        response_mode="summary",
        driver_id="memory",
    )
    assert trace.action_id == "act-1"
    assert trace.error is None
    assert trace.handle_id is None


def test_route_plan() -> None:
    plan = RoutePlan(capability_id="cap.x", driver_ids=["memory", "http"])
    assert plan.driver_ids == ["memory", "http"]


def test_capability_token_from_to_dict() -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    token = CapabilityToken(
        token_id="tok-1",
        capability_id="cap.x",
        principal_id="user-1",
        issued_at=now,
        expires_at=now + datetime.timedelta(hours=1),
        constraints={"max_rows": 10},
        audit_id="audit-1",
        signature="sig",
    )
    d = token.to_dict()
    assert d["token_id"] == "tok-1"
    assert d["signature"] == "sig"

    restored = CapabilityToken.from_dict(d)
    assert restored.token_id == "tok-1"
    assert restored.constraints == {"max_rows": 10}
