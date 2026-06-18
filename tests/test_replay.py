"""Tests for the trace-replay regression harness (issue #213)."""

from __future__ import annotations

from typing import Any

from weaver_kernel import (
    Capability,
    DecisionRecord,
    DefaultPolicyEngine,
    Principal,
    SafetyClass,
    record_decision,
    replay,
)
from weaver_kernel.errors import PolicyDenied
from weaver_kernel.models import CapabilityRequest
from weaver_kernel.policy_reasons import DenialReason


class _StubEngine:
    """Minimal policy engine: always allow, or always deny with a fixed code."""

    def __init__(self, *, allow: bool, reason_code: str | None = None) -> None:
        self._allow = allow
        self._reason_code = reason_code

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> Any:
        if self._allow:
            return None
        raise PolicyDenied("denied", reason_code=self._reason_code)


_READ_CAP = Capability(
    capability_id="cap.read",
    name="read",
    description="read something",
    safety_class=SafetyClass.READ,
)
_REQ = CapabilityRequest(capability_id="cap.read", goal="read")
_PRINCIPAL = Principal(principal_id="p1", roles=["reader"], attributes={"tenant": "acme"})


def _records(engine: Any, count: int = 3) -> list[DecisionRecord]:
    return [
        record_decision(engine, _REQ, _READ_CAP, _PRINCIPAL, justification="audit")
        for _ in range(count)
    ]


def test_same_engine_yields_empty_diff() -> None:
    engine = DefaultPolicyEngine()
    records = [
        record_decision(engine, _REQ, _READ_CAP, _PRINCIPAL, justification="audit"),
    ]
    diff = replay(records, engine)
    assert diff.empty
    assert diff.flips == []
    assert diff.evaluated == 1


def test_allow_to_deny_flips() -> None:
    records = _records(_StubEngine(allow=True))
    diff = replay(records, _StubEngine(allow=False, reason_code="missing_role"))
    assert diff.evaluated == 3
    assert len(diff.flips) == 3
    assert all(flip.kind == "allow_to_deny" for flip in diff.flips)
    assert diff.flips[0].candidate_reason_code == "missing_role"
    assert not diff.empty


def test_deny_to_allow_flips() -> None:
    records = _records(_StubEngine(allow=False, reason_code="missing_role"))
    diff = replay(records, _StubEngine(allow=True))
    assert len(diff.flips) == 3
    assert all(flip.kind == "deny_to_allow" for flip in diff.flips)


def test_reason_code_change_flip() -> None:
    records = _records(_StubEngine(allow=False, reason_code="missing_role"))
    diff = replay(records, _StubEngine(allow=False, reason_code="insufficient_justification"))
    assert len(diff.flips) == 3
    assert all(flip.kind == "reason_code_change" for flip in diff.flips)


def test_same_reason_code_is_not_a_flip() -> None:
    records = _records(_StubEngine(allow=False, reason_code="missing_role"))
    diff = replay(records, _StubEngine(allow=False, reason_code="missing_role"))
    assert diff.empty
    assert diff.flips == []


def test_rate_limited_flips_are_separated() -> None:
    records = _records(_StubEngine(allow=True))
    diff = replay(records, _StubEngine(allow=False, reason_code=DenialReason.RATE_LIMITED.value))
    # Rate-limit flips are replay-order-sensitive, so they are surfaced apart
    # from structural flips and do not make the structural diff non-empty.
    assert diff.flips == []
    assert diff.empty
    assert len(diff.rate_limited) == 3


def test_ordering_is_deterministic() -> None:
    records = _records(_StubEngine(allow=True), count=5)
    diff = replay(records, _StubEngine(allow=False, reason_code="missing_role"))
    assert [id(flip.record) for flip in diff.flips] == [id(r) for r in records]
