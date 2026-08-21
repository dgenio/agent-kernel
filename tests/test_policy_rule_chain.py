"""Agreement and read-only invariants for DefaultPolicyEngine's shared rule chain."""

from __future__ import annotations

from copy import deepcopy

import pytest

from weaver_kernel import (
    Capability,
    DefaultPolicyEngine,
    PolicyDenied,
    Principal,
    SafetyClass,
    SensitivityTag,
)
from weaver_kernel.models import CapabilityRequest
from weaver_kernel.policy_reasons import DenialReason


def _cap(
    safety: SafetyClass,
    *,
    sensitivity: SensitivityTag = SensitivityTag.NONE,
    allowed_fields: list[str] | None = None,
) -> Capability:
    return Capability(
        capability_id="cap.test",
        name="test",
        description="test capability",
        safety_class=safety,
        sensitivity=sensitivity,
        allowed_fields=allowed_fields or [],
    )


def _request(
    *, max_rows: object | None = None, memory_scope: str | None = None
) -> CapabilityRequest:
    constraints = {} if max_rows is None else {"max_rows": max_rows}
    scope = {} if memory_scope is None else {"memory_scope": memory_scope}
    return CapabilityRequest(
        capability_id="cap.test",
        goal="test",
        constraints=constraints,
        scope=scope,
    )


_CASES = [
    pytest.param(
        _request(),
        _cap(SafetyClass.READ),
        Principal(principal_id="reader"),
        "",
        False,
        None,
        id="read-allowed",
    ),
    pytest.param(
        _request(),
        _cap(SafetyClass.WRITE),
        Principal(principal_id="no-writer", roles=["reader"]),
        "long enough justification",
        True,
        str(DenialReason.MISSING_ROLE),
        id="write-role",
    ),
    pytest.param(
        _request(),
        _cap(SafetyClass.WRITE),
        Principal(principal_id="writer", roles=["writer"]),
        "short",
        True,
        str(DenialReason.INSUFFICIENT_JUSTIFICATION),
        id="write-justification",
    ),
    pytest.param(
        _request(),
        _cap(SafetyClass.DESTRUCTIVE),
        Principal(principal_id="not-admin", roles=["writer"]),
        "long enough justification",
        True,
        str(DenialReason.MISSING_ROLE),
        id="destructive-role",
    ),
    pytest.param(
        _request(),
        _cap(SafetyClass.READ, sensitivity=SensitivityTag.PII),
        Principal(principal_id="pii"),
        "",
        True,
        str(DenialReason.MISSING_TENANT_ATTRIBUTE),
        id="pii-tenant",
    ),
    pytest.param(
        _request(),
        _cap(SafetyClass.READ, sensitivity=SensitivityTag.SECRETS),
        Principal(principal_id="secret-reader", roles=["reader"]),
        "long enough justification",
        True,
        str(DenialReason.MISSING_ROLE),
        id="secrets-role",
    ),
    pytest.param(
        _request(),
        _cap(SafetyClass.WRITE, sensitivity=SensitivityTag.MEMORY),
        Principal(principal_id="memory-writer", roles=["writer"]),
        "long enough justification",
        True,
        str(DenialReason.MEMORY_WRITE_REQUIRES_WRITER),
        id="memory-write-role",
    ),
    pytest.param(
        _request(memory_scope="sensitive"),
        _cap(SafetyClass.READ, sensitivity=SensitivityTag.MEMORY),
        Principal(principal_id="memory-reader", roles=["reader"]),
        "",
        True,
        str(DenialReason.MEMORY_SENSITIVE_READ_DENIED),
        id="memory-sensitive-read-role",
    ),
    pytest.param(
        _request(max_rows="not-an-int"),
        _cap(SafetyClass.READ),
        Principal(principal_id="invalid-constraint"),
        "",
        True,
        str(DenialReason.INVALID_CONSTRAINT),
        id="invalid-max-rows",
    ),
    pytest.param(
        _request(max_rows=9999),
        _cap(SafetyClass.READ, sensitivity=SensitivityTag.PII, allowed_fields=["id"]),
        Principal(principal_id="service", roles=["service"], attributes={"tenant": "acme"}),
        "",
        False,
        None,
        id="allowed-with-constraints",
    ),
]


@pytest.mark.parametrize(
    (
        "cap_request",
        "capability",
        "principal",
        "justification",
        "denied",
        "reason_code",
    ),
    _CASES,
)
def test_explain_prediction_matches_evaluate(
    cap_request: CapabilityRequest,
    capability: Capability,
    principal: Principal,
    justification: str,
    denied: bool,
    reason_code: str | None,
) -> None:
    engine = DefaultPolicyEngine()

    explanation = engine.explain(
        cap_request,
        capability,
        principal,
        justification=justification,
    )

    try:
        decision = engine.evaluate(
            cap_request,
            capability,
            principal,
            justification=justification,
        )
    except PolicyDenied as exc:
        evaluated_denied = True
        evaluated_reason = exc.reason_code
    else:
        evaluated_denied = not decision.allowed
        evaluated_reason = decision.reason_code if evaluated_denied else None

    assert explanation.denied is denied
    assert evaluated_denied is denied
    assert explanation.denied == evaluated_denied
    assert explanation.reason_code == reason_code
    assert evaluated_reason == reason_code


def _limiter_state(engine: DefaultPolicyEngine) -> dict[str, list[float]]:
    return {
        key: list(entry.timestamps)
        for key, entry in engine._limiter._windows.items()  # noqa: SLF001 - invariant test
    }


def test_explain_rate_limit_path_is_strictly_read_only() -> None:
    now = [100.0]
    engine = DefaultPolicyEngine(
        rate_limits={SafetyClass.READ: (1, 60.0)},
        clock=lambda: now[0],
    )
    request = _request()
    capability = _cap(SafetyClass.READ)
    principal = Principal(principal_id="rate-user")

    first = engine.evaluate(request, capability, principal, justification="")
    assert first.allowed is True
    before = deepcopy(_limiter_state(engine))

    explanation = engine.explain(request, capability, principal, justification="")

    assert explanation.denied is True
    assert explanation.reason_code == str(DenialReason.RATE_LIMITED)
    assert _limiter_state(engine) == before
    with pytest.raises(PolicyDenied) as excinfo:
        engine.evaluate(request, capability, principal, justification="")
    assert excinfo.value.reason_code == str(DenialReason.RATE_LIMITED)


def test_explain_does_not_prune_expired_rate_entries() -> None:
    now = [100.0]
    engine = DefaultPolicyEngine(
        rate_limits={SafetyClass.READ: (1, 60.0)},
        clock=lambda: now[0],
    )
    request = _request()
    capability = _cap(SafetyClass.READ)
    principal = Principal(principal_id="rate-user")
    engine.evaluate(request, capability, principal, justification="")
    now[0] = 161.0
    before = deepcopy(_limiter_state(engine))

    explanation = engine.explain(request, capability, principal, justification="")

    assert explanation.denied is False
    assert _limiter_state(engine) == before
    assert engine.evaluate(request, capability, principal, justification="").allowed is True


def test_explain_collects_all_failures_while_evaluate_short_circuits() -> None:
    engine = DefaultPolicyEngine()
    request = _request(max_rows="bad")
    capability = _cap(SafetyClass.WRITE, sensitivity=SensitivityTag.PII)
    principal = Principal(principal_id="many-failures", roles=["reader"])

    explanation = engine.explain(request, capability, principal, justification="short")

    assert explanation.denied is True
    assert [failure.condition for failure in explanation.failed_conditions] == [
        "roles",
        "min_justification",
        "tenant_attribute",
        "max_rows",
    ]
    with pytest.raises(PolicyDenied) as excinfo:
        engine.evaluate(request, capability, principal, justification="short")
    assert excinfo.value.reason_code == str(DenialReason.MISSING_ROLE)
