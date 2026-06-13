"""Property-based invariant tests for the authorization surface (issue #99).

These tests use Hypothesis to generate varied principals, capabilities,
requests, scopes, constraints, handles, and tokens, then assert that the
core security/audit invariants always hold — the failure modes that
example-based unit tests miss (token-scope confusion, handle expansion
outside the original grant, policy traces leaking raw argument values, etc.).

Invariants under test (see ``docs/agent-context/invariants.md`` and AGENTS.md):

* **I-02 — every decision is stable and auditable**
    - :func:`test_decision_always_carries_a_stable_reason_code` — an allow
      returns ``allowed=True`` with a stable :class:`AllowReason`; a deny
      *raises* :class:`PolicyDenied` with a stable :class:`DenialReason`
      (so a denied capability never silently yields a grant/token/frame).
* **Constraint integrity**
    - :func:`test_max_rows_never_exceeds_policy_cap`
    - :func:`test_handle_expand_never_exceeds_grant` — the indirect /
      handle-expansion scenario: an expand query never returns more rows or
      wider fields than the original grant authorised.
* **I-06 — tokens bind principal + capability + expiry**
    - :func:`test_token_never_verifies_outside_its_scope`
    - :func:`test_tampered_token_is_always_rejected`
* **Redaction safety (feeds the #94 export contract)**
    - :func:`test_policy_trace_never_leaks_raw_scope_values`
    - :func:`test_trace_export_is_always_json_serialisable`

Reproducing failures: on failure Hypothesis prints a minimal falsifying
example plus a ``@reproduce_failure(...)`` decorator, and persists the case in
its example database so the next run replays it first. The rate limiter is
disabled in :func:`_engine` so repeated generated examples do not spuriously
deny on the sliding window.
"""

from __future__ import annotations

import datetime
import json
import string
from dataclasses import asdict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from weaver_kernel import (
    ActionTrace,
    AllowReason,
    Capability,
    CapabilityRequest,
    DefaultPolicyEngine,
    DenialReason,
    HandleConstraintViolation,
    HandleStore,
    HMACTokenProvider,
    PolicyDenied,
    Principal,
    SafetyClass,
    SensitivityTag,
    TokenExpired,
    TokenInvalid,
    TokenScopeError,
    export_action_traces,
)
from weaver_kernel.policy import _MAX_ROWS_SERVICE, _MAX_ROWS_USER

# ── Shared strategies & helpers ─────────────────────────────────────────────

_ROLE_POOL = [
    "reader",
    "writer",
    "admin",
    "service",
    "pii_reader",
    "secrets_reader",
    "memory_writer",
    "memory_reader_sensitive",
]
_ID_ALPHABET = string.ascii_letters + string.digits + "-_"
_DENIAL_CODES = {code.value for code in DenialReason}
_ALLOW_CODES = {code.value for code in AllowReason}

# Effectively unlimited rate limits: Hypothesis runs many examples against a
# fresh engine, and the sliding-window limiter would otherwise deny later
# examples for reasons unrelated to the property under test.
_NO_RATE_LIMIT = {sc: (1_000_000, 3600.0) for sc in SafetyClass}

_ids = st.text(alphabet=_ID_ALPHABET, min_size=1, max_size=16)
_roles = st.lists(st.sampled_from(_ROLE_POOL), unique=True, max_size=5)
_attributes = st.dictionaries(
    st.sampled_from(["tenant", "region", "team"]),
    st.text(alphabet=string.ascii_letters, min_size=1, max_size=8),
    max_size=3,
)
_justifications = st.text(max_size=40)
_ROW_FIELDS = ["id", "email", "amount", "status"]


def _engine() -> DefaultPolicyEngine:
    """A fresh engine with rate limiting disabled (see module docstring)."""
    return DefaultPolicyEngine(rate_limits=_NO_RATE_LIMIT)


def _read_capability() -> Capability:
    """A READ capability with no sensitivity — always reaches the allow path."""
    return Capability(
        capability_id="cap.read",
        name="read",
        description="generated read capability",
        safety_class=SafetyClass.READ,
        sensitivity=SensitivityTag.NONE,
    )


@st.composite
def _principals(draw: st.DrawFn) -> Principal:
    return Principal(
        principal_id=draw(_ids),
        roles=draw(_roles),
        attributes=draw(_attributes),
    )


@st.composite
def _capabilities(draw: st.DrawFn) -> Capability:
    cap_id = draw(_ids)
    return Capability(
        capability_id=cap_id,
        name=cap_id,
        description="generated capability",
        safety_class=draw(st.sampled_from(list(SafetyClass))),
        sensitivity=draw(st.sampled_from(list(SensitivityTag))),
    )


@st.composite
def _rows(draw: st.DrawFn) -> list[dict[str, object]]:
    count = draw(st.integers(min_value=0, max_value=12))
    return [
        {
            "id": f"R-{i}",
            "email": draw(st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=6)),
            "amount": draw(st.integers(min_value=0, max_value=1000)),
            "status": draw(st.sampled_from(["paid", "unpaid", "overdue"])),
        }
        for i in range(count)
    ]


@st.composite
def _action_traces(draw: st.DrawFn) -> ActionTrace:
    has_error = draw(st.booleans())
    return ActionTrace(
        action_id=draw(_ids),
        capability_id=draw(_ids),
        principal_id=draw(_ids),
        token_id=draw(_ids),
        invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
        args=draw(st.dictionaries(st.text(min_size=1, max_size=8), st.integers(), max_size=4)),
        response_mode=draw(st.sampled_from(["summary", "table", "handle_only", "raw"])),
        driver_id=draw(_ids),
        sensitivity=draw(st.sampled_from(list(SensitivityTag))),
        error=draw(st.text(max_size=20)) if has_error else None,
        result_summary=(
            None if has_error else {"row_count": draw(st.integers(min_value=0, max_value=100))}
        ),
    )


# ── I-02: every decision is stable and auditable ────────────────────────────


@settings(deadline=None, max_examples=200)
@given(principal=_principals(), capability=_capabilities(), justification=_justifications)
def test_decision_always_carries_a_stable_reason_code(
    principal: Principal, capability: Capability, justification: str
) -> None:
    engine = _engine()
    request = CapabilityRequest(capability_id=capability.capability_id, goal="generated goal")
    try:
        decision = engine.evaluate(request, capability, principal, justification=justification)
    except PolicyDenied as exc:
        # A denial raises before any token is issued, so a denied capability
        # can never produce a usable grant or frame. The code must be stable.
        assert str(exc.reason_code) in _DENIAL_CODES
        return
    assert decision.allowed is True
    assert decision.reason_code is not None
    assert str(decision.reason_code) in _ALLOW_CODES


# ── Constraint integrity ────────────────────────────────────────────────────


@settings(deadline=None, max_examples=200)
@given(
    principal=_principals(),
    requested_max_rows=st.one_of(st.none(), st.integers(min_value=-10, max_value=10_000)),
)
def test_max_rows_never_exceeds_policy_cap(
    principal: Principal, requested_max_rows: int | None
) -> None:
    engine = _engine()
    capability = _read_capability()
    constraints = {} if requested_max_rows is None else {"max_rows": requested_max_rows}
    request = CapabilityRequest(
        capability_id=capability.capability_id, goal="g", constraints=constraints
    )
    decision = engine.evaluate(request, capability, principal, justification="")
    cap_limit = _MAX_ROWS_SERVICE if "service" in principal.roles else _MAX_ROWS_USER
    capped = decision.constraints["max_rows"]
    assert 0 <= capped <= cap_limit
    if requested_max_rows is not None and requested_max_rows >= 0:
        assert capped <= requested_max_rows


@settings(deadline=None, max_examples=200)
@given(
    rows=_rows(),
    granted_max_rows=st.one_of(st.none(), st.integers(min_value=0, max_value=20)),
    granted_fields=st.lists(st.sampled_from(_ROW_FIELDS), unique=True, max_size=4),
    query_limit=st.one_of(st.none(), st.integers(min_value=-5, max_value=30)),
    query_offset=st.integers(min_value=0, max_value=10),
    query_fields=st.lists(st.sampled_from(_ROW_FIELDS), unique=True, max_size=4),
)
def test_handle_expand_never_exceeds_grant(
    rows: list[dict[str, object]],
    granted_max_rows: int | None,
    granted_fields: list[str],
    query_limit: int | None,
    query_offset: int,
    query_fields: list[str],
) -> None:
    store = HandleStore()
    constraints: dict[str, object] = {}
    if granted_max_rows is not None:
        constraints["max_rows"] = granted_max_rows
    if granted_fields:
        constraints["allowed_fields"] = granted_fields
    handle = store.store("cap.read", rows, principal_id="p1", constraints=constraints)

    query: dict[str, object] = {"offset": query_offset}
    if query_limit is not None:
        query["limit"] = query_limit
    if query_fields:
        query["fields"] = query_fields

    try:
        frame = store.expand(handle, query=query, principal_id="p1")
    except HandleConstraintViolation:
        return  # rejecting the over-broad request is the safe outcome

    preview = frame.table_preview
    if granted_max_rows is not None:
        assert len(preview) <= granted_max_rows
    if granted_fields:
        for row in preview:
            assert set(row).issubset(set(granted_fields))


# ── I-06: tokens bind principal + capability + expiry ───────────────────────


@settings(deadline=None, max_examples=200)
@given(
    capability_id=_ids,
    principal_id=_ids,
    other_principal_id=_ids,
    other_capability_id=_ids,
    ttl=st.one_of(
        st.integers(min_value=-86_400, max_value=-1),
        st.integers(min_value=120, max_value=86_400),
    ),
)
def test_token_never_verifies_outside_its_scope(
    capability_id: str,
    principal_id: str,
    other_principal_id: str,
    other_capability_id: str,
    ttl: int,
) -> None:
    provider = HMACTokenProvider(secret="prop-test-secret")
    token = provider.issue(capability_id, principal_id, ttl_seconds=ttl)

    if ttl <= 0:
        with pytest.raises(TokenExpired):
            provider.verify(
                token,
                expected_principal_id=principal_id,
                expected_capability_id=capability_id,
            )
        return

    # In-scope verification of a live token succeeds.
    provider.verify(
        token, expected_principal_id=principal_id, expected_capability_id=capability_id
    )
    if other_principal_id != principal_id:
        with pytest.raises(TokenScopeError):
            provider.verify(
                token,
                expected_principal_id=other_principal_id,
                expected_capability_id=capability_id,
            )
    if other_capability_id != capability_id:
        with pytest.raises(TokenScopeError):
            provider.verify(
                token,
                expected_principal_id=principal_id,
                expected_capability_id=other_capability_id,
            )


@settings(deadline=None, max_examples=100)
@given(
    capability_id=_ids,
    principal_id=_ids,
    flip_index=st.integers(min_value=0, max_value=63),
)
def test_tampered_token_is_always_rejected(
    capability_id: str, principal_id: str, flip_index: int
) -> None:
    provider = HMACTokenProvider(secret="prop-test-secret")
    token = provider.issue(capability_id, principal_id, ttl_seconds=3600)
    sig = token.signature
    idx = flip_index % len(sig)
    replacement = "0" if sig[idx] != "0" else "1"
    token.signature = sig[:idx] + replacement + sig[idx + 1 :]
    with pytest.raises(TokenInvalid):
        provider.verify(
            token, expected_principal_id=principal_id, expected_capability_id=capability_id
        )


# ── Redaction safety (feeds the #94 export contract) ────────────────────────


@settings(deadline=None, max_examples=200)
@given(
    principal=_principals(),
    scope_value=st.text(alphabet=string.ascii_letters + string.digits, min_size=4, max_size=16),
)
def test_policy_trace_never_leaks_raw_scope_values(principal: Principal, scope_value: str) -> None:
    engine = _engine()
    capability = _read_capability()
    sentinel = f"SCOPEVAL{scope_value}SCOPEVAL"
    request = CapabilityRequest(
        capability_id=capability.capability_id,
        goal="g",
        scope={"customer_id": sentinel},
    )
    decision = engine.evaluate(request, capability, principal, justification="")
    trace = decision.trace
    assert trace is not None
    # The scope *key* is recorded for audit, but its raw *value* must not be.
    assert "customer_id" in trace.scope_keys
    serialised = json.dumps(asdict(trace))
    assert sentinel not in serialised


@settings(deadline=None, max_examples=200)
@given(traces=st.lists(_action_traces(), max_size=6))
def test_trace_export_is_always_json_serialisable(traces: list[ActionTrace]) -> None:
    envelope = export_action_traces(traces)
    assert envelope["version"] == "1"
    assert len(envelope["traces"]) == len(traces)
    blob = json.dumps(envelope)  # must not raise
    assert isinstance(blob, str)
    for exported, trace in zip(envelope["traces"], traces, strict=True):
        assert exported["status"] == ("failed" if trace.error is not None else "succeeded")
        assert exported["sensitivity"] == trace.sensitivity.value
