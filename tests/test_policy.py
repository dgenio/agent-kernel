"""Tests for DefaultPolicyEngine."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from weaver_kernel import (
    AgentKernelError,
    Capability,
    DeclarativePolicyEngine,
    DefaultPolicyEngine,
    PolicyConfigError,
    PolicyDenied,
    Principal,
    SafetyClass,
    SensitivityTag,
)
from weaver_kernel.models import CapabilityRequest
from weaver_kernel.policy import RateLimiter


def _req(cap_id: str, **constraints: object) -> CapabilityRequest:
    return CapabilityRequest(capability_id=cap_id, goal="test", constraints=dict(constraints))


def _cap(
    cap_id: str,
    safety: SafetyClass,
    sensitivity: SensitivityTag = SensitivityTag.NONE,
    allowed_fields: list[str] | None = None,
) -> Capability:
    return Capability(
        capability_id=cap_id,
        name=cap_id,
        description="test",
        safety_class=safety,
        sensitivity=sensitivity,
        allowed_fields=allowed_fields or [],
    )


@pytest.fixture()
def engine() -> DefaultPolicyEngine:
    """Fresh engine per test to avoid shared rate-limit state."""
    return DefaultPolicyEngine()


# ── READ ───────────────────────────────────────────────────────────────────────


def test_read_allowed_no_roles(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert dec.allowed is True


def test_read_sets_max_rows_user(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert dec.constraints["max_rows"] == 50


def test_read_sets_max_rows_service(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="svc1", roles=["service"])
    dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert dec.constraints["max_rows"] == 500


def test_read_respects_tighter_constraint(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=5), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 5


def test_read_tighter_constraint_cannot_exceed_cap(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=9999), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 50


# ── WRITE ──────────────────────────────────────────────────────────────────────


def test_write_denied_no_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    with pytest.raises(PolicyDenied, match="writer.*admin"):
        engine.evaluate(
            _req("cap.w"),
            _cap("cap.w", SafetyClass.WRITE),
            p,
            justification="long enough justification here",
        )


def test_write_denied_short_justification(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(
            _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="too short"
        )


def test_write_denied_whitespace_justification(engine: DefaultPolicyEngine) -> None:
    """Whitespace-only justification must not bypass the length requirement."""
    p = Principal(principal_id="u1", roles=["writer"])
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(
            _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="               "
        )


def test_write_allowed_writer_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    dec = engine.evaluate(
        _req("cap.w"),
        _cap("cap.w", SafetyClass.WRITE),
        p,
        justification="this is a long enough justification string",
    )
    assert dec.allowed is True


def test_write_allowed_admin_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    dec = engine.evaluate(
        _req("cap.w"),
        _cap("cap.w", SafetyClass.WRITE),
        p,
        justification="this is a long enough justification string",
    )
    assert dec.allowed is True


# ── DESTRUCTIVE ────────────────────────────────────────────────────────────────


def test_destructive_denied_short_justification(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    with pytest.raises(PolicyDenied, match="DESTRUCTIVE capabilities require a justification"):
        engine.evaluate(
            _req("cap.d"),
            _cap("cap.d", SafetyClass.DESTRUCTIVE),
            p,
            justification="short",
        )


def test_destructive_denied_whitespace_justification(engine: DefaultPolicyEngine) -> None:
    """Whitespace-only justification must not bypass the length requirement."""
    p = Principal(principal_id="u1", roles=["admin"])
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(
            _req("cap.d"),
            _cap("cap.d", SafetyClass.DESTRUCTIVE),
            p,
            justification="               ",
        )


def test_destructive_denied_no_admin(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    with pytest.raises(PolicyDenied, match="admin"):
        engine.evaluate(
            _req("cap.d"),
            _cap("cap.d", SafetyClass.DESTRUCTIVE),
            p,
            justification="long enough justification",
        )


def test_destructive_allowed_admin(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    dec = engine.evaluate(
        _req("cap.d"),
        _cap("cap.d", SafetyClass.DESTRUCTIVE),
        p,
        justification="long enough justification",
    )
    assert dec.allowed is True


# ── PII / PCI ──────────────────────────────────────────────────────────────────


def test_pii_requires_tenant(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
    with pytest.raises(PolicyDenied, match="tenant"):
        engine.evaluate(_req("cap.pii"), cap, p, justification="")


def test_pii_allowed_with_tenant(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"], attributes={"tenant": "acme"})
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
    dec = engine.evaluate(_req("cap.pii"), cap, p, justification="")
    assert dec.allowed is True


def test_pii_enforces_allowed_fields(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"], attributes={"tenant": "acme"})
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII, allowed_fields=["id", "name"])
    dec = engine.evaluate(_req("cap.pii"), cap, p, justification="")
    assert dec.constraints.get("allowed_fields") == ["id", "name"]


def test_pii_reader_skips_allowed_fields(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader", "pii_reader"], attributes={"tenant": "acme"})
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII, allowed_fields=["id", "name"])
    dec = engine.evaluate(_req("cap.pii"), cap, p, justification="")
    assert "allowed_fields" not in dec.constraints


def test_pci_requires_tenant(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.pci", SafetyClass.READ, SensitivityTag.PCI)
    with pytest.raises(PolicyDenied, match="tenant"):
        engine.evaluate(_req("cap.pci"), cap, p, justification="")


# ── SECRETS ────────────────────────────────────────────────────────────────────


def test_secrets_denied_no_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="secrets_reader"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")


def test_secrets_denied_short_justification(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["secrets_reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="too short")


def test_secrets_denied_whitespace_justification(engine: DefaultPolicyEngine) -> None:
    """Whitespace-only justification must not bypass the length requirement."""
    p = Principal(principal_id="u1", roles=["secrets_reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="               ")


def test_secrets_allowed_secrets_reader_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["secrets_reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    dec = engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")
    assert dec.allowed is True


def test_secrets_allowed_admin_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    dec = engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")
    assert dec.allowed is True


def test_secrets_denied_writer_role(engine: DefaultPolicyEngine) -> None:
    """Writer role is insufficient for SECRETS capabilities."""
    p = Principal(principal_id="u1", roles=["writer"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="secrets_reader"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")


# ── MEMORY (#75) ──────────────────────────────────────────────────────────────


def _memory_request(scope: dict[str, object] | None = None) -> CapabilityRequest:
    return CapabilityRequest(
        capability_id="memory.read",
        goal="test memory",
        scope=scope or {},
    )


def test_memory_read_project_scope_allowed(engine: DefaultPolicyEngine) -> None:
    """Reading project-scoped memory works for any reader."""
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("memory.read", SafetyClass.READ, SensitivityTag.MEMORY)
    dec = engine.evaluate(_memory_request({"memory_scope": "project"}), cap, p, justification="")
    assert dec.allowed is True


def test_memory_read_sensitive_denied_without_role(engine: DefaultPolicyEngine) -> None:
    """Reading sensitive-scoped memory requires memory_reader_sensitive."""
    from weaver_kernel.policy_reasons import DenialReason

    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("memory.read", SafetyClass.READ, SensitivityTag.MEMORY)
    with pytest.raises(PolicyDenied) as exc:
        engine.evaluate(_memory_request({"memory_scope": "sensitive"}), cap, p, justification="")
    assert exc.value.reason_code == DenialReason.MEMORY_SENSITIVE_READ_DENIED


def test_memory_read_sensitive_allowed_with_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader", "memory_reader_sensitive"])
    cap = _cap("memory.read", SafetyClass.READ, SensitivityTag.MEMORY)
    dec = engine.evaluate(_memory_request({"memory_scope": "sensitive"}), cap, p, justification="")
    assert dec.allowed is True


def test_memory_read_sensitive_allowed_with_admin(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    cap = _cap("memory.read", SafetyClass.READ, SensitivityTag.MEMORY)
    dec = engine.evaluate(_memory_request({"memory_scope": "sensitive"}), cap, p, justification="")
    assert dec.allowed is True


def test_memory_write_denied_without_writer_role(engine: DefaultPolicyEngine) -> None:
    """memory.write requires the memory_writer role even when SafetyClass=WRITE
    would otherwise be satisfied by a generic writer."""
    from weaver_kernel.policy_reasons import DenialReason

    p = Principal(principal_id="u1", roles=["writer"])
    cap = _cap("memory.write", SafetyClass.WRITE, SensitivityTag.MEMORY)
    req = CapabilityRequest(capability_id="memory.write", goal="store a note")
    with pytest.raises(PolicyDenied) as exc:
        engine.evaluate(req, cap, p, justification="needs durable notes for session")
    # Writer role passes the safety_class check (no MISSING_ROLE there) and we
    # reach the MEMORY branch.
    assert exc.value.reason_code == DenialReason.MEMORY_WRITE_REQUIRES_WRITER


def test_memory_write_allowed_with_memory_writer_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["writer", "memory_writer"])
    cap = _cap("memory.write", SafetyClass.WRITE, SensitivityTag.MEMORY)
    req = CapabilityRequest(capability_id="memory.write", goal="store a note")
    dec = engine.evaluate(req, cap, p, justification="needs durable notes for session")
    assert dec.allowed is True


def test_memory_write_allowed_with_admin(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    cap = _cap("memory.write", SafetyClass.WRITE, SensitivityTag.MEMORY)
    req = CapabilityRequest(capability_id="memory.write", goal="store a note")
    dec = engine.evaluate(req, cap, p, justification="needs durable notes for session")
    assert dec.allowed is True


def test_memory_destructive_requires_writer(engine: DefaultPolicyEngine) -> None:
    """DESTRUCTIVE memory (e.g. memory.forget) is treated as write-class."""
    from weaver_kernel.policy_reasons import DenialReason

    p = Principal(principal_id="u1", roles=["admin"])
    # admin passes the DESTRUCTIVE safety_class. The MEMORY branch then needs
    # memory_writer OR admin; admin satisfies it.
    cap = _cap("memory.forget", SafetyClass.DESTRUCTIVE, SensitivityTag.MEMORY)
    req = CapabilityRequest(capability_id="memory.forget", goal="purge notes")
    dec = engine.evaluate(req, cap, p, justification="user requested deletion of all notes")
    assert dec.allowed is True

    # A principal with destructive role but no memory_writer fails the memory rule.
    p2 = Principal(principal_id="u2", roles=["writer"])
    cap2 = _cap("memory.forget", SafetyClass.DESTRUCTIVE, SensitivityTag.MEMORY)
    with pytest.raises(PolicyDenied) as exc:
        engine.evaluate(req, cap2, p2, justification="user requested deletion of all notes")
    # writer is not admin, so DESTRUCTIVE fails first on MISSING_ROLE.
    assert exc.value.reason_code == DenialReason.MISSING_ROLE


def test_memory_explain_lists_failed_conditions() -> None:
    """explain() lists the memory denial alongside the FailedCondition reason_code."""
    from weaver_kernel.policy_reasons import DenialReason

    eng = DefaultPolicyEngine()
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("memory.read", SafetyClass.READ, SensitivityTag.MEMORY)
    explanation = eng.explain(
        _memory_request({"memory_scope": "sensitive"}), cap, p, justification=""
    )
    assert explanation.denied is True
    codes = [fc.reason_code for fc in explanation.failed_conditions]
    assert str(DenialReason.MEMORY_SENSITIVE_READ_DENIED) in codes


# ── Confused-deputy binding (via token) ────────────────────────────────────────


def test_max_rows_enforcement(engine: DefaultPolicyEngine) -> None:
    """max_rows in constraints is capped by the policy ceiling."""
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=200), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 50


def test_max_rows_invalid_raises_policy_denied(engine: DefaultPolicyEngine) -> None:
    """Non-numeric max_rows raises PolicyDenied, not bare ValueError."""
    p = Principal(principal_id="u1")
    with pytest.raises(PolicyDenied, match="Invalid 'max_rows'"):
        engine.evaluate(
            _req("cap.r", max_rows="abc"),
            _cap("cap.r", SafetyClass.READ),
            p,
            justification="",
        )


def test_max_rows_negative_clamped_to_zero(engine: DefaultPolicyEngine) -> None:
    """Negative max_rows is clamped to 0."""
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=-10), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 0


# ── Rate limiting ─────────────────────────────────────────────────────────────────


def _make_clock(start: float = 0.0) -> tuple[list[float], Callable[[], float]]:
    """Return a controllable clock: (time_ref, clock_fn).

    Advance time by mutating ``time_ref[0]``.
    """
    time_ref = [start]
    return time_ref, lambda: time_ref[0]


def test_rate_limiter_under_limit() -> None:
    """Requests within the limit are allowed."""
    _, clock = _make_clock()
    limiter = RateLimiter(clock=clock)
    for _ in range(5):
        assert limiter.check("k", 5, 60.0) is True
        limiter.record("k")
    # 6th should be denied
    assert limiter.check("k", 5, 60.0) is False


def test_rate_limiter_window_expires() -> None:
    """Old entries expire and free up capacity."""
    t, clock = _make_clock(0.0)
    limiter = RateLimiter(clock=clock)
    # Fill window
    for _ in range(5):
        limiter.check("k", 5, 60.0)
        limiter.record("k")
    assert limiter.check("k", 5, 60.0) is False
    # Advance past window
    t[0] = 61.0
    assert limiter.check("k", 5, 60.0) is True


def test_read_rate_limit_exceeded() -> None:
    """61st READ invocation in 60s raises PolicyDenied."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(clock=clock)
    p = Principal(principal_id="u1")
    cap = _cap("cap.r", SafetyClass.READ)
    for _ in range(60):
        eng.evaluate(_req("cap.r"), cap, p, justification="")
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.r"), cap, p, justification="")


def test_write_rate_limit_exceeded() -> None:
    """11th WRITE invocation in 60s raises PolicyDenied."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(clock=clock)
    p = Principal(principal_id="u1", roles=["writer"])
    cap = _cap("cap.w", SafetyClass.WRITE)
    just = "this is a long enough justification string"
    for _ in range(10):
        eng.evaluate(_req("cap.w"), cap, p, justification=just)
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.w"), cap, p, justification=just)


def test_destructive_rate_limit_exceeded() -> None:
    """3rd DESTRUCTIVE invocation in 60s raises PolicyDenied."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(clock=clock)
    p = Principal(principal_id="u1", roles=["admin"])
    cap = _cap("cap.d", SafetyClass.DESTRUCTIVE)
    just = "long enough justification"
    for _ in range(2):
        eng.evaluate(_req("cap.d"), cap, p, justification=just)
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.d"), cap, p, justification=just)


def test_rate_limit_per_principal_capability_pair() -> None:
    """Rate limits are scoped to (principal_id, capability_id), not global."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(clock=clock)
    p1 = Principal(principal_id="u1")
    p2 = Principal(principal_id="u2")
    cap = _cap("cap.r", SafetyClass.READ)
    # Exhaust u1's limit
    for _ in range(60):
        eng.evaluate(_req("cap.r"), cap, p1, justification="")
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.r"), cap, p1, justification="")
    # u2 is unaffected
    eng.evaluate(_req("cap.r"), cap, p2, justification="")


def test_service_role_gets_10x_limit() -> None:
    """Principals with 'service' role get 10x the default rate limits."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(clock=clock)
    p = Principal(principal_id="svc1", roles=["service"])
    cap = _cap("cap.r", SafetyClass.READ)
    # Default READ is 60; service gets 600
    for _ in range(600):
        eng.evaluate(_req("cap.r"), cap, p, justification="")
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.r"), cap, p, justification="")


def test_rate_limit_configurable() -> None:
    """Rate limits are configurable via constructor."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(
        rate_limits={SafetyClass.READ: (3, 10.0)},
        clock=clock,
    )
    p = Principal(principal_id="u1")
    cap = _cap("cap.r", SafetyClass.READ)
    for _ in range(3):
        eng.evaluate(_req("cap.r"), cap, p, justification="")
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.r"), cap, p, justification="")


def test_partial_rate_limits_preserves_defaults() -> None:
    """Partial rate_limits override must not disable defaults for other classes."""
    _, clock = _make_clock()
    eng = DefaultPolicyEngine(
        rate_limits={SafetyClass.READ: (3, 10.0)},
        clock=clock,
    )
    p = Principal(principal_id="u1", roles=["admin"])
    cap_d = _cap("cap.d", SafetyClass.DESTRUCTIVE)
    just = "long enough justification"
    # DESTRUCTIVE default is 2 per 60s — must still be enforced
    for _ in range(2):
        eng.evaluate(_req("cap.d"), cap_d, p, justification=just)
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.d"), cap_d, p, justification=just)


def test_rate_limit_rejects_zero_limit() -> None:
    """Rate limit with limit < 1 raises at construction time."""
    with pytest.raises(AgentKernelError, match="limit must be >= 1"):
        DefaultPolicyEngine(rate_limits={SafetyClass.READ: (0, 60.0)})


def test_rate_limit_rejects_non_positive_window() -> None:
    """Rate limit with window <= 0 raises at construction time."""
    with pytest.raises(AgentKernelError, match="window must be > 0"):
        DefaultPolicyEngine(rate_limits={SafetyClass.WRITE: (10, 0.0)})


def test_rate_limit_window_slides() -> None:
    """Old entries expire, allowing new invocations after the window slides."""
    t, clock = _make_clock(0.0)
    eng = DefaultPolicyEngine(
        rate_limits={SafetyClass.READ: (2, 10.0)},
        clock=clock,
    )
    p = Principal(principal_id="u1")
    cap = _cap("cap.r", SafetyClass.READ)
    # Use both
    eng.evaluate(_req("cap.r"), cap, p, justification="")
    t[0] = 5.0
    eng.evaluate(_req("cap.r"), cap, p, justification="")
    # Blocked
    with pytest.raises(PolicyDenied, match="Rate limit exceeded"):
        eng.evaluate(_req("cap.r"), cap, p, justification="")
    # Advance past first entry's window
    t[0] = 11.0
    eng.evaluate(_req("cap.r"), cap, p, justification="")  # should succeed


# ═══════════════════════════════════════════════════════════════════════════════
# DefaultPolicyEngine.explain()
# ═══════════════════════════════════════════════════════════════════════════════


def test_explain_read_allowed(engine: DefaultPolicyEngine) -> None:
    """READ with no special sensitivity returns denied=False."""
    p = Principal(principal_id="u1")
    result = engine.explain(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert result.denied is False
    assert result.failed_conditions == []
    assert result.remediation == []
    assert "allowed" in result.narrative


def test_explain_write_missing_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    result = engine.explain(
        _req("cap.w"),
        _cap("cap.w", SafetyClass.WRITE),
        p,
        justification="long enough justification here",
    )
    assert result.denied is True
    assert len(result.failed_conditions) == 1
    fc = result.failed_conditions[0]
    assert fc.condition == "roles"
    assert "writer" in str(fc.required)
    assert sorted(["reader"]) == fc.actual
    assert result.remediation == [fc.suggestion]
    assert "denied" in result.narrative


def test_explain_write_short_justification(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    result = engine.explain(
        _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="short"
    )
    assert result.denied is True
    assert any(fc.condition == "min_justification" for fc in result.failed_conditions)
    fc = next(f for f in result.failed_conditions if f.condition == "min_justification")
    assert fc.required == 15
    assert fc.actual == len("short")


def test_explain_write_both_failures(engine: DefaultPolicyEngine) -> None:
    """Missing role AND short justification both appear in failed_conditions."""
    p = Principal(principal_id="u1", roles=["reader"])
    result = engine.explain(
        _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="too short"
    )
    assert result.denied is True
    conditions = {fc.condition for fc in result.failed_conditions}
    assert "roles" in conditions
    assert "min_justification" in conditions
    assert len(result.remediation) == 2


def test_explain_destructive_missing_admin(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    result = engine.explain(
        _req("cap.d"),
        _cap("cap.d", SafetyClass.DESTRUCTIVE),
        p,
        justification="long enough justification here",
    )
    assert result.denied is True
    assert result.failed_conditions[0].condition == "roles"
    assert result.failed_conditions[0].required == ["admin"]


def test_explain_pii_missing_tenant(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
    result = engine.explain(_req("cap.pii"), cap, p, justification="")
    assert result.denied is True
    assert result.failed_conditions[0].condition == "tenant_attribute"
    assert "tenant" in result.failed_conditions[0].suggestion


def test_explain_secrets_missing_role(engine: DefaultPolicyEngine) -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    result = engine.explain(_req("cap.sec"), cap, p, justification="long enough justification")
    assert result.denied is True
    fc = result.failed_conditions[0]
    assert fc.condition == "roles"
    assert "secrets_reader" in str(fc.required)


# ═══════════════════════════════════════════════════════════════════════════════
# DeclarativePolicyEngine
# ═══════════════════════════════════════════════════════════════════════════════


def _dce(rules: list[dict], *, default: str = "deny") -> DeclarativePolicyEngine:
    return DeclarativePolicyEngine.from_dict({"rules": rules, "default": default})


# ── from_dict: basic evaluation ───────────────────────────────────────────────


def test_declarative_allow_rule_matches() -> None:
    engine = _dce([{"name": "r1", "match": {"safety_class": ["READ"]}, "action": "allow"}])
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")
    assert dec.allowed is True
    assert "r1" in dec.reason


def test_declarative_deny_rule_raises() -> None:
    engine = _dce(
        [
            {"name": "block-all", "match": {}, "action": "deny", "reason": "blocked for test"},
        ]
    )
    p = Principal(principal_id="u1")
    with pytest.raises(PolicyDenied, match="blocked for test"):
        engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")


def test_declarative_default_deny_no_match() -> None:
    engine = _dce([{"name": "r1", "match": {"safety_class": ["WRITE"]}, "action": "allow"}])
    p = Principal(principal_id="u1")
    with pytest.raises(PolicyDenied, match="Default action is deny"):
        engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")


def test_declarative_default_allow_no_match() -> None:
    engine = _dce(
        [{"name": "r1", "match": {"safety_class": ["WRITE"]}, "action": "allow"}],
        default="allow",
    )
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")
    assert dec.allowed is True


def test_declarative_first_match_wins() -> None:
    engine = _dce(
        [
            {"name": "allow-read", "match": {"safety_class": ["READ"]}, "action": "allow"},
            {
                "name": "deny-read",
                "match": {"safety_class": ["READ"]},
                "action": "deny",
                "reason": "x",
            },
        ]
    )
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")
    assert dec.allowed is True
    assert "allow-read" in dec.reason


def test_declarative_role_condition() -> None:
    engine = _dce(
        [
            {
                "name": "w",
                "match": {"safety_class": ["WRITE"], "roles": ["writer"]},
                "action": "allow",
            },
        ]
    )
    p_writer = Principal(principal_id="u1", roles=["writer"])
    p_reader = Principal(principal_id="u2", roles=["reader"])
    dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.WRITE), p_writer, justification="")
    assert dec.allowed is True
    with pytest.raises(PolicyDenied):
        engine.evaluate(_req("c"), _cap("c", SafetyClass.WRITE), p_reader, justification="")


def test_declarative_min_justification_condition() -> None:
    engine = _dce(
        [
            {
                "name": "w",
                "match": {"safety_class": ["WRITE"], "min_justification": 10},
                "action": "allow",
            },
        ]
    )
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.WRITE), p, justification="1234567890")
    assert dec.allowed is True
    with pytest.raises(PolicyDenied):
        engine.evaluate(_req("c"), _cap("c", SafetyClass.WRITE), p, justification="short")


def test_declarative_attribute_condition() -> None:
    engine = _dce(
        [
            {
                "name": "pii",
                "match": {"sensitivity": ["PII"], "attributes": {"tenant": "*"}},
                "action": "allow",
            }
        ]
    )
    p_tenant = Principal(principal_id="u1", attributes={"tenant": "acme"})
    p_no_tenant = Principal(principal_id="u2")
    dec = engine.evaluate(
        _req("c"), _cap("c", SafetyClass.READ, SensitivityTag.PII), p_tenant, justification=""
    )
    assert dec.allowed is True
    with pytest.raises(PolicyDenied):
        engine.evaluate(
            _req("c"),
            _cap("c", SafetyClass.READ, SensitivityTag.PII),
            p_no_tenant,
            justification="",
        )


def test_declarative_constraints_merged() -> None:
    engine = _dce(
        [
            {
                "name": "r",
                "match": {"safety_class": ["READ"]},
                "action": "allow",
                "constraints": {"max_rows": 10},
            }
        ]
    )
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")
    assert dec.constraints["max_rows"] == 10


# ── config validation errors ──────────────────────────────────────────────────


def test_declarative_invalid_default() -> None:
    with pytest.raises(PolicyConfigError, match="default"):
        DeclarativePolicyEngine.from_dict({"default": "maybe", "rules": []})


def test_declarative_invalid_action() -> None:
    with pytest.raises(PolicyConfigError, match="action"):
        _dce([{"name": "r", "match": {}, "action": "perhaps"}])


def test_declarative_invalid_safety_class() -> None:
    with pytest.raises(PolicyConfigError, match="safety_class"):
        _dce([{"name": "r", "match": {"safety_class": ["SUPER_DANGEROUS"]}, "action": "allow"}])


# ── YAML round-trip ───────────────────────────────────────────────────────────


def test_declarative_from_yaml_round_trip() -> None:
    yaml_text = """\
rules:
  - name: read-allowed
    match:
      safety_class: [READ]
    action: allow
  - name: write-role
    match:
      safety_class: [WRITE]
      roles: [writer, admin]
      min_justification: 10
    action: allow
default: deny
"""
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(yaml_text)
        path = Path(f.name)
    try:
        engine = DeclarativePolicyEngine.from_yaml(path)
        p_reader = Principal(principal_id="u1")
        dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p_reader, justification="")
        assert dec.allowed is True
        p_writer = Principal(principal_id="u2", roles=["writer"])
        dec2 = engine.evaluate(
            _req("c"), _cap("c", SafetyClass.WRITE), p_writer, justification="1234567890"
        )
        assert dec2.allowed is True
        with pytest.raises(PolicyDenied):
            engine.evaluate(_req("c"), _cap("c", SafetyClass.WRITE), p_reader, justification="")
    finally:
        path.unlink(missing_ok=True)


# ── TOML round-trip ───────────────────────────────────────────────────────────


def test_declarative_from_toml_round_trip() -> None:
    toml_text = """\
default = "deny"

[[rules]]
name = "read-allowed"
action = "allow"
[rules.match]
safety_class = ["READ"]

[[rules]]
name = "write-role"
action = "allow"
[rules.match]
safety_class = ["WRITE"]
roles = ["writer", "admin"]
min_justification = 10
"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write(toml_text)
        path = Path(f.name)
    try:
        engine = DeclarativePolicyEngine.from_toml(path)
        p = Principal(principal_id="u1")
        dec = engine.evaluate(_req("c"), _cap("c", SafetyClass.READ), p, justification="")
        assert dec.allowed is True
        with pytest.raises(PolicyDenied):
            engine.evaluate(_req("c"), _cap("c", SafetyClass.WRITE), p, justification="")
    finally:
        path.unlink(missing_ok=True)


# ── explain() on DeclarativePolicyEngine ─────────────────────────────────────


def test_declarative_explain_allowed() -> None:
    engine = _dce([{"name": "r", "match": {"safety_class": ["READ"]}, "action": "allow"}])
    p = Principal(principal_id="u1")
    result = engine.explain(_req("c"), _cap("c", SafetyClass.READ), p, justification="")
    assert result.denied is False
    assert result.failed_conditions == []


def test_declarative_explain_missing_role() -> None:
    engine = _dce(
        [
            {
                "name": "write-needs-writer",
                "match": {"safety_class": ["WRITE"], "roles": ["writer"]},
                "action": "allow",
            },
        ]
    )
    p = Principal(principal_id="u1", roles=["reader"])
    result = engine.explain(_req("c"), _cap("c", SafetyClass.WRITE), p, justification="")
    assert result.denied is True
    assert result.rule_name == "write-needs-writer"
    fc = result.failed_conditions[0]
    assert fc.condition == "roles"


def test_declarative_explain_no_structural_match() -> None:
    """When no rule targets the capability type, report no_matching_rule."""
    engine = _dce([{"name": "r", "match": {"safety_class": ["WRITE"]}, "action": "allow"}])
    p = Principal(principal_id="u1")
    result = engine.explain(_req("c"), _cap("c", SafetyClass.DESTRUCTIVE), p, justification="")
    assert result.denied is True
    assert result.failed_conditions[0].condition == "no_matching_rule"


def test_declarative_explain_explicit_deny_full_match() -> None:
    """An explicit deny rule that fully matches is reported as the cause.

    Regression test for the bug where ``explain()`` fell through to the
    ``no_matching_rule`` fallback when a deny rule with no remaining
    conditions matched — the deny rule's ``reason`` was silently dropped.
    """
    engine = _dce(
        [
            {
                "name": "deny-all-write",
                "match": {"safety_class": ["WRITE"]},
                "action": "deny",
                "reason": "WRITE is currently blocked for maintenance",
            },
        ]
    )
    p = Principal(principal_id="u1", roles=["writer"])
    result = engine.explain(
        _req("c"),
        _cap("c", SafetyClass.WRITE),
        p,
        justification="long enough justification",
    )
    assert result.denied is True
    assert result.rule_name == "deny-all-write"
    assert len(result.failed_conditions) == 1
    fc = result.failed_conditions[0]
    assert fc.condition == "denied_by_rule"
    assert "deny-all-write" in str(fc.actual)
    # The rule's reason propagates into the suggestion (not the no_matching_rule fallback).
    assert "maintenance" in fc.suggestion.lower()


def test_declarative_explain_skips_partial_match_deny() -> None:
    """Partial-match deny rules don't pollute the explanation.

    A deny rule whose conditions are *not* fully satisfied did not cause the
    denial; suggesting how to satisfy it would invite the caller to trigger
    the deny. Explain should look past it to the first allow rule that
    structurally matches.
    """
    engine = _dce(
        [
            # Deny rule that doesn't apply here (roles don't match).
            {
                "name": "deny-secrets-admin-only",
                "match": {"sensitivity": ["SECRETS"], "roles": ["admin"]},
                "action": "deny",
                "reason": "internal: admins routed via different path",
            },
            # Allow rule that explains the real path forward.
            {
                "name": "allow-secrets-service",
                "match": {"sensitivity": ["SECRETS"], "roles": ["service"]},
                "action": "allow",
            },
        ]
    )
    p = Principal(principal_id="u1", roles=["reader"])  # neither admin nor service
    cap = _cap("c", SafetyClass.READ, SensitivityTag.SECRETS)
    result = engine.explain(_req("c"), cap, p, justification="")
    assert result.denied is True
    # Explanation should come via the allow rule (missing 'service' role),
    # NOT via the deny rule (which would suggest adding 'admin' — triggers deny).
    assert result.rule_name == "allow-secrets-service"
    assert len(result.failed_conditions) == 1
    fc = result.failed_conditions[0]
    assert fc.condition == "roles"
    assert "service" in str(fc.required)


# ── _parse_rule type validation ────────────────────────────────────────────────


def test_declarative_invalid_roles_not_list() -> None:
    """'roles' must be a list, not a bare string."""
    with pytest.raises(PolicyConfigError, match="roles.*list of strings"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"], "roles": "admin"},
                    "action": "allow",
                }
            ]
        )


def test_declarative_invalid_roles_element_type() -> None:
    """'roles' list elements must be strings."""
    with pytest.raises(PolicyConfigError, match="roles.*list of strings"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"], "roles": [1, 2]},
                    "action": "allow",
                }
            ]
        )


def test_declarative_invalid_attributes_type() -> None:
    """'attributes' must be a mapping of string keys to string values."""
    with pytest.raises(PolicyConfigError, match="attributes.*mapping"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"], "attributes": ["tenant"]},
                    "action": "allow",
                }
            ]
        )


def test_declarative_invalid_attributes_value_type() -> None:
    """'attributes' values must be strings (not ints, lists, etc.)."""
    with pytest.raises(PolicyConfigError, match="attributes.*mapping"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"], "attributes": {"tenant": 42}},
                    "action": "allow",
                }
            ]
        )


def test_declarative_invalid_min_justification_type() -> None:
    """'min_justification' must be an integer."""
    with pytest.raises(PolicyConfigError, match="min_justification.*integer"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"], "min_justification": "ten"},
                    "action": "allow",
                }
            ]
        )


def test_declarative_invalid_min_justification_bool_rejected() -> None:
    """'min_justification' must not be a bool (which is an int subclass)."""
    with pytest.raises(PolicyConfigError, match="min_justification.*integer"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"], "min_justification": True},
                    "action": "allow",
                }
            ]
        )


def test_declarative_invalid_constraints_type() -> None:
    """'constraints' must be a mapping."""
    with pytest.raises(PolicyConfigError, match="constraints.*mapping"):
        _dce(
            [
                {
                    "name": "r",
                    "match": {"safety_class": ["READ"]},
                    "action": "allow",
                    "constraints": ["max_rows"],
                }
            ]
        )


# ── Comparative test: DeclarativePolicyEngine ≡ DefaultPolicyEngine ──────────


def test_declarative_replicates_default_policy_decisions() -> None:
    """DeclarativePolicyEngine can express DefaultPolicyEngine's decisions.

    Validates #42's acceptance criterion: a declarative rule set can replicate
    DefaultPolicyEngine's allow/deny behaviour for every condition the DSL is
    able to express. Walks a curated scenario matrix through both engines and
    asserts the same outcome.

    Out of scope (DSL has no equivalent operator today, by design):
      - Rate limiting (sliding-window per principal/capability)
      - max_rows ceiling (hardcoded 50/500 in DefaultPolicyEngine)
      - allowed_fields enforcement (paired with sensitivity in DefaultPolicyEngine)

    The illustrative ``examples/policies/default.{yaml,toml}`` file uses the
    same rule shape but a slightly different policy (``editor`` role with
    longer justification thresholds) to show DSL flexibility — equivalence to
    DefaultPolicyEngine is asserted via an inline rule set built here.
    """
    declarative_rules = {
        "default": "deny",
        "rules": [
            # READ on non-sensitive data → allowed for anyone
            {
                "name": "allow-read-nonsensitive",
                "action": "allow",
                "match": {"safety_class": ["READ"], "sensitivity": ["NONE"]},
            },
            # READ on PII/PCI → require tenant attribute
            {
                "name": "allow-read-pii-with-tenant",
                "action": "allow",
                "match": {
                    "safety_class": ["READ"],
                    "sensitivity": ["PII"],
                    "attributes": {"tenant": "*"},
                },
            },
            {
                "name": "allow-read-pci-with-tenant",
                "action": "allow",
                "match": {
                    "safety_class": ["READ"],
                    "sensitivity": ["PCI"],
                    "attributes": {"tenant": "*"},
                },
            },
            # SECRETS → admin or secrets_reader with justification
            {
                "name": "allow-secrets-admin",
                "action": "allow",
                "match": {
                    "sensitivity": ["SECRETS"],
                    "roles": ["admin"],
                    "min_justification": 15,
                },
            },
            {
                "name": "allow-secrets-reader",
                "action": "allow",
                "match": {
                    "sensitivity": ["SECRETS"],
                    "roles": ["secrets_reader"],
                    "min_justification": 15,
                },
            },
            # WRITE → writer or admin with justification (≥ 15 chars)
            {
                "name": "allow-write-writers",
                "action": "allow",
                "match": {
                    "safety_class": ["WRITE"],
                    "sensitivity": ["NONE"],
                    "roles": ["writer", "admin"],
                    "min_justification": 15,
                },
            },
            # DESTRUCTIVE → admin with justification (≥ 15 chars)
            {
                "name": "allow-destructive-admin",
                "action": "allow",
                "match": {
                    "safety_class": ["DESTRUCTIVE"],
                    "roles": ["admin"],
                    "min_justification": 15,
                },
            },
        ],
    }
    declarative = DeclarativePolicyEngine.from_dict(declarative_rules)

    long_justification = "this is a long enough justification string"

    scenarios: list[tuple[str, Capability, Principal, str, bool]] = [
        # READ on non-sensitive → allowed for anyone
        (
            "read-nonsensitive",
            _cap("c", SafetyClass.READ),
            Principal(principal_id="u1"),
            "",
            True,
        ),
        # READ on PII without tenant → denied by both
        (
            "read-pii-no-tenant",
            _cap("c", SafetyClass.READ, SensitivityTag.PII),
            Principal(principal_id="u1", roles=["reader"]),
            "",
            False,
        ),
        # READ on PII with tenant → allowed by both
        (
            "read-pii-with-tenant",
            _cap("c", SafetyClass.READ, SensitivityTag.PII),
            Principal(principal_id="u1", roles=["reader"], attributes={"tenant": "acme"}),
            "",
            True,
        ),
        # READ on PCI with tenant → allowed by both
        (
            "read-pci-with-tenant",
            _cap("c", SafetyClass.READ, SensitivityTag.PCI),
            Principal(principal_id="u1", roles=["reader"], attributes={"tenant": "acme"}),
            "",
            True,
        ),
        # WRITE without writer role → denied
        (
            "write-no-role",
            _cap("c", SafetyClass.WRITE),
            Principal(principal_id="u1", roles=["reader"]),
            long_justification,
            False,
        ),
        # WRITE with writer role + long justification → allowed
        (
            "write-writer-allowed",
            _cap("c", SafetyClass.WRITE),
            Principal(principal_id="u1", roles=["writer"]),
            long_justification,
            True,
        ),
        # WRITE with writer role + short justification → denied
        (
            "write-writer-short-justification",
            _cap("c", SafetyClass.WRITE),
            Principal(principal_id="u1", roles=["writer"]),
            "too short",
            False,
        ),
        # DESTRUCTIVE without admin → denied
        (
            "destructive-no-admin",
            _cap("c", SafetyClass.DESTRUCTIVE),
            Principal(principal_id="u1", roles=["writer"]),
            long_justification,
            False,
        ),
        # DESTRUCTIVE with admin + long justification → allowed
        (
            "destructive-admin-allowed",
            _cap("c", SafetyClass.DESTRUCTIVE),
            Principal(principal_id="u1", roles=["admin"]),
            long_justification,
            True,
        ),
        # SECRETS without role → denied
        (
            "secrets-no-role",
            _cap("c", SafetyClass.READ, SensitivityTag.SECRETS),
            Principal(principal_id="u1", roles=["reader"]),
            long_justification,
            False,
        ),
        # SECRETS with secrets_reader + justification → allowed
        (
            "secrets-reader-allowed",
            _cap("c", SafetyClass.READ, SensitivityTag.SECRETS),
            Principal(principal_id="u1", roles=["secrets_reader"]),
            long_justification,
            True,
        ),
        # SECRETS with admin + justification → allowed
        (
            "secrets-admin-allowed",
            _cap("c", SafetyClass.READ, SensitivityTag.SECRETS),
            Principal(principal_id="u1", roles=["admin"]),
            long_justification,
            True,
        ),
    ]

    for name, capability, principal, justification, expected_allow in scenarios:
        # Fresh DefaultPolicyEngine per scenario to avoid rate-limit state.
        default = DefaultPolicyEngine()
        if expected_allow:
            d_decision = default.evaluate(
                _req("c"), capability, principal, justification=justification
            )
            r_decision = declarative.evaluate(
                _req("c"), capability, principal, justification=justification
            )
            assert d_decision.allowed is True, f"{name}: DefaultPolicyEngine expected allow"
            assert r_decision.allowed is True, f"{name}: DeclarativePolicyEngine expected allow"
        else:
            with pytest.raises(PolicyDenied):
                default.evaluate(_req("c"), capability, principal, justification=justification)
            with pytest.raises(PolicyDenied):
                declarative.evaluate(_req("c"), capability, principal, justification=justification)


# ── Optional-deps install hint ────────────────────────────────────────────────


def test_declarative_from_yaml_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """When pyyaml is unavailable, ``from_yaml`` raises with the install hint."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "yaml":
            raise ImportError("simulated: pyyaml missing")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(PolicyConfigError, match="weaver-kernel\\[policy\\]"):
        DeclarativePolicyEngine.from_yaml(Path("does-not-matter.yaml"))


def test_declarative_from_toml_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """On 3.10 without tomli, ``from_toml`` raises with the install hint.

    On 3.11+ ``tomllib`` is in stdlib and always importable, so this test
    only exercises the install-hint path on 3.10. We assert by simulating
    an ``ImportError`` for whichever module the loader uses on this version.
    """
    import builtins
    import sys

    target = "tomllib" if sys.version_info >= (3, 11) else "tomli"
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == target:
            raise ImportError(f"simulated: {target} missing")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(PolicyConfigError, match="weaver-kernel\\[policy\\]"):
        DeclarativePolicyEngine.from_toml(Path("does-not-matter.toml"))


# ═══════════════════════════════════════════════════════════════════════════════
# Stable denial reason codes — #77
# ═══════════════════════════════════════════════════════════════════════════════


from weaver_kernel import AllowReason, DenialReason  # noqa: E402


class TestDefaultEngineReasonCodes:
    """Every built-in denial path on DefaultPolicyEngine carries a stable code."""

    def test_write_missing_role_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(
                _req("cap.w"),
                _cap("cap.w", SafetyClass.WRITE),
                p,
                justification="long enough justification",
            )
        assert exc.value.reason_code == DenialReason.MISSING_ROLE

    def test_write_short_justification_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["writer"])
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(
                _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="short"
            )
        assert exc.value.reason_code == DenialReason.INSUFFICIENT_JUSTIFICATION

    def test_destructive_missing_role_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["writer"])
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(
                _req("cap.d"),
                _cap("cap.d", SafetyClass.DESTRUCTIVE),
                p,
                justification="long enough justification",
            )
        assert exc.value.reason_code == DenialReason.MISSING_ROLE

    def test_destructive_short_justification_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["admin"])
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(
                _req("cap.d"),
                _cap("cap.d", SafetyClass.DESTRUCTIVE),
                p,
                justification="short",
            )
        assert exc.value.reason_code == DenialReason.INSUFFICIENT_JUSTIFICATION

    def test_pii_missing_tenant_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(_req("cap.pii"), cap, p, justification="")
        assert exc.value.reason_code == DenialReason.MISSING_TENANT_ATTRIBUTE

    def test_secrets_missing_role_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        cap = _cap("cap.s", SafetyClass.READ, SensitivityTag.SECRETS)
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(_req("cap.s"), cap, p, justification="long enough justification")
        assert exc.value.reason_code == DenialReason.MISSING_ROLE

    def test_secrets_short_justification_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["secrets_reader"])
        cap = _cap("cap.s", SafetyClass.READ, SensitivityTag.SECRETS)
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(_req("cap.s"), cap, p, justification="short")
        assert exc.value.reason_code == DenialReason.INSUFFICIENT_JUSTIFICATION

    def test_invalid_max_rows_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(
                _req("cap.r", max_rows="nope"),
                _cap("cap.r", SafetyClass.READ),
                p,
                justification="",
            )
        assert exc.value.reason_code == DenialReason.INVALID_CONSTRAINT

    def test_rate_limited_code(self) -> None:
        # Force a low limit by using a custom engine.
        engine = DefaultPolicyEngine(rate_limits={SafetyClass.READ: (1, 60.0)})
        p = Principal(principal_id="u1", roles=["reader"])
        cap = _cap("cap.r", SafetyClass.READ)
        engine.evaluate(_req("cap.r"), cap, p, justification="")
        with pytest.raises(PolicyDenied) as exc:
            engine.evaluate(_req("cap.r"), cap, p, justification="")
        assert exc.value.reason_code == DenialReason.RATE_LIMITED

    def test_allow_has_reason_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.allowed is True
        assert dec.reason_code == AllowReason.DEFAULT_POLICY_ALLOW


class TestDefaultEngineExplainReasonCodes:
    """``explain()`` populates a reason_code on each FailedCondition."""

    def test_write_missing_role_reason_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        result = engine.explain(
            _req("cap.w"),
            _cap("cap.w", SafetyClass.WRITE),
            p,
            justification="long enough justification",
        )
        assert result.denied is True
        assert result.reason_code == DenialReason.MISSING_ROLE
        assert result.failed_conditions[0].reason_code == DenialReason.MISSING_ROLE

    def test_write_two_failures_codes(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        result = engine.explain(
            _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="too short"
        )
        codes = {fc.reason_code for fc in result.failed_conditions}
        assert DenialReason.MISSING_ROLE in codes
        assert DenialReason.INSUFFICIENT_JUSTIFICATION in codes

    def test_pii_missing_tenant_reason_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
        result = engine.explain(_req("cap.pii"), cap, p, justification="")
        assert result.reason_code == DenialReason.MISSING_TENANT_ATTRIBUTE

    def test_allowed_has_no_reason_code(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1")
        result = engine.explain(
            _req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification=""
        )
        assert result.denied is False
        assert result.reason_code is None


# ═══════════════════════════════════════════════════════════════════════════════
# Structured policy decision trace — #73
# ═══════════════════════════════════════════════════════════════════════════════


class TestDefaultEngineDecisionTrace:
    """DefaultPolicyEngine.evaluate() attaches a structured trace."""

    def test_allow_trace_engine_and_final_outcome(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        assert dec.trace.engine == "DefaultPolicyEngine"
        assert dec.trace.capability_id == "cap.r"
        assert dec.trace.principal_id == "u1"
        assert dec.trace.final_outcome == "allowed"
        assert dec.trace.final_reason_code == AllowReason.DEFAULT_POLICY_ALLOW

    def test_allow_trace_has_constraint_step(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        outcomes = [s.outcome for s in dec.trace.steps]
        assert "constraint_applied" in outcomes
        assert "allowed" in outcomes

    def test_trace_echoes_intent_and_scope(self, engine: DefaultPolicyEngine) -> None:
        p = Principal(principal_id="u1", roles=["reader"])
        req = CapabilityRequest(
            capability_id="cap.r",
            goal="g",
            intent="support_lookup",
            scope={"region": "eu-west"},
        )
        dec = engine.evaluate(req, _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        assert dec.trace.intent == "support_lookup"
        assert dec.trace.scope_keys == ["region"]

    def test_trace_no_raw_args_leaked(self, engine: DefaultPolicyEngine) -> None:
        """Sensitive values from request.constraints must never appear in trace details."""
        p = Principal(principal_id="u1", roles=["reader"])
        req = _req("cap.r", api_token="super-secret-do-not-leak-XYZ")
        dec = engine.evaluate(req, _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        for step in dec.trace.steps:
            assert "super-secret-do-not-leak-XYZ" not in step.detail


class TestDeclarativeEngineDecisionTrace:
    """DeclarativePolicyEngine produces a trace on allow, explicit-deny, and default-deny."""

    @staticmethod
    def _engine(rules: list[dict[str, object]], default: str = "deny") -> DeclarativePolicyEngine:
        return DeclarativePolicyEngine.from_dict({"default": default, "rules": rules})

    def test_allow_rule_trace(self) -> None:
        eng = self._engine(
            [{"name": "all_reads", "match": {"safety_class": ["READ"]}, "action": "allow"}]
        )
        p = Principal(principal_id="u1")
        dec = eng.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        assert dec.trace.engine == "DeclarativePolicyEngine"
        assert dec.trace.final_outcome == "allowed"
        assert dec.trace.final_reason_code == AllowReason.RULE_ALLOW
        # First step should be a matched rule.
        assert dec.trace.steps[0].outcome == "matched"
        assert dec.trace.steps[0].name == "rule:all_reads"

    def test_explicit_deny_rule_trace(self) -> None:
        eng = self._engine(
            [
                {
                    "name": "no_destructive",
                    "match": {"safety_class": ["DESTRUCTIVE"]},
                    "action": "deny",
                    "reason": "destructive disabled",
                }
            ]
        )
        p = Principal(principal_id="u1", roles=["admin"])
        with pytest.raises(PolicyDenied) as exc:
            eng.evaluate(
                _req("cap.d"),
                _cap("cap.d", SafetyClass.DESTRUCTIVE),
                p,
                justification="long enough justification",
            )
        assert exc.value.reason_code == DenialReason.EXPLICIT_DENY_RULE

    def test_default_deny_trace(self) -> None:
        eng = self._engine([])
        p = Principal(principal_id="u1")
        with pytest.raises(PolicyDenied) as exc:
            eng.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert exc.value.reason_code == DenialReason.NO_MATCHING_RULE

    def test_default_fallthrough_allow_trace(self) -> None:
        eng = self._engine([], default="allow")
        p = Principal(principal_id="u1")
        dec = eng.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        assert dec.trace.final_reason_code == AllowReason.DEFAULT_FALLTHROUGH_ALLOW

    def test_trace_skipped_rule_count(self) -> None:
        """Non-matching rules appear as 'skipped' steps before the matching one."""
        eng = self._engine(
            [
                {"name": "writes", "match": {"safety_class": ["WRITE"]}, "action": "allow"},
                {"name": "reads", "match": {"safety_class": ["READ"]}, "action": "allow"},
            ]
        )
        p = Principal(principal_id="u1")
        dec = eng.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
        assert dec.trace is not None
        outcomes = [s.outcome for s in dec.trace.steps]
        assert outcomes[0] == "skipped"  # writes rule skipped first
        assert "matched" in outcomes
        assert "allowed" in outcomes


# ═══════════════════════════════════════════════════════════════════════════════
# Intent and scope — #72
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntentAndScopeMatching:
    """DeclarativePolicyEngine matches on CapabilityRequest.intent and .scope."""

    @staticmethod
    def _engine(rules: list[dict[str, object]], default: str = "deny") -> DeclarativePolicyEngine:
        return DeclarativePolicyEngine.from_dict({"default": default, "rules": rules})

    def test_intent_allow_matches(self) -> None:
        eng = self._engine(
            [
                {
                    "name": "support_lookup_only",
                    "match": {"safety_class": ["READ"], "intent": ["support_lookup"]},
                    "action": "allow",
                }
            ]
        )
        req = CapabilityRequest(capability_id="cap.r", goal="g", intent="support_lookup")
        dec = eng.evaluate(
            req, _cap("cap.r", SafetyClass.READ), Principal(principal_id="u1"), justification=""
        )
        assert dec.allowed is True
        assert dec.reason_code == AllowReason.RULE_ALLOW

    def test_intent_mismatch_falls_through_to_default_deny(self) -> None:
        eng = self._engine(
            [
                {
                    "name": "support_lookup_only",
                    "match": {"safety_class": ["READ"], "intent": ["support_lookup"]},
                    "action": "allow",
                }
            ]
        )
        req = CapabilityRequest(capability_id="cap.r", goal="g", intent="marketing_export")
        with pytest.raises(PolicyDenied) as exc:
            eng.evaluate(
                req,
                _cap("cap.r", SafetyClass.READ),
                Principal(principal_id="u1"),
                justification="",
            )
        assert exc.value.reason_code == DenialReason.NO_MATCHING_RULE

    def test_intent_none_does_not_match_intent_aware_rule(self) -> None:
        """A request without an intent must NOT silently match an intent-aware allow rule."""
        eng = self._engine(
            [
                {
                    "name": "support_lookup_only",
                    "match": {"safety_class": ["READ"], "intent": ["support_lookup"]},
                    "action": "allow",
                }
            ]
        )
        req = _req("cap.r")  # intent=None
        with pytest.raises(PolicyDenied):
            eng.evaluate(
                req,
                _cap("cap.r", SafetyClass.READ),
                Principal(principal_id="u1"),
                justification="",
            )

    def test_scope_matches_value(self) -> None:
        eng = self._engine(
            [
                {
                    "name": "eu_only",
                    "match": {"safety_class": ["READ"], "scope": {"region": "eu-west"}},
                    "action": "allow",
                }
            ]
        )
        req = CapabilityRequest(capability_id="cap.r", goal="g", scope={"region": "eu-west"})
        dec = eng.evaluate(
            req, _cap("cap.r", SafetyClass.READ), Principal(principal_id="u1"), justification=""
        )
        assert dec.allowed is True

    def test_scope_wildcard_requires_presence(self) -> None:
        eng = self._engine(
            [
                {
                    "name": "any_region",
                    "match": {"safety_class": ["READ"], "scope": {"region": "*"}},
                    "action": "allow",
                }
            ]
        )
        # Missing key: denied
        req_missing = _req("cap.r")
        with pytest.raises(PolicyDenied):
            eng.evaluate(
                req_missing,
                _cap("cap.r", SafetyClass.READ),
                Principal(principal_id="u1"),
                justification="",
            )
        # Present key: allowed
        req_present = CapabilityRequest(
            capability_id="cap.r", goal="g", scope={"region": "anything"}
        )
        dec = eng.evaluate(
            req_present,
            _cap("cap.r", SafetyClass.READ),
            Principal(principal_id="u1"),
            justification="",
        )
        assert dec.allowed is True

    def test_intent_explain_reports_code(self) -> None:
        """explain() surfaces INTENT_NOT_ALLOWED on a rule that requires a specific intent."""
        eng = self._engine(
            [
                {
                    "name": "support_lookup_only",
                    "match": {"safety_class": ["READ"], "intent": ["support_lookup"]},
                    "action": "allow",
                }
            ]
        )
        req = CapabilityRequest(capability_id="cap.r", goal="g", intent="marketing_export")
        result = eng.explain(
            req,
            _cap("cap.r", SafetyClass.READ),
            Principal(principal_id="u1"),
            justification="",
        )
        assert result.denied is True
        codes = {fc.reason_code for fc in result.failed_conditions}
        assert DenialReason.INTENT_NOT_ALLOWED in codes

    def test_scope_explain_reports_code(self) -> None:
        eng = self._engine(
            [
                {
                    "name": "eu_only",
                    "match": {"safety_class": ["READ"], "scope": {"region": "eu-west"}},
                    "action": "allow",
                }
            ]
        )
        req = CapabilityRequest(capability_id="cap.r", goal="g", scope={"region": "us-east"})
        result = eng.explain(
            req,
            _cap("cap.r", SafetyClass.READ),
            Principal(principal_id="u1"),
            justification="",
        )
        codes = {fc.reason_code for fc in result.failed_conditions}
        assert DenialReason.SCOPE_NOT_ALLOWED in codes


# ═══════════════════════════════════════════════════════════════════════════════
# DSL parser: intent / scope validation
# ═══════════════════════════════════════════════════════════════════════════════


def test_dsl_parser_rejects_non_list_intent() -> None:
    with pytest.raises(PolicyConfigError, match="'intent' must be a list"):
        DeclarativePolicyEngine.from_dict(
            {"rules": [{"name": "x", "match": {"intent": "support"}, "action": "allow"}]}
        )


def test_dsl_parser_rejects_non_dict_scope() -> None:
    with pytest.raises(PolicyConfigError, match="'scope' must be a mapping"):
        DeclarativePolicyEngine.from_dict(
            {"rules": [{"name": "x", "match": {"scope": "eu-west"}, "action": "allow"}]}
        )


def test_dsl_parser_rejects_non_string_scope_value() -> None:
    with pytest.raises(PolicyConfigError, match="string keys to string values"):
        DeclarativePolicyEngine.from_dict(
            {"rules": [{"name": "x", "match": {"scope": {"k": 1}}, "action": "allow"}]}
        )


# ═══════════════════════════════════════════════════════════════════════════════
# PolicyDenied carries reason_code through raise / except
# ═══════════════════════════════════════════════════════════════════════════════


def test_policy_denied_default_reason_code_is_none() -> None:
    err = PolicyDenied("bare message")
    assert err.reason_code is None
    assert str(err) == "bare message"


def test_policy_denied_carries_reason_code() -> None:
    err = PolicyDenied("msg", reason_code=DenialReason.MISSING_ROLE)
    assert err.reason_code == DenialReason.MISSING_ROLE
