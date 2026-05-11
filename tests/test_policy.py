"""Tests for DefaultPolicyEngine."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_kernel import (
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
from agent_kernel.models import CapabilityRequest
from agent_kernel.policy import RateLimiter


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
