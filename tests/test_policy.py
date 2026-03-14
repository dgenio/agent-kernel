"""Tests for DefaultPolicyEngine."""

from __future__ import annotations

import pytest

from agent_kernel import (
    AgentKernelError,
    Capability,
    DefaultPolicyEngine,
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


engine = DefaultPolicyEngine()


# ── READ ───────────────────────────────────────────────────────────────────────


def test_read_allowed_no_roles() -> None:
    p = Principal(principal_id="u1")
    dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert dec.allowed is True


def test_read_sets_max_rows_user() -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert dec.constraints["max_rows"] == 50


def test_read_sets_max_rows_service() -> None:
    p = Principal(principal_id="svc1", roles=["service"])
    dec = engine.evaluate(_req("cap.r"), _cap("cap.r", SafetyClass.READ), p, justification="")
    assert dec.constraints["max_rows"] == 500


def test_read_respects_tighter_constraint() -> None:
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=5), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 5


def test_read_tighter_constraint_cannot_exceed_cap() -> None:
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=9999), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 50


# ── WRITE ──────────────────────────────────────────────────────────────────────


def test_write_denied_no_role() -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    with pytest.raises(PolicyDenied, match="writer.*admin"):
        engine.evaluate(
            _req("cap.w"),
            _cap("cap.w", SafetyClass.WRITE),
            p,
            justification="long enough justification here",
        )


def test_write_denied_short_justification() -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(
            _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="too short"
        )


def test_write_denied_whitespace_justification() -> None:
    """Whitespace-only justification must not bypass the length requirement."""
    p = Principal(principal_id="u1", roles=["writer"])
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(
            _req("cap.w"), _cap("cap.w", SafetyClass.WRITE), p, justification="               "
        )


def test_write_allowed_writer_role() -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    dec = engine.evaluate(
        _req("cap.w"),
        _cap("cap.w", SafetyClass.WRITE),
        p,
        justification="this is a long enough justification string",
    )
    assert dec.allowed is True


def test_write_allowed_admin_role() -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    dec = engine.evaluate(
        _req("cap.w"),
        _cap("cap.w", SafetyClass.WRITE),
        p,
        justification="this is a long enough justification string",
    )
    assert dec.allowed is True


# ── DESTRUCTIVE ────────────────────────────────────────────────────────────────


def test_destructive_denied_short_justification() -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    with pytest.raises(PolicyDenied, match="DESTRUCTIVE capabilities require a justification"):
        engine.evaluate(
            _req("cap.d"),
            _cap("cap.d", SafetyClass.DESTRUCTIVE),
            p,
            justification="short",
        )


def test_destructive_denied_whitespace_justification() -> None:
    """Whitespace-only justification must not bypass the length requirement."""
    p = Principal(principal_id="u1", roles=["admin"])
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(
            _req("cap.d"),
            _cap("cap.d", SafetyClass.DESTRUCTIVE),
            p,
            justification="               ",
        )


def test_destructive_denied_no_admin() -> None:
    p = Principal(principal_id="u1", roles=["writer"])
    with pytest.raises(PolicyDenied, match="admin"):
        engine.evaluate(
            _req("cap.d"),
            _cap("cap.d", SafetyClass.DESTRUCTIVE),
            p,
            justification="long enough justification",
        )


def test_destructive_allowed_admin() -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    dec = engine.evaluate(
        _req("cap.d"),
        _cap("cap.d", SafetyClass.DESTRUCTIVE),
        p,
        justification="long enough justification",
    )
    assert dec.allowed is True


# ── PII / PCI ──────────────────────────────────────────────────────────────────


def test_pii_requires_tenant() -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
    with pytest.raises(PolicyDenied, match="tenant"):
        engine.evaluate(_req("cap.pii"), cap, p, justification="")


def test_pii_allowed_with_tenant() -> None:
    p = Principal(principal_id="u1", roles=["reader"], attributes={"tenant": "acme"})
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII)
    dec = engine.evaluate(_req("cap.pii"), cap, p, justification="")
    assert dec.allowed is True


def test_pii_enforces_allowed_fields() -> None:
    p = Principal(principal_id="u1", roles=["reader"], attributes={"tenant": "acme"})
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII, allowed_fields=["id", "name"])
    dec = engine.evaluate(_req("cap.pii"), cap, p, justification="")
    assert dec.constraints.get("allowed_fields") == ["id", "name"]


def test_pii_reader_skips_allowed_fields() -> None:
    p = Principal(principal_id="u1", roles=["reader", "pii_reader"], attributes={"tenant": "acme"})
    cap = _cap("cap.pii", SafetyClass.READ, SensitivityTag.PII, allowed_fields=["id", "name"])
    dec = engine.evaluate(_req("cap.pii"), cap, p, justification="")
    assert "allowed_fields" not in dec.constraints


def test_pci_requires_tenant() -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.pci", SafetyClass.READ, SensitivityTag.PCI)
    with pytest.raises(PolicyDenied, match="tenant"):
        engine.evaluate(_req("cap.pci"), cap, p, justification="")


# ── SECRETS ────────────────────────────────────────────────────────────────────


def test_secrets_denied_no_role() -> None:
    p = Principal(principal_id="u1", roles=["reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="secrets_reader"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")


def test_secrets_denied_short_justification() -> None:
    p = Principal(principal_id="u1", roles=["secrets_reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="too short")


def test_secrets_denied_whitespace_justification() -> None:
    """Whitespace-only justification must not bypass the length requirement."""
    p = Principal(principal_id="u1", roles=["secrets_reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="justification"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="               ")


def test_secrets_allowed_secrets_reader_role() -> None:
    p = Principal(principal_id="u1", roles=["secrets_reader"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    dec = engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")
    assert dec.allowed is True


def test_secrets_allowed_admin_role() -> None:
    p = Principal(principal_id="u1", roles=["admin"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    dec = engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")
    assert dec.allowed is True


def test_secrets_denied_writer_role() -> None:
    """Writer role is insufficient for SECRETS capabilities."""
    p = Principal(principal_id="u1", roles=["writer"])
    cap = _cap("cap.sec", SafetyClass.READ, SensitivityTag.SECRETS)
    with pytest.raises(PolicyDenied, match="secrets_reader"):
        engine.evaluate(_req("cap.sec"), cap, p, justification="long enough justification here")


# ── Confused-deputy binding (via token) ────────────────────────────────────────


def test_max_rows_enforcement() -> None:
    """max_rows in constraints is capped by the policy ceiling."""
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=200), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 50


def test_max_rows_invalid_raises_policy_denied() -> None:
    """Non-numeric max_rows raises PolicyDenied, not bare ValueError."""
    p = Principal(principal_id="u1")
    with pytest.raises(PolicyDenied, match="Invalid 'max_rows'"):
        engine.evaluate(
            _req("cap.r", max_rows="abc"),
            _cap("cap.r", SafetyClass.READ),
            p,
            justification="",
        )


def test_max_rows_negative_clamped_to_zero() -> None:
    """Negative max_rows is clamped to 0."""
    p = Principal(principal_id="u1")
    dec = engine.evaluate(
        _req("cap.r", max_rows=-10), _cap("cap.r", SafetyClass.READ), p, justification=""
    )
    assert dec.constraints["max_rows"] == 0


# ── Rate limiting ─────────────────────────────────────────────────────────────────


def _make_clock(start: float = 0.0) -> tuple[list[float], callable]:
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
