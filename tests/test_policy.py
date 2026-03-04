"""Tests for DefaultPolicyEngine."""

from __future__ import annotations

import pytest

from agent_kernel import (
    Capability,
    DefaultPolicyEngine,
    PolicyDenied,
    Principal,
    SafetyClass,
    SensitivityTag,
)
from agent_kernel.models import CapabilityRequest


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
