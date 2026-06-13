"""Tests for the persisted-trace encode/decode codec."""

from __future__ import annotations

import datetime

import pytest

from weaver_kernel.errors import AgentKernelError
from weaver_kernel.models import ActionTrace
from weaver_kernel.stores._trace_codec import decode_trace, encode_trace


def _trace() -> ActionTrace:
    return ActionTrace(
        action_id="a",
        capability_id="cap.x",
        principal_id="u1",
        token_id="t",
        invoked_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        args={"k": "v"},
        response_mode="summary",
        driver_id="memory",
    )


def test_round_trip() -> None:
    decoded = decode_trace(encode_trace(_trace()))
    assert decoded.action_id == "a"
    assert decoded.invoked_at == datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def test_missing_field_raises_typed_error() -> None:
    payload = encode_trace(_trace())
    del payload["capability_id"]
    with pytest.raises(AgentKernelError, match="missing required field"):
        decode_trace(payload)


def test_malformed_timestamp_raises_typed_error() -> None:
    payload = encode_trace(_trace())
    payload["invoked_at"] = "not-a-timestamp"
    with pytest.raises(AgentKernelError, match="malformed"):
        decode_trace(payload)


def test_unknown_sensitivity_raises_typed_error() -> None:
    payload = encode_trace(_trace())
    payload["sensitivity"] = "BOGUS"
    with pytest.raises(AgentKernelError, match="malformed"):
        decode_trace(payload)
