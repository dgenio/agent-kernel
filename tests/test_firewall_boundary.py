"""Boundary regression tests for the raw → Frame / Handle / ActionTrace seam (#74).

These tests pin the I-01 contract from a different angle than ``test_firewall.py``:
they construct synthetic records with obviously-fake secret and PII-like values,
push them through the firewall and kernel, then assert *negatively* — those
values must not appear anywhere a downstream consumer (LLM, audit reader, log
sink) is expected to look.

The intent is to catch a future refactor that quietly drops a redaction step
or routes raw data through a new path. New response modes or trace fields
should add a case here.
"""

from __future__ import annotations

import asyncio
import datetime
import json
from typing import Any

import pytest

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    HandleStore,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
    TraceStore,
)
from weaver_kernel.firewall.transform import Firewall
from weaver_kernel.models import CapabilityRequest, Handle, RawResult

# Fake values — these strings exist nowhere except this test file. Any test
# failure that prints them is loud about which boundary leaked.
_FAKE_EMAIL = "alice.fake-victim@example.invalid"
_FAKE_BEARER = "Bearer fake-bearer-zzz-9999-do-not-use"
_FAKE_CARD = "4111 1111 1111 1234"
_FAKE_SSN = "123-45-6789"
_FAKE_API_KEY_VALUE = "ZZZZ_FAKEKEY_ABCDEF12345"
_FAKE_INTERNAL_NOTE = "INTERNAL-ONLY-zzz-do-not-leak"


def _record() -> dict[str, Any]:
    """A synthetic 'customer' row carrying every field type we redact."""
    return {
        "id": 1,
        "name": "Alice Public",
        "email": _FAKE_EMAIL,
        "ssn": _FAKE_SSN,
        "card_number": _FAKE_CARD,
        "authorization": _FAKE_BEARER,
        "secret_handshake": f"api_key={_FAKE_API_KEY_VALUE}",
        "internal_notes": _FAKE_INTERNAL_NOTE,
        "public_status": "active",
    }


def _handle() -> Handle:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return Handle(
        handle_id="bh1",
        capability_id="cap.customers",
        created_at=now,
        expires_at=now + datetime.timedelta(hours=1),
        total_rows=1,
    )


def _frame_text(frame: object) -> str:
    """Serialize the entire frame to JSON for global negative assertions."""
    return json.dumps(frame, default=lambda o: getattr(o, "__dict__", str(o)))


# ── Raw → Frame redaction boundary ────────────────────────────────────────────


@pytest.mark.parametrize("mode", ["summary", "table"])
def test_inline_secrets_never_reach_default_modes(mode: str) -> None:
    fw = Firewall()
    raw = RawResult(capability_id="cap.customers", data=[_record()])
    frame = fw.transform(
        raw,
        action_id="a1",
        principal_id="u1",
        principal_roles=["reader"],
        response_mode=mode,  # type: ignore[arg-type]
        handle=_handle(),
    )
    serialized = _frame_text(frame)
    for needle in (_FAKE_BEARER, _FAKE_API_KEY_VALUE, _FAKE_SSN, _FAKE_CARD):
        assert needle not in serialized, (
            f"{mode}: secret/PII pattern {needle!r} leaked through firewall"
        )


def test_allowed_fields_strips_disallowed_columns() -> None:
    """When allowed_fields constrains output, the disallowed column is dropped
    even if it contained otherwise-benign text."""
    fw = Firewall()
    raw = RawResult(capability_id="cap.customers", data=[_record()])
    frame = fw.transform(
        raw,
        action_id="a2",
        principal_id="u1",
        principal_roles=["reader"],
        response_mode="table",
        constraints={"allowed_fields": ["id", "public_status"]},
        handle=_handle(),
    )
    serialized = _frame_text(frame)
    assert _FAKE_INTERNAL_NOTE not in serialized, "internal_notes leaked"
    assert _FAKE_EMAIL not in serialized, "email leaked"
    # And no remnants of the disallowed *key names* in the table rows either.
    for row in frame.table_preview:
        assert "internal_notes" not in row
        assert "email" not in row


def test_handle_only_mode_drops_raw_payload() -> None:
    """handle_only frames carry a Handle reference but never the raw rows."""
    fw = Firewall()
    raw = RawResult(capability_id="cap.customers", data=[_record()])
    frame = fw.transform(
        raw,
        action_id="a3",
        principal_id="u1",
        principal_roles=["reader"],
        response_mode="handle_only",
        handle=_handle(),
    )
    assert frame.handle is not None, "handle_only must carry a handle reference"
    assert frame.table_preview == [], "handle_only must not include row preview"
    assert frame.raw_data is None, "handle_only must not include raw data"
    assert frame.facts == [], "handle_only must not include facts"


def test_raw_mode_downgrades_for_non_admin() -> None:
    """A non-admin asking for raw must NOT receive raw data — the firewall
    transparently downgrades to summary. This pins invariant I-01 for raw."""
    fw = Firewall()
    raw = RawResult(capability_id="cap.customers", data=[_record()])
    frame = fw.transform(
        raw,
        action_id="a4",
        principal_id="u1",
        principal_roles=["reader"],
        response_mode="raw",
        handle=_handle(),
    )
    assert frame.response_mode == "summary", "raw must downgrade to summary for non-admin"
    assert frame.raw_data is None, "raw_data must remain unpopulated after downgrade"
    serialized = _frame_text(frame)
    for needle in (_FAKE_BEARER, _FAKE_API_KEY_VALUE, _FAKE_SSN):
        assert needle not in serialized


def test_raw_mode_admin_carries_raw_data_redacted() -> None:
    """An admin in raw mode does see raw data — but inline secret patterns
    are still scrubbed because redact() always runs first."""
    fw = Firewall()
    raw = RawResult(capability_id="cap.customers", data=[_record()])
    frame = fw.transform(
        raw,
        action_id="a5",
        principal_id="u1",
        principal_roles=["admin"],
        response_mode="raw",
        handle=_handle(),
    )
    assert frame.response_mode == "raw", "admin keeps raw mode"
    assert frame.raw_data is not None
    serialized = _frame_text(frame.raw_data)
    # Bearer / api_key / JWT-shaped tokens are matched by the redaction regex
    # set, so even raw-mode admin output should not contain them verbatim.
    assert _FAKE_BEARER not in serialized
    assert _FAKE_API_KEY_VALUE not in serialized


# ── Kernel-level: ActionTrace must not leak memory payloads (#75) ─────────────


def _build_kernel() -> tuple[Kernel, Principal, Capability]:
    registry = CapabilityRegistry()
    cap = Capability(
        capability_id="memory.write",
        name="memory write",
        description="store agent note",
        safety_class=SafetyClass.WRITE,
        sensitivity=SensitivityTag.MEMORY,
    )
    registry.register(cap)
    driver = InMemoryDriver(driver_id="memory")
    driver.register_handler("memory.write", lambda _ctx: [{"ok": True}])
    router = StaticRouter(routes={"memory.write": ["memory"]})
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        handle_store=HandleStore(),
        trace_store=TraceStore(),
    )
    kernel.register_driver(driver)
    return kernel, Principal(principal_id="agent-1", roles=["admin"]), cap


def test_action_trace_redacts_memory_payload_arg() -> None:
    """ActionTrace.args must not contain raw memory payloads for memory.* caps."""
    kernel, principal, cap = _build_kernel()
    request = CapabilityRequest(
        capability_id=cap.capability_id, goal="store a durable note for later"
    )
    grant = kernel.grant_capability(
        request, principal, justification="agent learned a project convention to remember"
    )

    payload = _FAKE_INTERNAL_NOTE  # the "memory content" the agent wants to store
    asyncio.run(
        kernel.invoke(
            grant.token,
            principal=principal,
            args={"payload": payload, "key": "project_convention"},
        )
    )
    trace_list = [t for t in kernel._trace_store.list_all() if t.capability_id == "memory.write"]
    assert trace_list, "expected an ActionTrace for the memory.write invocation"
    trace = trace_list[-1]
    # The payload (raw memory content) must have been redacted...
    assert trace.args.get("payload") == "[REDACTED]"
    # ...while the non-sensitive metadata key is preserved for audit value.
    assert trace.args.get("key") == "project_convention"


def test_action_trace_keeps_non_memory_args_verbatim() -> None:
    """The redaction is scoped to memory.* — other capabilities are untouched."""
    registry = CapabilityRegistry()
    cap = Capability(
        capability_id="billing.refund",
        name="refund",
        description="issue refund",
        safety_class=SafetyClass.WRITE,
    )
    registry.register(cap)
    driver = InMemoryDriver(driver_id="billing")
    driver.register_handler("billing.refund", lambda _ctx: [{"ok": True}])
    router = StaticRouter(routes={"billing.refund": ["billing"]})
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
    )
    kernel.register_driver(driver)
    principal = Principal(principal_id="agent-1", roles=["writer"])
    request = CapabilityRequest(
        capability_id="billing.refund", goal="user requested refund processing"
    )
    grant = kernel.grant_capability(
        request, principal, justification="refund authorized in ticket #12345"
    )
    asyncio.run(
        kernel.invoke(
            grant.token,
            principal=principal,
            args={"payload": "this is not memory data", "amount": 42},
        )
    )
    trace = kernel._trace_store.list_all()[-1]
    assert trace.args.get("payload") == "this is not memory data"
    assert trace.args.get("amount") == 42
