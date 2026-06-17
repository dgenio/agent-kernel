"""Secret-canary regression suite covering every Frame egress path (#206).

Where ``test_firewall_boundary.py`` pins individual mechanisms, this suite
pins the *global* property the I-01 boundary promises: a distinctive secret
planted in driver output must never appear, verbatim, in **any** kernel
egress a downstream consumer (LLM, audit reader, log sink) can read —
regardless of which path produced it.

Each canary string exists nowhere except this file, so a failure prints the
exact string that leaked and names the path. The suite is the regression net
for the redaction-leak fixes in #149 (depth fail-open), #150 (handle
expansion), #151 (cross-chunk streaming), and #172 (trace args/errors). A new
egress path or response mode should add a case here.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    Firewall,
    HandleStore,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
    TraceStore,
)
from weaver_kernel.adapters._base import frame_to_payload
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.errors import DriverError
from weaver_kernel.firewall.redaction import StreamRedactor, redact
from weaver_kernel.models import CapabilityRequest, Handle, ResponseMode

# ── Canaries — these strings exist nowhere else in the codebase ────────────────

_CANARY_BEARER = "Bearer canary-zzz-9999-do-not-leak-token"
_CANARY_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.Qk9HVVNfQ0FOQVJZX1NJRw"
_CANARY_API_KEY_VALUE = "ZZZZ_CANARYKEY_ABCDEF12345"
_CANARY_CONN = "postgresql://canary:zzz-secret-pw@db.invalid/main"
_CANARY_EMAIL = "canary.victim@example.invalid"

# Every canary that the redaction pattern set is expected to catch.
_ALL_CANARIES = (
    _CANARY_BEARER,
    _CANARY_JWT,
    _CANARY_API_KEY_VALUE,
    _CANARY_CONN,
    _CANARY_EMAIL,
)


def _assert_no_canary(blob: str, *, path: str, canaries: tuple[str, ...] = _ALL_CANARIES) -> None:
    for canary in canaries:
        assert canary not in blob, f"{path}: canary {canary!r} escaped the firewall"


def _dump(obj: object) -> str:
    """Serialize anything to JSON text for a global negative assertion."""
    return json.dumps(obj, default=lambda o: getattr(o, "__dict__", str(o)))


# ── #149: depth fail-open ──────────────────────────────────────────────────────


def test_canary_below_max_depth_is_not_returned_verbatim() -> None:
    """A secret nested below ``max_depth`` must not flow through unredacted."""
    nested = {"l0": {"l1": {"l2": {"l3": {"note": f"auth={_CANARY_BEARER}"}}}}}
    redacted, _warnings = redact(nested, max_depth=3)
    _assert_no_canary(_dump(redacted), path="redact(depth>max_depth)")


def test_canary_string_at_depth_boundary_is_scrubbed() -> None:
    """A scalar string sitting *at* the depth boundary is still scrubbed."""
    # The list element is visited at depth == max_depth.
    redacted, _warnings = redact({"a": {"b": {"c": [f"key {_CANARY_BEARER}"]}}}, max_depth=3)
    _assert_no_canary(_dump(redacted), path="redact(string at boundary)")


# ── #150: handle expansion ─────────────────────────────────────────────────────


def _store_with_secret_rows() -> tuple[HandleStore, Handle]:
    store = HandleStore()
    rows = [
        {"id": 1, "name": "Alice", "note": f"call token {_CANARY_BEARER}"},
        {"id": 2, "name": "Bob", "note": f"db {_CANARY_CONN}"},
    ]
    handle = store.store("cap.customers", rows, principal_id="agent-1")
    return store, handle


def test_canary_never_leaks_through_handle_expand() -> None:
    """expand() must redact inline secrets in permitted fields (#150)."""
    store, handle = _store_with_secret_rows()
    frame = store.expand(handle, query={}, principal_id="agent-1")
    _assert_no_canary(_dump(frame), path="HandleStore.expand")
    # The non-secret data is still present (redaction is surgical).
    assert any("Alice" in _dump(row) for row in frame.table_preview)


def test_canary_never_leaks_through_field_projected_expand() -> None:
    """A permitted field carrying a secret is scrubbed, not just dropped."""
    store, handle = _store_with_secret_rows()
    frame = store.expand(handle, query={"fields": ["id", "note"]}, principal_id="agent-1")
    _assert_no_canary(_dump(frame), path="HandleStore.expand(fields=note)")


# ── #151: cross-chunk streaming ────────────────────────────────────────────────


def _collect_stream_text(parts: list[str]) -> str:
    fw = Firewall()

    async def _chunks() -> AsyncIterator[dict[str, Any]]:
        for part in parts:
            yield {"text": part}
        yield {"__is_final__": True}

    async def _run() -> str:
        out: list[str] = []
        async for frame in fw.apply_stream(
            _chunks(),
            action_id="s1",
            capability_id="cap.stream",
            principal_id="u1",
            principal_roles=["reader"],
            response_mode="summary",
        ):
            out.append(_dump(frame))
        return "".join(out)

    return asyncio.run(_run())


@pytest.mark.parametrize(
    "parts",
    [
        ["prefix Bearer canary-zzz-9999", "-do-not-leak-token suffix"],
        ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ", ".Qk9HVVNfQ0FOQVJZX1NJRw end"],
        ["host postgresql://canary:zzz-secret", "-pw@db.invalid/main tail"],
    ],
)
def test_canary_split_across_chunks_is_redacted(parts: list[str]) -> None:
    """A secret whose characters span two chunks must not leak (#151)."""
    combined = _collect_stream_text(parts)
    _assert_no_canary(combined, path="Firewall.apply_stream(split)")


def test_stream_redactor_preserves_full_text_minus_secret() -> None:
    """Holdback must not drop non-secret text — only the secret is replaced."""
    redactor = StreamRedactor(overlap=8)
    emitted = ""
    for piece in ["hello wor", "ld and ", f"{_CANARY_BEARER}", " bye"]:
        text, _warns = redactor.feed(piece)
        emitted += text
    tail, _warns = redactor.flush()
    emitted += tail
    assert "hello world and" in emitted
    assert "bye" in emitted
    _assert_no_canary(emitted, path="StreamRedactor", canaries=(_CANARY_BEARER,))


# ── #172: trace args and error text ────────────────────────────────────────────


def _build_kernel(
    handler: Any, *, capability_id: str = "billing.refund"
) -> tuple[Kernel, Principal]:
    registry = CapabilityRegistry()
    cap = Capability(
        capability_id=capability_id,
        name="refund",
        description="issue refund",
        safety_class=SafetyClass.WRITE,
    )
    registry.register(cap)
    driver = InMemoryDriver(driver_id="billing")
    driver.register_handler(capability_id, handler)
    router = StaticRouter(routes={capability_id: ["billing"]})
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="test-secret-do-not-use-in-prod"),
        router=router,
        handle_store=HandleStore(),
        trace_store=TraceStore(),
    )
    kernel.register_driver(driver)
    return kernel, Principal(principal_id="agent-1", roles=["admin"])


def _grant_and_invoke(
    kernel: Kernel,
    principal: Principal,
    capability_id: str,
    args: dict[str, Any],
    *,
    response_mode: ResponseMode = "summary",
):
    request = CapabilityRequest(capability_id=capability_id, goal="canary test")
    grant = kernel.grant_capability(request, principal, justification="canary regression coverage")
    return asyncio.run(
        kernel.invoke(grant.token, principal=principal, args=args, response_mode=response_mode)
    )


def test_canary_in_non_memory_arg_is_redacted_in_trace() -> None:
    """A secret passed as an argument to a non-memory capability is scrubbed (#172)."""
    kernel, principal = _build_kernel(lambda _ctx: [{"ok": True}])
    _grant_and_invoke(
        kernel,
        principal,
        "billing.refund",
        {"reference": f"authorize {_CANARY_BEARER}", "amount": 42},
    )
    trace = kernel._trace_store.list_all()[-1]
    _assert_no_canary(_dump(trace.args), path="ActionTrace.args")
    # Non-sensitive scalar args are preserved.
    assert trace.args.get("amount") == 42


def test_canary_in_driver_error_is_redacted_in_trace() -> None:
    """A secret embedded in a driver error message is scrubbed before tracing (#172)."""

    def _boom(_ctx: ExecutionContext) -> Any:
        raise DriverError(f"upstream rejected token {_CANARY_BEARER}")

    kernel, principal = _build_kernel(_boom)
    with pytest.raises(DriverError):
        _grant_and_invoke(kernel, principal, "billing.refund", {"amount": 1})
    trace = kernel._trace_store.list_all()[-1]
    assert trace.error is not None
    _assert_no_canary(trace.error, path="ActionTrace.error", canaries=(_CANARY_BEARER,))


# ── Adapter-rendered egress ────────────────────────────────────────────────────


def test_canary_never_leaks_through_adapter_payload() -> None:
    """The adapter tool-result payload renders only a redacted Frame."""
    kernel, principal = _build_kernel(
        lambda _ctx: [{"id": 1, "secret_note": f"api_key={_CANARY_API_KEY_VALUE}"}]
    )
    frame = _grant_and_invoke(kernel, principal, "billing.refund", {"amount": 1})
    payload = frame_to_payload(frame)
    _assert_no_canary(_dump(payload), path="frame_to_payload")


def test_canary_never_leaks_through_raw_admin_frame() -> None:
    """The admin-only ``raw`` response mode still redacts inline secrets (#206)."""
    kernel, principal = _build_kernel(
        lambda _ctx: [{"id": 1, "secret_note": f"db {_CANARY_CONN}"}]
    )
    frame = _grant_and_invoke(
        kernel, principal, "billing.refund", {"amount": 1}, response_mode="raw"
    )
    # Confirm we exercised the raw path, not the admin-role fallback to summary.
    assert frame.response_mode == "raw"
    _assert_no_canary(_dump(frame), path="response_mode=raw")
    _assert_no_canary(_dump(frame_to_payload(frame)), path="frame_to_payload(raw)")
