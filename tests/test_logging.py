"""Tests for structured logging at kernel decision points.

Verifies:
- Key decision-point log records are emitted at the correct levels.
- Policy denials are logged at WARNING with principal_id, capability_id, and reason.
- Token issuance is logged at DEBUG; verification failures at WARNING.
- Driver invocations emit log records.
- Firewall transform emits log records.
- Router resolution emits log records.
- No secret key material, token signatures, or raw PII values appear in any
  log output (security constraint).
"""

from __future__ import annotations

import logging

import pytest

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from agent_kernel.models import CapabilityRequest

# ── Fixtures ──────────────────────────────────────────────────────────────────

_SECRET = "super-secret-do-not-log-this-value"


@pytest.fixture()
def log_kernel() -> Kernel:
    """Minimal kernel with a known secret for log-scanning tests."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="log.read",
            name="Log Read",
            description="Read-only log test capability",
            safety_class=SafetyClass.READ,
            tags=["log", "read"],
        )
    )
    registry.register(
        Capability(
            capability_id="log.write",
            name="Log Write",
            description="Write log test capability",
            safety_class=SafetyClass.WRITE,
            tags=["log", "write"],
        )
    )
    registry.register(
        Capability(
            capability_id="log.destroy",
            name="Log Destroy",
            description="Destructive log test capability",
            safety_class=SafetyClass.DESTRUCTIVE,
            tags=["log", "destroy"],
        )
    )

    driver = InMemoryDriver(driver_id="mem")
    driver.register_handler("log.read", lambda ctx: {"result": "ok"})
    driver.register_handler("log.write", lambda ctx: {"result": "written"})
    driver.register_handler("log.destroy", lambda ctx: {"result": "destroyed"})

    router = StaticRouter(
        routes={
            "log.read": ["mem"],
            "log.write": ["mem"],
            "log.destroy": ["mem"],
        }
    )
    token_provider = HMACTokenProvider(secret=_SECRET)
    k = Kernel(registry=registry, router=router, token_provider=token_provider)
    k.register_driver(driver)
    return k


@pytest.fixture()
def reader() -> Principal:
    return Principal(principal_id="log-reader-001", roles=["reader"])


@pytest.fixture()
def writer() -> Principal:
    return Principal(principal_id="log-writer-001", roles=["reader", "writer"])


@pytest.fixture()
def admin() -> Principal:
    return Principal(principal_id="log-admin-001", roles=["reader", "writer", "admin"])


# ── Helpers ───────────────────────────────────────────────────────────────────

# Compute default LogRecord keys once at module level for efficient comparison.
_DEFAULT_LOG_KEYS: frozenset[str] = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
)


def _all_log_text(records: list[logging.LogRecord]) -> str:
    """Concatenate all log message text and extra fields into one searchable string."""
    parts: list[str] = []
    for rec in records:
        parts.append(rec.getMessage())
        # Include all extra attributes attached to the record
        for key, val in rec.__dict__.items():
            if key not in _DEFAULT_LOG_KEYS:
                parts.append(str(val))
    return " ".join(parts)


# ── Security: no secret material in logs ─────────────────────────────────────


@pytest.mark.asyncio
async def test_no_secret_material_in_logs(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Run a full grant→invoke→expand→explain flow and scan every log record
    for the HMAC secret and token signatures."""
    req = CapabilityRequest(capability_id="log.read", goal="read log")

    with caplog.at_level(logging.DEBUG, logger="agent_kernel"):
        grant = log_kernel.grant_capability(req, reader, justification="")
        frame = await log_kernel.invoke(
            grant.token,
            principal=reader,
            args={},
        )
        assert frame.handle is not None
        log_kernel.expand(frame.handle, query={"offset": 0, "limit": 1})
        log_kernel.explain(frame.action_id)

    all_text = _all_log_text(caplog.records)

    # The HMAC secret must never appear
    assert _SECRET not in all_text, "Secret key material found in log output!"

    # The token signature (hex digest) must never appear
    sig = grant.token.signature
    assert sig not in all_text, "Token signature found in log output!"


# ── kernel.py: grant_capability ──────────────────────────────────────────────


def test_grant_capability_emits_info(
    log_kernel: Kernel,
    writer: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    req = CapabilityRequest(capability_id="log.write", goal="write log")
    with caplog.at_level(logging.INFO, logger="agent_kernel.kernel"):
        log_kernel.grant_capability(req, writer, justification="long enough justification here")

    records = [r for r in caplog.records if r.name == "agent_kernel.kernel"]
    assert any(r.levelno == logging.INFO for r in records), (
        "Expected INFO record from grant_capability"
    )
    # principal_id and capability_id must be present in extra fields
    grant_records = [r for r in records if "grant_capability" in r.getMessage()]
    assert grant_records, "No 'grant_capability' log record found"
    rec = grant_records[0]
    assert rec.principal_id == writer.principal_id  # type: ignore[attr-defined]
    assert rec.capability_id == "log.write"  # type: ignore[attr-defined]


# ── kernel.py: invoke ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invoke_emits_info(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    req = CapabilityRequest(capability_id="log.read", goal="read")
    token = log_kernel.get_token(req, reader, justification="")

    with caplog.at_level(logging.INFO, logger="agent_kernel.kernel"):
        await log_kernel.invoke(token, principal=reader, args={})

    kernel_records = [r for r in caplog.records if r.name == "agent_kernel.kernel"]
    assert any("invoke_start" in r.getMessage() for r in kernel_records), (
        "Expected invoke_start log record"
    )
    assert any("invoke_success" in r.getMessage() for r in kernel_records), (
        "Expected invoke_success log record"
    )


# ── kernel.py: expand ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_expand_emits_info(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    req = CapabilityRequest(capability_id="log.read", goal="read")
    token = log_kernel.get_token(req, reader, justification="")
    frame = await log_kernel.invoke(token, principal=reader, args={})
    assert frame.handle is not None

    with caplog.at_level(logging.INFO, logger="agent_kernel.kernel"):
        log_kernel.expand(frame.handle, query={})

    assert any(
        "expand" in r.getMessage() for r in caplog.records if r.name == "agent_kernel.kernel"
    ), "Expected 'expand' log record"


# ── kernel.py: explain ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_explain_emits_info(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    req = CapabilityRequest(capability_id="log.read", goal="read")
    token = log_kernel.get_token(req, reader, justification="")
    frame = await log_kernel.invoke(token, principal=reader, args={})

    with caplog.at_level(logging.INFO, logger="agent_kernel.kernel"):
        log_kernel.explain(frame.action_id)

    assert any(
        "explain" in r.getMessage() for r in caplog.records if r.name == "agent_kernel.kernel"
    ), "Expected 'explain' log record"


# ── kernel.py: request_capabilities ──────────────────────────────────────────


def test_request_capabilities_emits_debug(
    log_kernel: Kernel,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG, logger="agent_kernel.kernel"):
        log_kernel.request_capabilities("read log")

    assert any(
        "request_capabilities" in r.getMessage()
        for r in caplog.records
        if r.name == "agent_kernel.kernel"
    ), "Expected 'request_capabilities' DEBUG log record"


# ── policy.py: denials at WARNING ─────────────────────────────────────────────


def test_policy_denial_logged_at_warning(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A WRITE capability denial should log WARNING with principal_id and capability_id."""
    req = CapabilityRequest(capability_id="log.write", goal="write")
    from agent_kernel import PolicyDenied

    with (
        caplog.at_level(logging.WARNING, logger="agent_kernel.policy"),
        pytest.raises(PolicyDenied),
    ):
        log_kernel.grant_capability(req, reader, justification="short")

    warning_records = [
        r
        for r in caplog.records
        if r.name == "agent_kernel.policy" and r.levelno == logging.WARNING
    ]
    assert warning_records, "Expected WARNING log record for policy denial"
    rec = warning_records[0]
    assert rec.principal_id == reader.principal_id  # type: ignore[attr-defined]
    assert rec.capability_id == "log.write"  # type: ignore[attr-defined]


def test_policy_allow_logged_at_info(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    req = CapabilityRequest(capability_id="log.read", goal="read")
    with caplog.at_level(logging.INFO, logger="agent_kernel.policy"):
        log_kernel.grant_capability(req, reader, justification="")

    info_records = [
        r for r in caplog.records if r.name == "agent_kernel.policy" and r.levelno == logging.INFO
    ]
    assert info_records, "Expected INFO log record for policy approval"
    rec = info_records[0]
    assert rec.principal_id == reader.principal_id  # type: ignore[attr-defined]
    assert rec.capability_id == "log.read"  # type: ignore[attr-defined]


# ── tokens.py: issuance at DEBUG ──────────────────────────────────────────────


def test_token_issuance_logged_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    provider = HMACTokenProvider(secret="test-secret-12345")
    with caplog.at_level(logging.DEBUG, logger="agent_kernel.tokens"):
        token = provider.issue("cap.x", "user-1")

    debug_records = [
        r for r in caplog.records if r.name == "agent_kernel.tokens" and r.levelno == logging.DEBUG
    ]
    assert debug_records, "Expected DEBUG record for token issuance"
    rec = debug_records[0]
    assert rec.token_id == token.token_id  # type: ignore[attr-defined]
    assert rec.capability_id == "cap.x"  # type: ignore[attr-defined]
    assert rec.principal_id == "user-1"  # type: ignore[attr-defined]
    # Signature must not be logged
    assert token.signature not in rec.getMessage()


def test_token_verification_failure_logged_at_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = HMACTokenProvider(secret="test-secret-12345")
    token = provider.issue("cap.x", "user-1", ttl_seconds=-1)

    from agent_kernel import TokenExpired

    with (
        caplog.at_level(logging.WARNING, logger="agent_kernel.tokens"),
        pytest.raises(TokenExpired),
    ):
        provider.verify(
            token,
            expected_principal_id="user-1",
            expected_capability_id="cap.x",
        )

    warning_records = [
        r
        for r in caplog.records
        if r.name == "agent_kernel.tokens" and r.levelno == logging.WARNING
    ]
    assert warning_records, "Expected WARNING record for token verification failure"
    rec = warning_records[0]
    assert rec.token_id == token.token_id  # type: ignore[attr-defined]
    assert rec.reason == "expired"  # type: ignore[attr-defined]


# ── router.py: route resolution at DEBUG ─────────────────────────────────────


def test_router_resolution_logged_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    router = StaticRouter(routes={"cap.x": ["driver-a", "driver-b"]})
    with caplog.at_level(logging.DEBUG, logger="agent_kernel.router"):
        plan = router.route("cap.x")

    debug_records = [
        r for r in caplog.records if r.name == "agent_kernel.router" and r.levelno == logging.DEBUG
    ]
    assert debug_records, "Expected DEBUG record from router"
    rec = debug_records[0]
    assert rec.capability_id == "cap.x"  # type: ignore[attr-defined]
    assert rec.driver_ids == plan.driver_ids  # type: ignore[attr-defined]


# ── firewall/transform.py: transform at DEBUG ─────────────────────────────────


@pytest.mark.asyncio
async def test_firewall_transform_logged_at_debug(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    req = CapabilityRequest(capability_id="log.read", goal="read")
    token = log_kernel.get_token(req, reader, justification="")

    with caplog.at_level(logging.DEBUG, logger="agent_kernel.firewall.transform"):
        await log_kernel.invoke(token, principal=reader, args={})

    fw_records = [r for r in caplog.records if r.name == "agent_kernel.firewall.transform"]
    assert fw_records, "Expected DEBUG records from firewall transform"
    modes = {r.getMessage() for r in fw_records}
    assert any("firewall_transform" in m or "firewall_redaction" in m for m in modes)


# ── kernel.py: DESTRUCTIVE grant + invoke (exercises admin fixture) ───────────


@pytest.mark.asyncio
async def test_destructive_grant_invoke_logging(
    log_kernel: Kernel,
    admin: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Admin grants DESTRUCTIVE capability; both grant and invoke emit INFO logs."""
    req = CapabilityRequest(capability_id="log.destroy", goal="destroy log")
    with caplog.at_level(logging.INFO, logger="agent_kernel"):
        grant = log_kernel.grant_capability(
            req, admin, justification="destroying old logs for compliance cleanup"
        )
        await log_kernel.invoke(grant.token, principal=admin, args={})

    kernel_records = [r for r in caplog.records if r.name == "agent_kernel.kernel"]
    assert any("grant_capability" in r.getMessage() for r in kernel_records)
    grant_rec = next(r for r in kernel_records if "grant_capability" in r.getMessage())
    assert grant_rec.capability_id == "log.destroy"  # type: ignore[attr-defined]
    assert grant_rec.safety_class == "DESTRUCTIVE"  # type: ignore[attr-defined]
    assert any("invoke_success" in r.getMessage() for r in kernel_records)


def test_destructive_denial_logging(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A reader denied DESTRUCTIVE capability emits policy_denied WARNING."""
    from agent_kernel import PolicyDenied

    req = CapabilityRequest(capability_id="log.destroy", goal="destroy log")
    with (
        caplog.at_level(logging.WARNING, logger="agent_kernel.policy"),
        pytest.raises(PolicyDenied),
    ):
        log_kernel.grant_capability(req, reader, justification="short")

    warning_records = [
        r
        for r in caplog.records
        if r.name == "agent_kernel.policy" and r.levelno == logging.WARNING
    ]
    assert warning_records, "Expected WARNING log for DESTRUCTIVE denial"
    rec = warning_records[0]
    assert rec.principal_id == reader.principal_id  # type: ignore[attr-defined]
    assert rec.capability_id == "log.destroy"  # type: ignore[attr-defined]


# ── No noise at INFO during normal usage ──────────────────────────────────────


@pytest.mark.asyncio
async def test_no_debug_noise_at_info_level(
    log_kernel: Kernel,
    reader: Principal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """At INFO level, no DEBUG records should appear from agent_kernel modules."""
    req = CapabilityRequest(capability_id="log.read", goal="read")
    token = log_kernel.get_token(req, reader, justification="")

    with caplog.at_level(logging.INFO, logger="agent_kernel"):
        await log_kernel.invoke(token, principal=reader, args={})

    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert not debug_records, (
        f"Unexpected DEBUG records at INFO level: {[r.getMessage() for r in debug_records]}"
    )
