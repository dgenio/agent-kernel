"""``weaver-kernel doctor`` — preflight checks for a local setup (issue #124).

Verifies environment, optional extras, and self-test vectors for token
signing/verification and the audit chain. Exits non-zero when a check *errors*
(broken setup); an insecure demo-only configuration (no ``WEAVER_KERNEL_SECRET``)
is reported as a warning, not a failure.

Never prints secret material — only whether a secret is configured.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import logging
import os
import sys
from dataclasses import dataclass

from .._secrets import SECRET_ENV_VAR
from ..models import ActionTrace
from ..stores.audit_chain import build_record, verify_chain
from ..tokens import CapabilityToken, HMACTokenProvider

OK = "ok"
WARN = "warn"
ERROR = "error"


@dataclass(slots=True)
class Check:
    """A single doctor check outcome."""

    name: str
    status: str
    detail: str


def _check_python() -> Check:
    v = sys.version_info
    detail = f"{v.major}.{v.minor}.{v.micro}"
    status = OK if v >= (3, 10) else ERROR
    return Check("python", status, detail)


def _check_secret() -> Check:
    if os.environ.get(SECRET_ENV_VAR):
        return Check("secret", OK, f"{SECRET_ENV_VAR} is set.")
    return Check(
        "secret",
        WARN,
        f"{SECRET_ENV_VAR} is not set — using an ephemeral dev secret "
        "(tokens/audit signatures do not survive restarts). Set it in production.",
    )


def _check_extra(name: str, module: str) -> Check:
    available = importlib.util.find_spec(module) is not None
    return Check(
        f"extra:{name}",
        OK if available else WARN,
        f"{module} {'available' if available else 'not installed'}.",
    )


def _check_token_vector() -> Check:
    """Issue, verify, then tamper with a token to prove signing works."""
    provider = HMACTokenProvider(secret="weaver-kernel-doctor-test-vector")
    token = provider.issue("doctor.cap", "doctor-principal")
    try:
        provider.verify(
            token,
            expected_principal_id="doctor-principal",
            expected_capability_id="doctor.cap",
        )
    except Exception as exc:  # pragma: no cover - would indicate a broken build
        return Check("token_vector", ERROR, f"verify() rejected a valid token: {exc}")
    tampered = CapabilityToken(
        token_id=token.token_id,
        capability_id=token.capability_id,
        principal_id=token.principal_id,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        constraints=token.constraints,
        audit_id=token.audit_id,
        signature="0" * len(token.signature),
    )
    # The tamper check deliberately fails verification; silence the expected
    # WARNING so the doctor output stays clean.
    tok_logger = logging.getLogger("weaver_kernel.tokens")
    previous_level = tok_logger.level
    tok_logger.setLevel(logging.ERROR)
    try:
        provider.verify(
            tampered,
            expected_principal_id="doctor-principal",
            expected_capability_id="doctor.cap",
        )
    except Exception:
        return Check("token_vector", OK, "sign/verify and tamper-detection pass.")
    finally:
        tok_logger.setLevel(previous_level)
    return Check("token_vector", ERROR, "verify() accepted a tampered signature.")


def _check_audit_chain_vector() -> Check:
    """Build a tiny chain, mutate it, and confirm verification flips."""
    secret = "weaver-kernel-doctor-test-vector"
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    trace = ActionTrace(
        action_id="doctor-1",
        capability_id="doctor.cap",
        principal_id="doctor-principal",
        token_id="doctor-tok",
        invoked_at=now,
        args={},
        response_mode="summary",
        driver_id="memory",
    )
    from ..stores._trace_codec import encode_trace
    from ..stores.audit_chain import GENESIS_HASH

    record = build_record(0, GENESIS_HASH, encode_trace(trace), secret=secret)
    if not verify_chain([record], secret=secret).ok:
        return Check("audit_chain", ERROR, "a valid single-record chain failed to verify.")
    record.trace["principal_id"] = "tampered"
    if verify_chain([record], secret=secret).ok:
        return Check("audit_chain", ERROR, "a mutated chain still verified.")
    return Check("audit_chain", OK, "hash chain detects mutation.")


def run_checks() -> list[Check]:
    """Run every doctor check and return the outcomes."""
    return [
        _check_python(),
        _check_secret(),
        _check_extra("policy", "yaml"),
        _check_extra("mcp", "mcp"),
        _check_extra("otel", "opentelemetry"),
        _check_token_vector(),
        _check_audit_chain_vector(),
    ]


def cmd_doctor(args: argparse.Namespace) -> int:
    """Handle ``doctor``. Returns non-zero if any check errored."""
    checks = run_checks()
    if args.json:
        print(
            json.dumps([{"name": c.name, "status": c.status, "detail": c.detail} for c in checks])
        )
    else:
        symbols = {OK: "✓", WARN: "!", ERROR: "✗"}
        for c in checks:
            print(f"  {symbols[c.status]} {c.name:<16} {c.detail}")
    return 1 if any(c.status == ERROR for c in checks) else 0


def build_doctor_parser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``doctor`` subcommand on *subparsers*."""
    doctor = subparsers.add_parser("doctor", help="Preflight-check the local setup.")
    doctor.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    doctor.set_defaults(handler=cmd_doctor)
