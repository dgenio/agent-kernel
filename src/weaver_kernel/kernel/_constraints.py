"""Invoke-time enforcement: signed argument constraints (#183) and per-invocation
rate limiting (#170).

Both checks run on the execution path — *after* token verification, *before* the
driver runs and *before* budget is reserved — so a violation costs nothing
downstream. They are invoked from :meth:`Kernel.invoke` and
:meth:`Kernel.invoke_stream` alike (via :func:`run_pre_invoke_checks`), so the
streaming path is covered too. Dry-run evaluates the identical checks for parity
but never records rate-limit usage. On a real (non-dry-run) violation a failure
:class:`~weaver_kernel.models.ActionTrace` is recorded before the error
propagates, so I-02 (auditability) holds.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..enums import SafetyClass
from ..errors import AgentKernelError, PolicyDenied, TokenScopeError
from ..models import Capability, Principal, ResponseMode
from ..policy_reasons import DenialReason
from ..tokens import CapabilityToken
from ._invoke import record_failure_trace

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

ARG_CONSTRAINTS_KEY = "args"
"""Token-constraint key carrying the argument-level rules enforced at invoke (#183)."""


def validate_invoke_rate_limits(
    limits: dict[SafetyClass, tuple[int, float]] | None,
) -> None:
    """Reject a malformed ``invoke_rate_limits`` configuration at construction (#170).

    Args:
        limits: The per-safety-class ``(max_invocations, window_seconds)`` map, or
            ``None``.

    Raises:
        AgentKernelError: If any limit is < 1 or any window is <= 0.
    """
    if not limits:
        return
    for safety_class, (limit, window) in limits.items():
        if limit < 1 or window <= 0:
            raise AgentKernelError(
                f"Invalid invoke_rate_limits for {safety_class.value}: limit must be "
                f">= 1 and window must be > 0, got limit={limit}, window={window}."
            )


def enforce_arg_constraints(args: dict[str, Any], constraints: dict[str, Any]) -> None:
    """Enforce a token's signed ``constraints["args"]`` against invocation *args* (#183).

    The v1 vocabulary is deliberately tiny and deterministic — no expression
    language (see ``docs/agent-context/invariants.md`` on determinism):

    * ``allowed_keys``: every argument key must be in this list.
    * ``pinned``: each named key must be present and exactly equal to the value.
    * ``prefix``: each named key must be a string starting with the given prefix.

    Only top-level argument keys are inspected in v1. A ``pinned``/``prefix`` rule
    on an omitted argument fails closed.

    Args:
        args: The invocation arguments.
        constraints: The verified token's ``constraints`` mapping.

    Raises:
        TokenScopeError: If any argument violates the spec, carrying
            :attr:`~weaver_kernel.policy_reasons.DenialReason.ARG_CONSTRAINT_VIOLATION`.
    """
    spec = constraints.get(ARG_CONSTRAINTS_KEY)
    if not spec:
        return
    if not isinstance(spec, dict):
        raise _violation(f"malformed 'args' constraint: expected an object, got {spec!r}.")

    allowed = spec.get("allowed_keys")
    if allowed is not None:
        extra = sorted(set(args) - set(allowed))
        if extra:
            raise _violation(f"arguments {extra} are not permitted by the token's allowed_keys.")

    pinned = spec.get("pinned")
    if isinstance(pinned, dict):
        for key, expected in pinned.items():
            if key not in args or args[key] != expected:
                raise _violation(f"argument '{key}' must equal the token's pinned value.")

    prefix = spec.get("prefix")
    if isinstance(prefix, dict):
        for key, required_prefix in prefix.items():
            value = args.get(key)
            if not isinstance(value, str) or not value.startswith(required_prefix):
                raise _violation(
                    f"argument '{key}' must be a string starting with '{required_prefix}'."
                )


def _violation(message: str) -> TokenScopeError:
    """Build a :class:`TokenScopeError` for an argument-constraint violation."""
    return TokenScopeError(message, reason_code=DenialReason.ARG_CONSTRAINT_VIOLATION)


def _check_invoke_rate(
    kernel: Kernel,
    token: CapabilityToken,
    capability: Capability,
    principal: Principal,
    *,
    dry_run: bool,
) -> None:
    """Apply the optional invoke-time sliding-window rate limit (#170).

    Independent of and additional to the grant-time limit. The check-then-record
    pair runs with no ``await`` between them, so concurrent invokes cannot
    over-admit. Dry-run checks but never records.
    """
    limits = kernel._invoke_rate_limits
    limit_window = limits.get(capability.safety_class)
    if limit_window is None:
        return
    limit, window = limit_window
    key = f"{principal.principal_id}:{token.capability_id}"
    if not kernel._invoke_limiter.check(key, limit, window):
        raise PolicyDenied(
            f"Invoke-time rate limit exceeded: {limit} {capability.safety_class.value} "
            f"invocations per {window}s for principal '{principal.principal_id}'.",
            reason_code=DenialReason.RATE_LIMITED,
        )
    if not dry_run:
        kernel._invoke_limiter.record(key)


def run_pre_invoke_checks(
    kernel: Kernel,
    *,
    token: CapabilityToken,
    capability: Capability,
    principal: Principal,
    args: dict[str, Any],
    response_mode: ResponseMode,
    dry_run: bool,
) -> None:
    """Run invoke-time argument-constraint and rate-limit checks (#183, #170).

    Args:
        kernel: The orchestrating :class:`Kernel`.
        token: The already-verified capability token.
        capability: The resolved capability (its sensitivity tags the audit trace).
        principal: The invoking principal.
        args: The invocation arguments.
        response_mode: The caller-requested response mode (recorded on a denial trace).
        dry_run: When ``True``, evaluate the checks for parity but record no
            rate-limit usage and write no audit trace.

    Raises:
        TokenScopeError: If *args* violate a signed argument constraint (#183).
        PolicyDenied: If the invoke-time rate limit is exceeded (#170).
    """
    try:
        enforce_arg_constraints(args, token.constraints)
        _check_invoke_rate(kernel, token, capability, principal, dry_run=dry_run)
    except (TokenScopeError, PolicyDenied) as exc:
        if not dry_run:
            # I-02: a denied execution attempt is still auditable. No driver ran
            # and no budget was reserved, so record a failure trace directly.
            record_failure_trace(
                action_id=str(uuid.uuid4()),
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                token_id=token.token_id,
                args=args,
                response_mode=response_mode,
                error_message=str(exc),
                trace_store=kernel._traces,
                sensitivity=capability.sensitivity,
                driver_id="",
            )
            kernel._stats.on_invocation(
                failed=True, fallback=False, redacted=False, downgraded=False
            )
        raise


# Re-exported for the kernel constructor's clock injection typing.
InvokeRateClock = Callable[[], float]

__all__ = [
    "ARG_CONSTRAINTS_KEY",
    "enforce_arg_constraints",
    "run_pre_invoke_checks",
    "validate_invoke_rate_limits",
    "InvokeRateClock",
]
