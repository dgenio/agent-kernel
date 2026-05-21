"""Dry-run result builder.

Split out of :mod:`kernel` to keep modules ≤ 300 lines (AGENTS.md). The
public ``Kernel.invoke(..., dry_run=True)`` API delegates to
:func:`build_dry_run_result`. This helper enforces the invariant that
the dry-run reports the response mode the caller would *actually*
receive at real-invoke time (see ``docs/agent-context/invariants.md``
— "Dry-run response-mode parity").
"""

from __future__ import annotations

from typing import Any, Literal

from ..enums import SafetyClass
from ..firewall.budget_manager import BudgetManager
from ..models import (
    Capability,
    DryRunResult,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
    ResponseMode,
    RoutePlan,
)
from ..policy_reasons import AllowReason
from ..tokens import CapabilityToken

_COST_MAP: dict[SafetyClass, Literal["low", "medium", "high"]] = {
    SafetyClass.READ: "low",
    SafetyClass.WRITE: "medium",
    SafetyClass.DESTRUCTIVE: "high",
}


def build_dry_run_result(
    *,
    token: CapabilityToken,
    principal: Principal,
    capability: Capability,
    plan: RoutePlan,
    args: dict[str, Any],
    response_mode: ResponseMode,
    budget_manager: BudgetManager | None,
) -> DryRunResult:
    """Construct the :class:`DryRunResult` for a dry-run invocation.

    The response mode is computed in the same order the real-invoke path
    uses: admin gate for ``raw`` first, then budget escalation if a
    :class:`BudgetManager` is attached. Operation resolution mirrors the
    drivers' own ``args.get("operation", capability_id)`` convention.
    """
    driver_id = plan.driver_ids[0] if plan.driver_ids else ""
    operation = str(args.get("operation", token.capability_id))

    effective_response_mode: ResponseMode = response_mode
    if response_mode == "raw" and "admin" not in principal.roles:
        effective_response_mode = "summary"
    if budget_manager is not None:
        effective_response_mode = budget_manager.suggested_mode(effective_response_mode)

    trace = PolicyDecisionTrace(
        engine="Kernel.invoke[dry_run]",
        capability_id=token.capability_id,
        principal_id=principal.principal_id,
        intent=None,
        scope_keys=[],
        steps=[
            PolicyTraceStep(
                name="token_verified",
                outcome="allowed",
                detail="Token verified; original policy decision was at grant time.",
                reason_code=str(AllowReason.TOKEN_VERIFIED),
            )
        ],
        final_outcome="allowed",
        final_reason_code=str(AllowReason.TOKEN_VERIFIED),
    )
    return DryRunResult(
        capability_id=token.capability_id,
        principal_id=principal.principal_id,
        policy_decision=PolicyDecision(
            allowed=True,
            reason="Token verified. Policy was evaluated at grant time.",
            constraints=dict(token.constraints),
            reason_code=str(AllowReason.TOKEN_VERIFIED),
            trace=trace,
        ),
        driver_id=driver_id,
        operation=operation,
        resolved_args=args,
        response_mode=effective_response_mode,
        budget_remaining=(budget_manager.remaining if budget_manager is not None else None),
        estimated_cost=_COST_MAP[capability.safety_class],
    )


__all__ = ["build_dry_run_result"]
