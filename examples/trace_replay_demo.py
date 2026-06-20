"""trace_replay_demo.py — validate a policy change against recorded decisions (#213).

Policy edits are the highest-blast-radius change in the kernel: one rule can
silently widen access or break every agent. This script records a corpus of
grant decisions under a *baseline* policy, then replays it against a *candidate*
policy and prints the decision diff — the deterministic "what would have
changed" answer a policy author wants before shipping.

The candidate here disables ``billing.list_invoices`` while leaving every other
rule intact, so the diff shows exactly one ``allow_to_deny`` flip. Everything is
offline and deterministic. Run with: ``python examples/trace_replay_demo.py``
"""

from __future__ import annotations

from typing import Any

from weaver_kernel import (
    Capability,
    DecisionRecord,
    DefaultPolicyEngine,
    Principal,
    SafetyClass,
    record_decision,
    replay,
)
from weaver_kernel.errors import PolicyDenied
from weaver_kernel.models import CapabilityRequest
from weaver_kernel.policy_reasons import DenialReason

_LIST = Capability(
    capability_id="billing.list_invoices",
    name="List Invoices",
    description="List invoices",
    safety_class=SafetyClass.READ,
)
_DELETE = Capability(
    capability_id="billing.delete_invoice",
    name="Delete Invoice",
    description="Delete an invoice",
    safety_class=SafetyClass.DESTRUCTIVE,
)

_READER = Principal(principal_id="agent-007", roles=["reader"], attributes={"tenant": "acme"})


class _CandidatePolicy:
    """Baseline policy plus a new rule disabling ``billing.list_invoices``."""

    def __init__(self, base: DefaultPolicyEngine) -> None:
        self._base = base

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> Any:
        if capability.capability_id == "billing.list_invoices":
            raise PolicyDenied(
                "list_invoices retired by 2026-Q3 policy",
                reason_code=DenialReason.EXPLICIT_DENY_RULE.value,
            )
        return self._base.evaluate(request, capability, principal, justification=justification)


def main() -> None:
    baseline = DefaultPolicyEngine()

    # Record the baseline decisions (a real corpus would come from history).
    records: list[DecisionRecord] = [
        record_decision(
            baseline,
            CapabilityRequest(capability_id="billing.list_invoices", goal="list"),
            _LIST,
            _READER,
            justification="monthly review",
        ),
        record_decision(
            baseline,
            CapabilityRequest(capability_id="billing.delete_invoice", goal="delete"),
            _DELETE,
            _READER,
            justification="cleanup",
        ),
    ]
    print("Baseline decisions:")
    for record in records:
        verdict = "allow" if record.baseline_allowed else f"deny({record.baseline_reason_code})"
        print(f"  {record.capability.capability_id:<24} -> {verdict}")

    diff = replay(records, _CandidatePolicy(baseline))

    print(f"\nReplayed {diff.evaluated} decisions against the candidate policy.")
    print(f"Structural flips: {len(diff.flips)}")
    for flip in diff.flips:
        print(
            f"  {flip.record.capability.capability_id:<24} {flip.kind}: "
            f"{flip.baseline_reason_code or 'allow'} -> {flip.candidate_reason_code or 'allow'}"
        )
    if diff.rate_limited:
        print(f"(rate-limit-dependent flips, surfaced separately: {len(diff.rate_limited)})")


if __name__ == "__main__":
    main()
