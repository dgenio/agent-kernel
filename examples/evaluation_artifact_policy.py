"""evaluation_artifact_policy.py — gate agent actions on evaluation artifacts.

The written walkthrough lives in ``docs/integrations/evaluation_artifacts.md``.
This script is the runnable companion. It shows the Weaver-ecosystem pattern for
letting an agent *summarize* a statistical/model-evaluation artifact (such as an
offline policy-evaluation report) while *denying* high-impact actions —
deployment or automatic rollout — when the artifact's support diagnostics say
the headline estimate is not trustworthy.

The key distinction the policy enforces:

  * **Summarizing evidence** is always allowed (with caveats surfaced).
  * **Acting on evidence** (recommending deployment / automatic rollout) is
    gated: it is downgraded to a *manual-review* recommendation whenever the
    support diagnostics are weak, the decision is unstable, or warnings exist.

``assess_artifact`` is a generic, producer-agnostic policy layer: it inspects
documented fields (``support_health``, ``warnings``, ``uncertainty``,
``decision_stable``, ``recommendation.intent``, ``limitations``) on a plain
dict artifact, so it works for any producer — not just ``skdr-eval``. agent-kernel
does **not** implement offline policy evaluation or any statistical estimation,
and takes no dependency on a specific producer; the artifacts here are fixtures.

Run with: ``python examples/evaluation_artifact_policy.py``
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

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
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.models import CapabilityRequest, ImplementationRef

_SECRET = "example-secret-do-not-use-in-prod"

# Stable decision codes (see docs/integrations/evaluation_artifacts.md). Kept as
# string constants so callers branch on a stable vocabulary, not on prose.
ALLOW_SUMMARY = "allow_summary"
ALLOW_MANUAL_REVIEW_RECOMMENDATION = "allow_manual_review_recommendation"
REQUIRE_HUMAN_REVIEW = "require_human_review"
DENY_DEPLOYMENT_RECOMMENDATION = "deny_deployment_recommendation"
DENY_AUTOMATIC_ROLLOUT = "deny_automatic_rollout"

# Support-health states an artifact may report, safest first when defaulting.
_HEALTH_OK = "ok"
_HEALTH_CAUTION = "caution"
_HEALTH_HIGH_RISK = "high_risk"
_KNOWN_HEALTH = frozenset({_HEALTH_OK, _HEALTH_CAUTION, _HEALTH_HIGH_RISK})


@dataclass(slots=True)
class ArtifactDecision:
    """The outcome of assessing an evaluation artifact for a deployment intent.

    ``allowed_actions`` / ``denied_actions`` carry the stable decision codes; the
    convenience flag :attr:`allows_deployment` is the top-level gate the host
    uses to decide whether to grant the high-impact capability. ``reasons``
    explains *why* — these strings are recorded in the audit trace when an
    action is downgraded.
    """

    support_health: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allows_deployment(self) -> bool:
        """True only when recommending deployment is not a denied action."""
        return DENY_DEPLOYMENT_RECOMMENDATION not in self.denied_actions


def assess_artifact(artifact: dict[str, Any]) -> ArtifactDecision:
    """Decide which actions an agent may take given an evaluation *artifact*.

    Generic and producer-agnostic: reads documented fields off a plain dict.
    Deployment is permitted only when *several* signals agree — support health
    is ``ok``, the decision is stable, no warnings are present, and the
    artifact's own recommendation does not say to hold. Relying on more than a
    single numeric metric is deliberate (a good point estimate with poor support
    must still be blocked).

    Args:
        artifact: A mapping with optional keys ``support_health`` (``"ok"`` /
            ``"caution"`` / ``"high_risk"``), ``warnings`` (list),
            ``decision_stable`` (bool), ``uncertainty`` (mapping/str),
            ``recommendation`` (mapping with ``intent``), and ``limitations``
            (list). Missing fields default to the safest interpretation.

    Returns:
        An :class:`ArtifactDecision`. Summarizing is always allowed; deployment
        is allowed only when every gating signal is satisfied.
    """
    # Default to — and normalise any unknown value to — the safest state, so a
    # missing or garbage support_health can never read as deployable.
    raw_health = str(artifact.get("support_health", _HEALTH_HIGH_RISK))
    support_health = raw_health if raw_health in _KNOWN_HEALTH else _HEALTH_HIGH_RISK
    warnings = list(artifact.get("warnings") or [])
    decision_stable = bool(artifact.get("decision_stable", False))
    recommendation = artifact.get("recommendation") or {}
    intent = (
        str(recommendation.get("intent", "")).lower() if isinstance(recommendation, dict) else ""
    )

    reasons: list[str] = []
    if support_health != _HEALTH_OK:
        reasons.append(f"support_health={support_health}")
    if not decision_stable:
        reasons.append("decision is not stable")
    if warnings:
        reasons.append(f"{len(warnings)} warning(s): {', '.join(str(w) for w in warnings)}")
    if intent in {"hold", "do_not_deploy", "manual_review"}:
        reasons.append(f"artifact recommends '{intent}'")

    # Summarizing evidence is always allowed.
    allowed: list[str] = [ALLOW_SUMMARY]
    denied: list[str] = []

    if reasons:
        # Acting on the evidence is downgraded to a manual-review recommendation.
        allowed.append(ALLOW_MANUAL_REVIEW_RECOMMENDATION)
        denied.extend([DENY_DEPLOYMENT_RECOMMENDATION, DENY_AUTOMATIC_ROLLOUT])
        if support_health == _HEALTH_HIGH_RISK:
            allowed.append(REQUIRE_HUMAN_REVIEW)

    return ArtifactDecision(
        support_health=support_health,
        allowed_actions=tuple(allowed),
        denied_actions=tuple(denied),
        reasons=tuple(reasons),
    )


def build_kernel() -> Kernel:
    """Wire a kernel with a summarize READ and two gated WRITE recommendations."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="eval.summarize_artifact",
            name="Summarize Evaluation Artifact",
            description="Summarize an evaluation artifact and surface its caveats",
            safety_class=SafetyClass.READ,
            tags=["eval", "artifact", "summarize", "report"],
            impl=ImplementationRef(driver_id="memory", operation="summarize_artifact"),
        )
    )
    registry.register(
        Capability(
            capability_id="eval.recommend_deployment",
            name="Recommend Deployment",
            description="Recommend deploying/rolling out the evaluated candidate",
            safety_class=SafetyClass.WRITE,
            tags=["eval", "deploy", "rollout", "recommendation"],
            impl=ImplementationRef(driver_id="memory", operation="recommend_deployment"),
        )
    )
    registry.register(
        Capability(
            capability_id="eval.recommend_manual_review",
            name="Recommend Manual Review",
            description="Recommend human review / improving logs instead of deploying",
            safety_class=SafetyClass.WRITE,
            tags=["eval", "manual", "review", "recommendation"],
            impl=ImplementationRef(driver_id="memory", operation="recommend_manual_review"),
        )
    )

    driver = InMemoryDriver()

    def summarize_artifact(ctx: ExecutionContext) -> dict[str, Any]:
        artifact = ctx.args.get("artifact", {})
        decision = assess_artifact(artifact)
        return {
            "artifact_type": artifact.get("artifact_type", "evaluation"),
            "support_health": decision.support_health,
            "caveats": list(artifact.get("limitations") or []) + list(decision.reasons),
        }

    def recommend_deployment(ctx: ExecutionContext) -> dict[str, Any]:
        return {"recommendation": "deploy", "candidate": ctx.args.get("candidate", "candidate")}

    def recommend_manual_review(ctx: ExecutionContext) -> dict[str, Any]:
        return {"recommendation": "manual_review", "reason": ctx.args.get("reason", "")}

    driver.register_handler("summarize_artifact", summarize_artifact)
    driver.register_handler("recommend_deployment", recommend_deployment)
    driver.register_handler("recommend_manual_review", recommend_manual_review)

    router = StaticRouter(
        routes={
            "eval.summarize_artifact": ["memory"],
            "eval.recommend_deployment": ["memory"],
            "eval.recommend_manual_review": ["memory"],
        }
    )
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret=_SECRET),
        router=router,
    )
    kernel.register_driver(driver)
    return kernel


async def summarize(kernel: Kernel, principal: Principal, artifact: dict[str, Any]) -> str:
    """Summarize the artifact (always allowed) and return the audit ``action_id``."""
    request = CapabilityRequest(
        capability_id="eval.summarize_artifact",
        goal="summarize the evaluation artifact and its caveats",
    )
    token = kernel.get_token(request, principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=principal,
        args={"operation": "summarize_artifact", "artifact": artifact},
    )
    return frame.action_id


async def act_on_artifact(
    kernel: Kernel, principal: Principal, artifact: dict[str, Any]
) -> tuple[str, str]:
    """Gate the deployment recommendation on the artifact assessment.

    Returns ``(capability_id, action_id)`` for whichever action was taken: the
    deployment recommendation when the artifact is trustworthy, otherwise the
    downgraded manual-review recommendation whose audit args record *why*.
    """
    decision = assess_artifact(artifact)
    if decision.allows_deployment:
        request = CapabilityRequest(
            capability_id="eval.recommend_deployment",
            goal="recommend deploying the evaluated candidate",
        )
        token = kernel.get_token(
            request,
            principal,
            justification="evaluation support is healthy and the decision is stable",
        )
        frame = await kernel.invoke(
            token,
            principal=principal,
            args={"operation": "recommend_deployment", "candidate": artifact.get("candidate", "")},
        )
        return ("eval.recommend_deployment", frame.action_id)

    # Downgrade: record the reasons in the audit args so the trace explains why
    # deployment was denied (ActionTrace.args is preserved for non-memory caps).
    request = CapabilityRequest(
        capability_id="eval.recommend_manual_review",
        goal="recommend manual review because the evaluation support is weak",
    )
    token = kernel.get_token(
        request,
        principal,
        justification="downgraded from deployment: weak support diagnostics",
    )
    frame = await kernel.invoke(
        token,
        principal=principal,
        args={
            "operation": "recommend_manual_review",
            "reason": "; ".join(decision.reasons),
            "downgraded_from": "recommend_deployment",
        },
    )
    return ("eval.recommend_manual_review", frame.action_id)


async def handle(
    kernel: Kernel, principal: Principal, label: str, artifact: dict[str, Any]
) -> None:
    """Summarize then (conditionally) act on one artifact, printing the audit."""
    print(f"\n=== Artifact: {label} (support_health={artifact.get('support_health')}) ===")
    summary_action = await summarize(kernel, principal, artifact)
    print(f"  summarize: allowed — action_id={summary_action} (always permitted)")

    capability_id, action_id = await act_on_artifact(kernel, principal, artifact)
    trace = kernel.explain(action_id)
    if capability_id == "eval.recommend_deployment":
        print(f"  action:    deployment recommended — action_id={trace.action_id}")
    else:
        print(f"  action:    DOWNGRADED to manual review — action_id={trace.action_id}")
        print(f"  audited reason: {trace.args.get('reason')}")
        assert trace.args.get("reason"), "the downgrade reason must be recorded in the audit trace"


async def main() -> None:
    kernel = build_kernel()
    # An analyst agent: may read and write recommendations, not an admin.
    analyst = Principal(principal_id="eval-analyst", roles=["reader", "writer"])

    print("=== Policy guardrails for statistical evaluation artifacts ===")

    healthy = {
        "artifact_type": "offline_policy_evaluation",
        "support_health": "ok",
        "decision_stable": True,
        "warnings": [],
        "uncertainty": {"ci_width": "narrow"},
        "recommendation": {"intent": "deploy"},
        "limitations": [],
        "candidate": "policy-v2",
    }
    cautious = {
        "artifact_type": "offline_policy_evaluation",
        "support_health": "caution",
        "decision_stable": True,
        "warnings": ["moderate overlap"],
        "recommendation": {"intent": "deploy"},
        "candidate": "policy-v2",
    }
    risky = {
        "artifact_type": "offline_policy_evaluation",
        "support_health": "high_risk",
        "decision_stable": False,
        "warnings": ["low effective sample size", "poor overlap"],
        "recommendation": {"intent": "hold"},
        "limitations": ["estimate extrapolates beyond logged support"],
        "candidate": "policy-v2",
    }

    await handle(kernel, analyst, "healthy", healthy)
    await handle(kernel, analyst, "caution", cautious)
    await handle(kernel, analyst, "high_risk", risky)

    print("\n✓ evaluation_artifact_policy.py complete.")


if __name__ == "__main__":
    asyncio.run(main())
