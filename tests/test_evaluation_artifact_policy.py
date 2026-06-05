"""Tests for the evaluation-artifact policy example (issue #96).

Covers the three required support-health states (``ok`` / ``caution`` /
``high_risk``), confirms the gate relies on more than a single signal, and
verifies that a downgraded action records *why* in the audit trace.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from weaver_kernel import Principal

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load_example(name: str) -> ModuleType:
    """Import an example module by file path (examples are not a package)."""
    spec = importlib.util.spec_from_file_location(name, _EXAMPLES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # let dataclass field resolution find the module
    spec.loader.exec_module(module)
    return module


eap = _load_example("evaluation_artifact_policy")


def test_ok_artifact_allows_deployment() -> None:
    """A healthy, stable artifact with no warnings permits deployment."""
    artifact = {
        "support_health": "ok",
        "decision_stable": True,
        "warnings": [],
        "recommendation": {"intent": "deploy"},
    }
    decision = eap.assess_artifact(artifact)
    assert decision.allows_deployment is True
    assert decision.denied_actions == ()
    assert eap.ALLOW_SUMMARY in decision.allowed_actions


def test_caution_artifact_downgrades_without_human_review() -> None:
    """A caution artifact denies deployment but does not force human review."""
    artifact = {
        "support_health": "caution",
        "decision_stable": True,
        "warnings": ["moderate overlap"],
        "recommendation": {"intent": "deploy"},
    }
    decision = eap.assess_artifact(artifact)
    assert decision.allows_deployment is False
    assert eap.DENY_DEPLOYMENT_RECOMMENDATION in decision.denied_actions
    assert eap.DENY_AUTOMATIC_ROLLOUT in decision.denied_actions
    assert eap.ALLOW_MANUAL_REVIEW_RECOMMENDATION in decision.allowed_actions
    assert eap.REQUIRE_HUMAN_REVIEW not in decision.allowed_actions


def test_high_risk_artifact_requires_human_review() -> None:
    """A high_risk artifact denies deployment and requires human review."""
    artifact = {
        "support_health": "high_risk",
        "decision_stable": False,
        "warnings": ["low effective sample size", "poor overlap"],
        "recommendation": {"intent": "hold"},
    }
    decision = eap.assess_artifact(artifact)
    assert decision.allows_deployment is False
    assert eap.DENY_DEPLOYMENT_RECOMMENDATION in decision.denied_actions
    assert eap.REQUIRE_HUMAN_REVIEW in decision.allowed_actions
    assert decision.reasons  # at least one reason recorded


def test_gate_is_not_single_metric() -> None:
    """Good support health is insufficient when the decision is unstable."""
    artifact = {
        "support_health": "ok",
        "decision_stable": False,
        "warnings": [],
        "recommendation": {"intent": "deploy"},
    }
    decision = eap.assess_artifact(artifact)
    assert decision.allows_deployment is False
    assert "decision is not stable" in "; ".join(decision.reasons)


def test_missing_fields_default_to_safest() -> None:
    """An artifact missing diagnostics is treated as high_risk, not deployable."""
    decision = eap.assess_artifact({})
    assert decision.support_health == "high_risk"
    assert decision.allows_deployment is False


def test_unknown_support_health_normalised_to_safest() -> None:
    """An unrecognised support_health value cannot read as deployable."""
    decision = eap.assess_artifact(
        {"support_health": "looks_fine", "decision_stable": True, "warnings": []}
    )
    assert decision.support_health == "high_risk"
    assert decision.allows_deployment is False


@pytest.mark.parametrize(
    ("artifact", "expected_capability"),
    [
        (
            {
                "support_health": "ok",
                "decision_stable": True,
                "warnings": [],
                "recommendation": {"intent": "deploy"},
            },
            "eval.recommend_deployment",
        ),
        (
            {
                "support_health": "high_risk",
                "decision_stable": False,
                "warnings": ["low ESS"],
                "recommendation": {"intent": "hold"},
            },
            "eval.recommend_manual_review",
        ),
    ],
)
async def test_act_on_artifact_audits_decision(
    artifact: dict[str, object], expected_capability: str
) -> None:
    """The chosen action is audited; a downgrade records its reason."""
    kernel = eap.build_kernel()
    analyst = Principal(principal_id="eval-analyst", roles=["reader", "writer"])
    capability_id, action_id = await eap.act_on_artifact(kernel, analyst, artifact)
    assert capability_id == expected_capability
    trace = kernel.explain(action_id)
    assert trace.capability_id == expected_capability
    if expected_capability == "eval.recommend_manual_review":
        assert trace.args.get("reason"), "downgrade must record the reason in the audit trace"
        assert trace.args.get("downgraded_from") == "recommend_deployment"
