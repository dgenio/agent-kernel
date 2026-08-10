"""Installed-package proof of least privilege for coding agents.

Run the maintained, hermetic scenario with::

    python -m weaver_kernel.coding_agent_demo

The fake driver performs no filesystem, network, package, or GitHub side
effects. The proof is about authorization, signed scope enforcement, and the
audit path that a real driver must mediate before performing those effects.
"""

from __future__ import annotations

import asyncio

from .coding_agent import CodingAgentPolicyEngine, enforce_coding_agent_constraints
from .drivers.base import ExecutionContext
from .drivers.memory import InMemoryDriver
from .enums import SafetyClass, SensitivityTag
from .errors import DriverError, PolicyDenied
from .kernel import Kernel
from .models import (
    ActionTrace,
    Capability,
    CapabilityGrant,
    CapabilityRequest,
    Frame,
    Principal,
    TraceEventType,
)
from .policy_reasons import DenialReason
from .registry import CapabilityRegistry
from .router import StaticRouter
from .tokens import HMACTokenProvider

_CAPABILITIES: tuple[tuple[str, SafetyClass, SensitivityTag], ...] = (
    ("repo.read.files", SafetyClass.READ, SensitivityTag.NONE),
    ("repo.write.files", SafetyClass.WRITE, SensitivityTag.NONE),
    ("shell.run.tests", SafetyClass.WRITE, SensitivityTag.NONE),
    ("shell.run.networked_command", SafetyClass.WRITE, SensitivityTag.NONE),
    ("secrets.read", SafetyClass.READ, SensitivityTag.SECRETS),
    ("github.create_pr", SafetyClass.WRITE, SensitivityTag.NONE),
    ("github.merge_pr", SafetyClass.DESTRUCTIVE, SensitivityTag.NONE),
)

EXPECTED_RECEIPT: tuple[str, ...] = (
    "ALLOW+EXECUTE repo.read.files path=README.md",
    "ALLOW+EXECUTE repo.write.files path=src/demo.py",
    "ALLOW+EXECUTE shell.run.tests command_class=test",
    "DENY repo.write.files path=.github/workflows/release.yml reason=scope_not_allowed",
    "DENY secrets.read path=.env reason=missing_role",
    "DENY github.create_pr task=ISSUE-253 reason=missing_attribute",
    "EXPLAIN deny capability=github.create_pr principal=coder reason=missing_attribute",
    "ESCALATE github.create_pr task=ISSUE-253 grant=one-task",
    "GRANT github.create_pr policy=CodingAgentPolicyEngine outcome=allowed bound=task_id",
    "ALLOW+EXECUTE github.create_pr task=ISSUE-253",
    "EXPLAIN invoke capability=github.create_pr principal=coder driver=coding-agent",
    "DENY scope-substitution path=src/demo.py -> .github/workflows/release.yml",
    "PASS: useful coding work stays usable while sensitive authority stays explicit.",
)


def _build_kernel() -> Kernel:
    registry = CapabilityRegistry()
    routes: dict[str, list[str]] = {}
    driver = InMemoryDriver(driver_id="coding-agent")

    def execute(ctx: ExecutionContext) -> dict[str, object]:
        enforce_coding_agent_constraints(ctx.constraints, ctx.args)
        return {"status": "executed", "capability": ctx.capability_id}

    for capability_id, safety_class, sensitivity in _CAPABILITIES:
        registry.register(
            Capability(
                capability_id=capability_id,
                name=capability_id,
                description=f"Demo capability {capability_id}",
                safety_class=safety_class,
                sensitivity=sensitivity,
            )
        )
        routes[capability_id] = ["coding-agent"]
        driver.register_handler(capability_id, execute)

    kernel = Kernel(
        registry=registry,
        policy=CodingAgentPolicyEngine(),
        router=StaticRouter(routes=routes),
        token_provider=HMACTokenProvider(secret="coding-agent-demo-not-for-production"),
    )
    kernel.register_driver(driver)
    return kernel


def _request(capability_id: str, **scope: str) -> CapabilityRequest:
    return CapabilityRequest(
        capability_id=capability_id,
        goal=f"coding-agent demo: {capability_id}",
        scope=scope,
    )


async def _grant_and_invoke(
    kernel: Kernel,
    principal: Principal,
    capability_id: str,
    *,
    justification: str,
    **scope: str,
) -> tuple[CapabilityGrant, Frame]:
    grant = kernel.grant_capability(
        _request(capability_id, **scope),
        principal,
        justification=justification,
    )
    frame = await kernel.invoke(grant.token, principal=principal, args=dict(scope))
    return grant, frame


def _latest_trace(
    kernel: Kernel,
    *,
    capability_id: str,
    event_type: TraceEventType,
) -> ActionTrace:
    matches = [
        trace
        for trace in kernel.list_traces()
        if trace.capability_id == capability_id and trace.event_type == event_type
    ]
    assert matches, f"missing {event_type} trace for {capability_id}"
    return kernel.explain(matches[-1].action_id)


async def run_demo() -> tuple[str, ...]:
    """Run the maintained proof and return its verified semantic receipt."""
    kernel = _build_kernel()
    coder = Principal(principal_id="coder", roles=["code_writer", "test_runner"])
    receipt: list[str] = []

    await _grant_and_invoke(
        kernel,
        coder,
        "repo.read.files",
        path="README.md",
        justification="Review the repository README",
    )
    receipt.append("ALLOW+EXECUTE repo.read.files path=README.md")

    write_grant, _ = await _grant_and_invoke(
        kernel,
        coder,
        "repo.write.files",
        path="src/demo.py",
        justification="Edit source for the approved task",
    )
    receipt.append("ALLOW+EXECUTE repo.write.files path=src/demo.py")

    await _grant_and_invoke(
        kernel,
        coder,
        "shell.run.tests",
        command_class="test",
        justification="Run the local test suite",
    )
    receipt.append("ALLOW+EXECUTE shell.run.tests command_class=test")

    try:
        kernel.get_token(
            _request("repo.write.files", path=".github/workflows/release.yml"),
            coder,
            justification="Change the release workflow",
        )
    except PolicyDenied as exc:
        assert exc.reason_code == DenialReason.SCOPE_NOT_ALLOWED
        receipt.append(
            "DENY repo.write.files path=.github/workflows/release.yml reason=scope_not_allowed"
        )
    else:  # pragma: no cover - defensive
        raise AssertionError("workflow mutation unexpectedly received a grant")

    try:
        kernel.get_token(
            _request("secrets.read", path=".env"),
            coder,
            justification="Read environment credentials",
        )
    except PolicyDenied as exc:
        assert exc.reason_code == DenialReason.MISSING_ROLE
        receipt.append("DENY secrets.read path=.env reason=missing_role")
    else:  # pragma: no cover - defensive
        raise AssertionError("secret access unexpectedly received a grant")

    task_id = "ISSUE-253"
    try:
        kernel.get_token(
            _request("github.create_pr", task_id=task_id),
            coder,
            justification="Publish the completed task for review",
        )
    except PolicyDenied as exc:
        assert exc.reason_code == DenialReason.MISSING_ATTRIBUTE
        receipt.append("DENY github.create_pr task=ISSUE-253 reason=missing_attribute")
    else:  # pragma: no cover - defensive
        raise AssertionError("PR creation unexpectedly bypassed task approval")

    denial_trace = _latest_trace(
        kernel,
        capability_id="github.create_pr",
        event_type="deny",
    )
    assert denial_trace.principal_id == "coder"
    assert denial_trace.reason_code == DenialReason.MISSING_ATTRIBUTE
    receipt.append(
        "EXPLAIN deny capability=github.create_pr principal=coder reason=missing_attribute"
    )

    receipt.append("ESCALATE github.create_pr task=ISSUE-253 grant=one-task")
    approved_coder = Principal(
        principal_id="coder",
        roles=list(coder.roles),
        attributes={"approved_task_id": task_id},
    )
    pr_grant, pr_frame = await _grant_and_invoke(
        kernel,
        approved_coder,
        "github.create_pr",
        task_id=task_id,
        justification="Create the explicitly approved PR",
    )
    policy_trace = pr_grant.decision.trace
    assert policy_trace is not None
    assert policy_trace.engine == "CodingAgentPolicyEngine"
    assert policy_trace.final_outcome == "allowed"
    assert pr_grant.token.constraints == {"coding_agent": {"task_id": task_id}}
    receipt.append(
        "GRANT github.create_pr policy=CodingAgentPolicyEngine outcome=allowed bound=task_id"
    )
    receipt.append("ALLOW+EXECUTE github.create_pr task=ISSUE-253")

    invocation_trace = kernel.explain(pr_frame.action_id)
    assert invocation_trace.event_type == "invoke"
    assert invocation_trace.capability_id == "github.create_pr"
    assert invocation_trace.principal_id == "coder"
    assert invocation_trace.driver_id == "coding-agent"
    receipt.append(
        "EXPLAIN invoke capability=github.create_pr principal=coder driver=coding-agent"
    )

    try:
        await kernel.invoke(
            write_grant.token,
            principal=coder,
            args={"path": ".github/workflows/release.yml"},
        )
    except DriverError:
        receipt.append("DENY scope-substitution path=src/demo.py -> .github/workflows/release.yml")
    else:  # pragma: no cover - defensive
        raise AssertionError("signed write scope was not enforced by the driver boundary")

    receipt.append(
        "PASS: useful coding work stays usable while sensitive authority stays explicit."
    )
    actual = tuple(receipt)
    assert actual == EXPECTED_RECEIPT, "coding-agent flagship receipt drifted"
    return actual


def main() -> None:
    """Run the demo, verify every assertion, then print the maintained receipt."""
    receipt = asyncio.run(run_demo())
    print("\n".join(receipt))


if __name__ == "__main__":
    main()
