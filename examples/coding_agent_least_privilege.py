"""Deterministic coding-agent least-privilege flagship demo.

Run with::

    python examples/coding_agent_least_privilege.py

The demo uses only the published ``weaver-kernel`` core package. No network,
real filesystem mutation, GitHub token, or sibling Weaver project is required.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

os.environ.setdefault("WEAVER_KERNEL_SECRET", "coding-agent-demo-not-for-production")

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
)
from weaver_kernel.coding_agent import (
    CodingAgentPolicyEngine,
    enforce_coding_agent_constraints,
)
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.errors import DriverError, PolicyDenied
from weaver_kernel.models import CapabilityRequest

CAPABILITIES: tuple[tuple[str, SafetyClass, SensitivityTag], ...] = (
    ("repo.read.files", SafetyClass.READ, SensitivityTag.NONE),
    ("repo.write.files", SafetyClass.WRITE, SensitivityTag.NONE),
    ("shell.run.tests", SafetyClass.WRITE, SensitivityTag.NONE),
    ("shell.run.networked_command", SafetyClass.WRITE, SensitivityTag.NONE),
    ("secrets.read", SafetyClass.READ, SensitivityTag.SECRETS),
    ("github.create_pr", SafetyClass.WRITE, SensitivityTag.NONE),
    ("github.merge_pr", SafetyClass.DESTRUCTIVE, SensitivityTag.NONE),
)
EXPECTED_RECEIPT = Path(__file__).with_name("coding_agent_expected.txt")


def build_kernel() -> Kernel:
    """Build a local kernel whose fake driver enforces signed grant scope."""
    registry = CapabilityRegistry()
    routes: dict[str, list[str]] = {}
    driver = InMemoryDriver(driver_id="coding-agent")

    def execute(ctx: ExecutionContext) -> dict[str, object]:
        enforce_coding_agent_constraints(ctx.constraints, ctx.args)
        return {"status": "executed", "capability": ctx.capability_id}

    for capability_id, safety_class, sensitivity in CAPABILITIES:
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
    )
    kernel.register_driver(driver)
    return kernel


def request(capability_id: str, **scope: str) -> CapabilityRequest:
    """Create one host-normalized coding-agent request."""
    return CapabilityRequest(
        capability_id=capability_id,
        goal=f"coding-agent demo: {capability_id}",
        scope=scope,
    )


def record(receipt: list[str], line: str) -> None:
    """Append one stable proof line and display it."""
    receipt.append(line)
    print(line)


async def invoke_allowed(
    kernel: Kernel,
    principal: Principal,
    capability_id: str,
    *,
    justification: str,
    **scope: str,
):
    """Grant and invoke one action using the same exact scope arguments."""
    token = kernel.get_token(
        request(capability_id, **scope),
        principal,
        justification=justification,
    )
    frame = await kernel.invoke(token, principal=principal, args=dict(scope))
    return token, frame


async def main() -> None:
    """Run the maintained ALLOW / DENY / escalation / anti-swap receipt."""
    kernel = build_kernel()
    coder = Principal(principal_id="coder")
    receipt: list[str] = []

    _, read_frame = await invoke_allowed(
        kernel,
        coder,
        "repo.read.files",
        path="README.md",
        justification="Review the repository README",
    )
    record(receipt, "ALLOW repo.read.files README.md")

    write_token, _ = await invoke_allowed(
        kernel,
        coder,
        "repo.write.files",
        path="src/demo.py",
        justification="Edit source for the approved task",
    )
    record(receipt, "ALLOW repo.write.files src/demo.py")

    try:
        kernel.get_token(
            request("repo.write.files", path=".github/workflows/release.yml"),
            coder,
            justification="Change the release workflow",
        )
    except PolicyDenied:
        record(receipt, "DENY repo.write.files .github/workflows/release.yml")
    else:  # pragma: no cover - defensive
        raise AssertionError("workflow mutation unexpectedly received a grant")

    try:
        kernel.get_token(
            request("secrets.read", path=".env"),
            coder,
            justification="Read environment credentials",
        )
    except PolicyDenied:
        record(receipt, "DENY secrets.read .env")
    else:  # pragma: no cover - defensive
        raise AssertionError("secret access unexpectedly received a grant")

    await invoke_allowed(
        kernel,
        coder,
        "shell.run.tests",
        command_class="test",
        justification="Run the local test suite",
    )
    record(receipt, "ALLOW shell.run.tests command_class=test")

    task_id = "ISSUE-253"
    try:
        kernel.get_token(
            request("github.create_pr", task_id=task_id),
            coder,
            justification="Publish the completed task for review",
        )
    except PolicyDenied:
        record(receipt, "DENY github.create_pr task=ISSUE-253 before approval")
    else:  # pragma: no cover - defensive
        raise AssertionError("PR creation unexpectedly bypassed task approval")

    approved_coder = Principal(
        principal_id="coder",
        attributes={"approved_task_id": task_id},
    )
    await invoke_allowed(
        kernel,
        approved_coder,
        "github.create_pr",
        task_id=task_id,
        justification="Create the explicitly approved PR",
    )
    record(receipt, "ALLOW github.create_pr task=ISSUE-253 after task-bound approval")

    try:
        await kernel.invoke(
            write_token,
            principal=coder,
            args={"path": ".github/workflows/release.yml"},
        )
    except DriverError:
        record(
            receipt,
            "DENY scope substitution src/demo.py -> .github/workflows/release.yml at execution",
        )
    else:  # pragma: no cover - defensive
        raise AssertionError("signed write scope was not enforced by the driver boundary")

    trace = kernel.explain(read_frame.action_id)
    assert trace.capability_id == "repo.read.files"
    assert trace.principal_id == "coder"
    assert trace.driver_id == "coding-agent"
    record(receipt, "TRACE repo.read.files principal=coder driver=coding-agent")
    record(
        receipt,
        "PASS: useful coding work stays usable while sensitive authority stays explicit.",
    )

    actual = "\n".join(receipt) + "\n"
    expected = EXPECTED_RECEIPT.read_text(encoding="utf-8")
    assert actual == expected, "coding-agent flagship receipt drifted from its maintained fixture"


if __name__ == "__main__":
    asyncio.run(main())
