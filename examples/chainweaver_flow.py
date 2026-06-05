"""chainweaver_flow.py — wrap a ChainWeaver compiled flow as a capability.

The written walkthrough lives in ``docs/integrations/chainweaver.md``. This
script is the runnable companion. It shows the Weaver-ecosystem pattern for
running a *ChainWeaver* compiled flow (an orchestration of ordered steps)
through the normal agent-kernel pipeline so the flow becomes a policy-checked,
audited capability rather than an out-of-band side channel:

  1. A compiled flow is wrapped behind a ``ChainWeaverDriver``. The driver
     implements the ``Driver`` protocol and runs the flow when the capability
     is invoked.
  2. Running the wrapped flow through ``Kernel.invoke()`` produces a
     kernel-visible execution record (an ``ActionTrace``) exactly like any
     other capability — so I-02 (every execution is audited) holds.
  3. When a flow step fails, the driver translates ChainWeaver's native
     ``FlowExecutionError`` into a kernel ``DriverError`` that *preserves* the
     flow id and the failing step, so the audit trail and the caller keep the
     orchestration context.

``chainweaver`` is **not** a dependency of this example. ``CompiledFlow`` and
``FlowExecutionError`` are tiny, deterministic stand-ins for the compiled-flow
object and native exception a real ChainWeaver build would hand you, so the
demo runs offline and in CI. In production you point ``ChainWeaverDriver`` at a
real compiled flow; the driver only relies on a ``run(inputs)`` method and a
``flow_id`` attribute, which keeps ChainWeaver an optional dependency.

Run with: ``python examples/chainweaver_flow.py``
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from weaver_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from weaver_kernel.drivers.base import ExecutionContext
from weaver_kernel.errors import DriverError
from weaver_kernel.models import CapabilityRequest, ImplementationRef, RawResult

_SECRET = "example-secret-do-not-use-in-prod"


# ── ChainWeaver stand-ins (a real build supplies these) ─────────────────────


class FlowExecutionError(Exception):
    """Stand-in for ChainWeaver's native flow-execution exception.

    Carries the orchestration context a real ChainWeaver error would: which
    flow failed and at which step. The :class:`ChainWeaverDriver` translates
    this into a kernel :class:`~weaver_kernel.errors.DriverError` so the context
    survives into the audit trail instead of leaking a raw stack trace.
    """

    def __init__(self, flow_id: str, step: str, cause: str) -> None:
        super().__init__(f"flow '{flow_id}' failed at step '{step}': {cause}")
        self.flow_id = flow_id
        self.step = step
        self.cause = cause


@dataclass(slots=True)
class FlowStep:
    """One named step in a compiled flow."""

    name: str
    run: Callable[[dict[str, Any]], dict[str, Any]]
    """Transforms the running context dict and returns the keys it produced."""


@dataclass(slots=True)
class CompiledFlow:
    """Deterministic stand-in for a ChainWeaver compiled flow.

    Executes its :attr:`steps` in order, threading a shared context dict. A step
    that raises is reported as a :class:`FlowExecutionError` naming the flow and
    the failing step — the shape a real ChainWeaver error carries.
    """

    flow_id: str
    steps: list[FlowStep] = field(default_factory=list)

    def run(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Run every step in order and return the accumulated context."""
        context: dict[str, Any] = dict(inputs)
        for step in self.steps:
            try:
                context.update(step.run(context))
            except Exception as exc:  # translate to ChainWeaver's error shape
                raise FlowExecutionError(self.flow_id, step.name, str(exc)) from exc
        return context


# ── The adapter: a compiled flow behind the Driver protocol ─────────────────


class ChainWeaverDriver:
    """Driver that runs ChainWeaver compiled flows as capabilities.

    Operations map to compiled flows. ``execute`` runs the flow named by
    ``ctx.args['operation']`` (falling back to ``ctx.capability_id``) with the
    remaining args as inputs. A :class:`FlowExecutionError` is re-raised as a
    :class:`~weaver_kernel.errors.DriverError` that keeps the flow id and failing
    step, so the orchestration context is preserved for the caller and the
    audit trail.
    """

    def __init__(self, flows: dict[str, CompiledFlow], *, driver_id: str = "chainweaver") -> None:
        self._flows = dict(flows)
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        """Unique identifier for this driver."""
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        """Run the compiled flow bound to this capability's operation."""
        operation = str(ctx.args.get("operation", ctx.capability_id))
        flow = self._flows.get(operation)
        if flow is None:
            raise DriverError(
                f"ChainWeaverDriver '{self._driver_id}' has no flow for operation='{operation}'."
            )
        inputs = {k: v for k, v in ctx.args.items() if k != "operation"}
        try:
            output = flow.run(inputs)
        except FlowExecutionError as exc:
            raise DriverError(
                f"ChainWeaver flow '{exc.flow_id}' failed at step '{exc.step}': {exc.cause}"
            ) from exc
        return RawResult(
            capability_id=ctx.capability_id,
            data=output,
            metadata={"flow_id": flow.flow_id, "steps": [s.name for s in flow.steps]},
        )


# ── A small, deterministic release-notes flow ───────────────────────────────


def _collect_changes(context: dict[str, Any]) -> dict[str, Any]:
    """Step 1: normalise the raw change list, failing loudly when absent."""
    changes = context.get("changes")
    if not changes:
        raise ValueError("no 'changes' provided to summarize")
    return {"changes": [str(c).strip() for c in changes]}


def _classify(context: dict[str, Any]) -> dict[str, Any]:
    """Step 2: split changes into highlights (feat/fix) and the rest."""
    highlights = [c for c in context["changes"] if c.startswith(("feat", "fix"))]
    return {"highlights": highlights}


def _render_summary(context: dict[str, Any]) -> dict[str, Any]:
    """Step 3: render the final, audit-friendly summary payload."""
    return {
        "release": context.get("release", "unreleased"),
        "change_count": len(context["changes"]),
        "highlights": context["highlights"],
    }


def build_release_flow() -> CompiledFlow:
    """A three-step compiled flow that summarizes release notes."""
    return CompiledFlow(
        flow_id="release_notes_summary",
        steps=[
            FlowStep("collect_changes", _collect_changes),
            FlowStep("classify", _classify),
            FlowStep("render_summary", _render_summary),
        ],
    )


def build_kernel() -> Kernel:
    """Wire a kernel with one capability backed by the compiled flow."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="flows.summarize_release",
            name="Summarize Release",
            description="Run the ChainWeaver release-notes summary flow",
            safety_class=SafetyClass.READ,
            tags=["flows", "release", "summary", "chainweaver"],
            impl=ImplementationRef(driver_id="chainweaver", operation="summarize_release"),
        )
    )
    router = StaticRouter(routes={"flows.summarize_release": ["chainweaver"]})
    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret=_SECRET),
        router=router,
    )
    kernel.register_driver(ChainWeaverDriver(flows={"summarize_release": build_release_flow()}))
    return kernel


async def run_flow(kernel: Kernel, principal: Principal, args: dict[str, Any]) -> str:
    """Invoke the flow-backed capability and return its audit ``action_id``."""
    request = CapabilityRequest(
        capability_id="flows.summarize_release",
        goal="summarize the release notes for the next tag",
    )
    token = kernel.get_token(request, principal, justification="")
    frame = await kernel.invoke(
        token,
        principal=principal,
        args={"operation": "summarize_release", **args},
    )
    return frame.action_id


async def main() -> None:
    kernel = build_kernel()
    # A release agent: may read (run flows), not an admin.
    agent = Principal(principal_id="release-bot", roles=["reader"])

    print("=== ChainWeaver compiled flow as a policy-controlled capability ===")

    print("\n=== Success: the wrapped flow runs and is audited ===")
    action_id = await run_flow(
        kernel,
        agent,
        {
            "release": "v1.4.0",
            "changes": ["feat: add export", "fix: token drift", "chore: bump deps"],
        },
    )
    trace = kernel.explain(action_id)
    print(f"  audited: action_id={trace.action_id} driver={trace.driver_id}")
    print(f"  result_summary={trace.result_summary}")
    assert trace.driver_id == "chainweaver", "the flow must run through the ChainWeaver driver"
    assert trace.error is None, "the success path must not record an error"

    print("\n=== Failure: a step error is preserved as kernel context ===")
    try:
        await run_flow(kernel, agent, {"release": "v1.4.1", "changes": []})
    except DriverError as exc:
        # The kernel wraps the driver error, but the ChainWeaver context — the
        # flow id and the failing step — is preserved inside the message.
        message = str(exc)
        print(f"  DriverError: {message}")
        assert "release_notes_summary" in message, "flow id must survive into the kernel error"
        assert "collect_changes" in message, "failing step must survive into the kernel error"
    else:  # pragma: no cover - defensive
        raise SystemExit("Expected DriverError when the flow's first step fails")

    print("\n✓ chainweaver_flow.py complete.")


if __name__ == "__main__":
    asyncio.run(main())
