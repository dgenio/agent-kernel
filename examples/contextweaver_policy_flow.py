"""contextweaver_policy_flow.py — routing is advisory; policy still decides.

The written walkthrough lives in ``docs/integrations/contextweaver.md``. This
script is the runnable companion. It demonstrates the Weaver-ecosystem
``policy-before-action`` contract: a context-compilation layer (``contextweaver``)
may *narrow* what the model considers, but it never *grants* permission. Every
selected action still flows through the agent-kernel pipeline (policy → token →
invoke → firewall → trace) before anything executes.

``contextweaver`` is not a dependency of this example. The
``compile_tool_shortlist`` helper is a tiny, deterministic stand-in for the
tool-card shortlist a real contextweaver build would produce, so the demo runs
offline and in CI.

What this demo proves end-to-end:
  1. The context layer shortlists candidate capabilities for a goal — including
     one the principal is *not* allowed to use. Being on the shortlist is not
     authorization.
  2. ``allow``  — a READ action the principal satisfies executes and is audited.
  3. ``ask``    — a WRITE action with no justification is denied with a
     *recoverable* ``insufficient_justification`` code; the host treats this as
     "ask the human to confirm", supplies the justification, and re-grants.
  4. ``deny``   — a DESTRUCTIVE action the principal can never satisfy is denied
     with a *terminal* ``missing_role`` code; confirmation cannot recover it.

Run with: ``python examples/contextweaver_policy_flow.py``
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("AGENT_KERNEL_SECRET", "example-secret-do-not-use-in-prod")

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
from agent_kernel.errors import PolicyDenied
from agent_kernel.models import CapabilityRequest, ImplementationRef
from agent_kernel.policy_reasons import DenialReason

_SECRET = "example-secret-do-not-use-in-prod"


def build_registry() -> CapabilityRegistry:
    """Register one capability per outcome the demo exercises."""
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="docs.search",
            name="Search Docs",
            description="Search the internal knowledge base for an answer",
            safety_class=SafetyClass.READ,
            tags=["docs", "search", "knowledge", "answer"],
            impl=ImplementationRef(driver_id="memory", operation="docs_search"),
        )
    )
    registry.register(
        Capability(
            capability_id="tickets.update_status",
            name="Update Ticket Status",
            description="Change the status of a support ticket",
            safety_class=SafetyClass.WRITE,
            tags=["tickets", "update", "status", "support"],
            impl=ImplementationRef(driver_id="memory", operation="update_status"),
        )
    )
    registry.register(
        Capability(
            capability_id="tickets.delete",
            name="Delete Ticket",
            description="Permanently delete a support ticket",
            safety_class=SafetyClass.DESTRUCTIVE,
            tags=["tickets", "delete", "support"],
            impl=ImplementationRef(driver_id="memory", operation="delete_ticket"),
        )
    )
    return registry


def build_driver() -> InMemoryDriver:
    """A driver whose handlers return tiny, synthetic, PII-free payloads."""
    driver = InMemoryDriver()

    def docs_search(ctx: ExecutionContext) -> list[dict[str, object]]:
        query = str(ctx.args.get("query", ""))
        return [
            {"doc": "refunds.md", "score": 0.92, "matched": query},
            {"doc": "billing-faq.md", "score": 0.71, "matched": query},
        ]

    def update_status(ctx: ExecutionContext) -> dict[str, object]:
        return {"ticket": ctx.args.get("ticket_id", "T-000"), "status": "resolved"}

    def delete_ticket(
        ctx: ExecutionContext,
    ) -> dict[str, object]:  # pragma: no cover - never reached
        return {"ticket": ctx.args.get("ticket_id", "T-000"), "deleted": True}

    driver.register_handler("docs_search", docs_search)
    driver.register_handler("update_status", update_status)
    driver.register_handler("delete_ticket", delete_ticket)
    return driver


def compile_tool_shortlist(goal: str, capabilities: list[Capability]) -> list[Capability]:
    """Stand-in for a contextweaver tool-card shortlist.

    Ranks capabilities by deterministic keyword overlap with *goal* (no
    randomness — the Weaver ecosystem forbids non-deterministic routing) and
    returns the matches in descending score order. This mirrors what a real
    contextweaver build would hand the model: a *narrowed* candidate set. It is
    deliberately permissive — it may include capabilities the principal is not
    authorized to use, because routing does not equal permission.
    """
    goal_terms = {term for term in goal.lower().split() if term}
    scored: list[tuple[int, int, Capability]] = []
    for index, cap in enumerate(capabilities):
        overlap = len(goal_terms & {tag.lower() for tag in cap.tags})
        if overlap:
            # Sort key: higher overlap first, then registration order for stability.
            scored.append((-overlap, index, cap))
    scored.sort()
    return [cap for _, _, cap in scored]


def build_kernel() -> Kernel:
    """Wire a kernel with explicit routes for the three demo capabilities."""
    router = StaticRouter(
        routes={
            "docs.search": ["memory"],
            "tickets.update_status": ["memory"],
            "tickets.delete": ["memory"],
        }
    )
    kernel = Kernel(
        registry=build_registry(),
        token_provider=HMACTokenProvider(secret=_SECRET),
        router=router,
    )
    kernel.register_driver(build_driver())
    return kernel


async def main() -> None:
    kernel = build_kernel()
    # A support agent: may read and write, but is not an admin.
    agent = Principal(principal_id="support-agent-7", roles=["reader", "writer"])

    print("=== Step 1: contextweaver compiles a tool-card shortlist ===")
    goal = "resolve a support ticket and search billing docs"
    shortlist = compile_tool_shortlist(goal, kernel.list_capabilities())
    for cap in shortlist:
        print(f"  • {cap.capability_id} ({cap.safety_class.value})")
    # Routing is advisory: the destructive capability is shortlisted even though
    # this principal can never invoke it. The shortlist is a suggestion, not a grant.
    shortlisted_ids = {cap.capability_id for cap in shortlist}
    assert "tickets.delete" in shortlisted_ids, (
        "demo expects the destructive capability on the shortlist to prove "
        "that contextweaver routing does not imply authorization"
    )
    print("  (note: a DESTRUCTIVE capability is shortlisted — routing is not permission)")

    print("\n=== Step 2: ALLOW — a READ action the principal satisfies ===")
    search_req = CapabilityRequest(capability_id="docs.search", goal=goal)
    token = kernel.get_token(search_req, agent, justification="")
    frame = await kernel.invoke(
        token, principal=agent, args={"operation": "docs_search", "query": "refund"}
    )
    print(f"  outcome:     allow ({frame.response_mode})")
    for fact in frame.facts:
        print(f"    • {fact}")
    trace = kernel.explain(frame.action_id)
    assert trace.capability_id == "docs.search"
    print(f"  audited:     action_id={trace.action_id} driver={trace.driver_id}")

    print("\n=== Step 3: ASK/CONFIRM — a WRITE action missing its justification ===")
    update_req = CapabilityRequest(
        capability_id="tickets.update_status",
        goal="mark the customer's ticket resolved",
    )
    try:
        kernel.get_token(update_req, agent, justification="")
    except PolicyDenied as exc:
        # A missing/short justification is a *recoverable* gate: the host should
        # ask the human to confirm and supply a reason, then retry. This is how
        # an "ask/confirm" outcome is represented on top of a binary policy.
        assert exc.reason_code == DenialReason.INSUFFICIENT_JUSTIFICATION
        outcome = _classify(exc.reason_code)
        print(f"  outcome:     {outcome} (reason_code={exc.reason_code})")
        print("  host action: prompt the human, capture confirmation + justification")
    else:  # pragma: no cover - defensive
        raise SystemExit("Expected PolicyDenied for a WRITE call with no justification")

    # Human confirmed — re-grant with the supplied justification.
    confirmed = "agent confirmed: customer verified, closing as resolved per call notes"
    token = kernel.get_token(update_req, agent, justification=confirmed)
    frame = await kernel.invoke(
        token,
        principal=agent,
        args={"operation": "update_status", "ticket_id": "T-4821"},
    )
    print(f"  after confirm: allow ({frame.response_mode})")
    for fact in frame.facts:
        print(f"    • {fact}")

    print("\n=== Step 4: DENY — a DESTRUCTIVE action the principal cannot satisfy ===")
    delete_req = CapabilityRequest(
        capability_id="tickets.delete", goal="delete the duplicate ticket"
    )
    try:
        kernel.get_token(
            delete_req,
            agent,
            justification="duplicate ticket cleanup requested by the customer",
        )
    except PolicyDenied as exc:
        # A missing role is *terminal*: no amount of confirmation lets a
        # non-admin run a DESTRUCTIVE capability. The host must not retry.
        assert exc.reason_code == DenialReason.MISSING_ROLE
        outcome = _classify(exc.reason_code)
        print(f"  outcome:     {outcome} (reason_code={exc.reason_code})")
        explanation = kernel.explain_denial(delete_req, agent, justification="cleanup")
        print(f"  remediation: {explanation.remediation[0]}")
    else:  # pragma: no cover - defensive
        raise SystemExit("Expected PolicyDenied for a non-admin on a DESTRUCTIVE capability")

    print("\n✓ contextweaver_policy_flow.py complete.")


def _classify(reason_code: str | None) -> str:
    """Map a denial reason code to a host-level outcome.

    Only ``insufficient_justification`` is treated as a recoverable
    ``ask``/confirm gate; every other denial is ``deny`` (terminal for this
    request as-is).
    """
    if reason_code == DenialReason.INSUFFICIENT_JUSTIFICATION:
        return "ask"
    return "deny"


if __name__ == "__main__":
    asyncio.run(main())
