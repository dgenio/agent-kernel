"""basic_cli.py — Full flow: request → grant → invoke → expand → explain.

Run with: python examples/basic_cli.py
"""

from __future__ import annotations

import asyncio
import os

# Use a stable test secret so the example is reproducible.
os.environ.setdefault("AGENT_KERNEL_SECRET", "example-secret-do-not-use-in-prod")

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    SensitivityTag,
    StaticRouter,
)
from agent_kernel.drivers.base import ExecutionContext
from agent_kernel.models import CapabilityRequest, ImplementationRef


def build_registry() -> CapabilityRegistry:
    registry = CapabilityRegistry()
    registry.register(
        Capability(
            capability_id="tasks.list",
            name="List Tasks",
            description="List all tasks for the current user",
            safety_class=SafetyClass.READ,
            sensitivity=SensitivityTag.NONE,
            tags=["tasks", "list", "todo"],
            impl=ImplementationRef(driver_id="memory", operation="list_tasks"),
        )
    )
    registry.register(
        Capability(
            capability_id="tasks.create",
            name="Create Task",
            description="Create a new task",
            safety_class=SafetyClass.WRITE,
            tags=["tasks", "create", "write"],
            impl=ImplementationRef(driver_id="memory", operation="create_task"),
        )
    )
    return registry


def build_driver() -> InMemoryDriver:
    driver = InMemoryDriver(driver_id="memory")

    tasks = [{"id": i, "title": f"Task {i}", "done": i % 3 == 0} for i in range(1, 21)]

    def list_tasks(ctx: ExecutionContext) -> list[dict[str, object]]:
        return tasks

    def create_task(ctx: ExecutionContext) -> dict[str, object]:
        task = {"id": len(tasks) + 1, "title": ctx.args.get("title", "Untitled"), "done": False}
        tasks.append(task)
        return task

    driver.register_handler("list_tasks", list_tasks)
    driver.register_handler("create_task", create_task)
    return driver


async def main() -> None:
    registry = build_registry()
    driver = build_driver()

    router = StaticRouter(
        routes={
            "tasks.list": ["memory"],
            "tasks.create": ["memory"],
        }
    )

    kernel = Kernel(
        registry=registry,
        token_provider=HMACTokenProvider(secret="example-secret-do-not-use-in-prod"),
        router=router,
    )
    kernel.register_driver(driver)

    reader = Principal(
        principal_id="cli-user-001",
        roles=["reader"],
        attributes={},
    )

    print("=== Step 1: Discover capabilities ===")
    requests = kernel.request_capabilities("list my tasks")
    print(f"Found {len(requests)} matching capabilities:")
    for req in requests:
        print(f"  - {req.capability_id}")

    print("\n=== Step 2: Grant (get token) ===")
    list_req = CapabilityRequest(capability_id="tasks.list", goal="list my tasks")
    token = kernel.get_token(list_req, reader, justification="")
    print(f"  Token ID: {token.token_id}")
    print(f"  Expires:  {token.expires_at.isoformat()}")

    print("\n=== Step 3: Invoke ===")
    frame = await kernel.invoke(
        token,
        principal=reader,
        args={"operation": "list_tasks"},
        response_mode="summary",
    )
    print(f"  Action ID:   {frame.action_id}")
    print(f"  Mode:        {frame.response_mode}")
    print("  Facts:")
    for fact in frame.facts:
        print(f"    • {fact}")

    print("\n=== Step 4: Expand handle ===")
    if frame.handle:
        expanded = kernel.expand(
            frame.handle,
            query={"offset": 0, "limit": 3, "fields": ["id", "title"]},
        )
        print("  First 3 rows (id + title only):")
        for row in expanded.table_preview:
            print(f"    {row}")

    print("\n=== Step 5: Explain ===")
    trace = kernel.explain(frame.action_id)
    print(f"  Action ID:   {trace.action_id}")
    print(f"  Capability:  {trace.capability_id}")
    print(f"  Principal:   {trace.principal_id}")
    print(f"  Driver:      {trace.driver_id}")
    print(f"  At:          {trace.invoked_at.isoformat()}")

    print("\n✓ basic_cli.py complete.")


if __name__ == "__main__":
    asyncio.run(main())
