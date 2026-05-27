"""readme_quickstart.py — runnable mirror of the README "Quickstart".

Kept in step with the quickstart in ``README.md`` so CI catches regressions in
the first code a new user runs (issue #83). ``make example`` and the CI
"Examples" step execute this file; the final ``assert`` fails the build if
handle expansion ever stops returning the documented result.

Run with: ``python examples/readme_quickstart.py``
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("AGENT_KERNEL_SECRET", "readme-quickstart-secret-not-for-prod")

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    InMemoryDriver,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from agent_kernel.models import CapabilityRequest

# 1. Register a capability
registry = CapabilityRegistry()
registry.register(
    Capability(
        capability_id="tasks.list",
        name="List Tasks",
        description="List all tasks",
        safety_class=SafetyClass.READ,
        tags=["tasks", "list"],
    )
)

# 2. Wire up a driver
driver = InMemoryDriver()
driver.register_handler("tasks.list", lambda ctx: [{"id": 1, "title": "Buy milk"}])

# 3. Build the kernel
kernel = Kernel(registry=registry, router=StaticRouter(routes={"tasks.list": ["memory"]}))
kernel.register_driver(driver)


async def main() -> None:
    principal = Principal(principal_id="alice", roles=["reader"])

    # 4. Discover → grant → invoke → expand → explain
    token = kernel.get_token(
        CapabilityRequest(capability_id="tasks.list", goal="list tasks"),
        principal,
        justification="",
    )
    frame = await kernel.invoke(token, principal=principal, args={})
    print(frame.facts)
    print(frame.handle)

    # `principal` is required: the handle is bound to the granting principal,
    # so an omitted principal raises HandleConstraintViolation (#83).
    expanded = kernel.expand(
        frame.handle, query={"limit": 1, "fields": ["title"]}, principal=principal
    )
    print(expanded.table_preview)
    assert expanded.table_preview == [{"title": "Buy milk"}], (
        f"README quickstart regression: expected [{{'title': 'Buy milk'}}], "
        f"got {expanded.table_preview!r}"
    )

    trace = kernel.explain(frame.action_id)
    print(trace.driver_id)


if __name__ == "__main__":
    asyncio.run(main())
