# Integrations

## MCP (Model Context Protocol)

The built-in `MCPDriver` supports both local stdio servers and remote Streamable HTTP servers.

Install the optional dependency first:

```bash
pip install "weaver-kernel[mcp]"
```

### Stdio transport

```python
import asyncio

from agent_kernel import CapabilityRegistry, Kernel, StaticRouter
from agent_kernel.drivers.mcp import MCPDriver


async def main() -> None:
    registry = CapabilityRegistry()
    router = StaticRouter(fallback=[])
    kernel = Kernel(registry=registry, router=router)

    # Connect to a local MCP server process.
    driver = MCPDriver.from_stdio(
        command="python",
        args=["-m", "my_mcp_server"],
        server_name="local-tools",
    )
    kernel.register_driver(driver)

    # Discover tools and register them as capabilities.
    capabilities = await driver.discover(namespace="local")
    registry.register_many(capabilities)

    # Route each discovered capability to this MCP driver.
    for capability in capabilities:
        router.add_route(capability.capability_id, [driver.driver_id])


asyncio.run(main())
```

### Streamable HTTP transport

```python
import asyncio

from agent_kernel import CapabilityRegistry, Kernel, StaticRouter
from agent_kernel.drivers.mcp import MCPDriver


async def main() -> None:
    registry = CapabilityRegistry()
    router = StaticRouter(fallback=[])
    kernel = Kernel(registry=registry, router=router)

    # Connect to a remote Streamable HTTP MCP server.
    # Note: max_retries > 0 creates at-least-once delivery semantics for
    # tools/call — if a connection drops after the server processes the
    # request but before the response arrives, the call will be repeated.
    # Ensure target tools are idempotent, or set max_retries=0 for
    # WRITE/DESTRUCTIVE capabilities.
    driver = MCPDriver.from_http(
        url="https://example.com/mcp",
        server_name="remote-tools",
        max_retries=1,
    )
    kernel.register_driver(driver)

    # Discover tools and register them as capabilities.
    capabilities = await driver.discover(namespace="remote")
    registry.register_many(capabilities)

    # Route each discovered capability to this MCP driver.
    for capability in capabilities:
        router.add_route(capability.capability_id, [driver.driver_id])


asyncio.run(main())
```

### Notes

- `discover()` converts `tools/list` results into `Capability` objects.
- `execute()` calls `tools/call` and normalizes MCP content blocks for the firewall.
- MCP `isError` responses raise `DriverError` with the server-provided detail.
- If `mcp` is not installed, factory methods raise a helpful `ImportError`.

## HTTPDriver

The built-in `HTTPDriver` supports GET, POST, PUT, DELETE:

```python
from agent_kernel.drivers.http import HTTPDriver, HTTPEndpoint

driver = HTTPDriver(driver_id="my_api")
driver.register_endpoint("users.list", HTTPEndpoint(
    url="https://api.example.com/users",
    method="GET",
    headers={"Authorization": "Bearer ..."},
))
kernel.register_driver(driver)
```

## Custom drivers

Any object implementing the `Driver` protocol can be registered:

```python
class Driver(Protocol):
    @property
    def driver_id(self) -> str: ...
    async def execute(self, ctx: ExecutionContext) -> RawResult: ...
```

## Capability mapping

When mapping MCP tools to capabilities, prefer task-shaped names:

| MCP tool | Capability ID | Safety class |
|----------|--------------|--------------|
| `list_files` | `fs.list_files` | READ |
| `read_file` | `fs.read_file` | READ |
| `write_file` | `fs.write_file` | WRITE |
| `delete_file` | `fs.delete_file` | DESTRUCTIVE |
| `execute_code` | `sandbox.run_code` | DESTRUCTIVE |
