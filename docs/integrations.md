# Integrations

## MCP (Model Context Protocol)

To integrate with an MCP server, implement a custom driver that wraps the MCP client:

```python
from agent_kernel.drivers.base import Driver, ExecutionContext
from agent_kernel.models import RawResult

class MCPDriver:
    def __init__(self, mcp_client, driver_id: str = "mcp"):
        self._client = mcp_client
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        operation = ctx.args.get("operation", ctx.capability_id)
        result = await self._client.call_tool(operation, ctx.args)
        return RawResult(capability_id=ctx.capability_id, data=result)
```

Then register it:

```python
kernel.register_driver(MCPDriver(mcp_client))
router.add_route("mcp.my_tool", ["mcp"])
```

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
