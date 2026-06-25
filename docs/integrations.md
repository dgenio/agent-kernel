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

from weaver_kernel import CapabilityRegistry, Kernel, StaticRouter
from weaver_kernel.drivers.mcp import MCPDriver


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

from weaver_kernel import CapabilityRegistry, Kernel, StaticRouter
from weaver_kernel.drivers.mcp import MCPDriver


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

The built-in `HTTPDriver` supports GET, POST, PUT, DELETE (and any other method
via the generic path):

```python
from weaver_kernel.drivers.http import HTTPDriver, HTTPEndpoint

driver = HTTPDriver(
    driver_id="my_api",
    # Optional response-size guard: reject bodies larger than this before they
    # are fully buffered, so an unbounded upstream cannot exhaust memory (#194).
    max_response_bytes=5_000_000,
)
driver.register_endpoint("users.list", HTTPEndpoint(
    url="https://api.example.com/users",
    method="GET",
    headers={"Authorization": "Bearer ..."},
))
kernel.register_driver(driver)
```

The driver holds a single long-lived `httpx.AsyncClient` so requests reuse the
connection pool and keep-alive instead of opening a fresh connection per call
(#194). You own its lifecycle — call `await driver.aclose()` on shutdown (e.g.
in a `finally` block) to release the pool.

A non-JSON body from a JSON endpoint raises a typed `DriverError` rather than
leaking a decode error (#197). For text APIs, set `response_format="text"` on
the endpoint to receive the decoded body verbatim:

```python
driver.register_endpoint("status.page", HTTPEndpoint(
    url="https://api.example.com/status",
    response_format="text",
))
```

### Bounding execution time

Any driver — HTTP, MCP, or custom — can be bounded by a per-invocation
deadline. Set the `invoke_timeout_s` constraint when the policy issues the
grant; because constraints are signed into the capability token, the deadline
is tamper-evident and travels with the grant. An attempt that exceeds it is
turned into a `DriverError`, so the kernel still records a failure trace and
releases any reserved budget (#191):

```python
# A policy engine that attaches a 10s deadline to issued tokens:
decision.constraints["invoke_timeout_s"] = 10.0
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

## LLM tool-format adapters

`weaver_kernel.adapters` converts `Capability` objects into the tool shapes
expected by OpenAI and Anthropic, and routes the matching tool-call objects
back through the kernel pipeline (grant → invoke → firewall → trace). The
adapters are pure dict transforms — there is **no runtime dependency** on the
`openai` or `anthropic` SDK packages.

### Input schemas with pydantic

Capabilities advertise their input schema via two optional fields on
`Capability`:

- `parameters_model: type[pydantic.BaseModel] | None` — pydantic model. The
  adapter calls `.model_json_schema()` and validates tool-call arguments
  against the model before invocation.
- `parameters_schema: dict | None` — raw JSON Schema, used verbatim. No
  argument validation is performed (use `parameters_model` for that).

`Capability.allowed_fields` is an **output redaction** control consumed by the
firewall — it is *not* used as an input schema source.

```python
from pydantic import BaseModel, Field

from weaver_kernel import Capability, SafetyClass


class ListInvoicesArgs(BaseModel):
    customer_id: str
    limit: int = Field(default=10, ge=1, le=100)


list_invoices = Capability(
    capability_id="billing.list_invoices",
    name="List Invoices",
    description="List invoices for a customer",
    safety_class=SafetyClass.READ,
    parameters_model=ListInvoicesArgs,
)
```

### OpenAI middleware

```python
import asyncio

from weaver_kernel import Kernel, OpenAIMiddleware, Principal


async def main() -> None:
    kernel = Kernel(registry=registry, ...)
    principal = Principal(principal_id="agent-1", roles=["reader"])
    mw = OpenAIMiddleware(kernel, principal)

    tools = mw.get_tools()                       # → list[dict] for OpenAI SDK
    # response = await openai_client.responses.create(model=..., tools=tools, ...)
    # outputs = await mw.handle_tool_calls(response.output)
    # → list of {"type": "function_call_output", "call_id", "output"} dicts.


asyncio.run(main())
```

The default output shape is **OpenAI Responses API**
(`function_call_output`). Use `format="chat_completions"` to emit nested
`{"type": "function", "function": {...}}` tool definitions and
`{"role": "tool", ...}` result messages instead:

```python
mw = OpenAIMiddleware(kernel, principal, format="chat_completions")
```

`handle_tool_calls` auto-detects the input shape per call regardless of the
configured output format, so you can pass either Responses-API
`response.output` items or Chat-Completions `message.tool_calls` items.

#### Namespace mapping

OpenAI tool names cannot contain `.`, so dotted capability IDs are mapped to
double-underscore form on the way out and restored on the way back:

| Capability ID | OpenAI tool name |
|---|---|
| `billing.list_invoices` | `billing__list_invoices` |
| `billing.invoices.list` | `billing__invoices__list` |

Capability IDs that already contain `__` cannot be round-tripped unambiguously
(`a__b` and `a.b` would both produce the OpenAI tool name `a__b`). The adapter
rejects them at tool-emit time with an `AdapterParseError` rather than
silently emitting colliding tools.

#### Strict mode

Set `Capability.tool_hints = ToolHints(strict=True)` to emit the tool
definition with OpenAI's `strict: true` flag. The adapter normalises the
schema so every property is required and `additionalProperties` is `false`
at every level. If normalisation fails (e.g. a schema feature OpenAI strict
mode does not accept) the adapter falls back to non-strict and emits a
warning.

**Strict mode caveats**

OpenAI strict mode requires every property be listed in `required`. The
adapter's normaliser enforces this unconditionally. That means pydantic
fields with non-`None` defaults — which pydantic itself emits as
*not* required — will be forced into `required` after normalisation. The
LLM is then expected to always include the field even though pydantic would
fall back to the default if it were omitted.

To express a truly-optional field under strict mode, use the `Optional[T]`
pattern (with `None` as the default):

```python
class ListInvoicesArgs(BaseModel):
    customer_id: str           # required, str
    limit: int = 10            # forced into required by strict mode
    cursor: str | None = None  # required + nullable (LLM can pass null)
```

Pydantic emits `Optional[str] = None` (or `str | None = None`) as
`{"anyOf": [{"type": "string"}, {"type": "null"}]}`. OpenAI strict mode
accepts `null` as a valid value for such fields, so the LLM can effectively
"omit" them by passing `null`.

### Anthropic middleware

```python
import asyncio

from weaver_kernel import AnthropicMiddleware, Kernel, Principal


async def main() -> None:
    kernel = Kernel(registry=registry, ...)
    principal = Principal(principal_id="agent-1", roles=["reader"])
    mw = AnthropicMiddleware(kernel, principal)

    tools = mw.get_tools()                       # → list[dict] for Anthropic SDK
    # message = await anthropic_client.messages.create(model=..., tools=tools, ...)
    # tool_results = await mw.handle_tool_uses(message.content)
    # → list of {"type": "tool_result", "tool_use_id", "content"} blocks.


asyncio.run(main())
```

#### Prompt cache control

Set `Capability.tool_hints = ToolHints(cache_control={"type": "ephemeral"})`
to attach Anthropic's prompt-cache control block to that capability's tool
definition. To apply a default to every tool that does not specify its own,
pass `default_cache_control` to the middleware:

```python
mw = AnthropicMiddleware(
    kernel,
    principal,
    default_cache_control={"type": "ephemeral"},
)
```

### Hooks (pre/post invocation)

Both middlewares accept synchronous or asynchronous callbacks via
`intercept_tool_call(callback)` and `intercept_tool_result(callback)`. Hooks
fire in registration order. Pre-hooks receive a mutable `ToolCallEvent`
(useful for logging, metrics, approval gates, injecting `justification` for
WRITE/DESTRUCTIVE calls); post-hooks receive a `ToolResultEvent` carrying
either the kernel `Frame` or an error string.

```python
async def audit(event):
    log.info("tool_call", capability=event.capability_id, principal=event.principal_id)

def gate(event):
    if event.capability_id.startswith("billing.delete"):
        event.aborted = True
        event.abort_reason = "deletions require manual approval"

mw.intercept_tool_call(audit)
mw.intercept_tool_call(gate)
```

Setting `event.aborted = True` skips kernel invocation and produces a
tool-result error block containing `event.abort_reason`. Setting
`event.justification = "..."` lets a hook supply the per-call justification
the policy engine requires for WRITE/DESTRUCTIVE capabilities. Per-call
overrides can also be threaded through arguments as `_justification` (the
adapter pops it before passing args to the driver).

### Errors are tool results, not exceptions

`PolicyDenied`, `CapabilityNotFound`, `DriverError`, argument-validation
failures, and hook abort signals are all returned to the LLM as a tool result
with `error: true` (Anthropic also sets `is_error: true`). Raised exceptions
would crash the surrounding agent loop; the LLM cannot react to an
exception.

## OpenTelemetry

`weaver_kernel.instrument_kernel(kernel)` wraps `Kernel.invoke` and
`Kernel.grant_capability` with OTel spans + metrics. The optional
`[otel]` extra brings in `opentelemetry-api`; everything is a strict
no-op when the extra is not installed.

```bash
pip install 'weaver-kernel[otel]'           # api only — for production
pip install 'weaver-kernel[otel]' opentelemetry-sdk \
            opentelemetry-exporter-otlp     # also the SDK + exporter
```

```python
from weaver_kernel import Kernel, instrument_kernel

kernel = Kernel(registry=...)
instrument_kernel(kernel)
# Production: rely on global TracerProvider/MeterProvider configured at
# process start. Tests can pass explicit providers:
#   instrument_kernel(kernel, tracer_provider=..., meter_provider=...)
```

| Telemetry | Name | Notes |
|-----------|------|-------|
| Span | `weaver_kernel.invoke` | attrs: `principal_id`, `capability_id`, `response_mode`, `dry_run` |
| Span | `weaver_kernel.grant` | attrs: `principal_id`, `capability_id` |
| Counter | `weaver_kernel.invocations` | labels: `capability_id`, `status` (`success`/`error`) |
| Histogram | `weaver_kernel.invocation_duration` | unit: ms |
| Counter | `weaver_kernel.policy_denials` | labels: `capability_id`, `reason_code` |

`instrument_kernel` is idempotent — calling twice on the same kernel is a
no-op. Use `weaver_kernel.otel.reset_instrumentation(kernel)` in tests to
re-instrument with a different provider.

## SIEM export (OCSF / OWASP AOS)

OpenTelemetry feeds the *observability* pipeline; SIEMs speak **OCSF** (the Open
Cybersecurity Schema Framework), the *security-operations* pipeline. The audit
trail maps to OCSF **API Activity** events (class `6003`), enriched per the OWASP
Agent Observability Standard (AOS), with no new dependency — the mapping is a pure
dict construction.

```python
from weaver_kernel import traces_to_ocsf

events = traces_to_ocsf(kernel.list_traces())   # list[dict], OCSF-shaped
# ship `events` to your SIEM (one JSON object per event)
```

`trace_to_ocsf(trace)` maps a single record. Runnable recipe:
[`examples/ocsf_export_demo.py`](../examples/ocsf_export_demo.py).

Field mapping (kernel `ActionTrace` → OCSF API Activity 6003):

| OCSF field | Source |
|------------|--------|
| `class_uid` / `class_name` | constant `6003` / `"API Activity"` |
| `category_uid` / `category_name` | constant `6` / `"Application Activity"` |
| `activity_id` / `activity_name` | `event_type`: invoke→Other(99), expand→Read(2), deny→Other(99) |
| `type_uid` | `class_uid * 100 + activity_id` |
| `status_id` / `status` | `2`/`Failure` when `error` is set, else `1`/`Success` |
| `status_detail` | `error` (already redacted at record time) |
| `severity_id` / `severity` | deny→Medium(3), else Informational(1) |
| `time` | `invoked_at` as epoch milliseconds (UTC) |
| `actor.user.uid` | `principal_id` |
| `api.operation` / `api.service.name` | `capability_id` / `driver_id` (or `"weaver-kernel"`) |
| `metadata` | product + OCSF version (`OCSF_VERSION`) + AOS extension marker |
| `unmapped` | kernel specifics: `action_id`, `token_id`, `event_type`, `response_mode`, `sensitivity`, `reason_code`, `handle_id`, `result_summary` |

The mapping is built only from already-redaction-safe trace fields, so exporting
cannot widen the I-01 boundary. AOS is young, so the mapping is versioned and
isolated in `weaver_kernel.ocsf`; output is validated structurally in the tests.

## Ecosystem integration patterns

These reference flows show how agent-kernel composes with neighboring Weaver
projects and external checkers. Each has a runnable, offline companion under
`examples/`.

- [contextweaver + agent-kernel: policy before action](integrations/contextweaver.md)
  — context routing is advisory; selection is not permission. Demonstrates the
  `allow` / `ask`-confirm / `deny` outcomes.
  Companion: [`examples/contextweaver_policy_flow.py`](../examples/contextweaver_policy_flow.py).
- [Repository safety checks as a policy-controlled capability](integrations/repository_safety_check.md)
  — gate a high-impact action behind a deterministic check that shells out to a
  local command (e.g. VibeGuard), with the result recorded in the audit trace.
  Companion: [`examples/repository_safety_check.py`](../examples/repository_safety_check.py).
- [ChainWeaver compiled flows as policy-controlled capabilities](integrations/chainweaver.md)
  — wrap a ChainWeaver compiled flow behind the `Driver` protocol so it runs
  through the normal policy/audit pipeline; step failures surface as a
  `DriverError` that preserves the flow id and failing step. ChainWeaver stays
  an optional dependency.
  Companion: [`examples/chainweaver_flow.py`](../examples/chainweaver_flow.py).
- [Policy guardrails for statistical evaluation artifacts](integrations/evaluation_artifacts.md)
  — let an agent summarize an evaluation artifact while gating deployment/rollout
  recommendations on its support diagnostics; the downgrade reason is recorded in
  the audit trace. Producer-agnostic; no statistical estimation in agent-kernel.
  Companion: [`examples/evaluation_artifact_policy.py`](../examples/evaluation_artifact_policy.py).
