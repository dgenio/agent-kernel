# ChainWeaver compiled flows as policy-controlled capabilities

[ChainWeaver](https://github.com/dgenio/ChainWeaver) is the Weaver-ecosystem
orchestration layer: it *compiles* a multi-step flow that an agent can run.
agent-kernel owns authorization, execution, and audit. Wrapping a compiled flow
as a capability means the flow runs through the normal pipeline
(policy → token → invoke → firewall → trace) instead of as an out-of-band side
channel — so a flow invocation is policy-checked and auditable like any other
capability (weaver-spec **I-02**).

This page describes the pattern. The runnable companion is
[`examples/chainweaver_flow.py`](../../examples/chainweaver_flow.py), which is
deterministic, offline, and depends on no ChainWeaver package.

> ChainWeaver is **not** a required dependency. The adapter only relies on a
> compiled flow exposing a `run(inputs)` method and a `flow_id` attribute. The
> example ships tiny `CompiledFlow` / `FlowExecutionError` stand-ins so it runs
> in CI; in production you pass a real compiled flow to `ChainWeaverDriver`.

## The pattern

```
agent invokes flows.summarize_release
        │
        ▼
ChainWeaverDriver.execute()  →  compiled_flow.run(inputs)
        │                              │
        │                              ├─ all steps ok → RawResult → Frame + ActionTrace
        │                              └─ step raises  → FlowExecutionError
        ▼                                                     │
   DriverError (flow id + failing step preserved) ◄───────────┘
```

| Component | Role |
|---|---|
| `CompiledFlow` | A ChainWeaver compiled flow: ordered, named steps run over a shared context. |
| `ChainWeaverDriver` | Implements the `Driver` protocol; maps a capability operation to a flow and runs it. |
| `flows.summarize_release` | A `READ` capability whose implementation is the compiled flow. |

## The adapter

`ChainWeaverDriver` implements the `Driver` protocol and runs the flow bound to
the capability's operation:

```python
class ChainWeaverDriver:
    def __init__(self, flows: dict[str, CompiledFlow], *, driver_id: str = "chainweaver") -> None:
        self._flows = dict(flows)
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        operation = str(ctx.args.get("operation", ctx.capability_id))
        flow = self._flows.get(operation)
        if flow is None:
            raise DriverError(f"... no flow for operation='{operation}'.")
        inputs = {k: v for k, v in ctx.args.items() if k != "operation"}
        try:
            output = flow.run(inputs)
        except FlowExecutionError as exc:
            raise DriverError(
                f"ChainWeaver flow '{exc.flow_id}' failed at step '{exc.step}': {exc.cause}"
            ) from exc
        return RawResult(capability_id=ctx.capability_id, data=output,
                         metadata={"flow_id": flow.flow_id, "steps": [s.name for s in flow.steps]})
```

## Errors preserve ChainWeaver context

A real ChainWeaver flow raises its own exception when a step fails. The adapter
**translates** that native error into a kernel `DriverError`, carrying the flow
id and the failing step into the message rather than leaking a raw traceback.
`Kernel.invoke()` then wraps it as
`All drivers failed for capability '...'. Last error: ChainWeaver flow '<flow_id>'
failed at step '<step>': <cause>`, so the orchestration context survives for the
caller — and a failed run still records an `ActionTrace` (with `error` set), so
I-02 holds even on failure.

## Audit trail

A successful invocation is recorded like any capability:

```python
action_id = await run_flow(kernel, principal, {"release": "v1.4.0", "changes": [...]})
trace = kernel.explain(action_id)
# trace.driver_id == "chainweaver"
# trace.result_summary == {"fact_count": ..., "row_count": ..., "warning_count": ..., "has_handle": ...}
```

## Non-goals

- agent-kernel does not compile flows — that is ChainWeaver's job.
- ChainWeaver is never a required dependency.
- Wrapping a flow does not bypass policy: the flow capability is granted and
  invoked through the same pipeline as every other capability.

## Related

- `examples/chainweaver_flow.py` — runnable, offline.
- [ChainWeaver](https://github.com/dgenio/ChainWeaver)
- [weaver-spec](https://github.com/dgenio/weaver-spec)
