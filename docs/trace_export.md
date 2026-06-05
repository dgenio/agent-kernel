# Action Trace Export

agent-kernel records an [`ActionTrace`](architecture.md) for every invocation.
The **trace export contract** turns those records into a stable,
JSON-serialisable shape that an external tool can consume — for example a
[LessonWeaver](https://github.com/dgenio/weaver-spec)-style lesson-extraction
layer that learns from past actions, policies, denials, corrections, and
outcomes.

```python
from weaver_kernel import export_action_traces

envelope = export_action_traces(kernel._traces.list_all())
```

Runnable companion: [`examples/trace_export_demo.py`](../examples/trace_export_demo.py).

## How this differs from OpenTelemetry export

agent-kernel also ships an OpenTelemetry integration
([`weaver_kernel.otel`](architecture.md), `pip install weaver-kernel[otel]`).
The two serve different consumers and do **not** compete:

| | OpenTelemetry (`instrument_kernel`) | Trace export (`export_action_traces`) |
|---|---|---|
| Consumer | Live observability backends (traces/metrics) | Offline analysis / learning tools |
| Shape | OTel spans + metrics, vendor-defined | Stable JSON envelope defined here |
| Timing | Emitted during execution | Pulled after the fact from the `TraceStore` |
| Stability | Tracks OTel semantic conventions | Versioned by `TRACE_EXPORT_VERSION` |

Use OTel for dashboards and alerting; use the export contract when another
program needs a durable, replayable record of what the agent did.

## Privacy

The export is derived **only** from fields the `ActionTrace` already holds,
all of which are redaction-safe by construction:

- `args` has memory payloads stripped at record time (keys like `payload`,
  `content`, `value`, `memory`, `text`, `body` for `memory.*` capabilities
  become `"[REDACTED]"`).
- `result_summary` carries counts and flags taken from the **post-firewall**
  `Frame` — never raw driver data.

The contract adds no field the trace did not already carry, so exporting can
never widen the I-01 firewall boundary or leak sensitive payloads. A *denied*
request never produces an `ActionTrace` — policy gates before invocation
(I-02) — so the export only ever describes authorised invocations; denials are
surfaced separately via `PolicyDenied` / `Kernel.explain_denial`.

## Envelope shape

`export_action_traces(...)` returns a versioned envelope:

```json
{
  "schema": "weaver_kernel.action_trace_export",
  "version": "1",
  "traces": [ /* one object per ActionTrace */ ]
}
```

Each trace object:

| Field | Type | Notes |
|-------|------|-------|
| `action_id` | string | Unique id; matches `Kernel.explain(action_id)`. |
| `capability_id` | string | The capability (tool) that was invoked. |
| `principal_id` | string | Who invoked it. |
| `token_id` | string | The capability token used. |
| `invoked_at` | string | ISO 8601 timestamp. |
| `response_mode` | string | `summary` / `table` / `handle_only` / `raw`. |
| `driver_id` | string | Driver that served the call (`""` on failure). |
| `handle_id` | string \| null | Handle for the full dataset, if one was minted. |
| `sensitivity` | string | `NONE` / `PII` / `PCI` / `SECRETS` / `MEMORY`. |
| `status` | string | `succeeded` or `failed` (derived from `error`). |
| `error` | string \| null | Failure reason; `null` on success. |
| `args` | object | Redacted invocation arguments. |
| `result_summary` | object \| null | Post-firewall counts/flags; `null` on failure. |
| `correction` | object \| null | Optional human-correction metadata (see below). |

### Human corrections

agent-kernel does not record human corrections itself. A downstream tool can
attach them at export time by passing a mapping of `action_id` → metadata:

```python
envelope = export_action_traces(
    traces,
    corrections={"act-123": {"corrected_by": "reviewer", "note": "wrong customer"}},
)
```

## Example output

```json
{
  "schema": "weaver_kernel.action_trace_export",
  "version": "1",
  "traces": [
    {
      "action_id": "0a1b...",
      "capability_id": "billing.list_invoices",
      "principal_id": "agent-007",
      "token_id": "f3c2...",
      "invoked_at": "2026-06-05T12:00:00+00:00",
      "response_mode": "summary",
      "driver_id": "billing",
      "handle_id": "9d7e...",
      "sensitivity": "PII",
      "status": "succeeded",
      "error": null,
      "args": {"operation": "list_invoices", "status": "paid"},
      "result_summary": {"fact_count": 4, "row_count": 0, "warning_count": 1, "has_handle": true},
      "correction": null
    },
    {
      "action_id": "5e6f...",
      "capability_id": "billing.flaky_report",
      "principal_id": "agent-007",
      "token_id": "11aa...",
      "invoked_at": "2026-06-05T12:00:01+00:00",
      "response_mode": "summary",
      "driver_id": "",
      "handle_id": null,
      "sensitivity": "NONE",
      "status": "failed",
      "error": "Handler for operation='flaky_report' raised: reporting backend is unavailable",
      "args": {"operation": "flaky_report"},
      "result_summary": null,
      "correction": {"corrected_by": "on-call", "note": "known outage; retried later"}
    }
  ]
}
```

## Stability

`TRACE_EXPORT_VERSION` is bumped only on a **breaking** change to the field
shape. New optional fields may be added without a bump, so consumers should
ignore unknown keys. Assert on `status`, `sensitivity`, and `reason`/`error`
rather than on human-readable strings, which may evolve.
