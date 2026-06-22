# Context Firewall

## Why it exists

Large tool ecosystems produce large, verbose outputs. Passing raw tool output to an LLM
causes context blowup, leaks PII, and makes the agent unpredictable. The firewall
transforms every `RawResult` into a bounded `Frame` before the LLM sees it.

## Budgets

```python
from weaver_kernel.firewall.budgets import Budgets

Budgets(
    max_rows=50,    # max rows in table_preview
    max_fields=20,  # max fields per row
    max_chars=4000, # total characters across all facts
    max_depth=3,    # recursion depth for nested structures
)
```

The character size used for budget comparisons is computed by an allocation-free
estimator (`weaver_kernel.firewall.estimated_size`) that walks the structure
rather than serialising it with `json.dumps` — so a multi-MB raw result is never
fully serialised just to measure it. The estimate is deterministic and tracks
the serialised length closely; only threshold comparisons depend on it.

## Response modes

| Mode | What you get | When to use |
|------|-------------|-------------|
| `summary` | ≤20 fact strings + handle | Default; best for LLM context |
| `table` | ≤max_rows dicts + handle | When the LLM needs tabular data |
| `handle_only` | handle + warnings | Defer all data to an expand() call |
| `raw` | Full data (admin only) | Debugging; never for LLM context |

## Handles

A `Handle` is an opaque reference to the full dataset stored server-side.

A handle is bound to the principal it was granted to, so `expand()` requires that
same `principal` — an omitted or mismatched principal raises
`HandleConstraintViolation` (handle IDs are not bearer credentials). See
[`docs/security.md#handle-expansion-boundary`](security.md#handle-expansion-boundary).

```python
# Stored automatically on every invoke()
handle = frame.handle

# Expand with pagination
expanded = kernel.expand(handle, query={"offset": 10, "limit": 5}, principal=principal)

# Field selection
expanded = kernel.expand(handle, query={"fields": ["id", "name"]}, principal=principal)

# Basic filtering
expanded = kernel.expand(handle, query={"filter": {"status": "unpaid"}}, principal=principal)
```

### Bounding handle memory by size

The store holds *raw, pre-firewall* datasets, and entry count is a poor proxy
for memory — one deployment's 10k entries are kilobytes, another's are
gigabytes. `HandleStore` accepts two optional byte budgets (both `None` =
disabled, so default behaviour is unchanged):

```python
from weaver_kernel import HandleStore

store = HandleStore(
    max_total_bytes=512 * 1024 * 1024,  # evict oldest-first until within budget
    max_entry_bytes=64 * 1024 * 1024,   # reject a single over-cap payload
)
```

Sizes are estimated with the same `estimated_size` walk used for budgets.
`max_total_bytes` evicts oldest-first after each store (never the just-stored
entry); `max_entry_bytes` rejects an over-cap payload with `HandleTooLarge`
rather than truncating it, keeping expansion faithful to the original dataset.
Expanding an evicted handle raises the usual `HandleNotFound`. Tighter budgets
mean more "handle expired/evicted" experiences — tune for your workload.

## Redaction

When a capability has `SensitivityTag.PII` or `SensitivityTag.PCI`:
- Fields in `Capability.allowed_fields` are kept (others removed)
- Sensitive field names (`email`, `phone`, `card_number`, `ssn`, etc.) are replaced with `[REDACTED]`
- Inline patterns in string values (email addresses, phone numbers, SSNs, card numbers) are redacted

Principals with the `pii_reader` role bypass `allowed_fields` enforcement.

Redaction is applied on **every** path that returns data to the LLM, not just
the first `transform()`:

- **Depth boundary (fail-closed).** The `max_depth` cap bounds recursion cost.
  At the boundary, scalar strings are still pattern-scrubbed, but a nested
  container is *elided* (`[REDACTED: nested data beyond depth limit]`) rather
  than returned verbatim — a deeply nested subtree never reaches the LLM
  unscanned.
- **Handle expansion.** `HandleStore.expand()` runs its projected rows through
  the same `redact()` as the first invocation, so a secret inline in a
  permitted field (e.g. a token in a `note` value) is scrubbed on expand too.
- **Streaming.** `Firewall.apply_stream()` keeps a per-field `StreamRedactor`
  that holds back a trailing overlap window, so a secret split across two
  chunks is reassembled and redacted before either half is emitted. Patterns
  containing internal whitespace (phone/SSN/spaced card numbers) split exactly
  at the held boundary may still evade detection — see `docs/security.md`.

Invocation **arguments** recorded on `ActionTrace.args`, and driver **error**
text, are run through the same redactor before persistence, so the trace store
never becomes a sensitive-data sink (see `docs/security.md`).

## Summarization

Summaries are produced deterministically:
- **list of dicts** → row count + top keys + numeric stats + categorical/boolean
  distributions
- **dict** → key list + per-value type/value
- **string** → truncated to 500 chars
- **other** → repr() truncated to 200 chars

Boolean columns are reported as `True`/`False` counts, never averaged (a `bool`
is an `int` subclass in Python, so "mean of `is_active` = 0.7" is nonsense). When
the fact list is capped by `max_facts`, the final fact is an explicit omission
marker (`… (N more facts omitted; full data via handle)`) so a truncated summary
is never mistaken for a complete one.

## Cross-invocation budgets

The per-invocation `Budgets` above cap a single Frame. A separate
`BudgetManager` tracks cumulative token usage *across* invocations within a
session. It is optional — if you don't attach one, kernel behavior is
unchanged.

```python
from weaver_kernel import BudgetManager, Kernel

manager = BudgetManager(total_budget=100_000)
kernel = Kernel(registry, budget_manager=manager)
```

Per `invoke()` the kernel:

1. Reserves a slice of the remaining budget (default 4,000 tokens). If the
   budget is empty, `BudgetExhausted` is raised before the driver runs.
2. Consults `manager.suggested_mode(requested)` to escalate the requested
   `response_mode` to a more aggressive tier as the remaining budget shrinks.
3. After the firewall produces a Frame, counts the actual tokens in the
   LLM-facing payload and reconciles them against the reservation.

Escalation table:

| Budget remaining | Suggested mode (effective `response_mode`)     |
|-----------------:|------------------------------------------------|
| > 50%            | Caller's requested mode (no change)            |
| 20% – 50%        | `table` (when caller requested `raw`)          |
| 5% – 20% (≥ 5%)  | `summary` (floor — never *relaxes* to `table`) |
| < 5%             | `handle_only`                                  |

Boundaries land in the more-conservative tier — exactly 50% remaining
downgrades `raw` to `table`, exactly 20% floors at `summary`, and only when
remaining drops *below* 5% does `handle_only` take over.

`Kernel.invoke(..., dry_run=True)` mirrors the escalation and reports
`budget_remaining` in the returned `DryRunResult`, so callers can preview
what their next live invocation would actually return.

The default counter (`default_token_counter`) is a character-based
`len(json.dumps(value)) // 4` approximation with no extra dependencies. For real
token counts, install the `tiktoken` extra and use the shipped factory:

```python
from weaver_kernel.firewall import BudgetManager, make_tiktoken_counter

# pip install weaver-kernel[tiktoken]
manager = BudgetManager(
    total_budget=128_000,
    token_counter=make_tiktoken_counter(),              # default cl100k_base
    # token_counter=make_tiktoken_counter("o200k_base"),  # GPT-4o / o-series
)
```

`make_tiktoken_counter` resolves and caches the encoder eagerly, so a missing
extra (`ImportError`) or an unknown encoding name (`FirewallError`) fails at
construction rather than mid-budgeting. The encoding is explicit because models
tokenize differently — name the one you budget against. `tiktoken` is imported
lazily, so `import weaver_kernel` never pulls the heavyweight dependency. Any
callable matching the `TokenCounter` protocol works too.

## Streaming

For large results that arrive incrementally (e.g. SSE-style HTTP responses,
chunked database cursors, line-by-line tool output), `Firewall.apply_stream()`
lets you process chunks one at a time. PII redaction and per-chunk budget
caps apply on every yielded Frame — secrets cannot leak just because they
arrived in chunk N rather than the final aggregate.

```python
from weaver_kernel.drivers.base import ExecutionContext, StreamingDriver

class MyStreamingDriver:
    driver_id = "stream"

    async def execute(self, ctx: ExecutionContext):
        # one-shot fallback, called when StreamingDriver isn't used.
        ...

    async def execute_stream(self, ctx: ExecutionContext):
        async for row in some_async_cursor(ctx):
            yield {"row": row}
        yield {"__is_final__": True}  # explicit sentinel (optional)


# isinstance(driver, StreamingDriver) is runtime-checkable.
assert isinstance(MyStreamingDriver(), StreamingDriver)

async for frame in kernel.invoke_stream(token, principal=p, args={}):
    handle_chunk(frame)
    if frame.is_final:
        break
```

When the resolved driver does **not** implement `StreamingDriver`,
`Kernel.invoke_stream` falls back to a single `Driver.execute()` call and
yields exactly one `Frame` with `is_final=True`. Each invocation produces
one `ActionTrace` covering the whole stream.

## Observability

`weaver_kernel.instrument_kernel(kernel)` installs OpenTelemetry spans and
metric emission on `Kernel.invoke` and `Kernel.grant_capability`:

```python
from weaver_kernel import Kernel, instrument_kernel, OTEL_AVAILABLE

kernel = Kernel(registry=...)
if OTEL_AVAILABLE:
    instrument_kernel(kernel)  # no-op when [otel] extra not installed
```

Spans: `weaver_kernel.invoke`, `weaver_kernel.grant`. Metrics:
`weaver_kernel.invocations` (counter), `weaver_kernel.invocation_duration`
(histogram, ms), `weaver_kernel.policy_denials` (counter). The call is
idempotent — repeat invocations on the same kernel are no-ops.
