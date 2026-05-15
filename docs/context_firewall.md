# Context Firewall

## Why it exists

Large tool ecosystems produce large, verbose outputs. Passing raw tool output to an LLM
causes context blowup, leaks PII, and makes the agent unpredictable. The firewall
transforms every `RawResult` into a bounded `Frame` before the LLM sees it.

## Budgets

```python
from agent_kernel.firewall.budgets import Budgets

Budgets(
    max_rows=50,    # max rows in table_preview
    max_fields=20,  # max fields per row
    max_chars=4000, # total characters across all facts
    max_depth=3,    # recursion depth for nested structures
)
```

## Response modes

| Mode | What you get | When to use |
|------|-------------|-------------|
| `summary` | ≤20 fact strings + handle | Default; best for LLM context |
| `table` | ≤max_rows dicts + handle | When the LLM needs tabular data |
| `handle_only` | handle + warnings | Defer all data to an expand() call |
| `raw` | Full data (admin only) | Debugging; never for LLM context |

## Handles

A `Handle` is an opaque reference to the full dataset stored server-side.

```python
# Stored automatically on every invoke()
handle = frame.handle

# Expand with pagination
expanded = kernel.expand(handle, query={"offset": 10, "limit": 5})

# Field selection
expanded = kernel.expand(handle, query={"fields": ["id", "name"]})

# Basic filtering
expanded = kernel.expand(handle, query={"filter": {"status": "unpaid"}})
```

## Redaction

When a capability has `SensitivityTag.PII` or `SensitivityTag.PCI`:
- Fields in `Capability.allowed_fields` are kept (others removed)
- Sensitive field names (`email`, `phone`, `card_number`, `ssn`, etc.) are replaced with `[REDACTED]`
- Inline patterns in string values (email addresses, phone numbers, SSNs, card numbers) are redacted

Principals with the `pii_reader` role bypass `allowed_fields` enforcement.

## Summarization

Summaries are produced deterministically:
- **list of dicts** → row count + top keys + numeric stats + categorical distributions
- **dict** → key list + per-value type/value
- **string** → truncated to 500 chars
- **other** → repr() truncated to 200 chars

## Cross-invocation budgets

The per-invocation `Budgets` above cap a single Frame. A separate
`BudgetManager` tracks cumulative token usage *across* invocations within a
session. It is optional — if you don't attach one, kernel behavior is
unchanged.

```python
from agent_kernel import BudgetManager, Kernel

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

Plug a different token counter (for example, a `tiktoken`-based one) via the
`TokenCounter` protocol:

```python
import tiktoken                         # pip install weaver-kernel[tiktoken]
enc = tiktoken.encoding_for_model("gpt-4o")

def tiktoken_counter(value):
    return len(enc.encode(str(value)))

manager = BudgetManager(total_budget=128_000, token_counter=tiktoken_counter)
```

The default counter (`default_token_counter`) is a character-based
`len(json.dumps(value)) // 4` approximation with no extra dependencies.
