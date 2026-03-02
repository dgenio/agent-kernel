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
