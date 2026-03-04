# Designing Capabilities

## Naming conventions

- Use `domain.verb_noun` format: `billing.list_invoices`, `users.get_profile`.
- Be specific: prefer `billing.cancel_invoice` over `billing.update`.
- Avoid generic names like `billing.execute` or `api.call`.

## Granularity

Each capability should map to a single, auditable action with clear side-effects.

**Good:**
- `billing.list_invoices` (READ, no side-effects)
- `billing.send_reminder` (WRITE, sends an email)
- `billing.void_invoice` (DESTRUCTIVE, irreversible)

**Avoid:**
- `billing.do_stuff` (too broad)
- `billing.list_or_update_invoices` (mixed safety classes)

## Safety classes

| Class | Examples | Policy |
|-------|---------|--------|
| READ | list, get, search, summarize | Always allowed |
| WRITE | create, update, send, approve | Justification + writer role |
| DESTRUCTIVE | delete, void, purge, terminate | Admin role only |

## Sensitivity tags

Use `SensitivityTag.PII` when results may contain: name, email, phone, SSN, address.
Use `SensitivityTag.PCI` when results may contain: card numbers, CVV, bank details.
Use `SensitivityTag.SECRETS` when results may contain: API keys, passwords, tokens.

Always pair sensitivity tags with `allowed_fields` to restrict which fields are returned
to non-privileged callers.

## Tags

Add descriptive tags to improve keyword matching:

```python
Capability(
    capability_id="billing.list_invoices",
    tags=["billing", "invoices", "list", "finance", "accounts receivable"],
    ...
)
```
