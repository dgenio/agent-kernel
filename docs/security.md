# Security Model

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Tool-space interference (agent calls wrong tool) | Capability registry + policy gate before any execution |
| Confused deputy attack | Tokens are bound to `principal_id` — cannot be reused by another principal |
| Token forgery / tampering | HMAC-SHA256 signature; any bit flip → `TokenInvalid` |
| Token replay after expiry | Expiry checked on every `verify()` call |
| Context injection via raw tool output | Firewall always transforms `RawResult → Frame`; raw data never reaches LLM by default |
| PII / PCI leakage | Redaction + `allowed_fields` enforcement in the firewall |
| Privilege escalation via WRITE/DESTRUCTIVE | Policy engine enforces role requirements |
| Audit evasion | Every `invoke()` creates an immutable `ActionTrace` |
| Handle scope escape (expand exceeds grant) | Handles persist grant constraints; `HandleStore.expand` rechecks `max_rows`, `allowed_fields`, `scope`, and principal binding (#76) |
| Memory exfiltration via tool output | `SensitivityTag.MEMORY` capabilities gate sensitive reads and durable writes; `ActionTrace.args` redacts payload-like fields for `memory.*` capabilities (#75) |
| Raw memory payload reaching audit log | Kernel strips `payload`/`content`/`value`/`memory`/`text`/`body` from `ActionTrace.args` for `memory.*` capabilities |
| Scanned content / raw result reaching audit log | `ActionTrace.result_summary` is built only from the post-firewall `Frame` (counts and flags, never raw driver data), so the audit trail records an invocation's outcome without re-introducing the data the firewall removed |

## Token scopes

A `CapabilityToken` binds:
- `capability_id` — which capability is authorized
- `principal_id` — who the token was issued to
- `constraints` — max_rows, allowed_fields, etc. (signed into the token)
- `expires_at` — validity window

Any change to these fields invalidates the HMAC signature.

## Confused deputy prevention

Consider an agent that obtains a token for `billing.list_invoices` then passes it to a different agent. The second agent cannot use it because `verify()` checks that `token.principal_id == expected_principal_id`.

The same principle extends to handles: every `Handle` carries the `principal_id`
the original grant was issued to. When `handle.principal_id` is non-empty,
`HandleStore.expand` rejects expansion unless the caller supplies a matching
`principal_id`. **An omitted or empty `principal_id` is treated as a
mismatch** (`HandleConstraintViolation`, `reason_code = HANDLE_PRINCIPAL_MISMATCH`),
so a handle ID alone is not a bearer credential — proof of the original
principal is always required. `Kernel.expand(..., principal=Principal(...))`
forwards the principal automatically.

## Handle expansion boundary

Calling `kernel.expand(handle, query=...)` does not re-run the policy engine —
the original grant already authorised the dataset, and handles are short-lived.
But the grant's _constraints_ must still apply, otherwise an over-broad
`expand` query would silently return data the original grant never covered.

`HandleStore.expand` rechecks the constraints the kernel persists on the handle
at creation time (`token.constraints`):

| Constraint | Enforced behavior on expand |
|------------|-----------------------------|
| `max_rows` | A request `limit` larger than the cap raises `HandleConstraintViolation`. An unspecified or larger implicit limit is silently clamped. |
| `allowed_fields` | A request `fields` entry that is not in `allowed_fields` raises `HandleConstraintViolation`. An unscoped expand applies `allowed_fields` as the default projection, so disallowed fields never leak. |
| `scope` (e.g. `{"region": "eu"}`) | The scope filter is AND-merged into the request filter. A request filter that disagrees on a scoped dimension raises `HandleConstraintViolation`. |
| `principal_id` | A mismatched `principal_id` parameter raises `HandleConstraintViolation` (`HANDLE_PRINCIPAL_MISMATCH`). |

Errors carry stable `reason_code` values (`handle_constraint_violation`,
`handle_principal_mismatch`) — assert on those, not on the message text.

## Memory actions

Capabilities tagged `SensitivityTag.MEMORY` represent durable agent memory
(project notes, session handoff, learned context). Reads of project-scoped
memory are allowed by default; reads of sensitive-scoped memory require an
explicit role. Writes always require the `memory_writer` role (or `admin`)
because they persist into future sessions.

| Action | Required role | Denial reason code |
|--------|---------------|--------------------|
| `memory.read` with `scope["memory_scope"] == "project"` | none | — |
| `memory.read` with `scope["memory_scope"] == "sensitive"` | `memory_reader_sensitive` or `admin` | `memory_sensitive_read_denied` |
| `memory.write` (any scope) | `memory_writer` or `admin` | `memory_write_requires_writer` |
| `memory.forget` (DESTRUCTIVE) | `admin` (then `memory_writer` or `admin`) | `missing_role`, then `memory_write_requires_writer` |

To prevent durable memory content from leaking into the audit log, the kernel
strips payload-like fields (`payload`, `content`, `value`, `memory`, `text`,
`body`) from `ActionTrace.args` for any capability whose ID begins with
`memory.`. Non-sensitive metadata keys (`key`, `id`, `scope`, ...) are
preserved so audit can still confirm an action took place.

## Audit-log integrity (hash chain)

When traces are persisted to a durable store (`SQLiteTraceStore`,
`JsonlTraceStore`), each record is wrapped in a hash chain: `record_hash =
HMAC-SHA256(secret, {seq, prev_hash, trace})`, where `prev_hash` is the previous
record's hash (the first record links to a genesis value). `verify_chain()`
recomputes every hash and checks the linkage, so it detects:

- **mutation** of any persisted record (recomputed hash diverges),
- **interior insertion, deletion, or reordering** (broken `prev_hash` linkage or a
  non-contiguous `seq`),

and reports the `seq` of the first divergent record. `SQLiteTraceStore.prune()`
removes old records while preserving verifiability of the retained suffix by
recording the last pruned record's hash as a checkpoint.

**Truncation is the exception.** The chain stores no signed head/length anchor, so
dropping the **most recent** records (tail truncation) — or deleting the whole
store — leaves a self-consistent prefix that still verifies: there is no broken
link or sequence gap to detect, and an empty store verifies vacuously. Detecting
truncation requires anchoring the expected head out of band (a separately stored,
signed record count + head hash); that is a planned follow-up. Until then, treat
append-only durability (JSONL shipped to a write-once collector, or a SQLite file
on append-only storage) as the truncation defense.

**What this is — and is not.** This is **tamper-evidence**: anyone who does not
hold `WEAVER_KERNEL_SECRET` cannot alter the log without `verify_chain()`
detecting it. It is **not non-repudiation**: a host that controls the secret can
forge a self-consistent chain, and the same secret signs tokens, so the audit
log is only as trustworthy as secret custody. It does not encrypt trace contents
at rest, and it does not anchor the chain to an external timestamping authority.
The chain payload is the redaction-safe export shape — chaining adds no field the
in-memory trace did not already hold and cannot widen the I-01 boundary.

The CLI exposes verification to operators: `weaver-kernel audit verify --store
audit.db` exits non-zero on any divergence (see [cli.md](cli.md)).

## Security disclaimers

> **v0.1 is not production-hardened for real authentication.**

- HMAC tokens are tamper-evident but **not encrypted**. Do not put sensitive data in token fields.
- The `WEAVER_KERNEL_SECRET` must be kept secret. Rotate it if compromised.
- The default `InMemoryDriver` has no persistence — suitable for testing only.
- PII redaction is heuristic (regex-based). It is not a substitute for proper data governance.
- Rate limiting is enforced per `(principal_id, capability_id)` pair using a sliding window.
  Default limits: 60 READ / 10 WRITE / 2 DESTRUCTIVE invocations per 60-second window.
  Principals with the `"service"` role receive 10× the default limits. Limits are
  configurable via `DefaultPolicyEngine(rate_limits=...)`. There is no distributed or
  persistent rate-limit state — limits reset on process restart.
