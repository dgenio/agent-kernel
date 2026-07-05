# Security Model

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Tool-space interference (agent calls wrong tool) | Capability registry + policy gate before any execution |
| Confused deputy attack | Tokens are bound to `principal_id` — cannot be reused by another principal |
| Token forgery / tampering | HMAC-SHA256 signature; any bit flip → `TokenInvalid` |
| Token replay after expiry | Expiry checked on every `verify()` call |
| Context injection via raw tool output | Firewall always transforms `RawResult → Frame`; raw data never reaches LLM by default |
| PII / PCI leakage | Redaction + `allowed_fields` enforcement in the firewall, applied on every egress path (summary/table/raw, handle expansion, streaming) |
| PII / secret leak below the depth budget | Redaction fails *closed* at `max_depth`: leaf strings are scrubbed; nested containers are elided rather than returned verbatim (#149) |
| Inline secret leak via handle expansion | `HandleStore.expand()` runs projected rows through the firewall redactor, so a secret in a permitted field is scrubbed (#150) |
| Cross-chunk secret split in streaming | `Firewall.apply_stream()` holds back a per-field overlap window so a secret spanning two chunks is reassembled before redaction (#151) |
| Privilege escalation via WRITE/DESTRUCTIVE | Policy engine enforces role requirements |
| Audit evasion | Every `invoke()` creates an immutable `ActionTrace` |
| Handle scope escape (expand exceeds grant) | Handles persist grant constraints; `HandleStore.expand` rechecks `max_rows`, `allowed_fields`, `scope`, and principal binding (#76) |
| Sensitive data reaching the audit log via args/errors | `ActionTrace.args` and driver `error` text are run through the firewall redactor for **every** capability; memory payloads (`payload`/`content`/`value`/`memory`/`text`/`body`) are additionally stripped wholesale for `memory.*` capabilities (#75, #172) |
| Scanned content / raw result reaching audit log | `ActionTrace.result_summary` is built only from the post-firewall `Frame` (counts and flags, never raw driver data), so the audit trail records an invocation's outcome without re-introducing the data the firewall removed |
| Runaway loop draining a single grant (agent loops `invoke()` on one token) | Opt-in, default-off per-invocation rate limit (`Kernel(invoke_rate_limits=...)`), enforced before every driver call, independent of the grant-time limit (#170) |
| Over-broad argument use within an authorized capability (e.g. `files.read` used outside an approved path) | Signed `constraints["args"]` (`allowed_keys`, `pinned`, `prefix`) enforced before the driver runs; tampering invalidates the token's HMAC (#183) |
| Compromised or rotated signing secret invalidating every live token at once | `HMACTokenProvider` accepts a `{key_id: secret}` `KeyRing` with one active key; retired keys still verify during a rotation's overlap window (#185) |

## Token scopes

A `CapabilityToken` binds:
- `capability_id` — which capability is authorized
- `principal_id` — who the token was issued to
- `constraints` — `max_rows`, `allowed_fields`, `args` (see below), etc. (signed into the token)
- `expires_at` — validity window, from a fixed default or a per-grant `ttl_s` (see below)
- `key_id` — which signing key produced the signature (see Signing-key rotation)

Any change to these fields invalidates the HMAC signature.

## Per-grant TTL (#203)

`Kernel.grant_capability(..., ttl_s=...)` lets a caller request a token
lifetime shorter (or, if permitted, longer) than the token provider's fixed
default (1 hour) — least privilege is temporal as well as scoped. `ttl_s` is
optional; omitting it preserves today's behavior exactly.

A `DefaultPolicyEngine` configured with `max_ttl_s={SafetyClass.WRITE: 300.0,
...}` validates the request via an optional `resolve_ttl()` method: a
non-positive `ttl_s` or one exceeding the configured maximum is **denied**
(`PolicyDenied`, `reason_code="ttl_exceeds_max"` or `"invalid_constraint"`) —
never silently clamped, so a caller is never handed a shorter-lived token than
it asked for without knowing it. `resolve_ttl` is deliberately *not* part of
the `PolicyEngine` protocol: a policy engine that doesn't implement it simply
leaves `ttl_s` unvalidated, so adding this feature never breaks a third-party
engine (the same non-breaking pattern used for `ExplainingPolicyEngine`).

Very short TTLs can expire mid-task for slow tools — consider pairing a short
`ttl_s` with a signed `invoke_timeout_s` constraint (see `docs/capabilities.md`)
so the token outlives the deadline it's meant to bound.

## Per-invocation rate limiting (#170)

`DefaultPolicyEngine`'s sliding-window rate limit (see Security disclaimers,
below) applies only at grant time: once issued, a token is unlimited-use until
it expires. `Kernel(invoke_rate_limits={SafetyClass.READ: (60, 60.0), ...})`
adds an **opt-in, default-off** second limit enforced on the invoke path
itself, before every driver call, so an agent that grants once and loops
`invoke()` cannot exceed the configured rate regardless of the token's TTL.

- Disabled by default — passing nothing preserves current behavior exactly.
- Keyed by `(principal_id, capability_id)`, the same key shape as the
  grant-time limiter, and backed by the same `RateLimiter` primitive (inject a
  clock via `Kernel(invoke_rate_limiter=RateLimiter(clock=...))` for tests).
- A violation raises `RateLimitExceeded` (`reason_code="invoke_rate_limited"`)
  and records an audited `"deny"` trace — never a silent drop.
- `dry_run=True` never checks or consumes this limit.
- Like the grant-time limiter, state is in-memory and per-process only — no
  distributed or persistent rate-limit state across replicas.

## Signed argument-level constraints (#183)

A capability token authorizes a *capability*, but by default any arguments —
a grant for `files.read` permits reading anything the driver can reach for
the token's lifetime. `constraints["args"]`, signed into the token at grant
time, narrows that down to a small, deterministic vocabulary evaluated
identically by `Kernel.invoke()` and dry-run (never a general expression
language, to keep evaluation reviewable and side-effect-free):

| Key | Effect |
|-----|--------|
| `allowed_keys` | A list of argument names; any other key in `args` is rejected. |
| `pinned` | A `{key: value}` map; a **present** key's value must equal the pinned value exactly. |
| `prefix` | A `{key: prefix}` map; a **present** key's value must be a string starting with the prefix. |

A key absent from the invocation's `args` never violates `pinned`/`prefix` —
those constrain a value the caller *chose to pass*, not argument presence.
All three operate on top-level keys only (v1 scope). A violation raises
`TokenScopeError` (`reason_code="arg_constraint_violation"`) **before** the
driver executes and before budget is reserved, with an audited `"deny"`
trace. Because the constraint lives inside the signed payload, tampering with
it (like tampering with any other constraint) invalidates the token's HMAC.

`DeclarativePolicyEngine` needs no code changes to attach `args` constraints —
`constraints` is already a free-form mapping merged into the issued token, so
a YAML/TOML rule can include a nested `args` block directly (see
`examples/policies/default.yaml`/`.toml`).

## Signing-key rotation (#185)

`HMACTokenProvider` can hold more than one named secret so
`WEAVER_KERNEL_SECRET` can be rotated without invalidating every outstanding
token at once:

```python
provider = HMACTokenProvider(
    secrets={"2026-a": "old-secret", "2026-b": "new-secret"},
    active_key_id="2026-b",
)
```

- New tokens are always signed under `active_key_id`, whose id (never the
  secret) is stamped into the token's `key_id` field — inside the signed
  payload, so tampering with it invalidates the signature like any other
  field.
- `verify()` resolves the secret by the token's own `key_id`. A `key_id` that
  isn't in the configured set fails closed as `TokenInvalid` — verification
  never falls back to a different secret.
- Verifying a token signed under a non-active (retired-but-still-configured)
  key logs `token_verified_non_active_key` at INFO with the key id (never the
  secret), so an operator can tell when it's safe to drop the old key
  entirely from `secrets`.
- A single `secret=...` (or no argument at all) keeps working exactly as
  before — that's a one-key ring under `key_id=""`.
- Precedence for the implicit (no `secrets=` argument) case:
  `WEAVER_KERNEL_SECRETS` (a JSON object of `{key_id: secret}`) takes priority
  over the legacy single `WEAVER_KERNEL_SECRET` env var.

**Recommended rotation procedure:** add the new key alongside the old one
(`secrets={"old": ..., "new": ...}`, `active_key_id` still `"old"`) → deploy →
flip `active_key_id` to `"new"` → deploy → after the longest outstanding
token's TTL has elapsed, remove `"old"` from `secrets` entirely.

**Breaking change for in-flight tokens across this upgrade.** The `key_id`
field is part of the signed payload for *every* token, including ones issued
by a single-secret, pre-#185 provider (`key_id=""`). A token issued by
code *before* this change was signed over a payload shape that didn't include
`key_id` at all, so it will fail verification as `TokenInvalid` after
upgrading — even under the same secret. Given the project's current alpha
status (see `CHANGELOG.md`), this is treated the same as the 0.10.0 import
rename: a clean break, not a compatibility shim. Tokens are short-lived
(1 hour by default) — expect at most one TTL window of "please re-grant"
errors immediately after a rolling deploy.

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

## What the audit trail captures (#175)

Auditability (I-02) covers authorization decisions and data-access events, not
only successful invocations. Every recorded `ActionTrace` carries an `event_type`:

- `invoke` — a capability invocation (success or driver failure).
- `expand` — a `Kernel.expand()` data-access event (more rows of a stored
  handle). Expansion Frames carry the expanding principal in
  `Provenance.principal_id`.
- `deny` — a `grant_capability()` rejected by policy, recorded with the stable
  `reason_code` (a `DenialReason`) and a redacted reason message *before* the
  `PolicyDenied` exception propagates.

So `explain()` and `query_traces()` can answer "who was refused what, when, and
why" and "which rows were expanded by whom". Expansion query arguments and denial
messages pass through the same firewall redactor as invocation args, so these new
records never make the trace store a sensitive-data sink.

## Retention bounding (#182)

Long-lived processes accumulate one trace per invocation and one revocation entry
per revoked token. Both in-memory structures are bounded:

- The in-memory `TraceStore` caps at `max_entries` (default 10 000), evicting
  oldest-first. Eviction discards audit data, so it is deliberately loud (a
  warning on first eviction) and counted (`evicted_count`). For unbounded
  retention, use a durable backend.
- Revocation state records each token's expiry and is swept for already-expired
  tokens (lazily, and via `HMACTokenProvider.sweep_revocations()`). A sweep never
  un-revokes a live token — only entries for tokens that already fail the expiry
  check are removed.

## Security disclaimers

> **v0.1 is not production-hardened for real authentication.**

- HMAC tokens are tamper-evident but **not encrypted**. Do not put sensitive data in token fields.
- The `WEAVER_KERNEL_SECRET` must be kept secret. Rotate it if compromised.
- The default `InMemoryDriver` has no persistence — suitable for testing only.
- PII redaction is heuristic (regex-based). It is not a substitute for proper data governance.
- Streaming redaction (`Firewall.apply_stream`) reassembles patterns split across
  chunks by holding back a bounded overlap window. A contiguous secret
  (JWT/Bearer/API-key/connection-string body) is never split across a commit
  boundary, but a pattern containing internal whitespace (phone, SSN, spaced card
  number) split exactly at the held boundary may still evade detection. The
  holdback buffer is also memory-bounded (`overlap * 4`); a single contiguous
  secret longer than that bound is force-committed and may be severed at the cut,
  so an extremely long unbroken token can escape per-segment detection — a
  deliberate memory-vs-safety trade.
- Grant-time rate limiting is enforced per `(principal_id, capability_id)` pair
  using a sliding window. Default limits: 60 READ / 10 WRITE / 2 DESTRUCTIVE
  invocations per 60-second window. Principals with the `"service"` role
  receive 10× the default limits. Limits are configurable via
  `DefaultPolicyEngine(rate_limits=...)`. An optional, separate invoke-time
  limit is also available — see "Per-invocation rate limiting" above. Neither
  has distributed or persistent state — both reset on process restart.
