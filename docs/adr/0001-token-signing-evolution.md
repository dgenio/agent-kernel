# ADR 0001 — Capability-token signing format evolution

- **Status:** Accepted (investigation; no production code change)
- **Tracks:** #224 · **Feeds:** #129 (delegated/attenuated grants), #103 (production-hardening roadmap)
- **Related code:** `tokens.py`, `_token_signing.py`, `_hmac_provider.py`, `federation_discovery.py`

## Context

agent-kernel authorizes tool calls with HMAC-SHA256 capability tokens. Today a
token binds `principal + capability + constraints` under a single shared secret
(now a rotatable key-ring, #185). Two roadmap directions push on that format:

- **Delegated, attenuated grants (#129):** an agent that holds a grant wants to
  hand a *narrower* grant to a sub-agent. HMAC cannot do this offline — narrowing
  requires re-issuance by the holder of the signing secret.
- **Cross-boundary verification (federation, manifest signing):** a peer that
  should *verify* a token must currently hold the *signing* secret, which is the
  wrong trust boundary for public verification.

This ADR evaluates whether to evolve the token format, and records a
recommendation. It changes no production code.

## Decision drivers (from the kernel's invariants)

1. **I-06** — a token must keep binding `principal + capability + constraints`;
   any format must preserve tamper-evidence of those fields.
2. **Minimal-dependency policy** (AGENTS.md, `invariants.md` #6) — runtime deps
   are `httpx` + `pydantic` only; a mandatory crypto dependency is a high bar.
3. **Determinism** — no randomness on the verification path.
4. **Revocation model** — the kernel relies on a server-side revocation store
   checked before signature (`_hmac_provider.verify` step 0). Offline-attenuable
   formats weaken the default "revoke by id" posture unless paired with it.
5. **`explain()` transparency** — denials must stay human- and agent-legible;
   a Datalog policy layer is powerful but less transparent than the current
   first-match rule chain.
6. **0.x migration cost** — pre-1.0, a format break is acceptable (tokens live
   ≤1h by default) but should not be gratuitous.

## Options considered

Measurements below are from this repo (`python 3.11`, `_token_signing.sign`),
recorded so the tradeoff is concrete rather than asserted.

### A. Status quo — shared-secret HMAC + re-issuance-based attenuation

- **Binding / determinism / deps:** all satisfied; stdlib `hmac` only.
- **Attenuation:** via re-issuance — a "delegation" is just `grant_capability`
  with narrower `constraints`. In the kernel's current single-process, in-process
  deployment this is a function call, not a network round-trip, so offline
  attenuation buys little.
- **Measured:** token ≈ **378 bytes** JSON (299-byte signable payload);
  **≈12.0 µs/verify**, ≈20.4 µs/issue.
- **Revocation:** native (server-side store, checked before crypto).

### B. Macaroon-style HMAC caveat chaining (in-tree, stdlib only)

- **Binding / determinism / deps:** all satisfied — caveats chain with stdlib
  `hmac` (no new dependency). Verified with a micro-prototype in this ADR's
  investigation.
- **Attenuation:** *offline* — a holder appends a caveat and re-chains the
  signature **without** the root secret. This is the capability HMAC lacks.
- **Measured (3-caveat prototype):** token ≈ **234 bytes**; **≈8.0 µs/verify**.
  Offline attenuation (narrowing `args.path.prefix` from `/safe/` to
  `/safe/reports/` with no root secret) confirmed working.
- **Costs:** first-party-caveat predicates become a small language to design and
  keep deterministic; revocation of a *delegated* leaf needs an identifier
  scheme layered on top of the existing store.

### C. Biscuit (public-key + Datalog attenuation, behind an extra)

- **Binding:** satisfied, plus public-key verification (verify without the
  signing secret) — the one thing neither A nor B offers.
- **Deps:** a **mandatory third-party library** with native crypto — directly
  against the minimal-dependency invariant; only viable behind an optional extra.
- **Determinism / transparency:** Datalog is expressive but reduces
  `explain()`-style transparency and adds a non-trivial evaluation surface.
- **Revocation:** offline-verifiable tokens are the *hardest* to revoke; needs a
  parallel revocation channel.

## Decision

**Stay on HMAC (Option A) for now**, strengthened by the key-ring rotation
shipped in #185 (which closes the "can't rotate the secret" gap that most
motivated looking elsewhere).

- **Defer Biscuit (C).** Its unique win — public-key verification — has no
  current consumer, and its mandatory dependency + weakened default revocation
  posture conflict with two invariants. Revisit only if cross-trust-boundary
  *offline* verification becomes a real requirement.
- **Keep macaroon-style chaining (B) as the documented evolution path** if an
  **offline** delegation requirement actually materializes (e.g. once a remote
  kernel mode, #227, makes delegation a network hop rather than a function call).
  The `constraints["args"]` vocabulary added in #183 (`allowed_keys` / `pinned` /
  `prefix`) is deliberately shaped to be reusable as a first-party caveat
  predicate language if that day comes.
- **Implement delegation (#129) via re-issuance** in the meantime: a delegation
  request is `grant_capability` with narrower `constraints`, which stays inside
  the existing policy → token → revocation pipeline.

## Consequences

- No dependency change; no token-format change beyond #185's `key_id`.
- #129 proceeds on re-issuance semantics; #103 records rotation as its first
  shipped hardening slice.
- The `TokenProvider` Protocol remains the seam: any future B/C provider slots in
  behind it with a dual-verification window, without kernel-wide changes.

## Revisit triggers

- A concrete need for **offline** attenuation or **secret-less** verification.
- A remote/sidecar kernel mode (#227) that turns delegation into a network hop.
