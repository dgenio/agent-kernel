# ADR 0001: Token signing format evolution (HMAC vs. Biscuit vs. macaroon-style chaining)

- **Status:** Accepted
- **Date:** 2026-07
- **Related:** #224 (this investigation), #129 (delegated/attenuated grants),
  #103 (production-hardening roadmap), #185 (signing-key rotation, shipped
  alongside this ADR)

## Context

`CapabilityToken` is signed with a single symmetric secret (HMAC-SHA256, now
with key-id-based rotation support — #185). Two roadmap directions strain
that design:

1. **Delegated, attenuated grants (#129)** want an agent holding a token to
   derive a *narrower* token for a sub-agent, offline, without contacting the
   kernel — the core trick behind macaroons and Biscuit.
2. **Federation across trust boundaries** (`federation_discovery.py`'s
   pairwise-shared-secret manifest signing) wants a peer to *verify* a token
   without holding the secret that signed it — which shared-secret HMAC
   structurally cannot do.

This ADR evaluates whether the kernel's token format should change to
support one or both, evaluates against the kernel's actual invariants and
constraints (not generic crypto-library shopping), and produces a
recommendation. Per #224's scope, this is **investigation only** — no
production code or dependency changes.

## Evaluation criteria

Derived from `docs/agent-context/invariants.md` and this repo's stated
engineering constraints (`AGENTS.md`):

| Criterion | Why it matters here |
|---|---|
| **I-06 binding** | Any replacement must still bind `principal_id + capability_id + constraints`, tamper-evidently, with no cross-principal reuse. |
| **Minimal-dependency policy** | `AGENTS.md`: "No new dependencies without justification... runtime dep list is intentionally minimal." A format needing a mandatory third-party library conflicts with this unless gated behind an optional extra. |
| **Determinism** | `AGENTS.md`: "No randomness in matching, routing, or summarization. Deterministic outputs always." A policy language embedded in the token (e.g. Datalog) must not introduce non-deterministic evaluation. |
| **Token size / verification cost** | Tokens are created and verified on every `grant_capability`/`invoke` call — this is a hot path, not a cold one. |
| **Revocation interaction** | The kernel's revocation model (`RevocationStoreProtocol`, `HMACTokenProvider.revoke`) assumes the issuer can always invalidate a `token_id`. Offline-verifiable formats weaken this by design (that's the point of attenuation), so the *combination* matters. |
| **Auditability / `explain()` transparency** | `Kernel.explain_denial()` and `DenialExplanation` promise a human-readable "why" for every decision. A policy language embedded in tokens must not become an opaque black box relative to today's rule-trace transparency. |
| **0.x migration cost** | The project is pre-1.0 (`pyproject.toml`: `Development Status :: 3 - Alpha`) and has already taken breaking changes at this stage (0.10.0 import rename; #185's token-payload shape change) — a migration is *acceptable* here if the destination is clearly better, but gratuitous churn is not. |

## Options considered

### A. Status quo (HMAC-SHA256) + re-issuance-based attenuation

Keep the current signed-shared-secret format. "Attenuation" is achieved by
having the kernel mint a **new**, narrower token on request (a delegation
request is just another `grant_capability` call with tighter `constraints`),
rather than letting a token holder derive one offline.

- **I-06 binding:** Unchanged — already satisfied today.
- **Dependencies:** None. Pure stdlib (`hmac`, `hashlib`), as today.
- **Determinism:** Unaffected.
- **Size / verify cost (measured on this repo's current implementation):** a
  representative token (`constraints={"max_rows": 50, "allowed_fields":
  [...]}`) serializes to **401 bytes** as JSON; `verify()` averages **~12.5
  µs/call** and `issue()` **~20.5 µs/call** on a single core in this sandbox
  (`python3 -m timeit`-style loop, 20 000 iterations — see measurement script
  in this ADR's PR). Both are dominated by UUID generation and JSON
  serialization, not the HMAC itself.
- **Revocation:** Fully compatible — this is exactly what `RevocationStoreProtocol`
  already assumes.
- **Auditability:** No change — `explain()`/`DenialExplanation` already cover
  every decision path.
- **Migration cost:** None.
- **Delegation cost:** Every delegation is a round-trip to the issuing
  kernel. For multi-agent delegation chains that stay within one kernel
  process (the common case today — see `docs/architecture.md`), this is a
  function call, not a network call, so the "offline" benefit macaroons/Biscuit
  offer is largely moot *for this deployment shape*. It only matters once
  #227 (remote kernel mode) ships and delegation crosses a process boundary.

### B. Macaroon-style HMAC caveat chaining

Keep symmetric HMAC, but let a token holder append "caveats" (additional
restrictions) and re-derive a new HMAC via `HMAC(K_n, caveat_n)` chaining,
without contacting the issuer, per the original macaroon construction.

- **I-06 binding:** Preserved *if* every caveat is a strict narrowing (harder
  to prevent structurally than it sounds — a caveat language needs its own
  "monotonic narrowing" proof, which is exactly the kind of subtle security
  invariant this codebase's own review checklist flags as a common mistake
  class).
- **Dependencies:** None required — chaining is stdlib `hmac`/`hashlib`, same
  as today.
- **Determinism:** Preserved, if the caveat predicate language is kept to the
  same tiny, deterministic vocabulary `constraints["args"]` (#183) already
  established (`allowed_keys`/`pinned`/`prefix` — no free-form expressions).
- **Size / verify cost:** Grows linearly with delegation depth (one HMAC
  chain link per caveat) but each link is a cheap HMAC, so verification stays
  fast even several levels deep — no asymmetric-crypto cost.
- **Revocation:** The classic macaroon weakness applies: revoking the root
  token must be checked at verify time regardless of caveat depth (doable —
  our `RevocationStoreProtocol` already keys on `token_id`, so this is a
  workable fit), but a compromised *intermediate* delegate can still mint
  further-caveated tokens the issuer never sees, which is a real reduction in
  audit visibility versus "every grant is a `grant_capability()` call."
- **Auditability:** Weaker than option A — an offline-derived caveat chain
  bypasses `record_denial_trace`/`ActionTrace` entirely until the final
  token is presented for `verify()`, at which point the whole chain must be
  replayed to explain a decision. This directly cuts against I-02's
  "every execution... auditable" spirit for the delegation step itself
  (the final invocation is still audited normally).
- **Migration cost:** Additive — `CapabilityToken` would need a `caveats:
  list[...]` field and `verify()` would need to fold the chain. Backward
  compatible with #185's `key_id` field (the root key is just the entry in
  the `KeyRing`).

### C. Biscuit (public-key, Datalog-based attenuation)

Adopt Biscuit tokens: public-key-signed (Ed25519), attenuable via appended
Datalog blocks, verifiable without the signing key.

- **I-06 binding:** Preserved — Biscuit's whole design is capability
  attenuation with a documented monotonic-restriction model, more rigorously
  specified than a hand-rolled macaroon caveat language would be.
- **Dependencies:** Requires the `biscuit-python` third-party package (or
  equivalent) as a **mandatory** import wherever Biscuit tokens are verified.
  This is the sharpest conflict with `AGENTS.md`'s minimal-dependency policy;
  it would need to live behind a new optional extra (mirroring `[mcp]`,
  `[otel]`, `[tiktoken]`), which is architecturally fine but means every
  consumer of Biscuit-format tokens must opt in explicitly — no
  "just works" default the way HMAC does today.
- **Determinism:** Datalog evaluation is deterministic by specification, but
  it is a real embedded policy *language* — a meaningfully bigger surface
  than today's flat dict-based `constraints`, and a bigger gap for
  `explain()` to bridge (a Datalog proof trace is not the same shape as
  today's `PolicyDecisionTrace`/`FailedCondition` model without new
  translation code).
- **Size / verify cost:** Ed25519 signatures and Datalog block encoding are
  categorically larger and slower than a 32-byte HMAC-SHA256 digest — by
  design (public-key crypto has this cost everywhere). This repo has no
  currently-committed number for Biscuit specifically (would require adding
  the dependency to measure, which #224 explicitly says not to do in this
  PR); qualitatively, expect verification cost at least an order of
  magnitude above the ~12.5 µs HMAC baseline measured above, purely from
  Ed25519 signature verification, before Datalog evaluation cost is added.
- **Revocation:** Structurally the hardest fit. Public-key offline
  verification is the *opposite* of "the issuer can always invalidate," so
  Biscuit's own guidance leans on short TTLs + revocation lists checked at
  the edge — which this kernel already does (`sweep_revocations`,
  `RevocationStoreProtocol`), but only for a verifier that has the *ability*
  to check revocation state remotely, which an offline verifier (the whole
  point of Biscuit) may not have.
- **Auditability:** A Biscuit proof is more powerful than today's rule trace
  but is a different representation entirely; `explain()` would need a real
  translation layer to keep parity, not a small patch.
- **Migration cost:** Highest of the three. `TokenProvider` is a `Protocol`
  (I-06 notes the seam is load-bearing) so a `BiscuitTokenProvider` *can*
  slot in without touching `Kernel`, but every downstream consumer
  (federation manifest signing, revocation store, CLI `audit` inspection,
  trace export) currently assumes the HMAC shape and would need a compatible
  view or a hard cutover.

## Recommendation

**Adopt Option A now (status quo + re-issuance), keep Option B (macaroon-style
chaining) as the documented evolution path for #129 if/when in-process
delegation genuinely needs to cross a process or trust boundary offline, and
reject Option C (Biscuit) for the foreseeable future.**

Rationale:

- #129's delegation need is satisfiable today via re-issuance
  (`grant_capability` with narrower `constraints`) for the deployment shape
  this kernel actually has (single process, in-memory or same-process
  registry) — see `docs/architecture.md`. Building offline attenuation ahead
  of an actual offline-delegation requirement would be exactly the kind of
  speculative "future-proofing" `AGENTS.md`'s review checklist warns against.
- Biscuit's mandatory-dependency, weakened-revocation, and
  `explain()`-parity costs are real and immediate; the benefit (offline,
  cross-trust-boundary verification) has no current consumer in this
  codebase. Revisit if/when #227 (remote kernel mode) or genuine
  cross-organization federation of live tokens (not just manifest
  advertising, which already has its own signature scheme in
  `federation_discovery.py`) becomes a committed feature.
- Macaroon-style chaining is the credible middle ground — no new dependency,
  same crypto primitive already in the codebase — but should wait until a
  concrete offline-delegation use case exists, so the caveat vocabulary can
  be scoped to that need rather than designed speculatively. #183's
  `constraints["args"]` vocabulary is deliberately shaped to be reusable as
  a future caveat predicate language if that day comes.

## Migration sketch (if Option B is later adopted)

1. Add `caveats: list[Caveat]` to `CapabilityToken` (additive, empty by
   default — no behavior change for existing tokens).
2. Extend `_signable_payload()` to fold caveats into the HMAC chain
   (`HMAC(K_n, caveat_n || previous_signature)`).
3. Add `Kernel.attenuate(token, *, args_constraint=...) -> CapabilityToken`
   as a **pure, local** operation (no kernel round-trip) that appends a
   caveat and re-derives the chained signature.
4. `HMACTokenProvider.verify()` folds the chain before the existing
   principal/capability checks — no change to `RevocationStoreProtocol`
   (revocation still keys on the root `token_id`).
5. Ship behind no new extra (stdlib-only) but bump `CapabilityToken`'s
   schema version marker if one exists by then, so old/new payload shapes
   are distinguishable during a rollout.

## Explicit rejection rationale for Biscuit

Rejected **for now**, not permanently: revisit only when a concrete feature
(remote kernel, cross-org live-token federation) needs offline,
non-issuer verification badly enough to justify the mandatory dependency,
the `explain()` translation work, and the weakened default revocation
posture. Until then it fails the minimal-dependency and revocation criteria
against a benefit this codebase does not yet have a consumer for.

## Follow-ups (comments left on referenced issues)

- #129: reference this ADR; delegation should ship as re-issuance
  (Option A) unless/until an offline requirement is identified.
- #103: reference this ADR under the "token signing/encryption" roadmap
  item — the roadmap's asymmetric-crypto question is answered "not yet,
  and here's why" rather than left open.
