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

## Token scopes

A `CapabilityToken` binds:
- `capability_id` — which capability is authorized
- `principal_id` — who the token was issued to
- `constraints` — max_rows, allowed_fields, etc. (signed into the token)
- `expires_at` — validity window

Any change to these fields invalidates the HMAC signature.

## Confused deputy prevention

Consider an agent that obtains a token for `billing.list_invoices` then passes it to a different agent. The second agent cannot use it because `verify()` checks that `token.principal_id == expected_principal_id`.

## Security disclaimers

> **v0.1 is not production-hardened for real authentication.**

- HMAC tokens are tamper-evident but **not encrypted**. Do not put sensitive data in token fields.
- The `AGENT_KERNEL_SECRET` must be kept secret. Rotate it if compromised.
- The default `InMemoryDriver` has no persistence — suitable for testing only.
- PII redaction is heuristic (regex-based). It is not a substitute for proper data governance.
- Rate limiting is enforced per `(principal_id, capability_id)` pair using a sliding window.
  Default limits: 60 READ / 10 WRITE / 2 DESTRUCTIVE invocations per 60-second window.
  Principals with the `"service"` role receive 10× the default limits. Limits are
  configurable via `DefaultPolicyEngine(rate_limits=...)`. There is no distributed or
  persistent rate-limit state — limits reset on process restart.
