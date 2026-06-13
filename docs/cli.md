# Command-line interface

agent-kernel installs a single console entry point, `weaver-kernel`, with two
subcommands. Both are stdlib-only (argparse) and depend on no third-party
packages.

```text
weaver-kernel audit   — inspect, filter, verify, and export persisted action traces
weaver-kernel doctor  — preflight-check the local environment and self-test vectors
```

## `weaver-kernel audit`

Operates on a **persisted** trace store — a `SQLiteTraceStore` database or a
`JsonlTraceStore` file (see [architecture.md](architecture.md#persistence--durable-stores)).
The format is inferred from the path suffix (`.jsonl` → JSONL, otherwise SQLite)
and can be forced with `--format`. Pass `--secret` to verify a chain written with
an explicit secret; by default the CLI uses `WEAVER_KERNEL_SECRET`.

Output is redaction-safe by construction: the CLI renders only what an
`ActionTrace` already holds. No flag surfaces raw driver output.

> Traces describe **authorised** invocations only. A *denied* request never
> produces an `ActionTrace` (policy gates before invocation, per I-02), so
> filtering is by outcome (`--status succeeded|failed`), not by an
> allow/deny/ask decision — the trace store does not record denials.

### `audit list`

Table (or `--json`) view with filters:

```bash
weaver-kernel audit list --store audit.db \
  --principal u1 --capability billing.list_invoices \
  --status succeeded --since 2026-01-01 --until 2026-02-01 --limit 50
```

### `audit show`

Full redaction-safe detail for one action (the CLI face of `kernel.explain()`):

```bash
weaver-kernel audit show <ACTION_ID> --store audit.db
```

Exits non-zero with an error on stderr if the action id is unknown.

### `audit verify`

Runs chain verification and reports OK or the first divergent record. **Exits
non-zero** when tampering is detected — suitable for a cron / CI integrity check:

```bash
weaver-kernel audit verify --store audit.db        # → "OK: Verified N record(s)."
weaver-kernel audit verify --store audit.db --json  # → {"ok": true, ...}
```

### `audit export`

Filtered export as JSONL (one redaction-safe trace per line), to stdout or a
file. Uses the same filter flags as `list`:

```bash
weaver-kernel audit export --store audit.db --principal u1 --out u1-traces.jsonl
```

## `weaver-kernel doctor`

Preflight checks for a local setup. Reports each check as `ok` / `warn` / `error`
and **exits non-zero only when a check errors** (a broken build). A missing
`WEAVER_KERNEL_SECRET` is a *warning* (insecure demo-only configuration), not a
failure.

```bash
weaver-kernel doctor          # human-readable
weaver-kernel doctor --json   # machine-readable list of checks
```

Checks: Python version; whether `WEAVER_KERNEL_SECRET` is set; availability of the
optional `policy` / `mcp` / `otel` extras; a token sign/verify + tamper-detection
self-test vector; and an audit-chain build/verify/mutate self-test vector. Secret
material is never printed — only whether a secret is configured.
