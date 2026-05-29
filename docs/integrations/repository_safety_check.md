# Repository safety checks as a policy-controlled capability

Agents that can write files, open PRs, or publish artifacts need a clear
pattern for running deterministic checks **before** a high-impact action.
agent-kernel already models policy enforcement, capabilities, firewall
redaction, and auditable tool calls — a repository-level check fits naturally
as a capability that is invoked under explicit policy and recorded in the audit
trace.

This page describes the pattern. The runnable companion is
[`examples/repository_safety_check.py`](../../examples/repository_safety_check.py),
which is deterministic, offline, and depends on no specific checker.

> agent-kernel does **not** implement scanning logic and does **not** depend on
> any particular checker. The check is an adapter that shells out to a local
> command. The example uses a tiny embedded scanner so it runs in CI; in
> production you point it at a real tool such as
> [VibeGuard](https://github.com/dgenio/vibeguard).

## The pattern

```
agent wants to publish
        │
        ▼
repo.code_safety_check  (READ capability → RepositoryCheckDriver shells out)
        │
        ├─ clean  → grant + invoke repo.publish_artifact (WRITE)
        └─ findings → host blocks the publish; check result is still audited
```

Two capabilities:

| Capability | Safety class | Backed by | Role |
|---|---|---|---|
| `repo.code_safety_check` | `READ` | `RepositoryCheckDriver` (shells out to a checker) | Runs a deterministic scan and returns findings. |
| `repo.publish_artifact` | `WRITE` | any execution driver | The high-impact action, gated behind a passing check. |

## The shell-out adapter

`RepositoryCheckDriver` implements the `Driver` protocol and runs the configured
command as `[*command, path]`:

```python
class RepositoryCheckDriver:
    def __init__(self, command: list[str], *, driver_id: str = "repo_safety") -> None:
        self._command = list(command)
        self._driver_id = driver_id

    @property
    def driver_id(self) -> str:
        return self._driver_id

    async def execute(self, ctx: ExecutionContext) -> RawResult:
        path = ctx.args.get("path")
        if not path:
            raise DriverError("repository check requires a 'path' argument ...")
        proc = await asyncio.create_subprocess_exec(
            *self._command, str(path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode not in (0, 1):           # checker itself failed
            raise DriverError(f"...: {stderr.decode(errors='replace').strip()}")
        findings = json.loads(stdout or b"[]")      # [] = clean
        return RawResult(capability_id=ctx.capability_id, data=findings,
                         metadata={"exit_code": proc.returncode})
```

Conventions the adapter relies on (and most scanners follow):

- **Exit `0`** = clean, **exit `1`** = findings present. Any other exit code is
  treated as the checker *failing* and surfaces as a `DriverError`.
- Findings are a JSON array on stdout. Non-JSON output raises `DriverError`
  rather than being silently treated as "clean".

To use VibeGuard instead of the embedded scanner, construct the driver with its
command, e.g. `RepositoryCheckDriver(command=["vibeguard", "scan", "--json"])`.

## Reading the verdict from the Frame

The gate decision is made on the **firewalled Frame**, not on raw driver output.
Invoke the check in `table` mode and treat a non-empty preview as a block:

```python
frame = await kernel.invoke(token, principal=principal,
                            args={"operation": "code_safety_check", "path": path},
                            response_mode="table")
findings = list(frame.table_preview)
passed = not findings
```

When `passed` is `False`, the host simply does not grant
`repo.publish_artifact`. Because the check ran through `Kernel.invoke()`, it
produced an `ActionTrace` — so the decision to block is auditable via
`Kernel.explain(action_id)`, satisfying weaver-spec **I-02**.

## Audit trail

Both the check and (when it passes) the publish are recorded:

```python
check_trace = kernel.explain(check_action_id)      # always available
publish_trace = kernel.explain(publish_action_id)  # only when the check passed
```

The trace records the capability, principal, driver, and timestamp for each
step, so a reviewer can see that the publish was preceded by a passing check.

## Non-goals

- agent-kernel does not implement scanning logic.
- VibeGuard (or any checker) is never a required dependency.
- The check does not bypass existing policy enforcement — it is *additional*
  to the normal grant/invoke pipeline.

## Related

- `examples/repository_safety_check.py` — runnable, offline.
- [VibeGuard](https://github.com/dgenio/vibeguard)
- [weaver-spec](https://github.com/dgenio/weaver-spec)
