# MCP tool safety classification

`MCPDriver.discover()` treats MCP tool annotations as **advisory metadata**, not as trusted authorization input.

## Default: reject missing safety metadata

A tool that has neither:

- an explicit operator classification in `safety_class_map`, nor
- a useful MCP `readOnlyHint` / `destructiveHint`

is rejected by default rather than silently becoming `SafetyClass.READ`.

```python
from weaver_kernel import SafetyClass

capabilities = await driver.discover(
    namespace="github",
    safety_class_map={
        "list_issues": SafetyClass.READ,
        "create_issue": SafetyClass.WRITE,
        "delete_repository": SafetyClass.DESTRUCTIVE,
    },
)
```

If any discovered tool remains unclassified, discovery raises `DriverError` and names every affected tool. This makes missing metadata visible before the capabilities are registered or invoked.

## Explicit fallback

For a controlled environment where an operator deliberately wants one fallback class, opt in explicitly:

```python
capabilities = await driver.discover(
    unannotated_safety=SafetyClass.WRITE,
)
```

Kernel logs a warning naming each tool that received the fallback. Choosing a fallback is an operator decision; it is never inferred from the absence of metadata.

To preserve the previous pre-#181 behavior deliberately, an adopter may pass:

```python
capabilities = await driver.discover(
    unannotated_safety=SafetyClass.READ,
)
```

That opt-back should be reviewed carefully: `READ` is the least-restricted default safety class and an MCP server can expose tools whose names or descriptions understate their side effects.

## Precedence

Classification uses this order:

1. explicit `safety_class_map[tool_name]` supplied by the operator;
2. `destructiveHint=True` → `DESTRUCTIVE`;
3. `readOnlyHint=True` → `READ`;
4. explicit `unannotated_safety` fallback, if configured;
5. otherwise reject.

If a server supplies conflicting read-only and destructive hints, destructive wins.

## Security boundary

This change prevents **missing MCP metadata** from silently granting READ-level authority. It does not make MCP annotations trustworthy. A compromised or incorrect server can still mislabel a destructive tool as read-only.

For high-assurance deployments, treat the operator-maintained classification map (or an equivalent reviewed policy artifact) as the authoritative safety classification. Combine classification with normal principal/capability policy, token constraints and the execution/audit boundary described in [`security.md`](security.md).

## Migration from earlier releases

Earlier versions inferred `READ` when annotations were absent. Code that relied on that behavior must now choose one of two explicit migrations:

- **recommended:** classify tools by name with `safety_class_map`;
- **compatibility opt-back:** set `unannotated_safety=SafetyClass.READ` and accept the warning/audit implications.

This is a deliberate fail-closed breaking change for a security-sensitive default.
