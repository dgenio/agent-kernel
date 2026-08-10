# Least privilege for coding agents

`weaver-kernel` can give a coding agent useful repository and shell authority
without turning that authority into an ambient "do anything" permission.

The maintained flagship demo is network-free and makes no real repository or
GitHub changes:

```bash
python -m pip install weaver-kernel
# From a source checkout of the matching release/commit:
python examples/coding_agent_least_privilege.py
```

Expected semantic receipt:

```text
ALLOW repo.read.files README.md
ALLOW repo.write.files src/demo.py
DENY repo.write.files .github/workflows/release.yml
DENY secrets.read .env
ALLOW shell.run.tests command_class=test
DENY github.create_pr task=ISSUE-253 before approval
ALLOW github.create_pr task=ISSUE-253 after task-bound approval
DENY scope substitution src/demo.py -> .github/workflows/release.yml at execution
TRACE repo.read.files principal=coder driver=coding-agent
PASS: useful coding work stays usable while sensitive authority stays explicit.
```

CI runs that exact demo and the script drift-checks the receipt against
`examples/coding_agent_expected.txt`.

## Capability vocabulary

The built-in `CodingAgentPolicyEngine` intentionally starts small:

| Capability | Default boundary |
| --- | --- |
| `repo.read.files` | normal paths allowed; secret-like paths require `secrets.read` |
| `repo.write.files` | requires `code_writer`; only configured source/test/docs globs |
| `shell.run.tests` | requires `test_runner`; only configured test command classes |
| `shell.run.networked_command` | separately requires `network_runner` |
| `secrets.read` | separately requires `secrets_reader` |
| `github.create_pr` | requires an approval attribute bound to the exact task ID |
| `github.merge_pr` | separately requires `admin` |

This split is deliberate: permission to edit code does not imply permission to
read credentials, access the network, create organizational work, or merge it.

## Signed scope, not grant-time theatre

A path check that happens only when the token is issued is insufficient. An
agent could ask for a token scoped to `src/app.py` and then try to invoke the
same capability with `.github/workflows/release.yml`.

`CodingAgentPolicyEngine` therefore puts the exact approved scope under the
signed token's `coding_agent` constraints. The execution-side driver calls:

```python
from weaver_kernel.coding_agent import enforce_coding_agent_constraints

enforce_coding_agent_constraints(ctx.constraints, ctx.args)
```

If actual invocation arguments differ from the signed grant scope, execution
fails closed. The flagship demo tests this substitution explicitly.

The host is responsible for supplying normalized, trustworthy request scope
(e.g. the actual repository-relative path or task ID) and the driver is
responsible for calling the execution-side constraint helper before the side
effect. Do not derive the trusted scope from LLM prose.

## Three practical authority profiles

You do not need three policy engines. Keep one policy and change which narrow
roles/approvals the principal carries for the current phase:

- **Review:** no `code_writer` / `test_runner`; read normal repository files.
- **Edit + test:** add `code_writer` and `test_runner`; writes remain limited to
  configured path globs and shell authority remains the test category.
- **Publish for review:** add a one-task `approved_task_id` attribute to permit
  `github.create_pr`. This still does **not** grant merge authority.

Use a fresh/task-scoped principal or equivalent session claims when moving
between phases; do not accumulate permissions indefinitely.

## What this is not

- It is an **embedded authorization boundary** for actions your runtime routes
  through `weaver-kernel`; it is not a VM/container sandbox.
- It does not make the LLM trustworthy or prevent prompt injection. It limits
  what a successful injection can do through mediated capabilities.
- Drivers that ignore signed constraints can undermine scoped grants. Use the
  provided helper (or an equivalently strict driver-specific check) before the
  side effect.
- If you only need a coarse external policy proxy around MCP traffic rather
  than an embedded capability runtime, AgentFence may be the simpler boundary.

For the general capability model see [Capabilities](capabilities.md); for hard
runtime invariants see [Security](security.md) and
[Agent-context invariants](agent-context/invariants.md).
