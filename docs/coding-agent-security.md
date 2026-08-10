# Least privilege for coding agents

`weaver-kernel` gives a coding agent useful repository and test authority
without turning either into ambient permission to read secrets, rewrite CI, or
publish work.

The maintained flagship scenario is included in the package, is network-free,
and makes no real filesystem or GitHub changes:

```bash
python -m pip install weaver-kernel
python -m weaver_kernel.coding_agent_demo
```

The direct module command is available in the first package release containing
[#253](https://github.com/dgenio/agent-kernel/issues/253). From a checkout of
that commit before the release, use `python -m pip install .` and run the same
module command.

Expected semantic receipt:

```text
ALLOW+EXECUTE repo.read.files path=README.md
ALLOW+EXECUTE repo.write.files path=src/demo.py
ALLOW+EXECUTE shell.run.tests command_class=test
DENY repo.write.files path=.github/workflows/release.yml reason=scope_not_allowed
DENY secrets.read path=.env reason=missing_role
DENY github.create_pr task=ISSUE-253 reason=missing_attribute
EXPLAIN deny capability=github.create_pr principal=coder reason=missing_attribute
ESCALATE github.create_pr task=ISSUE-253 grant=one-task
GRANT github.create_pr policy=CodingAgentPolicyEngine outcome=allowed bound=task_id
ALLOW+EXECUTE github.create_pr task=ISSUE-253
EXPLAIN invoke capability=github.create_pr principal=coder driver=coding-agent
DENY scope-substitution path=src/demo.py -> .github/workflows/release.yml
PASS: useful coding work stays usable while sensitive authority stays explicit.
```

The demo verifies every policy result and scope binding before printing. CI
runs both the installed-package module and the source wrapper; the wrapper
compares the output byte-for-byte with
[`examples/coding_agent_expected.txt`](../examples/coding_agent_expected.txt).

## What the trace proves

The publish-for-review path deliberately shows four distinct facts:

1. `github.create_pr` is denied without task-bound approval, producing a
   `deny` `ActionTrace` with `reason=missing_attribute`.
2. the host explicitly escalates by issuing a one-task principal attribute;
3. the resulting policy grant binds `task_id` into the signed token; and
4. after the fake driver executes, `kernel.explain()` returns the matching
   successful invocation trace.

That is a reproducible authorization and audit proof. It is not evidence that
an LLM is trustworthy, and the demo driver intentionally performs no external
side effect.

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

Permission to edit code does not imply permission to read credentials, access
the network, create organizational work, or merge it.

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
(for example, the actual repository-relative path or task ID), and the driver
must call the execution-side constraint helper before the side effect. Do not
derive trusted scope from LLM prose.

## Three practical authority profiles

Keep one policy and change which narrow roles or approvals the principal
carries for the current phase:

- **Review:** read normal repository files; no `code_writer` or `test_runner`.
- **Edit + test:** add `code_writer` and `test_runner`; writes remain limited to
  configured path globs and shell authority remains in the test category.
- **Publish for review:** add a one-task `approved_task_id` attribute to permit
  `github.create_pr`. This still does not grant merge authority.

Use a fresh, task-scoped principal or equivalent session claims when moving
between phases; do not accumulate permissions indefinitely.

## Boundaries and when not to use it

| Project | Boundary |
| --- | --- |
| **agent-kernel / `weaver-kernel`** | embedded capability authorization, signed scope, execution audit |
| **AgentFence** | external firewall at a tool/process boundary |
| **ContextWeaver** | capability and context visibility/selection for the current phase |
| **ChainWeaver** | deterministic multi-step execution |

- This is not a VM or container sandbox. Use an OS/container isolation layer
  when you need to contain arbitrary host process behavior.
- It does not prevent prompt injection. It bounds mediated capabilities after
  an injection or model mistake succeeds.
- A driver that ignores signed constraints undermines scoped grants. Use the
  provided helper or an equivalently strict driver-side check.
- If you cannot change the agent host and only need an external MCP policy
  boundary, AgentFence is the simpler fit.
- If a small allowlist around a single fixed command is enough, a dedicated
  wrapper may be simpler than adopting a capability runtime.

For the general capability model see [Capabilities](capabilities.md); for hard
runtime invariants see [Security](security.md) and
[Agent-context invariants](agent-context/invariants.md).
