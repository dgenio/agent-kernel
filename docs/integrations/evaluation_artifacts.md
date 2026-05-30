# Policy guardrails for statistical evaluation artifacts

Agents increasingly consume *evaluation artifacts* — structured reports such as
an offline policy-evaluation result (e.g. from
[`skdr-eval`](https://github.com/dgenio/skdr-eval)). These artifacts are easy to
misuse: an agent that reads a favorable headline estimate and recommends
deployment, while ignoring the support diagnostics, uncertainty, and warnings,
turns a *caveated* result into an *unconditional* action.

agent-kernel already separates **reading** from **acting** through safety
classes. This page adds a small, generic policy layer on top: an agent may
always *summarize* an artifact (with caveats), but recommending **deployment**
or **automatic rollout** is gated on the artifact's diagnostics.

The runnable companion is
[`examples/evaluation_artifact_policy.py`](../../examples/evaluation_artifact_policy.py),
which is deterministic, offline, and uses fixture artifacts.

> agent-kernel does **not** implement offline policy evaluation or any
> statistical estimation, and takes no dependency on a specific producer. The
> policy reads documented fields off a plain dict artifact, so it works for any
> producer — not just `skdr-eval`.

## Summarizing evidence vs. acting on evidence

This is the distinction the guardrail enforces:

| Action | Capability | Safety class | Gated? |
|---|---|---|---|
| Summarize the artifact and its caveats | `eval.summarize_artifact` | `READ` | No — always allowed. |
| Recommend deployment / rollout | `eval.recommend_deployment` | `WRITE` | Yes — only when diagnostics are healthy. |
| Recommend manual review / better logs | `eval.recommend_manual_review` | `WRITE` | The downgrade target when deployment is denied. |

Summarizing a high-risk result is fine — it informs the human. Recommending
deployment *as if the result were reliable* is what the policy blocks.

## The generic assessment

`assess_artifact(artifact)` is producer-agnostic. It inspects documented fields
and returns stable decision codes:

```python
decision = assess_artifact(artifact)
# decision.allowed_actions  → e.g. ("allow_summary", "allow_manual_review_recommendation", ...)
# decision.denied_actions   → e.g. ("deny_deployment_recommendation", "deny_automatic_rollout")
# decision.reasons          → e.g. ("support_health=high_risk", "decision is not stable")
# decision.allows_deployment → bool gate the host branches on
```

Fields inspected (all optional; missing fields default to the safest reading):

| Field | Meaning |
|---|---|
| `support_health` | `"ok"` / `"caution"` / `"high_risk"`. |
| `decision_stable` | Whether the comparison is robust to reasonable perturbation. |
| `warnings` | Producer warnings (e.g. low ESS, poor overlap). |
| `recommendation.intent` | The artifact's own steer (`"deploy"`, `"hold"`, …). |
| `uncertainty` / `limitations` | Surfaced as caveats in the summary. |

Deployment is permitted **only** when several signals agree: `support_health`
is `ok`, the decision is stable, there are no warnings, and the artifact does
not itself recommend holding. This is deliberately *not* a single-metric gate —
a good point estimate with poor support is still blocked.

| `support_health` | Deployment | Outcome |
|---|---|---|
| `ok` (stable, no warnings) | allowed | `allow_summary` + deployment recommendation |
| `caution` | denied | downgraded to manual-review recommendation |
| `high_risk` | denied | downgraded + `require_human_review` |

## Audit trail records why

When deployment is denied, the host does not grant `eval.recommend_deployment`;
instead it invokes `eval.recommend_manual_review` with the reasons in the call
args. Because `ActionTrace.args` is preserved for non-memory capabilities, the
audit trace records *why* the action was downgraded:

```python
capability_id, action_id = await act_on_artifact(kernel, principal, artifact)
trace = kernel.explain(action_id)
# capability_id == "eval.recommend_manual_review"
# trace.args["reason"] == "support_health=high_risk; decision is not stable; 2 warning(s): ..."
# trace.args["downgraded_from"] == "recommend_deployment"
```

## Non-goals

- No OPE / statistical estimation in agent-kernel.
- No hard dependency on `skdr-eval` or any producer.
- No decision based on a single numeric metric.

## Aligning with `weaver-spec`

If `weaver-spec` publishes a formal `EvaluationArtifact` contract, the field
names read by `assess_artifact` should be aligned to it; the decision codes here
(`allow_summary`, `allow_manual_review_recommendation`, `require_human_review`,
`deny_deployment_recommendation`, `deny_automatic_rollout`) are intended to be a
stable, producer-neutral vocabulary in the meantime.

## Related

- `examples/evaluation_artifact_policy.py` — runnable, offline.
- [skdr-eval](https://github.com/dgenio/skdr-eval)
- [weaver-spec](https://github.com/dgenio/weaver-spec)
