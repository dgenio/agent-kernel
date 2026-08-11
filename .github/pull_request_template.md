## What changed

<!-- Describe the smallest logical change in this PR. -->

## Why

<!-- Link the issue/user/security evidence. Explain why this belongs on the current roadmap. -->

## Security / contract impact

- [ ] No security/public-contract impact
- [ ] Changes a principal / policy / capability / token / constraint path
- [ ] Changes execution or driver mediation
- [ ] Changes Firewall / Frame / handle behavior
- [ ] Changes audit / trace / evidence behavior
- [ ] Changes protocol/framework compatibility or coverage
- [ ] Changes the Security Contract or a documented non-goal

<!-- If any box other than “No impact” applies, explain the invariant/claim and the fail-closed behavior. -->

## Compatibility / migration

<!-- State whether this is additive, behavior-changing, deprecated, or breaking. Link docs/versioning.md and include a migration path for supported behavior changes. -->

## Validation

- [ ] `make ci` passes on the exact PR head
- [ ] Tests cover the behavior change, including a negative/fail-closed case when security-sensitive
- [ ] I checked whether `tests/test_invariants.py` or `tests/test_policy_properties.py` should change
- [ ] Documentation matches implementation
- [ ] CHANGELOG/release notes are updated when user-visible behavior or compatibility changes
- [ ] New dependency/protocol ranges are justified by tested compatibility, not speculative version widening

## Review notes

<!-- Call out risky files, known limitations, follow-ups, or intentionally unsupported surfaces. -->
