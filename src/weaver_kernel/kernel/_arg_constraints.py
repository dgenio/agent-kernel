"""Signed argument-level constraint enforcement (#183).

A :class:`~weaver_kernel.tokens.CapabilityToken` authorises a *capability*,
but by default any arguments. ``constraints["args"]`` lets a grant pin down
*which* arguments an invocation may use — a deterministic, tiny vocabulary
(never a general expression language, per
``docs/agent-context/invariants.md``'s determinism rule):

- ``allowed_keys``: a list of argument names; any other key is rejected.
- ``pinned``: a ``{key: value}`` map; a *present* key must equal the pinned
  value exactly.
- ``prefix``: a ``{key: prefix}`` map; a *present* key's value must be a
  string starting with the given prefix.

All three operate on **top-level keys only** (v1 scope, documented in #183)
and are enforced identically by both :func:`weaver_kernel.Kernel.invoke` and
dry-run, so a dry-run's predicted outcome always matches the real one.

A key absent from ``args`` never violates ``pinned``/``prefix`` — those
constrain a value the caller *chose to pass*, not argument presence (a
missing required argument is the capability/driver's own concern). This
choice is deliberate and documented per #183's "decide, document it" ask.
"""

from __future__ import annotations

from typing import Any

from ..errors import TokenScopeError
from ..policy_reasons import DenialReason


def validate_arg_constraints(constraints: dict[str, Any], args: dict[str, Any]) -> None:
    """Enforce a token's signed ``constraints["args"]`` rules against *args*.

    A no-op when the token carries no ``"args"`` constraint.

    Args:
        constraints: The verified token's ``constraints`` dict.
        args: The invocation's driver arguments.

    Raises:
        TokenScopeError: If *args* violates ``allowed_keys``, ``pinned``, or
            ``prefix``. Carries
            :attr:`~weaver_kernel.policy_reasons.DenialReason.ARG_CONSTRAINT_VIOLATION`
            as ``reason_code``.
    """
    rules = constraints.get("args")
    if not rules:
        return

    allowed_keys = rules.get("allowed_keys")
    if allowed_keys is not None:
        extra = sorted(set(args) - set(allowed_keys))
        if extra:
            raise TokenScopeError(
                f"Argument(s) {extra} are not in the token's allowed_keys constraint.",
                reason_code=str(DenialReason.ARG_CONSTRAINT_VIOLATION),
            )

    pinned: dict[str, Any] | None = rules.get("pinned")
    if pinned:
        for key, expected in pinned.items():
            if key in args and args[key] != expected:
                raise TokenScopeError(
                    f"Argument {key!r} must equal {expected!r} per the token's "
                    f"pinned constraint, got {args[key]!r}.",
                    reason_code=str(DenialReason.ARG_CONSTRAINT_VIOLATION),
                )

    prefix: dict[str, str] | None = rules.get("prefix")
    if prefix:
        for key, expected_prefix in prefix.items():
            if key not in args:
                continue
            value = args[key]
            if not isinstance(value, str) or not value.startswith(expected_prefix):
                raise TokenScopeError(
                    f"Argument {key!r} must be a string starting with "
                    f"{expected_prefix!r} per the token's prefix constraint.",
                    reason_code=str(DenialReason.ARG_CONSTRAINT_VIOLATION),
                )


__all__ = ["validate_arg_constraints"]
