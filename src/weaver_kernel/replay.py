"""Replay recorded policy decisions against a candidate policy (#213).

Policy changes are the highest-blast-radius configuration change in the kernel:
one edited rule can silently widen access or break every agent. Shadow mode
compares policies on *live* traffic; this harness covers the *pre-deployment*
gap by replaying a recorded set of grant decisions against a candidate engine
and reporting the **decision diffs** (allow→deny, deny→allow, reason-code
changes), so a policy author gets a deterministic "what would have changed"
answer before shipping.

A :class:`DecisionRecord` captures the inputs to one
:meth:`~weaver_kernel.PolicyEngine.evaluate` call plus the *baseline* outcome.
:func:`replay` re-evaluates every record against a candidate engine and diffs
against the baseline; replaying records against the engine that produced them
yields an empty diff.

Fidelity note: the diff validates **policy structure** (role/justification/
constraint rules), not argument-dependent rules whose inputs the audit trail
redacts. Rate-limit decisions are replay-order-sensitive (the default engine's
limiter is stateful), so flips involving :attr:`DenialReason.RATE_LIMITED` are
surfaced separately in :attr:`DecisionDiff.rate_limited` rather than mixed into
:attr:`DecisionDiff.flips`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from .errors import PolicyDenied
from .models import Capability, CapabilityRequest, Principal
from .policy import PolicyEngine
from .policy_reasons import DenialReason

FlipKind = Literal["allow_to_deny", "deny_to_allow", "reason_code_change"]


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """One replayable policy decision: evaluate inputs plus the baseline outcome.

    Build these with :func:`record_decision` (which captures the baseline by
    evaluating against a known-good engine) or construct them directly from
    historical data.
    """

    request: CapabilityRequest
    capability: Capability
    principal: Principal
    justification: str = ""
    baseline_allowed: bool = True
    baseline_reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class DecisionFlip:
    """A single decision that changed between baseline and candidate policy."""

    record: DecisionRecord
    kind: FlipKind
    baseline_allowed: bool
    candidate_allowed: bool
    baseline_reason_code: str | None
    candidate_reason_code: str | None


@dataclass(frozen=True, slots=True)
class DecisionDiff:
    """The outcome of replaying records against a candidate policy.

    Attributes:
        evaluated: Number of records replayed.
        flips: Structural decision changes (allow↔deny, reason-code changes)
            excluding rate-limit noise, in input order.
        rate_limited: Flips where either side was a rate-limit denial, surfaced
            separately because they depend on replay order, not policy structure.
    """

    evaluated: int
    flips: list[DecisionFlip] = field(default_factory=list)
    rate_limited: list[DecisionFlip] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        """``True`` when no structural flips were found (rate-limit flips ignored)."""
        return not self.flips


def _is_rate_limited(code: str | None) -> bool:
    return code is not None and code == DenialReason.RATE_LIMITED.value


def _evaluate(engine: PolicyEngine, record: DecisionRecord) -> tuple[bool, str | None]:
    """Return ``(allowed, reason_code)`` for *record* under *engine*."""
    try:
        engine.evaluate(
            record.request,
            record.capability,
            record.principal,
            justification=record.justification,
        )
        return True, None
    except PolicyDenied as exc:
        return False, exc.reason_code


def record_decision(
    engine: PolicyEngine,
    request: CapabilityRequest,
    capability: Capability,
    principal: Principal,
    *,
    justification: str = "",
) -> DecisionRecord:
    """Evaluate *engine* once and capture the result as a baseline record.

    Convenience for building a replay corpus from a known-good engine, so a
    later :func:`replay` against the same engine yields an empty diff.
    """
    allowed, reason_code = _evaluate(
        engine,
        DecisionRecord(
            request=request,
            capability=capability,
            principal=principal,
            justification=justification,
        ),
    )
    return DecisionRecord(
        request=request,
        capability=capability,
        principal=principal,
        justification=justification,
        baseline_allowed=allowed,
        baseline_reason_code=reason_code,
    )


def _classify(
    record: DecisionRecord, candidate_allowed: bool, candidate_reason_code: str | None
) -> DecisionFlip | None:
    """Return a :class:`DecisionFlip` if the candidate differs, else ``None``."""
    if record.baseline_allowed and not candidate_allowed:
        kind: FlipKind = "allow_to_deny"
    elif not record.baseline_allowed and candidate_allowed:
        kind = "deny_to_allow"
    elif (
        not record.baseline_allowed
        and not candidate_allowed
        and record.baseline_reason_code != candidate_reason_code
    ):
        kind = "reason_code_change"
    else:
        return None
    return DecisionFlip(
        record=record,
        kind=kind,
        baseline_allowed=record.baseline_allowed,
        candidate_allowed=candidate_allowed,
        baseline_reason_code=record.baseline_reason_code,
        candidate_reason_code=candidate_reason_code,
    )


def replay(records: Iterable[DecisionRecord], engine: PolicyEngine) -> DecisionDiff:
    """Replay *records* against *engine* and report decision diffs.

    Args:
        records: Baseline decisions to replay, in evaluation order.
        engine: The candidate policy engine to evaluate against.

    Returns:
        A :class:`DecisionDiff`. Ordering is deterministic (input order). Flips
        involving a rate-limit denial on either side are placed in
        :attr:`DecisionDiff.rate_limited`, never :attr:`DecisionDiff.flips`.
    """
    flips: list[DecisionFlip] = []
    rate_limited: list[DecisionFlip] = []
    evaluated = 0
    for record in records:
        evaluated += 1
        candidate_allowed, candidate_reason_code = _evaluate(engine, record)
        flip = _classify(record, candidate_allowed, candidate_reason_code)
        if flip is None:
            continue
        if _is_rate_limited(record.baseline_reason_code) or _is_rate_limited(
            candidate_reason_code
        ):
            rate_limited.append(flip)
        else:
            flips.append(flip)
    return DecisionDiff(evaluated=evaluated, flips=flips, rate_limited=rate_limited)


__all__ = [
    "DecisionDiff",
    "DecisionFlip",
    "DecisionRecord",
    "FlipKind",
    "record_decision",
    "replay",
]
