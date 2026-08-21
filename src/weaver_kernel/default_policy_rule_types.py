"""Internal data structures shared by the default-policy rule modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .enums import SafetyClass
from .models import (
    Capability,
    CapabilityRequest,
    FailedCondition,
    PolicyTraceStep,
    Principal,
)
from .rate_limit import RateLimiter

MIN_JUSTIFICATION = 15
MAX_ROWS_USER = 50
MAX_ROWS_SERVICE = 500


@dataclass(slots=True)
class RuleFailure:
    """One failed default-policy condition and its decision/explanation views."""

    detail: str
    condition: FailedCondition
    reason_code: str
    cause: Exception | None = None


@dataclass(slots=True)
class RuleContext:
    """Mutable traversal context shared by the ordered rule checks."""

    request: CapabilityRequest
    capability: Capability
    principal: Principal
    justification: str
    constraints: dict[str, Any]
    rate_limits: dict[SafetyClass, tuple[int, float]]
    limiter: RateLimiter
    read_only: bool
    trace_steps: list[PolicyTraceStep] = field(default_factory=list)


@dataclass(slots=True)
class RuleChainResult:
    """Result of traversing the ordered default-policy rule chain."""

    constraints: dict[str, Any]
    failures: list[RuleFailure] = field(default_factory=list)
    trace_steps: list[PolicyTraceStep] = field(default_factory=list)


__all__ = [
    "MAX_ROWS_SERVICE",
    "MAX_ROWS_USER",
    "MIN_JUSTIFICATION",
    "RuleChainResult",
    "RuleContext",
    "RuleFailure",
]
