"""Policy engine: role-based access control with confused-deputy prevention."""

from __future__ import annotations

from typing import Any, Protocol

from .enums import SafetyClass, SensitivityTag
from .errors import PolicyDenied
from .models import Capability, CapabilityRequest, PolicyDecision, Principal

# Minimum justification length for WRITE operations.
_MIN_JUSTIFICATION = 15

# Default max_rows caps.
_MAX_ROWS_USER = 50
_MAX_ROWS_SERVICE = 500


class PolicyEngine(Protocol):
    """Interface for a policy engine."""

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate whether *principal* may perform *request* on *capability*.

        Args:
            request: The capability request being evaluated.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification from the caller.

        Returns:
            A :class:`PolicyDecision` (allowed or denied with reason).
        """
        ...


class DefaultPolicyEngine:
    """Rule-based policy engine implementing the default access control policy.

    Rules (evaluated in order):

    1. **READ** — allowed (subject to sensitivity and row-cap rules below).
    2. **WRITE** — requires:
       - ``justification`` of at least 15 characters.
       - Principal role ``"writer"`` **or** ``"admin"``.
    3. **DESTRUCTIVE** — requires principal role ``"admin"``.
    4. **PII / PCI sensitivity** — requires the ``tenant`` attribute on the
       principal.  Enforces ``allowed_fields`` unless the principal has the
       ``pii_reader`` role.
    5. **SECRETS sensitivity** — requires principal role ``"admin"`` or
       ``"secrets_reader"`` and a justification of at least 15 characters.
    6. **max_rows** — 50 for regular users; 500 for principals with the
       ``"service"`` role.
    """

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate the request against the default policy rules.

        Args:
            request: The capability request being evaluated.
            capability: The target capability.
            principal: The requesting principal.
            justification: Free-text justification from the caller.

        Returns:
            :class:`PolicyDecision` with ``allowed=True`` and any imposed
            constraints, or raises :class:`PolicyDenied`.

        Raises:
            PolicyDenied: When the request violates a policy rule.
        """
        roles = set(principal.roles)
        constraints: dict[str, Any] = dict(request.constraints)

        # ── Safety class checks ───────────────────────────────────────────────

        if capability.safety_class == SafetyClass.WRITE:
            stripped_len = len(justification.strip())
            if stripped_len < _MIN_JUSTIFICATION:
                raise PolicyDenied(
                    f"WRITE capabilities require a justification of at least "
                    f"{_MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace)."
                )
            if not (roles & {"writer", "admin"}):
                raise PolicyDenied(
                    f"WRITE capabilities require the 'writer' or 'admin' role. "
                    f"Principal '{principal.principal_id}' has roles: {sorted(roles)}."
                )

        elif capability.safety_class == SafetyClass.DESTRUCTIVE:
            stripped_len = len(justification.strip())
            if stripped_len < _MIN_JUSTIFICATION:
                raise PolicyDenied(
                    f"DESTRUCTIVE capabilities require a justification of at least "
                    f"{_MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace)."
                )
            if "admin" not in roles:
                raise PolicyDenied(
                    f"DESTRUCTIVE capabilities require the 'admin' role. "
                    f"Principal '{principal.principal_id}' has roles: {sorted(roles)}."
                )

        # ── Sensitivity checks ────────────────────────────────────────────────

        if capability.sensitivity in (SensitivityTag.PII, SensitivityTag.PCI):
            if "tenant" not in principal.attributes:
                raise PolicyDenied(
                    f"Capability '{capability.capability_id}' has "
                    f"{capability.sensitivity.value} sensitivity and requires "
                    "the principal to have a 'tenant' attribute."
                )
            # Enforce allowed_fields unless the principal is a pii_reader.
            if capability.allowed_fields and "pii_reader" not in roles:
                constraints["allowed_fields"] = capability.allowed_fields

        if capability.sensitivity == SensitivityTag.SECRETS:
            stripped_len = len(justification.strip())
            if stripped_len < _MIN_JUSTIFICATION:
                raise PolicyDenied(
                    f"SECRETS capabilities require a justification of at least "
                    f"{_MIN_JUSTIFICATION} characters. "
                    f"Got {len(justification)} characters "
                    f"({stripped_len} after trimming whitespace)."
                )
            if not (roles & {"admin", "secrets_reader"}):
                raise PolicyDenied(
                    f"SECRETS capabilities require the 'admin' or 'secrets_reader' role. "
                    f"Principal '{principal.principal_id}' has roles: {sorted(roles)}."
                )

        # ── Row cap ───────────────────────────────────────────────────────────

        max_rows = _MAX_ROWS_SERVICE if "service" in roles else _MAX_ROWS_USER
        # Respect any tighter constraint from the request itself.
        if "max_rows" in constraints:
            try:
                requested = int(constraints["max_rows"])
            except (TypeError, ValueError) as exc:
                raise PolicyDenied(
                    f"Invalid 'max_rows' constraint: {constraints['max_rows']!r} "
                    "is not a valid integer."
                ) from exc
            constraints["max_rows"] = min(max(requested, 0), max_rows)
        else:
            constraints["max_rows"] = max_rows

        return PolicyDecision(
            allowed=True,
            reason="Request approved by DefaultPolicyEngine.",
            constraints=constraints,
        )
