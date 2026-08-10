"""Least-privilege policy helpers for coding-agent runtimes.

The policy binds the concrete scope approved at grant time into the signed
capability token. Drivers call :func:`enforce_coding_agent_constraints` before
performing the side effect so an agent cannot obtain a grant for one path/task
and then substitute different invocation arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, NoReturn

from .enums import SafetyClass
from .errors import DriverError, PolicyDenied
from .models import (
    Capability,
    CapabilityRequest,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
)
from .policy import _MIN_JUSTIFICATION
from .policy_matching import scope_globs_match
from .policy_reasons import AllowReason, DenialReason


@dataclass(frozen=True, slots=True)
class CodingAgentPolicyConfig:
    """Configuration for :class:`CodingAgentPolicyEngine`.

    Defaults allow ordinary source/test/docs work only to principals carrying
    explicit work roles, while secrets, workflow mutation, networked commands,
    PR creation, and merges remain behind narrower grants.
    """

    writable_path_globs: tuple[str, ...] = ("src/**", "tests/**", "docs/**")
    secret_path_globs: tuple[str, ...] = (
        ".env",
        "**/.env",
        "secrets/**",
        "**/secrets/**",
    )
    test_command_classes: tuple[str, ...] = ("test",)
    write_role: str = "code_writer"
    test_role: str = "test_runner"
    network_role: str = "network_runner"
    secrets_role: str = "secrets_reader"
    merge_role: str = "admin"
    pr_approval_attribute: str = "approved_task_id"


class CodingAgentPolicyEngine:
    """Policy engine for a minimal coding-agent capability vocabulary.

    Supported capability IDs are ``repo.read.files``, ``repo.write.files``,
    ``shell.run.tests``, ``shell.run.networked_command``, ``secrets.read``,
    ``github.create_pr``, and ``github.merge_pr``. Unknown capabilities fail
    closed.
    """

    def __init__(self, config: CodingAgentPolicyConfig | None = None) -> None:
        """Initialize the policy.

        Args:
            config: Optional policy configuration. Defaults to conservative
                local-development scopes.
        """
        self.config = config or CodingAgentPolicyConfig()

    def evaluate(
        self,
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        *,
        justification: str,
    ) -> PolicyDecision:
        """Evaluate a coding-agent capability request and bind its exact scope.

        Args:
            request: Capability request with trusted host-supplied scope.
            capability: Registered capability.
            principal: Requesting principal.
            justification: Human-readable justification for audit. WRITE and
                DESTRUCTIVE grants preserve the repository-wide minimum length
                invariant after trimming whitespace.

        Returns:
            An allowed decision whose ``coding_agent`` constraint contains the
            exact grant-time scope that execution must re-check.

        Raises:
            PolicyDenied: If the requested action exceeds configured authority.
        """
        cid = capability.capability_id
        if cid != request.capability_id:
            self._deny("Capability request does not match the registered capability.")

        if cid == "repo.read.files":
            path = self._required_scope(request, "path")
            if scope_globs_match({"path": path}, {"path": list(self.config.secret_path_globs)}):
                self._deny("Secret-like repository paths require the secrets.read capability.")
            return self._allow(request, capability, principal, {"path": path})

        if cid == "repo.write.files":
            self._require_role(principal, self.config.write_role, "repository writes")
            path = self._required_scope(request, "path")
            if scope_globs_match({"path": path}, {"path": list(self.config.secret_path_globs)}):
                self._deny("Secret-like paths are never writable through repo.write.files.")
            if not scope_globs_match(
                {"path": path}, {"path": list(self.config.writable_path_globs)}
            ):
                self._deny(
                    f"Path {path!r} is outside the configured coding-agent write scope.",
                    reason_code=str(DenialReason.SCOPE_NOT_ALLOWED),
                )
            self._require_justification(capability, justification)
            return self._allow(request, capability, principal, {"path": path})

        if cid == "shell.run.tests":
            self._require_role(principal, self.config.test_role, "test execution")
            command_class = self._required_scope(request, "command_class")
            if command_class not in self.config.test_command_classes:
                self._deny(
                    f"Command class {command_class!r} is not an allowed test command class.",
                    reason_code=str(DenialReason.SCOPE_NOT_ALLOWED),
                )
            self._require_justification(capability, justification)
            return self._allow(request, capability, principal, {"command_class": command_class})

        if cid == "shell.run.networked_command":
            self._require_role(principal, self.config.network_role, "networked shell commands")
            command_class = self._required_scope(request, "command_class")
            self._require_justification(capability, justification)
            return self._allow(request, capability, principal, {"command_class": command_class})

        if cid == "secrets.read":
            self._require_role(principal, self.config.secrets_role, "secret access")
            path = self._required_scope(request, "path")
            return self._allow(request, capability, principal, {"path": path})

        if cid == "github.create_pr":
            task_id = self._required_scope(request, "task_id")
            approved = principal.attributes.get(self.config.pr_approval_attribute)
            if approved != task_id:
                self._deny(
                    f"PR creation requires an approval bound to task {task_id!r}.",
                    reason_code=str(DenialReason.MISSING_ATTRIBUTE),
                )
            self._require_justification(capability, justification)
            return self._allow(request, capability, principal, {"task_id": task_id})

        if cid == "github.merge_pr":
            self._require_role(principal, self.config.merge_role, "PR merge")
            task_id = self._required_scope(request, "task_id")
            self._require_justification(capability, justification)
            return self._allow(request, capability, principal, {"task_id": task_id})

        self._deny(
            f"CodingAgentPolicyEngine has no rule for capability {cid!r}.",
            reason_code=str(DenialReason.NO_MATCHING_RULE),
        )

    @staticmethod
    def _required_scope(request: CapabilityRequest, key: str) -> str:
        value = request.scope.get(key)
        if not isinstance(value, str) or not value:
            raise PolicyDenied(
                f"Coding-agent capability {request.capability_id!r} requires non-empty scope {key!r}.",
                reason_code=str(DenialReason.SCOPE_NOT_ALLOWED),
            )
        return value

    @classmethod
    def _require_role(cls, principal: Principal, role: str, action: str) -> None:
        if role not in principal.roles:
            cls._deny(
                f"Required role {role!r} is missing for {action}.",
                reason_code=str(DenialReason.MISSING_ROLE),
            )

    @classmethod
    def _require_justification(cls, capability: Capability, justification: str) -> None:
        if capability.safety_class not in (SafetyClass.WRITE, SafetyClass.DESTRUCTIVE):
            return
        stripped_len = len(justification.strip())
        if stripped_len < _MIN_JUSTIFICATION:
            cls._deny(
                f"{capability.safety_class.value.upper()} capabilities require a justification "
                f"of at least {_MIN_JUSTIFICATION} characters after trimming whitespace.",
                reason_code=str(DenialReason.INSUFFICIENT_JUSTIFICATION),
            )

    @staticmethod
    def _deny(message: str, *, reason_code: str | None = None) -> NoReturn:
        raise PolicyDenied(
            message,
            reason_code=reason_code or str(DenialReason.EXPLICIT_DENY_RULE),
        )

    @staticmethod
    def _allow(
        request: CapabilityRequest,
        capability: Capability,
        principal: Principal,
        bound_scope: dict[str, str],
    ) -> PolicyDecision:
        reason = f"Coding-agent scope approved for {capability.capability_id}."
        code = str(AllowReason.RULE_ALLOW)
        trace = PolicyDecisionTrace(
            engine="CodingAgentPolicyEngine",
            capability_id=capability.capability_id,
            principal_id=principal.principal_id,
            intent=request.intent,
            scope_keys=sorted(request.scope),
        )
        trace.steps.append(
            PolicyTraceStep(
                name="coding-agent-scope",
                outcome="allowed",
                detail=f"bound scope keys={sorted(bound_scope)}",
                reason_code=code,
            )
        )
        trace.final_outcome = "allowed"
        trace.final_reason_code = code
        return PolicyDecision(
            allowed=True,
            reason=reason,
            constraints={"coding_agent": dict(bound_scope)},
            reason_code=code,
            trace=trace,
        )


def enforce_coding_agent_constraints(constraints: dict[str, Any], args: dict[str, Any]) -> None:
    """Fail closed if invocation arguments differ from signed coding-agent scope.

    Args:
        constraints: Verified token constraints passed through
            :class:`~weaver_kernel.drivers.base.ExecutionContext`.
        args: Actual driver invocation arguments.

    Raises:
        DriverError: If a bound scope key is missing or changed at invocation.
    """
    bound = constraints.get("coding_agent")
    if not isinstance(bound, dict) or not bound:
        raise DriverError("Missing signed coding-agent scope constraints.")
    for key, expected in bound.items():
        actual = args.get(key)
        if actual != expected:
            raise DriverError(
                f"Invocation changed signed coding-agent scope {key!r}: "
                f"expected {expected!r}, got {actual!r}."
            )


__all__ = [
    "CodingAgentPolicyConfig",
    "CodingAgentPolicyEngine",
    "enforce_coding_agent_constraints",
]
