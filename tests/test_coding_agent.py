"""Tests for the coding-agent least-privilege policy surface."""

from __future__ import annotations

import pytest

from weaver_kernel.coding_agent import (
    CodingAgentPolicyEngine,
    enforce_coding_agent_constraints,
)
from weaver_kernel.enums import SafetyClass, SensitivityTag
from weaver_kernel.errors import DriverError, PolicyDenied
from weaver_kernel.models import Capability, CapabilityRequest, Principal
from weaver_kernel.policy_reasons import DenialReason


def _cap(
    capability_id: str,
    safety: SafetyClass,
    sensitivity: SensitivityTag = SensitivityTag.NONE,
) -> Capability:
    return Capability(
        capability_id=capability_id,
        name=capability_id,
        description="test coding-agent capability",
        safety_class=safety,
        sensitivity=sensitivity,
    )


def _request(capability_id: str, **scope: str) -> CapabilityRequest:
    return CapabilityRequest(capability_id=capability_id, goal="test", scope=scope)


def test_repo_read_allows_normal_path_but_not_secret_path() -> None:
    engine = CodingAgentPolicyEngine()
    principal = Principal(principal_id="coder")
    cap = _cap("repo.read.files", SafetyClass.READ)

    decision = engine.evaluate(
        _request("repo.read.files", path="README.md"),
        cap,
        principal,
        justification="inspect repo",
    )
    assert decision.constraints == {"coding_agent": {"path": "README.md"}}

    with pytest.raises(PolicyDenied, match="Secret-like"):
        engine.evaluate(
            _request("repo.read.files", path=".env"),
            cap,
            principal,
            justification="inspect repo",
        )


def test_repo_write_requires_role_and_is_path_scoped() -> None:
    engine = CodingAgentPolicyEngine()
    cap = _cap("repo.write.files", SafetyClass.WRITE)

    with pytest.raises(PolicyDenied) as role_exc:
        engine.evaluate(
            _request("repo.write.files", path="src/app.py"),
            cap,
            Principal(principal_id="reviewer"),
            justification="edit source",
        )
    assert role_exc.value.reason_code == DenialReason.MISSING_ROLE

    principal = Principal(principal_id="coder", roles=["code_writer"])
    decision = engine.evaluate(
        _request("repo.write.files", path="src/app.py"),
        cap,
        principal,
        justification="edit source",
    )
    assert decision.constraints["coding_agent"]["path"] == "src/app.py"

    with pytest.raises(PolicyDenied) as exc:
        engine.evaluate(
            _request("repo.write.files", path=".github/workflows/release.yml"),
            cap,
            principal,
            justification="edit workflow",
        )
    assert exc.value.reason_code == DenialReason.SCOPE_NOT_ALLOWED


def test_test_commands_are_separate_from_networked_commands() -> None:
    engine = CodingAgentPolicyEngine()
    principal = Principal(principal_id="coder", roles=["test_runner"])

    test_cap = _cap("shell.run.tests", SafetyClass.WRITE)
    decision = engine.evaluate(
        _request("shell.run.tests", command_class="test"),
        test_cap,
        principal,
        justification="run tests",
    )
    assert decision.constraints["coding_agent"]["command_class"] == "test"

    network_cap = _cap("shell.run.networked_command", SafetyClass.WRITE)
    with pytest.raises(PolicyDenied) as exc:
        engine.evaluate(
            _request("shell.run.networked_command", command_class="package-install"),
            network_cap,
            principal,
            justification="install dependency",
        )
    assert exc.value.reason_code == DenialReason.MISSING_ROLE


def test_pr_creation_requires_task_bound_approval_and_merge_is_separate() -> None:
    engine = CodingAgentPolicyEngine()
    principal = Principal(principal_id="coder")
    create_cap = _cap("github.create_pr", SafetyClass.WRITE)
    request = _request("github.create_pr", task_id="ISSUE-253")

    with pytest.raises(PolicyDenied) as exc:
        engine.evaluate(request, create_cap, principal, justification="open PR")
    assert exc.value.reason_code == DenialReason.MISSING_ATTRIBUTE

    approved = Principal(
        principal_id="coder",
        attributes={"approved_task_id": "ISSUE-253"},
    )
    decision = engine.evaluate(request, create_cap, approved, justification="open approved PR")
    assert decision.constraints["coding_agent"]["task_id"] == "ISSUE-253"

    merge_cap = _cap("github.merge_pr", SafetyClass.DESTRUCTIVE)
    with pytest.raises(PolicyDenied) as merge_exc:
        engine.evaluate(
            _request("github.merge_pr", task_id="ISSUE-253"),
            merge_cap,
            approved,
            justification="merge PR",
        )
    assert merge_exc.value.reason_code == DenialReason.MISSING_ROLE


def test_secret_read_requires_explicit_secrets_role() -> None:
    engine = CodingAgentPolicyEngine()
    cap = _cap("secrets.read", SafetyClass.READ, SensitivityTag.SECRETS)
    request = _request("secrets.read", path=".env")

    with pytest.raises(PolicyDenied):
        engine.evaluate(request, cap, Principal(principal_id="coder"), justification="read env")

    decision = engine.evaluate(
        request,
        cap,
        Principal(principal_id="coder", roles=["secrets_reader"]),
        justification="approved secret lookup",
    )
    assert decision.allowed is True


def test_execution_helper_blocks_scope_substitution_after_grant() -> None:
    constraints = {"coding_agent": {"path": "src/app.py"}}
    enforce_coding_agent_constraints(constraints, {"path": "src/app.py"})

    with pytest.raises(DriverError, match="changed signed coding-agent scope"):
        enforce_coding_agent_constraints(
            constraints,
            {"path": ".github/workflows/release.yml"},
        )


def test_execution_helper_fails_closed_without_signed_scope() -> None:
    with pytest.raises(DriverError, match="Missing signed coding-agent scope"):
        enforce_coding_agent_constraints({}, {"path": "src/app.py"})
