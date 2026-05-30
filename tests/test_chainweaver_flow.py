"""Tests for the ChainWeaver integration example (issue #95).

Verifies the two acceptance-critical behaviors of
``examples/chainweaver_flow.py``: running a wrapped compiled flow produces a
kernel-visible execution record (an ``ActionTrace``), and a failing flow step
surfaces as a ``DriverError`` that preserves the ChainWeaver context (flow id
and failing step).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from agent_kernel import Principal
from agent_kernel.errors import DriverError

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load_example(name: str) -> ModuleType:
    """Import an example module by file path (examples are not a package)."""
    spec = importlib.util.spec_from_file_location(name, _EXAMPLES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # let dataclass field resolution find the module
    spec.loader.exec_module(module)
    return module


cw = _load_example("chainweaver_flow")


def test_compiled_flow_runs_steps_in_order() -> None:
    """The compiled-flow stand-in threads context through every step."""
    flow = cw.build_release_flow()
    result = flow.run({"release": "v1.0.0", "changes": ["feat: a", "chore: b"]})
    assert result["change_count"] == 2
    assert result["highlights"] == ["feat: a"]


def test_compiled_flow_raises_flow_error_with_context() -> None:
    """A failing step is reported with the flow id and failing step name."""
    flow = cw.build_release_flow()
    with pytest.raises(cw.FlowExecutionError) as excinfo:
        flow.run({"release": "v1.0.0", "changes": []})
    assert excinfo.value.flow_id == "release_notes_summary"
    assert excinfo.value.step == "collect_changes"


async def test_wrapped_flow_produces_audit_trace() -> None:
    """Invoking the flow-backed capability records a kernel-visible trace."""
    kernel = cw.build_kernel()
    principal = Principal(principal_id="release-bot", roles=["reader"])
    action_id = await cw.run_flow(
        kernel, principal, {"release": "v2.0.0", "changes": ["feat: x", "fix: y"]}
    )
    trace = kernel.explain(action_id)
    assert trace.capability_id == "flows.summarize_release"
    assert trace.driver_id == "chainweaver"
    assert trace.error is None
    assert trace.result_summary is not None


async def test_flow_failure_preserves_chainweaver_context() -> None:
    """A flow step failure surfaces as DriverError keeping flow id + step."""
    kernel = cw.build_kernel()
    principal = Principal(principal_id="release-bot", roles=["reader"])
    with pytest.raises(DriverError, match="release_notes_summary.*collect_changes"):
        await cw.run_flow(kernel, principal, {"release": "v2.0.1", "changes": []})
