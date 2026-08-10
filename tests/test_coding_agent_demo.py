"""Regression tests for the installed-package coding-agent proof."""

from __future__ import annotations

import subprocess
import sys

import pytest

from weaver_kernel.coding_agent_demo import EXPECTED_RECEIPT, main


def test_demo_verifies_before_emitting_exact_receipt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main()
    captured = capsys.readouterr()
    assert captured.out == "\n".join(EXPECTED_RECEIPT) + "\n"
    assert captured.err == ""


def test_demo_refuses_optimized_python_before_printing() -> None:
    completed = subprocess.run(
        [sys.executable, "-O", "-m", "weaver_kernel.coding_agent_demo"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "requires Python assertions; rerun without -O" in completed.stderr
