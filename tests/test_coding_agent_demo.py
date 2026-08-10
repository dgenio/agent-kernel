"""Regression tests for the installed-package coding-agent proof."""

from __future__ import annotations

import pytest

from weaver_kernel.coding_agent_demo import EXPECTED_RECEIPT, main


def test_demo_verifies_before_emitting_exact_receipt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main()
    captured = capsys.readouterr()
    assert captured.out == "\n".join(EXPECTED_RECEIPT) + "\n"
    assert captured.err == ""
