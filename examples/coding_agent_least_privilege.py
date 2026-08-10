"""Source-checkout wrapper for the installed-package coding-agent demo."""

from __future__ import annotations

import asyncio
from pathlib import Path

from weaver_kernel.coding_agent_demo import run_demo

EXPECTED_RECEIPT = Path(__file__).with_name("coding_agent_expected.txt")


def main() -> None:
    """Verify the package demo against the committed receipt before printing."""
    receipt = asyncio.run(run_demo())
    actual = "\n".join(receipt) + "\n"
    expected = EXPECTED_RECEIPT.read_text(encoding="utf-8")
    assert actual == expected, "coding-agent flagship receipt fixture drifted"
    print(actual, end="")


if __name__ == "__main__":
    main()
