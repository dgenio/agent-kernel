"""README quickstart consistency test.

Extracts the Quickstart code block from ``README.md`` and runs it so CI fails
if the inline snippet ever stops producing the result a new user is told to
expect (issue #83). This guards the *inline* README snippet directly, alongside
``examples/readme_quickstart.py`` (the standalone runnable mirror executed by
``make example``).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_README = _REPO_ROOT / "README.md"
_EXPECTED_OUTPUT = "[{'title': 'Buy milk'}]"


def _extract_quickstart_snippet() -> str:
    """Return the README ``python`` block that holds the quickstart flow."""
    blocks = re.findall(
        r"```python\n(.*?)```", _README.read_text(encoding="utf-8"), flags=re.DOTALL
    )
    for block in blocks:
        if "asyncio.run(main())" in block and "kernel.expand(" in block:
            return block
    raise AssertionError(
        "Could not locate the Quickstart python block (containing "
        "'asyncio.run(main())' and 'kernel.expand(') in README.md."
    )


def test_readme_quickstart_runs_and_matches_documented_output() -> None:
    """The README quickstart snippet runs and prints the documented preview."""
    snippet = _extract_quickstart_snippet()
    result = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        timeout=60,
    )
    assert result.returncode == 0, (
        "README quickstart snippet failed to execute.\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    assert _EXPECTED_OUTPUT in result.stdout, (
        f"README quickstart output drifted: expected {_EXPECTED_OUTPUT!r} in "
        f"stdout.\n--- stdout ---\n{result.stdout}"
    )
