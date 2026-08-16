"""Executable documentation for current process-local consistency semantics (#226)."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import pytest

from weaver_kernel import HandleStore, HMACTokenProvider, TokenRevoked
from weaver_kernel.rate_limit import RateLimiter

_SECRET = "multi-worker-consistency-test-secret"


def _run_fresh_python(source: str, payload: dict[str, Any]) -> str:
    """Run a probe in a separate Python process and return its stdout."""
    completed = subprocess.run(
        [sys.executable, "-c", source],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def test_token_signature_verifies_across_processes_that_share_a_secret() -> None:
    worker_a = HMACTokenProvider(secret=_SECRET)
    token = worker_a.issue("tickets.read", "alice")

    result = _run_fresh_python(
        """
import json
import sys
from weaver_kernel import CapabilityToken, HMACTokenProvider

payload = json.load(sys.stdin)
token = CapabilityToken.from_dict(payload["token"])
provider = HMACTokenProvider(secret=payload["secret"])
provider.verify(
    token,
    expected_principal_id="alice",
    expected_capability_id="tickets.read",
)
print("verified")
""",
        {"secret": _SECRET, "token": token.to_dict()},
    )

    assert result == "verified"


def test_in_memory_revocation_does_not_propagate_to_fresh_process() -> None:
    worker_a = HMACTokenProvider(secret=_SECRET)
    token = worker_a.issue("tickets.read", "alice")
    worker_a.revoke(token.token_id)

    with pytest.raises(TokenRevoked):
        worker_a.verify(
            token,
            expected_principal_id="alice",
            expected_capability_id="tickets.read",
        )

    result = _run_fresh_python(
        """
import json
import sys
from weaver_kernel import CapabilityToken, HMACTokenProvider

payload = json.load(sys.stdin)
token = CapabilityToken.from_dict(payload["token"])
provider = HMACTokenProvider(secret=payload["secret"])
provider.verify(
    token,
    expected_principal_id="alice",
    expected_capability_id="tickets.read",
)
print("verified")
""",
        {"secret": _SECRET, "token": token.to_dict()},
    )

    assert result == "verified"


def test_rate_limit_windows_are_process_local() -> None:
    def fixed_clock() -> float:
        return 100.0

    worker_a = RateLimiter(clock=fixed_clock)
    key = "alice:tickets.read"

    assert worker_a.check(key, limit=1, window_seconds=60.0)
    worker_a.record(key)
    assert not worker_a.check(key, limit=1, window_seconds=60.0)

    result = _run_fresh_python(
        """
import json
import sys
from weaver_kernel.rate_limit import RateLimiter

payload = json.load(sys.stdin)
limiter = RateLimiter(clock=lambda: 100.0)
print("allowed" if limiter.check(payload["key"], limit=1, window_seconds=60.0) else "blocked")
""",
        {"key": key},
    )

    assert result == "allowed"


def test_default_handle_store_is_not_portable_to_fresh_process() -> None:
    worker_a = HandleStore()
    handle = worker_a.store(
        "tickets.read",
        [{"id": 1, "title": "Example"}],
        principal_id="alice",
    )
    assert worker_a.get(handle.handle_id) == [{"id": 1, "title": "Example"}]

    result = _run_fresh_python(
        """
import json
import sys
from weaver_kernel import HandleNotFound, HandleStore

payload = json.load(sys.stdin)
try:
    HandleStore().get(payload["handle_id"])
except HandleNotFound:
    print("missing")
else:
    print("found")
""",
        {"handle_id": handle.handle_id},
    )

    assert result == "missing"
