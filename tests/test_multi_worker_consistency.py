"""Executable documentation for current process-local consistency semantics (#226)."""

from __future__ import annotations

import pytest

from weaver_kernel.errors import HandleNotFound, TokenRevoked
from weaver_kernel.handles import HandleStore
from weaver_kernel.rate_limit import RateLimiter
from weaver_kernel.tokens import HMACTokenProvider


_SECRET = "multi-worker-consistency-test-secret"


def test_token_signature_verifies_across_workers_that_share_a_secret() -> None:
    worker_a = HMACTokenProvider(secret=_SECRET)
    worker_b = HMACTokenProvider(secret=_SECRET)
    token = worker_a.issue("tickets.read", "alice")

    worker_b.verify(
        token,
        expected_principal_id="alice",
        expected_capability_id="tickets.read",
    )


def test_in_memory_revocation_does_not_propagate_between_workers() -> None:
    worker_a = HMACTokenProvider(secret=_SECRET)
    worker_b = HMACTokenProvider(secret=_SECRET)
    token = worker_a.issue("tickets.read", "alice")

    worker_a.revoke(token.token_id)

    with pytest.raises(TokenRevoked):
        worker_a.verify(
            token,
            expected_principal_id="alice",
            expected_capability_id="tickets.read",
        )

    # The same signed token remains valid in worker B because its default
    # revocation store is a different in-memory object.
    worker_b.verify(
        token,
        expected_principal_id="alice",
        expected_capability_id="tickets.read",
    )


def test_rate_limit_windows_are_process_local() -> None:
    def fixed_clock() -> float:
        return 100.0

    worker_a = RateLimiter(clock=fixed_clock)
    worker_b = RateLimiter(clock=fixed_clock)
    key = "alice:tickets.read"

    assert worker_a.check(key, limit=1, window_seconds=60.0)
    worker_a.record(key)
    assert not worker_a.check(key, limit=1, window_seconds=60.0)

    # An independent worker has an empty window for the same logical key.
    assert worker_b.check(key, limit=1, window_seconds=60.0)


def test_default_handle_store_is_not_portable_between_workers() -> None:
    worker_a = HandleStore()
    worker_b = HandleStore()
    handle = worker_a.store(
        "tickets.read",
        [{"id": 1, "title": "Example"}],
        principal_id="alice",
    )

    assert worker_a.get(handle.handle_id) == [{"id": 1, "title": "Example"}]
    with pytest.raises(HandleNotFound):
        worker_b.get(handle.handle_id)
