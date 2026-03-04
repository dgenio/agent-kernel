"""Tests for HandleStore."""

from __future__ import annotations

import datetime

import pytest

from agent_kernel import HandleExpired, HandleNotFound, HandleStore
from agent_kernel.models import Handle


@pytest.fixture()
def store() -> HandleStore:
    return HandleStore(default_ttl_seconds=3600)


def test_store_and_retrieve(store: HandleStore) -> None:
    data = [{"id": i} for i in range(10)]
    handle = store.store("cap.x", data)
    assert handle.total_rows == 10
    retrieved = store.get(handle.handle_id)
    assert retrieved == data


def test_get_meta(store: HandleStore) -> None:
    handle = store.store("cap.x", [1, 2, 3])
    meta = store.get_meta(handle.handle_id)
    assert meta.handle_id == handle.handle_id
    assert meta.capability_id == "cap.x"


def test_get_unknown_raises(store: HandleStore) -> None:
    with pytest.raises(HandleNotFound):
        store.get("nonexistent-handle-id")


def test_get_expired_raises(store: HandleStore) -> None:
    handle = store.store("cap.x", [1, 2, 3], ttl_seconds=-1)
    with pytest.raises(HandleExpired):
        store.get(handle.handle_id)


def test_evict_expired(store: HandleStore) -> None:
    store.store("cap.x", [1], ttl_seconds=-1)
    store.store("cap.x", [2], ttl_seconds=-1)
    store.store("cap.x", [3], ttl_seconds=3600)
    evicted = store.evict_expired()
    assert evicted == 2


# ── Expand ─────────────────────────────────────────────────────────────────────


def _make_handle(store: HandleStore) -> Handle:
    data = [
        {"id": i, "status": "paid" if i % 2 == 0 else "unpaid", "amount": float(i * 10)}
        for i in range(20)
    ]
    return store.store("cap.x", data)


def test_expand_pagination(store: HandleStore) -> None:
    handle = _make_handle(store)
    frame = store.expand(handle, query={"offset": 5, "limit": 3})
    assert len(frame.table_preview) == 3
    assert frame.table_preview[0]["id"] == 5


def test_expand_field_selection(store: HandleStore) -> None:
    handle = _make_handle(store)
    frame = store.expand(handle, query={"fields": ["id", "status"]})
    assert all(set(r.keys()) == {"id", "status"} for r in frame.table_preview)


def test_expand_filter(store: HandleStore) -> None:
    handle = _make_handle(store)
    frame = store.expand(handle, query={"filter": {"status": "paid"}})
    assert all(r["status"] == "paid" for r in frame.table_preview)


def test_expand_combined(store: HandleStore) -> None:
    handle = _make_handle(store)
    frame = store.expand(
        handle,
        query={"filter": {"status": "unpaid"}, "offset": 0, "limit": 2, "fields": ["id"]},
    )
    assert len(frame.table_preview) <= 2
    assert all("id" in r for r in frame.table_preview)
    assert all("status" not in r for r in frame.table_preview)


def test_expand_expired_raises(store: HandleStore) -> None:
    handle = store.store("cap.x", [1, 2, 3], ttl_seconds=-1)
    with pytest.raises(HandleExpired):
        store.expand(handle, query={})


def test_expand_handle_not_found(store: HandleStore) -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    fake_handle = Handle(
        handle_id="fake-id",
        capability_id="cap.x",
        created_at=now,
        expires_at=now + datetime.timedelta(hours=1),
    )
    with pytest.raises(HandleNotFound):
        store.expand(fake_handle, query={})


# ── Bounded store ──────────────────────────────────────────────────────────────


def test_max_entries_evicts_oldest() -> None:
    s = HandleStore(default_ttl_seconds=3600, max_entries=5)
    handles = [s.store("cap.x", [i]) for i in range(7)]
    # Only 5 should remain; the 2 oldest were evicted
    assert len(s._meta) == 5
    # Oldest handles should be gone
    with pytest.raises(HandleNotFound):
        s.get(handles[0].handle_id)
    with pytest.raises(HandleNotFound):
        s.get(handles[1].handle_id)
    # Newest should still be accessible
    assert s.get(handles[6].handle_id) == [6]


def test_max_entries_prefers_expired_over_live() -> None:
    s = HandleStore(default_ttl_seconds=3600, max_entries=3)
    # Store 2 already-expired + 1 live
    s.store("cap.x", ["expired1"], ttl_seconds=-1)
    s.store("cap.x", ["expired2"], ttl_seconds=-1)
    live = s.store("cap.x", ["live"], ttl_seconds=3600)
    # Now add a 4th — should evict the 2 expired first, then no overflow
    new = s.store("cap.x", ["new"], ttl_seconds=3600)
    assert len(s._meta) == 2
    assert s.get(live.handle_id) == ["live"]
    assert s.get(new.handle_id) == ["new"]


def test_periodic_eviction_on_store() -> None:
    s = HandleStore(default_ttl_seconds=3600, max_entries=10_000)
    # Fill with expired entries below the cap
    for i in range(HandleStore._EVICT_INTERVAL):
        s.store("cap.x", [i], ttl_seconds=-1)
    # All expired entries should have been evicted at the interval boundary
    assert len(s._meta) == 0
