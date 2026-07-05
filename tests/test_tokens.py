"""Tests for HMACTokenProvider."""

from __future__ import annotations

import datetime

import pytest

from weaver_kernel import (
    AgentKernelError,
    HMACTokenProvider,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
    TokenScopeError,
)
from weaver_kernel.stores import InMemoryRevocationStore

_UTC = datetime.timezone.utc


@pytest.fixture()
def provider() -> HMACTokenProvider:
    return HMACTokenProvider(secret="test-secret-12345")


def test_issue_returns_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    assert token.capability_id == "cap.x"
    assert token.principal_id == "user-1"
    assert token.signature != ""
    assert token.token_id != ""


def test_verify_valid_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    # Should not raise
    provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_verify_expired_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1", ttl_seconds=-1)
    with pytest.raises(TokenExpired):
        provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_verify_tampered_signature(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    # Flip the first character of the signature
    flipped = ("a" if token.signature[0] != "a" else "b") + token.signature[1:]
    from dataclasses import replace

    tampered = replace(token, signature=flipped)
    with pytest.raises(TokenInvalid):
        provider.verify(tampered, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_verify_wrong_principal(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    with pytest.raises(TokenScopeError, match="principal"):
        provider.verify(token, expected_principal_id="user-2", expected_capability_id="cap.x")


def test_verify_wrong_capability(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    with pytest.raises(TokenScopeError, match="capability"):
        provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.y")


def test_token_with_constraints(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1", constraints={"max_rows": 10})
    assert token.constraints["max_rows"] == 10
    # Verification should still pass
    provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_token_serialization_roundtrip(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1", constraints={"foo": "bar"})
    d = token.to_dict()
    from weaver_kernel.tokens import CapabilityToken

    restored = CapabilityToken.from_dict(d)
    assert restored.token_id == token.token_id
    assert restored.signature == token.signature
    # Verification should still pass on the restored token
    provider.verify(restored, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_tamper_constraints_invalidates_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1", constraints={"max_rows": 10})
    d = token.to_dict()
    d["constraints"]["max_rows"] = 9999  # tamper
    from weaver_kernel.tokens import CapabilityToken

    tampered = CapabilityToken.from_dict(d)
    with pytest.raises(TokenInvalid):
        provider.verify(tampered, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_dev_secret_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A provider with no secret should generate a warning."""
    import logging

    import weaver_kernel._secrets as sec_mod

    # Save and restore _DEV_SECRET to avoid leaking state to other tests. The
    # secret-loading path now lives in weaver_kernel._secrets (shared by token
    # signing and audit-chain hashing).
    original = sec_mod._DEV_SECRET
    try:
        sec_mod._DEV_SECRET = None
        provider_no_secret = HMACTokenProvider(secret=None)
        with caplog.at_level(logging.WARNING, logger="weaver_kernel._secrets"):
            token = provider_no_secret.issue("cap.x", "user-1")
        assert "WEAVER_KERNEL_SECRET" in caplog.text
        assert token.signature != ""
    finally:
        sec_mod._DEV_SECRET = original


# ── Revocation ─────────────────────────────────────────────────────────────────


def test_revoke_single_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    provider.revoke(token.token_id)
    with pytest.raises(TokenRevoked, match="revoked"):
        provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_revoke_idempotent(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1")
    provider.revoke(token.token_id)
    provider.revoke(token.token_id)  # should not raise
    with pytest.raises(TokenRevoked):
        provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_revoke_does_not_affect_other_tokens(provider: HMACTokenProvider) -> None:
    token_a = provider.issue("cap.x", "user-1")
    token_b = provider.issue("cap.y", "user-1")
    provider.revoke(token_a.token_id)
    # token_b should still verify
    provider.verify(token_b, expected_principal_id="user-1", expected_capability_id="cap.y")


def test_revoke_all_principal(provider: HMACTokenProvider) -> None:
    t1 = provider.issue("cap.x", "user-1")
    t2 = provider.issue("cap.y", "user-1")
    _other = provider.issue("cap.x", "user-2")
    count = provider.revoke_all("user-1")
    assert count == 2
    with pytest.raises(TokenRevoked):
        provider.verify(t1, expected_principal_id="user-1", expected_capability_id="cap.x")
    with pytest.raises(TokenRevoked):
        provider.verify(t2, expected_principal_id="user-1", expected_capability_id="cap.y")
    # user-2 token is unaffected
    provider.verify(_other, expected_principal_id="user-2", expected_capability_id="cap.x")


def test_revoke_all_unknown_principal(provider: HMACTokenProvider) -> None:
    count = provider.revoke_all("nonexistent")
    assert count == 0


def test_revoke_all_excludes_already_revoked(provider: HMACTokenProvider) -> None:
    t1 = provider.issue("cap.x", "user-1")
    _t2 = provider.issue("cap.y", "user-1")
    provider.revoke(t1.token_id)
    count = provider.revoke_all("user-1")
    assert count == 1  # only t2 newly revoked


def test_revoked_checked_before_signature(provider: HMACTokenProvider) -> None:
    """Revocation check runs before HMAC — even a tampered token raises TokenRevoked."""
    token = provider.issue("cap.x", "user-1")
    provider.revoke(token.token_id)
    from dataclasses import replace

    tampered = replace(token, signature="invalid-signature")
    with pytest.raises(TokenRevoked):
        provider.verify(tampered, expected_principal_id="user-1", expected_capability_id="cap.x")


# ── Revocation-state bounding / expiry sweep (issue #182) ────────────────────


def test_sweep_keeps_revoked_but_unexpired_entry() -> None:
    store = InMemoryRevocationStore()
    now = datetime.datetime(2026, 1, 1, tzinfo=_UTC)
    store.track("p1", "t1", now + datetime.timedelta(hours=1))
    store.revoke("t1")
    removed = store.sweep_expired(now)
    assert removed == 0
    assert store.is_revoked("t1")  # a live, revoked token is never un-revoked


def test_sweep_removes_expired_entry() -> None:
    store = InMemoryRevocationStore()
    now = datetime.datetime(2026, 1, 1, tzinfo=_UTC)
    store.track("p1", "t1", now - datetime.timedelta(hours=1))
    store.revoke("t1")
    removed = store.sweep_expired(now)
    assert removed == 1
    assert not store.is_revoked("t1")  # expired anyway — verify() fails on expiry


def test_provider_sweep_preserves_revoked_unexpired_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1", ttl_seconds=3600)
    provider.revoke(token.token_id)
    # now precedes expiry, so the entry is kept and the token still fails closed.
    provider.sweep_revocations(datetime.datetime.now(tz=_UTC))
    with pytest.raises(TokenRevoked):
        provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_revocation_state_bounded_under_grant_revoke_loop() -> None:
    store = InMemoryRevocationStore()
    # Tokens are live (future expiry) when revoked — the normal lifecycle.
    expiry = datetime.datetime(2099, 1, 1, tzinfo=_UTC)
    for i in range(500):
        store.track("p1", f"t{i}", expiry)
        store.revoke(f"t{i}")
    # Before expiry, a sweep removes nothing (every token is still live).
    assert store.sweep_expired(datetime.datetime(2026, 1, 1, tzinfo=_UTC)) == 0
    assert len(store._revoked) == 500
    # Once expired, a single sweep drops all bookkeeping → growth is bounded.
    store.sweep_expired(expiry + datetime.timedelta(seconds=1))
    assert store._expiry == {}
    assert store._revoked == set()
    assert store._principal_tokens == {}


def test_track_and_sweep_accept_naive_datetimes() -> None:
    """Naive expiry/now are treated as UTC — no naive-vs-aware TypeError."""
    store = InMemoryRevocationStore()
    store.track("p1", "t1", datetime.datetime(2099, 1, 1))  # naive expiry
    store.revoke("t1")
    # Naive 'now' before expiry keeps the (live) revoked token.
    assert store.sweep_expired(datetime.datetime(2026, 1, 1)) == 0
    assert store.is_revoked("t1")
    # Naive 'now' after expiry removes it.
    assert store.sweep_expired(datetime.datetime(2099, 1, 2)) == 1
    assert not store.is_revoked("t1")


# ── Signing-key rotation (#185) ──────────────────────────────────────────────


def test_legacy_single_secret_unaffected(provider: HMACTokenProvider) -> None:
    """A provider built with `secret=...` (no rotation) behaves exactly as before."""
    token = provider.issue("cap.x", "user-1")
    assert token.key_id == ""
    provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_issue_stamps_active_key_id() -> None:
    provider = HMACTokenProvider(secrets={"v1": "secret-v1"}, active_key_id="v1")
    token = provider.issue("cap.x", "user-1")
    assert token.key_id == "v1"


def test_rotated_key_verifies_during_overlap_window() -> None:
    """A token issued under the previous active key still verifies once a new
    key becomes active, as long as both keys remain in the ring (#185)."""
    old_provider = HMACTokenProvider(secrets={"v1": "secret-v1"}, active_key_id="v1")
    old_token = old_provider.issue("cap.x", "user-1")

    rotated_provider = HMACTokenProvider(
        secrets={"v1": "secret-v1", "v2": "secret-v2"}, active_key_id="v2"
    )
    # Should not raise — v1 is still a known key, just no longer active.
    rotated_provider.verify(
        old_token, expected_principal_id="user-1", expected_capability_id="cap.x"
    )

    new_token = rotated_provider.issue("cap.x", "user-1")
    assert new_token.key_id == "v2"
    rotated_provider.verify(
        new_token, expected_principal_id="user-1", expected_capability_id="cap.x"
    )


def test_verify_unknown_key_id_fails_closed() -> None:
    """A token whose key_id was retired (or never existed) fails closed as TokenInvalid."""
    from dataclasses import replace

    provider = HMACTokenProvider(secrets={"v2": "secret-v2"}, active_key_id="v2")
    token = provider.issue("cap.x", "user-1")
    orphaned = replace(token, key_id="v1-retired")
    with pytest.raises(TokenInvalid, match="Unknown signing key"):
        provider.verify(orphaned, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_verify_logs_when_key_is_not_active(caplog: pytest.LogCaptureFixture) -> None:
    """Verifying a token signed under a non-active (overlap-window) key is logged
    at INFO — with the key id, never the secret — so operators can tell when a
    rotation's old key is safe to retire."""
    import logging

    old_provider = HMACTokenProvider(secrets={"v1": "secret-v1"}, active_key_id="v1")
    v1_token = old_provider.issue("cap.x", "user-1")

    rotated_provider = HMACTokenProvider(
        secrets={"v1": "secret-v1", "v2": "secret-v2"}, active_key_id="v2"
    )
    active_token = rotated_provider.issue("cap.x", "user-1")

    with caplog.at_level(logging.INFO):
        rotated_provider.verify(
            v1_token, expected_principal_id="user-1", expected_capability_id="cap.x"
        )
    non_active_logs = [
        r for r in caplog.records if r.getMessage() == "token_verified_non_active_key"
    ]
    assert len(non_active_logs) == 1
    assert non_active_logs[0].key_id == "v1"
    assert "secret-v1" not in str(non_active_logs[0].__dict__)

    # The active key never triggers this log.
    caplog.clear()
    with caplog.at_level(logging.INFO):
        rotated_provider.verify(
            active_token, expected_principal_id="user-1", expected_capability_id="cap.x"
        )
    assert not any(r.getMessage() == "token_verified_non_active_key" for r in caplog.records)


def test_key_ring_requires_active_key_id_when_ambiguous() -> None:
    """Configuring multiple secrets without an active_key_id is a config error,
    not a silent pick of an arbitrary key."""
    with pytest.raises(AgentKernelError, match="active_key_id is required"):
        HMACTokenProvider(secrets={"v1": "s1", "v2": "s2"})


def test_key_ring_rejects_unknown_active_key_id() -> None:
    with pytest.raises(AgentKernelError, match="not a key in the configured secrets"):
        HMACTokenProvider(secrets={"v1": "s1"}, active_key_id="nope")


# ── Typed errors from CapabilityToken.from_dict (#200) ───────────────────────


def _valid_token_dict() -> dict[str, object]:
    return {
        "token_id": "t1",
        "capability_id": "cap.x",
        "principal_id": "user-1",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-01-01T01:00:00+00:00",
        "constraints": {},
        "audit_id": "",
        "signature": "sig",
        "key_id": "",
    }


def test_from_dict_valid_roundtrip_unchanged(provider: HMACTokenProvider) -> None:
    """A well-formed to_dict() -> from_dict() round-trip still works exactly as before."""
    from weaver_kernel.tokens import CapabilityToken

    token = provider.issue("cap.x", "user-1", constraints={"foo": "bar"})
    restored = CapabilityToken.from_dict(token.to_dict())
    assert restored == token


@pytest.mark.parametrize("missing_field", ["token_id", "capability_id", "principal_id"])
def test_from_dict_missing_required_field_raises_token_invalid(missing_field: str) -> None:
    from weaver_kernel.tokens import CapabilityToken

    data = _valid_token_dict()
    del data[missing_field]
    with pytest.raises(TokenInvalid, match=f"missing field '{missing_field}'"):
        CapabilityToken.from_dict(data)


@pytest.mark.parametrize("field_name", ["token_id", "capability_id", "principal_id"])
def test_from_dict_wrong_type_field_raises_token_invalid(field_name: str) -> None:
    from weaver_kernel.tokens import CapabilityToken

    data = _valid_token_dict()
    data[field_name] = 12345  # not a string
    with pytest.raises(TokenInvalid, match=f"field '{field_name}' must be a string"):
        CapabilityToken.from_dict(data)


@pytest.mark.parametrize("ts_field", ["issued_at", "expires_at"])
def test_from_dict_invalid_timestamp_raises_token_invalid(ts_field: str) -> None:
    from weaver_kernel.tokens import CapabilityToken

    data = _valid_token_dict()
    data[ts_field] = "not-a-timestamp"
    with pytest.raises(TokenInvalid, match=f"invalid timestamp in field '{ts_field}'"):
        CapabilityToken.from_dict(data)


def test_from_dict_non_dict_constraints_raises_token_invalid() -> None:
    from weaver_kernel.tokens import CapabilityToken

    data = _valid_token_dict()
    data["constraints"] = ["not", "a", "dict"]
    with pytest.raises(TokenInvalid, match="'constraints' must be an object"):
        CapabilityToken.from_dict(data)


def test_from_dict_missing_optional_fields_use_defaults() -> None:
    """audit_id/signature/key_id default to '' when absent, as before."""
    from weaver_kernel.tokens import CapabilityToken

    data = _valid_token_dict()
    del data["audit_id"]
    del data["signature"]
    del data["key_id"]
    token = CapabilityToken.from_dict(data)
    assert token.audit_id == ""
    assert token.signature == ""
    assert token.key_id == ""
