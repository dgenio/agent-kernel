"""Tests for HMACTokenProvider."""

from __future__ import annotations

import datetime
from dataclasses import replace

import pytest

from weaver_kernel import (
    AgentKernelError,
    CapabilityToken,
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


# ── Signing-key rotation (#185) ────────────────────────────────────────────────


def test_single_secret_uses_default_key_id() -> None:
    """Legacy single-secret config files the key under the 'default' key id."""
    provider = HMACTokenProvider(secret="s1")
    token = provider.issue("cap.x", "user-1")
    assert token.key_id == "default"
    provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_rotation_overlap_window_verifies_previous_key() -> None:
    """A token signed under a retired key still verifies while both keys are present."""
    old = HMACTokenProvider(secrets={"k1": "s1"}, active_key_id="k1")
    token = old.issue("cap.x", "user-1")
    assert token.key_id == "k1"
    # Operator rotates: new active key k2, but k1 kept for the overlap window.
    rotated = HMACTokenProvider(secrets={"k1": "s1", "k2": "s2"}, active_key_id="k2")
    rotated.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")
    # New tokens are signed under the active key.
    assert rotated.issue("cap.x", "user-1").key_id == "k2"


def test_unknown_key_id_fails_closed() -> None:
    """A token whose key id is not in the verifier's keyring fails as TokenInvalid."""
    issuer = HMACTokenProvider(secrets={"k1": "s1"}, active_key_id="k1")
    token = issuer.issue("cap.x", "user-1")
    # k1 was retired entirely — only k2 remains.
    verifier = HMACTokenProvider(secrets={"k2": "s2"}, active_key_id="k2")
    with pytest.raises(TokenInvalid, match="unknown key id"):
        verifier.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_key_id_is_signed_tamper_evident() -> None:
    """Re-labelling a token's key_id to a present key breaks the signature."""
    provider = HMACTokenProvider(secrets={"k1": "s1", "k2": "s2"}, active_key_id="k1")
    token = provider.issue("cap.x", "user-1")
    relabelled = replace(token, key_id="k2")
    with pytest.raises(TokenInvalid, match="invalid signature"):
        provider.verify(relabelled, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_non_active_key_verification_logs_key_id_not_secret(caplog) -> None:  # type: ignore[no-untyped-def]
    """Verifying a non-active-key token logs the key id (never the secret)."""
    provider = HMACTokenProvider(secrets={"k1": "s1", "k2": "s2"}, active_key_id="k2")
    token = replace(
        HMACTokenProvider(secrets={"k1": "s1"}, active_key_id="k1").issue("cap.x", "u1")
    )
    with caplog.at_level("INFO"):
        provider.verify(token, expected_principal_id="u1", expected_capability_id="cap.x")
    records = [r for r in caplog.records if r.message == "token_verified_non_active_key"]
    assert records and getattr(records[0], "key_id", None) == "k1"
    assert "s1" not in caplog.text and "s2" not in caplog.text


def test_secret_and_secrets_together_is_rejected() -> None:
    with pytest.raises(AgentKernelError, match="either 'secret' or 'secrets'"):
        HMACTokenProvider(secret="s", secrets={"k1": "s1"})


def test_empty_keyring_is_rejected() -> None:
    with pytest.raises(AgentKernelError, match="empty"):
        HMACTokenProvider(secrets={})


def test_multi_key_without_active_key_id_is_rejected() -> None:
    with pytest.raises(AgentKernelError, match="active key id must be specified"):
        HMACTokenProvider(secrets={"k1": "s1", "k2": "s2"})


def test_active_key_id_absent_from_keyring_is_rejected() -> None:
    with pytest.raises(AgentKernelError, match="not present"):
        HMACTokenProvider(secrets={"k1": "s1"}, active_key_id="k9")


def test_env_secrets_json_used_when_no_explicit_config(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("WEAVER_KERNEL_SECRETS", '{"k1": "s1", "k2": "s2"}')
    monkeypatch.setenv("WEAVER_KERNEL_ACTIVE_KEY", "k2")
    provider = HMACTokenProvider()
    token = provider.issue("cap.x", "user-1")
    assert token.key_id == "k2"
    provider.verify(token, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_env_secrets_precedes_legacy_single_secret(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("WEAVER_KERNEL_SECRETS", '{"k1": "s1"}')
    monkeypatch.setenv("WEAVER_KERNEL_SECRET", "legacy")
    provider = HMACTokenProvider()
    assert provider.issue("cap.x", "u1").key_id == "k1"


def test_env_secrets_malformed_json_fails_closed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("WEAVER_KERNEL_SECRETS", "{not json")
    provider = HMACTokenProvider()
    with pytest.raises(AgentKernelError, match="not valid JSON"):
        provider.issue("cap.x", "u1")


# ── Typed from_dict errors (#200) ──────────────────────────────────────────────


def _valid_token_dict() -> dict:  # type: ignore[type-arg]
    provider = HMACTokenProvider(secret="s1")
    return provider.issue("cap.x", "user-1").to_dict()


def test_from_dict_valid_roundtrip_unchanged() -> None:
    provider = HMACTokenProvider(secret="s1")
    token = provider.issue("cap.x", "user-1", constraints={"max_rows": 5})
    restored = CapabilityToken.from_dict(token.to_dict())
    assert restored == token
    provider.verify(restored, expected_principal_id="user-1", expected_capability_id="cap.x")


@pytest.mark.parametrize("field", ["token_id", "capability_id", "principal_id"])
def test_from_dict_missing_required_field_raises_token_invalid(field: str) -> None:
    data = _valid_token_dict()
    del data[field]
    with pytest.raises(TokenInvalid, match=f"missing field '{field}'"):
        CapabilityToken.from_dict(data)


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_from_dict_missing_timestamp_raises_token_invalid(field: str) -> None:
    data = _valid_token_dict()
    del data[field]
    with pytest.raises(TokenInvalid, match=f"missing field '{field}'"):
        CapabilityToken.from_dict(data)


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_from_dict_bad_timestamp_raises_token_invalid(field: str) -> None:
    data = _valid_token_dict()
    data[field] = "not-a-timestamp"
    with pytest.raises(TokenInvalid, match=f"invalid timestamp in field '{field}'"):
        CapabilityToken.from_dict(data)


def test_from_dict_wrong_type_field_raises_token_invalid() -> None:
    data = _valid_token_dict()
    data["token_id"] = 123
    with pytest.raises(TokenInvalid, match="must be a string"):
        CapabilityToken.from_dict(data)


def test_from_dict_non_object_constraints_raises_token_invalid() -> None:
    data = _valid_token_dict()
    data["constraints"] = ["not", "a", "dict"]
    with pytest.raises(TokenInvalid, match="'constraints' must be an object"):
        CapabilityToken.from_dict(data)


def test_from_dict_tolerates_unknown_extra_keys() -> None:
    data = _valid_token_dict()
    data["future_field"] = "ignored"
    restored = CapabilityToken.from_dict(data)
    assert restored.token_id == data["token_id"]


# ── Additional fail-closed coverage (#185 / #200) ──────────────────────────────


def test_keyring_non_string_values_rejected() -> None:
    with pytest.raises(AgentKernelError, match="string key ids to string secrets"):
        HMACTokenProvider(secrets={"k1": 123})  # type: ignore[dict-item]


def test_env_secrets_non_object_json_rejected(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("WEAVER_KERNEL_SECRETS", '"just-a-string"')
    provider = HMACTokenProvider()
    with pytest.raises(AgentKernelError, match="JSON object"):
        provider.issue("cap.x", "u1")


def test_env_active_key_absent_from_map_rejected(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("WEAVER_KERNEL_SECRETS", '{"k1": "s1", "k2": "s2"}')
    monkeypatch.setenv("WEAVER_KERNEL_ACTIVE_KEY", "k9")
    provider = HMACTokenProvider()
    with pytest.raises(AgentKernelError, match="not present"):
        provider.issue("cap.x", "u1")


@pytest.mark.parametrize("field", ["audit_id", "signature", "key_id"])
def test_from_dict_non_string_optional_field_rejected(field: str) -> None:
    data = _valid_token_dict()
    data[field] = 123
    with pytest.raises(TokenInvalid, match="must be a string"):
        CapabilityToken.from_dict(data)


def test_from_dict_non_string_timestamp_rejected() -> None:
    data = _valid_token_dict()
    data["issued_at"] = 123
    with pytest.raises(TokenInvalid, match="must be an ISO-8601 string"):
        CapabilityToken.from_dict(data)
