"""Tests for HMACTokenProvider."""

from __future__ import annotations

import pytest

from agent_kernel import (
    HMACTokenProvider,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
    TokenScopeError,
)


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
    from agent_kernel.tokens import CapabilityToken

    restored = CapabilityToken.from_dict(d)
    assert restored.token_id == token.token_id
    assert restored.signature == token.signature
    # Verification should still pass on the restored token
    provider.verify(restored, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_tamper_constraints_invalidates_token(provider: HMACTokenProvider) -> None:
    token = provider.issue("cap.x", "user-1", constraints={"max_rows": 10})
    d = token.to_dict()
    d["constraints"]["max_rows"] = 9999  # tamper
    from agent_kernel.tokens import CapabilityToken

    tampered = CapabilityToken.from_dict(d)
    with pytest.raises(TokenInvalid):
        provider.verify(tampered, expected_principal_id="user-1", expected_capability_id="cap.x")


def test_dev_secret_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A provider with no secret should generate a warning."""
    import logging

    import agent_kernel.tokens as tok_mod

    # Save and restore _DEV_SECRET to avoid leaking state to other tests
    original = tok_mod._DEV_SECRET
    try:
        tok_mod._DEV_SECRET = None
        provider_no_secret = HMACTokenProvider(secret=None)
        with caplog.at_level(logging.WARNING, logger="agent_kernel.tokens"):
            token = provider_no_secret.issue("cap.x", "user-1")
        assert "AGENT_KERNEL_SECRET" in caplog.text
        assert token.signature != ""
    finally:
        tok_mod._DEV_SECRET = original


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
