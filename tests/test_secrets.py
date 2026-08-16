"""Tests for HMAC secret resolution and the first-run development warning."""

from __future__ import annotations

import logging

import weaver_kernel._secrets as secret_module


def test_missing_secret_warns_once_with_consequence_and_fix(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.delenv(secret_module.SECRET_ENV_VAR, raising=False)
    monkeypatch.setattr(secret_module, "_DEV_SECRET", None)

    with caplog.at_level(logging.WARNING, logger="weaver_kernel._secrets"):
        first = secret_module.resolve_hmac_secret()
        second = secret_module.resolve_hmac_secret()

    assert first == second
    messages = [
        record.getMessage()
        for record in caplog.records
        if secret_module.SECRET_ENV_VAR in record.getMessage()
        and "process-local random development secret" in record.getMessage()
    ]
    assert len(messages) == 1
    message = messages[0]
    assert secret_module.SECRET_ENV_VAR in message
    assert "process-local random development secret" in message
    assert "invalid after restart" in message
    assert "another process" in message
    assert secret_module.PRODUCTION_CHECKLIST_PATH in message


def test_environment_secret_avoids_development_warning(monkeypatch, caplog) -> None:
    monkeypatch.setenv(secret_module.SECRET_ENV_VAR, "explicit-test-secret")
    monkeypatch.setattr(secret_module, "_DEV_SECRET", None)

    with caplog.at_level(logging.WARNING, logger="weaver_kernel._secrets"):
        resolved = secret_module.resolve_hmac_secret()

    assert resolved == "explicit-test-secret"
    assert caplog.records == []


def test_explicit_secret_takes_precedence_without_warning(monkeypatch, caplog) -> None:
    monkeypatch.delenv(secret_module.SECRET_ENV_VAR, raising=False)
    monkeypatch.setattr(secret_module, "_DEV_SECRET", None)

    with caplog.at_level(logging.WARNING, logger="weaver_kernel._secrets"):
        resolved = secret_module.resolve_hmac_secret("constructor-secret")

    assert resolved == "constructor-secret"
    assert caplog.records == []
