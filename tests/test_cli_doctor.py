"""Tests for ``weaver-kernel doctor`` (issue #124)."""

from __future__ import annotations

import json

import pytest

from weaver_kernel.cli import main


def test_doctor_passes_with_secret_set(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WEAVER_KERNEL_SECRET", "doctor-test-secret")
    rc = main(["doctor"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "token_vector" in out
    assert "audit_chain" in out
    assert "WEAVER_KERNEL_SECRET is set" in out


def test_doctor_warns_without_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("WEAVER_KERNEL_SECRET", raising=False)
    rc = main(["doctor"])
    out = capsys.readouterr().out
    # Missing secret is a warning, not an error: doctor still exits 0.
    assert rc == 0
    assert "not set" in out


def test_doctor_json(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("WEAVER_KERNEL_SECRET", "doctor-test-secret")
    rc = main(["doctor", "--json"])
    assert rc == 0
    checks = json.loads(capsys.readouterr().out)
    names = {c["name"] for c in checks}
    assert {"python", "secret", "token_vector", "audit_chain"} <= names
    assert all(c["status"] in {"ok", "warn", "error"} for c in checks)
