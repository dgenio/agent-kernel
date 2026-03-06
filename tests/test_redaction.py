"""Unit tests for PII/PCI regex patterns and the redact() function."""

from __future__ import annotations

import pytest

from agent_kernel.firewall.redaction import (
    _API_KEY_RE,
    _BEARER_RE,
    _CARD_RE,
    _CONN_STR_RE,
    _EMAIL_RE,
    _JWT_RE,
    _PHONE_RE,
    _SSN_RE,
    redact,
)

# ── _EMAIL_RE ──────────────────────────────────────────────────────────────────


class TestEmailRegex:
    """True-positive and true-negative tests for _EMAIL_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "user@example.com",
            "first.last@company.co.uk",
            "name+tag@domain.org",
            "user_name@sub.domain.com",
            "user-name@example.io",
        ],
    )
    def test_matches_valid_emails(self, text: str) -> None:
        assert _EMAIL_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "plaintext",
            "user@",
            "@domain.com",
            "user@@domain.com",
        ],
    )
    def test_rejects_non_emails(self, text: str) -> None:
        assert not _EMAIL_RE.search(text), f"Unexpected match for: {text}"


# ── _PHONE_RE ──────────────────────────────────────────────────────────────────


class TestPhoneRegex:
    """True-positive and true-negative tests for _PHONE_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "+1-555-123-4567",
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567",
            "+44 20 7946 0958",
            "(020) 7946-0958",
            "123 456 7890",
            "+1 800 555 0199",
        ],
    )
    def test_matches_phone_numbers(self, text: str) -> None:
        assert _PHONE_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "2026-03-04",
            "100.00 - 200.00",
            "v1.2.3.456",
            "192.168.1.100",
            "order-12345",
            "1234567",
            "(100)",
            "3.14159",
            "2026/03/04",
            "ID: 9876543",
        ],
    )
    def test_rejects_non_phones(self, text: str) -> None:
        assert not _PHONE_RE.search(text), f"Unexpected match for: {text}"


# ── _CARD_RE ──────────────────────────────────────────────────────────────────


class TestCardRegex:
    """True-positive and true-negative tests for _CARD_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "5500000000000004",
        ],
    )
    def test_matches_card_numbers(self, text: str) -> None:
        assert _CARD_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "12345",
            "abcdefghijklmnop",
            "123-45-6789",
        ],
    )
    def test_rejects_non_cards(self, text: str) -> None:
        assert not _CARD_RE.search(text), f"Unexpected match for: {text}"


# ── _SSN_RE ───────────────────────────────────────────────────────────────────


class TestSSNRegex:
    """True-positive and true-negative tests for _SSN_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "123-45-6789",
            "123 45 6789",
        ],
    )
    def test_matches_ssn(self, text: str) -> None:
        assert _SSN_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "123456789",
            "12-345-6789",
            "1234-56-789",
            "abc-de-fghi",
        ],
    )
    def test_rejects_non_ssn(self, text: str) -> None:
        assert not _SSN_RE.search(text), f"Unexpected match for: {text}"


# ── redact() integration ──────────────────────────────────────────────────────


class TestRedactFunction:
    """Integration tests for the redact() function with pattern redaction."""

    def test_phone_in_string_redacted(self) -> None:
        data = "Call me at (555) 123-4567 please"
        result, warnings = redact(data)
        assert "(555) 123-4567" not in result
        assert "[REDACTED]" in result
        assert len(warnings) == 1

    def test_date_not_redacted(self) -> None:
        data = "Date: 2026-03-04"
        result, warnings = redact(data)
        assert result == data
        assert not warnings

    def test_price_range_not_redacted(self) -> None:
        data = "Price: 100.00 - 200.00"
        result, warnings = redact(data)
        assert result == data
        assert not warnings

    def test_ip_address_not_redacted(self) -> None:
        data = "Server: 192.168.1.100"
        result, warnings = redact(data)
        assert result == data
        assert not warnings

    def test_email_in_dict_field_redacted(self) -> None:
        data = {"email": "user@example.com", "name": "Alice"}
        result, warnings = redact(data)
        assert result["email"] == "[REDACTED]"
        assert result["name"] == "Alice"

    def test_ssn_in_string_redacted(self) -> None:
        data = "SSN: 123-45-6789"
        result, warnings = redact(data)
        assert "123-45-6789" not in result
        assert "[REDACTED]" in result


# ── _BEARER_RE ────────────────────────────────────────────────────────────────


class TestBearerRegex:
    """True-positive and true-negative tests for _BEARER_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "Bearer abc123XYZ",
            "bearer eyJhbGciOiJIUzI1NiJ9",
            "Authorization: Bearer my-token+value/here==",
        ],
    )
    def test_matches_bearer_tokens(self, text: str) -> None:
        assert _BEARER_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "Basic dXNlcjpwYXNz",
            "no token here",
        ],
    )
    def test_rejects_non_bearer(self, text: str) -> None:
        assert not _BEARER_RE.search(text), f"Unexpected match for: {text}"


# ── _JWT_RE ───────────────────────────────────────────────────────────────────


class TestJWTRegex:
    """True-positive and true-negative tests for _JWT_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            # minimal realistic JWT (header.payload.signature)
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
        ],
    )
    def test_matches_jwt(self, text: str) -> None:
        assert _JWT_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "eyJhbGciOiJIUzI1NiJ9",  # only one segment (no dots)
            "notajwt.notajwt.notajwt",  # doesn't start with eyJ
            "aaa.bbb.ccc",  # valid Base64url but no eyJ prefix
        ],
    )
    def test_rejects_non_jwt(self, text: str) -> None:
        assert not _JWT_RE.search(text), f"Unexpected match for: {text}"


# ── _API_KEY_RE ───────────────────────────────────────────────────────────────


class TestAPIKeyRegex:
    """True-positive and true-negative tests for _API_KEY_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "api_key=ABCDEFGH12345678",
            "apikey: sk-proj-abc123defgh456",
            "API_KEY = MySecretKeyValue1",
            "access_key ABCD1234EFGH5678",
            "api-token=someRandomToken99",
        ],
    )
    def test_matches_api_keys(self, text: str) -> None:
        assert _API_KEY_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "api_key=short",  # value too short (< 8 chars)
            "no key here",
        ],
    )
    def test_rejects_non_api_keys(self, text: str) -> None:
        assert not _API_KEY_RE.search(text), f"Unexpected match for: {text}"


# ── _CONN_STR_RE ──────────────────────────────────────────────────────────────


class TestConnStrRegex:
    """True-positive and true-negative tests for _CONN_STR_RE."""

    @pytest.mark.parametrize(
        "text",
        [
            "postgresql://admin:s3cret@db.example.com/mydb",
            "mysql://user:password@localhost:3306/schema",
            "redis://default:hunter2@cache.example.com:6379",
            "amqp://guest:guest@rabbitmq.internal/vhost",
        ],
    )
    def test_matches_connection_strings(self, text: str) -> None:
        assert _CONN_STR_RE.search(text), f"Expected match for: {text}"

    @pytest.mark.parametrize(
        "text",
        [
            "https://example.com/path",  # no credentials
            "ftp://files.example.com/pub",  # no credentials
        ],
    )
    def test_rejects_non_connection_strings(self, text: str) -> None:
        assert not _CONN_STR_RE.search(text), f"Unexpected match for: {text}"


# ── Secret pattern redact() integration ──────────────────────────────────────


class TestSecretRedaction:
    """Integration tests verifying secrets are removed by redact()."""

    def test_bearer_token_redacted(self) -> None:
        data = "Authorization: Bearer supersecrettoken123"
        result, warnings = redact(data)
        assert "supersecrettoken123" not in result
        assert "[REDACTED]" in result

    def test_jwt_redacted(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
        result, warnings = redact(jwt)
        assert jwt not in result
        assert "[REDACTED]" in result

    def test_api_key_redacted(self) -> None:
        data = "Set api_key=ABCDEFGH12345678 in config"
        result, warnings = redact(data)
        assert "ABCDEFGH12345678" not in result
        assert "[REDACTED]" in result

    def test_connection_string_redacted(self) -> None:
        data = "DB_URL=postgresql://admin:s3cret@db.example.com/mydb"
        result, warnings = redact(data)
        assert "s3cret" not in result
        assert "[REDACTED]" in result

    def test_no_false_positive_plain_url(self) -> None:
        data = "Visit https://example.com/page for more info."
        result, warnings = redact(data)
        assert result == data
        assert not warnings
