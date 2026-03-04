"""Unit tests for PII/PCI regex patterns and the redact() function."""

from __future__ import annotations

import pytest

from agent_kernel.firewall.redaction import (
    _CARD_RE,
    _EMAIL_RE,
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
