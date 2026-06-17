"""PII/PCI/Secrets field redaction for the context firewall."""

from __future__ import annotations

import re
from typing import Any

# Fields that are always redacted when PII/PCI sensitivity is active
# (unless the principal has the pii_reader role).
_SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {
        "email",
        "phone",
        "card_number",
        "ssn",
        "social_security_number",
        "cvv",
        "credit_card",
        "password",
        "secret",
    }
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_PHONE_RE = re.compile(
    r"""
    (?<!\d)(?<![./])               # not preceded by digit, dot, or slash
    (?:\+\d{1,3}[\s.\-])?         # optional intl prefix  (+1, +44 20)
    (?:                            # area / city code
      \(\d{2,4}\)[\s.\-]?         #   (555)  or  (020)
    | \d{2,4}[\s.\-]              #   555-   or  020.
    )
    \d{3,4}                        # subscriber part 1
    [\s.\-]?                       # optional separator
    \d{3,5}                        # subscriber part 2
    (?!\d)(?![./])                 # not followed by digit, dot, or slash
    """,
    re.VERBOSE,
)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_SSN_RE = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")

# ── Secret patterns ───────────────────────────────────────────────────────────

_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
"""Matches HTTP Bearer tokens, e.g. ``Authorization: Bearer <token>``."""

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
"""Matches JSON Web Tokens (three Base64url segments starting with ``eyJ``)."""

_API_KEY_RE = re.compile(
    r"((?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key)"
    r"(?:\s*[=:]\s*|\s+))"
    r"[A-Za-z0-9\-._~+/]{8,}",
    re.IGNORECASE,
)
"""Matches common API key assignment patterns such as ``api_key=<value>``."""

_CONN_STR_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+\-.]*://)"  # scheme
    r"[^:@/\s]+"  # user
    r":[^@/\s]+"  # :password
    r"(@[^\s]+)"  # @host[/path]
)
"""Matches connection strings containing embedded credentials (``scheme://user:pass@host``)."""

_REDACTED = "[REDACTED]"
_DEPTH_ELIDED = "[REDACTED: nested data beyond depth limit]"


def _is_sensitive_field_name(name: str) -> bool:
    return name.lower() in _SENSITIVE_FIELDS


def _redact_string(data: str) -> tuple[str, list[str]]:
    """Redact inline sensitive patterns from a single string.

    Pure leaf helper shared by :func:`redact` and :class:`StreamRedactor` so
    the pattern set lives in exactly one place.

    Args:
        data: The string to scrub.

    Returns:
        A tuple of ``(redacted_string, warnings)``.
    """
    original = data
    data = _EMAIL_RE.sub(_REDACTED, data)
    data = _PHONE_RE.sub(_REDACTED, data)
    data = _CARD_RE.sub(_REDACTED, data)
    data = _SSN_RE.sub(_REDACTED, data)
    data = _BEARER_RE.sub(_REDACTED, data)
    data = _JWT_RE.sub(_REDACTED, data)
    data = _API_KEY_RE.sub(r"\1" + _REDACTED, data)
    data = _CONN_STR_RE.sub(r"\1" + _REDACTED + r"\2", data)
    if data != original:
        return data, ["String value contained sensitive patterns and was redacted."]
    return data, []


def redact(
    data: Any,
    *,
    allowed_fields: list[str] | None = None,
    depth: int = 0,
    max_depth: int = 3,
) -> tuple[Any, list[str]]:
    """Recursively redact sensitive data from *data*.

    If *allowed_fields* is non-empty, only those fields are kept in dicts;
    all others are removed.  Sensitive field names are replaced with
    ``[REDACTED]`` regardless.

    The ``max_depth`` cap bounds recursion cost; it must **fail closed**. At
    the boundary, scalar strings are still pattern-redacted (a leaf scan is
    cheap and cannot recurse), but any nested container is *elided* and
    replaced with a marker rather than returned verbatim — a deeply nested
    subtree must never reach the LLM unscanned (the I-01 boundary; see
    ``docs/agent-context/invariants.md``).

    Args:
        data: The data to redact.
        allowed_fields: If non-empty, only keep these field names in dicts.
        depth: Current recursion depth (used internally).
        max_depth: Maximum recursion depth.

    Returns:
        A tuple of ``(redacted_data, warnings)`` where *warnings* is a list of
        human-readable strings describing what was redacted.
    """
    if depth >= max_depth:
        # Fail closed at the depth boundary: scrub leaf strings, elide nested
        # containers (they would otherwise flow through unredacted).
        if isinstance(data, str):
            return _redact_string(data)
        if isinstance(data, dict | list):
            return _DEPTH_ELIDED, [
                "Nested data beyond the configured max_depth was elided (not scanned)."
            ]
        return data, []

    warnings: list[str] = []

    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for k, v in data.items():
            if allowed_fields and k not in allowed_fields:
                warnings.append(f"Field '{k}' omitted (not in allowed_fields).")
                continue
            if _is_sensitive_field_name(str(k)):
                result[k] = _REDACTED
                warnings.append(f"Field '{k}' redacted (sensitive field name).")
            else:
                child, child_warnings = redact(
                    v, allowed_fields=None, depth=depth + 1, max_depth=max_depth
                )
                result[k] = child
                warnings.extend(child_warnings)
        return result, warnings

    if isinstance(data, list):
        redacted_list = []
        for item in data:
            child, child_warnings = redact(
                item, allowed_fields=allowed_fields, depth=depth + 1, max_depth=max_depth
            )
            redacted_list.append(child)
            warnings.extend(child_warnings)
        return redacted_list, warnings

    if isinstance(data, str):
        return _redact_string(data)

    return data, warnings


# Characters that can appear *inside* a contiguous secret token (JWT, Bearer
# value, API key, connection-string body). A commit boundary is never placed
# inside a run of these, so such a token is never split across chunks.
_TOKEN_CHAR_RE = re.compile(r"[A-Za-z0-9._~+/:=@-]")

# How many trailing characters of a string stream are held back before
# emission so a pattern split across two chunks is reassembled first.
_STREAM_OVERLAP = 256


class StreamRedactor:
    """Redacts an incrementally delivered text stream with cross-chunk safety.

    A per-chunk regex pass cannot catch a secret whose characters are split
    across two chunks (e.g. ``"...eyJ"`` then ``"abc.def..."``). This buffer
    holds back the trailing :data:`_STREAM_OVERLAP` characters of the stream
    and only commits text once enough right-context has arrived, so a pattern
    straddling a chunk boundary is reassembled before either half is emitted.

    Commit boundaries are placed only at non-token separators, so a contiguous
    secret (JWT/Bearer/API-key/connection-string body) is never severed across
    a commit. Patterns that contain internal whitespace (phone, SSN, spaced
    card numbers) and are split exactly at the held boundary may still evade
    detection — a documented limit, mirrored in ``docs/security.md``.

    Second documented limit: to bound memory the buffer force-commits when it
    grows past ``overlap * 4`` without hitting a separator. A *single
    contiguous* secret longer than that bound (e.g. a very large JWT) can then
    be severed at the forced cut and escape per-segment detection. This is the
    deliberate memory-vs-safety trade and is mirrored in ``docs/security.md``.

    The redactor is single-stream and stateful: feed chunks in order, then
    call :meth:`flush` once at end-of-stream.
    """

    __slots__ = ("_pending", "_overlap", "_max_pending")

    def __init__(self, *, overlap: int = _STREAM_OVERLAP) -> None:
        self._pending = ""
        self._overlap = overlap
        # Bound the buffer: a single unbroken token longer than this is
        # force-committed rather than held indefinitely (memory safety).
        self._max_pending = overlap * 4

    def feed(self, text: str) -> tuple[str, list[str]]:
        """Accept the next chunk; return ``(redacted_committed_text, warnings)``.

        The returned text is the portion now safe to emit; the trailing
        overlap window is retained until a later :meth:`feed` or :meth:`flush`.
        """
        if text:
            self._pending += text
        if len(self._pending) <= self._overlap:
            return "", []
        cut = len(self._pending) - self._overlap
        if len(self._pending) <= self._max_pending:
            # Back the cut off a contiguous token so we never sever one.
            while cut > 0 and _TOKEN_CHAR_RE.match(self._pending[cut - 1]):
                cut -= 1
            if cut <= 0:
                return "", []
        committed = self._pending[:cut]
        self._pending = self._pending[cut:]
        return _redact_string(committed)

    def flush(self) -> tuple[str, list[str]]:
        """Redact and return any buffered remainder at end-of-stream."""
        if not self._pending:
            return "", []
        out = _redact_string(self._pending)
        self._pending = ""
        return out
