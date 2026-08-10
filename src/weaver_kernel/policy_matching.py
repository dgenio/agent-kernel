"""Shared deterministic match helpers for declarative policy rules."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any


def scope_globs_match(scope: dict[str, Any], required: dict[str, list[str]] | None) -> bool:
    """Return whether string scope values match every configured glob set.

    Args:
        scope: Trusted, host-supplied request scope values.
        required: Mapping of scope key to one-or-more shell-style glob patterns.

    Returns:
        ``True`` when every required key is present as a string and matches at
        least one pattern for that key. ``None`` means no glob condition.
    """
    if required is None:
        return True
    for key, patterns in required.items():
        value = scope.get(key)
        if not isinstance(value, str) or not any(
            fnmatchcase(value, pattern) for pattern in patterns
        ):
            return False
    return True


def matching_scope_glob_patterns(value: Any, patterns: list[str]) -> list[str]:
    """Return configured patterns matching one trusted scope value.

    Args:
        value: Scope value to inspect.
        patterns: Candidate shell-style glob patterns.

    Returns:
        Matching patterns in configuration order; non-string values match none.
    """
    if not isinstance(value, str):
        return []
    return [pattern for pattern in patterns if fnmatchcase(value, pattern)]


__all__ = ["matching_scope_glob_patterns", "scope_globs_match"]
