"""Tests for shared declarative/coding-agent match helpers."""

from weaver_kernel.policy_matching import matching_scope_glob_patterns, scope_globs_match


def test_scope_globs_require_every_key_and_match_one_pattern() -> None:
    assert scope_globs_match(
        {"path": "src/app/main.py", "command_class": "test"},
        {"path": ["src/**", "tests/**"], "command_class": ["test"]},
    )
    assert not scope_globs_match(
        {"path": ".github/workflows/release.yml", "command_class": "test"},
        {"path": ["src/**", "tests/**"], "command_class": ["test"]},
    )


def test_scope_globs_fail_closed_for_missing_or_non_string_values() -> None:
    assert not scope_globs_match({}, {"path": ["src/**"]})
    assert not scope_globs_match({"path": 42}, {"path": ["src/**"]})


def test_matching_scope_glob_patterns_preserves_configuration_order() -> None:
    assert matching_scope_glob_patterns("src/app.py", ["**/*.py", "src/**", "tests/**"]) == [
        "**/*.py",
        "src/**",
    ]
    assert matching_scope_glob_patterns(None, ["**"]) == []
