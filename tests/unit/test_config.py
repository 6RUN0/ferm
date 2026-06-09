"""Unit tests for :mod:`pyferm.config` (the ``%option`` model)."""

from __future__ import annotations

from pyferm.config import Options


def test_defaults_match_oracle_baseline() -> None:
    options = Options()
    # fast is the only flag that defaults true (Perl ``fast = not --slow``)
    assert options.fast is True
    assert options.test is False
    assert options.noexec is False
    assert options.nolegacy is False
    assert options.timeout == 30
    assert options.domain is None
    assert options.mock_previous == {}


def test_mock_previous_is_per_instance() -> None:
    a = Options()
    a.mock_previous["ip"] = "/tmp/a"
    # the default_factory must not be shared between instances
    assert Options().mock_previous == {}
