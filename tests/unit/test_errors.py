"""Unit tests for :mod:`pyferm.errors` (the ``error``/``warning`` port).

Locks the exit-code contract (``error`` raises :class:`FermError`) and
the byte-exact stderr layout of the re-indented code context, so a future
refactor cannot silently drift from the Perl original.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from pyferm import errors
from pyferm.errors import FermError, error, set_error_context, warning


@dataclass
class _Script:
    filename: str = "test.ferm"
    line: int = 0
    past_tokens: list[list[object]] = field(default_factory=list)


@pytest.fixture(autouse=True)
def _reset_context() -> None:
    set_error_context(None)


def test_error_raises_ferm_error_with_joined_message() -> None:
    set_error_context(_Script(line=7))
    with pytest.raises(FermError) as info:
        error("no such", "keyword")
    assert str(info.value) == "no such keyword"


def test_error_prints_location_header_and_footer(
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_error_context(_Script(filename="rules.ferm", line=42))
    with pytest.raises(FermError):
        error("boom")
    err = capsys.readouterr().err
    assert err.startswith("Error in rules.ferm line 42:\n")
    assert err.endswith("<--\n")


def test_error_reindents_past_tokens_byte_exact(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Nested table/chain block; locks the indentation algorithm and the
    # deliberate trailing spaces emitted by Perl's "$word . ' '".
    tokens: list[object] = [
        "table",
        "filter",
        "{",
        "chain",
        "INPUT",
        "{",
        "proto",
        "tcp",
        ";",
        "}",
        "}",
    ]
    set_error_context(
        _Script(filename="test.ferm", line=4, past_tokens=[tokens])
    )
    with pytest.raises(FermError):
        error("oops")
    err = capsys.readouterr().err
    assert err == (
        "Error in test.ferm line 4:\n"
        "    { \n"
        "        proto tcp ; \n"
        "    } \n"
        "} \n"
        "<--\n"
    )


def test_error_without_context_only_raises(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(FermError) as info:
        error("early failure")
    assert str(info.value) == "early failure"
    assert capsys.readouterr().err == ""


def test_warning_writes_located_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_error_context(_Script(filename="w.ferm", line=3))
    warning("deprecated keyword")
    assert capsys.readouterr().err == (
        "Warning in w.ferm line 3: deprecated keyword\n"
    )


def test_set_error_context_module_state() -> None:
    script = _Script(line=1)
    set_error_context(script)
    assert errors._context is script  # noqa: SLF001 -- state under test
    set_error_context(None)
    assert errors._context is None  # noqa: SLF001 -- state under test
