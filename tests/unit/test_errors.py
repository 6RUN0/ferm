"""
Unit tests for :mod:`pyferm.errors` (the ``error``/``warning`` port).

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


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        pytest.param(
            ["a", "(", "b", ")", "(", "c", ")", "option", "z", ";"],
            "Error in test.ferm line 4:\n    c \n) \noption z \n; \n<--\n",
            id="paren-depth-branches",
        ),
        pytest.param(
            ["{", "option", "a", "option", "b", "option", "c", ";", "}"],
            "Error in test.ferm line 4:\n"
            "    option b \n"
            "    option c \n"
            "    ; \n"
            "} \n"
            "<--\n",
            id="option-branch-tabs-nonzero",
        ),
        pytest.param(
            ["option", "foo", ";", "option", "bar", ";"],
            "Error in test.ferm line 4:\n"
            "option foo \n"
            "; \n"
            "option bar \n"
            "; \n"
            "<--\n",
            id="short-stream-clamped-start",
        ),
        pytest.param(
            ["option", "foo", ";"],
            "Error in test.ferm line 4:\noption foo \n; \n<--\n",
            id="tiny-stream-cursor-origin",
        ),
        pytest.param(
            ["a", "(", "b", ")"],
            "Error in test.ferm line 4:\na \n( \n    b \n) \n<--\n",
            id="paren-open-at-top-level",
        ),
        pytest.param(
            ["{", "a", "(", "b"],
            "Error in test.ferm line 4:\n"
            "\n"
            "{ \n"
            "    a \n"
            "    ( \n"
            "        b <--\n",
            id="paren-open-indented",
        ),
        pytest.param(
            [
                "{",
                "p",
                ";",
                "q",
                ";",
                "r",
                ";",
                "s",
                ";",
                "option",
                "t",
                ";",
                "}",
            ],
            "Error in test.ferm line 4:\n"
            "    s ; \n"
            "    option t \n"
            "    ; \n"
            "} \n"
            "<--\n",
            id="option-indent-in-window",
        ),
        pytest.param(
            ["{", "{", "x", ";", "}", "y", ";", "}"],
            "Error in test.ferm line 4:\n"
            "        x ; \n"
            "    } \n"
            "    y ; \n"
            "} \n"
            "<--\n",
            id="brace-close-reindent",
        ),
        pytest.param(
            ["a", "(", "b", ")", "{", "c", "}"],
            "Error in test.ferm line 4:\n) \n{ \n    c \n} \n<--\n",
            id="paren-close-before-brace",
        ),
    ],
)
def test_error_reindents_bracket_and_option_streams_byte_exact(
    capsys: pytest.CaptureFixture[str],
    tokens: list[object],
    expected: str,
) -> None:
    # Exercises the paren depth branches, the ``prev == "option"`` branch at
    # non-zero indent, and the ``max(start, 0)`` clamp on a sub-five-line view
    # that the single nested-block fixture never reaches.
    set_error_context(
        _Script(filename="test.ferm", line=4, past_tokens=[tokens])
    )
    with pytest.raises(FermError):
        error("oops")
    assert capsys.readouterr().err == expected


def test_error_renders_non_string_token_via_str(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A consumed deferred value can land among the past tokens; ``error`` must
    # stringify it with ``str(word)``, not collapse it to a constant.
    class _Deferred:
        def __str__(self) -> str:
            return "@deferred"

    tokens: list[object] = ["option", "foo", ";", "option", _Deferred(), ";"]
    set_error_context(
        _Script(filename="test.ferm", line=4, past_tokens=[tokens])
    )
    with pytest.raises(FermError):
        error("oops")
    assert capsys.readouterr().err == (
        "Error in test.ferm line 4:\n"
        "option foo \n"
        "; \n"
        "option @deferred \n"
        "; \n"
        "<--\n"
    )


def test_internal_error_default_detail() -> None:
    exc = errors.internal_error()
    assert str(exc) == "internal error: unexpected value type"


def test_warning_without_context_writes_bare_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    warning("no context here")
    assert capsys.readouterr().err == "Warning: no context here\n"


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
    assert errors._context is script
    set_error_context(None)
    assert errors._context is None
