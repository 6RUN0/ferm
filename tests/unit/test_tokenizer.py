"""Unit tests for :mod:`pyferm.tokenizer`.

Covers the lexer pattern, the lazy line-numbered token stream, the
``past_tokens`` reconstruction, the peek/expect/require helpers, the stop
at a deferred queue token and ``@include`` cycle detection.
"""

from __future__ import annotations

import io
from collections import deque
from pathlib import Path

import pytest

from pyferm.errors import FermError
from pyferm.tokenizer import (
    Line,
    Script,
    Tokenizer,
    make_line_token,
    open_script,
    tokenize_string,
)
from pyferm.values import Deferred


def _tokenizer(text: str) -> Tokenizer:
    return Tokenizer(Script(filename="t.ferm", handle=io.StringIO(text)))


def test_tokenize_string_words_and_specials() -> None:
    assert tokenize_string("proto tcp dport 80;") == [
        "proto",
        "tcp",
        "dport",
        "80",
        ";",
    ]
    assert tokenize_string("a=$b") == ["a", "=", "$", "b"]


def test_tokenize_string_quotes_and_function() -> None:
    assert tokenize_string('saddr "a b" ;') == ["saddr", '"a b"', ";"]
    assert tokenize_string("x `cmd arg`") == ["x", "`cmd arg`"]
    assert tokenize_string("@resolve(host)") == ["@resolve", "(", "host", ")"]


def test_tokenize_string_stops_at_comment() -> None:
    assert tokenize_string("a b # comment c") == ["a", "b"]


def test_make_line_token() -> None:
    assert make_line_token(7) == Line(7)


def test_next_token_sequence_and_line_tracking() -> None:
    tk = _tokenizer("proto tcp;\ndport 80;\n")
    seen: list[tuple[str | None, int]] = []
    while True:
        token = tk.next_token()
        if token is None:
            break
        assert isinstance(token, str)
        seen.append((token, tk.script.line))
    assert seen == [
        ("proto", 1),
        ("tcp", 1),
        (";", 1),
        ("dport", 2),
        ("80", 2),
        (";", 2),
    ]


def test_peek_does_not_consume() -> None:
    tk = _tokenizer("proto tcp;")
    assert tk.peek_token() == "proto"
    assert tk.peek_token() == "proto"
    assert tk.next_token() == "proto"
    assert tk.next_token() == "tcp"


def test_next_raw_token_yields_line_sentinel() -> None:
    tk = _tokenizer("a\n")
    assert tk.next_raw_token() == Line(1)
    assert tk.next_raw_token() == "a"
    assert tk.next_raw_token() is None


def test_eof_returns_none() -> None:
    tk = _tokenizer("")
    assert tk.next_token() is None
    assert tk.peek_token() is None


def test_past_tokens_reset_after_statement_end() -> None:
    tk = _tokenizer("a b ; c")
    for _ in range(3):  # consume "a", "b", ";"
        tk.next_token()
    assert tk.script.past_tokens == [["a", "b", ";"]]
    tk.next_token()  # "c" starts a fresh statement group
    assert tk.script.past_tokens == [["c"]]


def test_expect_token_success_and_failure() -> None:
    tk = _tokenizer("proto tcp")
    tk.expect_token("proto")  # no raise
    with pytest.raises(FermError, match="'nope' expected"):
        tk.expect_token("nope")


def test_require_next_token_rejects_eof_and_structure() -> None:
    with pytest.raises(FermError, match="unexpected end of file"):
        _tokenizer("").require_next_token()
    with pytest.raises(FermError, match="not allowed here"):
        _tokenizer(";").require_next_token()
    with pytest.raises(FermError, match="not allowed here"):
        _tokenizer("{").require_next_token()


def test_require_next_token_custom_source() -> None:
    tk = _tokenizer("")
    assert tk.require_next_token(code=lambda: "fromcode") == "fromcode"


def test_handle_special_tokens_stops_at_deferred() -> None:
    deferred = Deferred(lambda _d, *_a: [], [])
    script = Script(
        filename="t.ferm",
        handle=io.StringIO(""),
        tokens=deque([Line(5), deferred, "x"]),
    )
    tk = Tokenizer(script)
    assert tk.peek_token() is deferred
    assert tk.script.line == 5  # the Line sentinel was consumed


def test_open_script_detects_cycles() -> None:
    parent = Script(filename="a.ferm", handle=io.StringIO(""), line=3)
    with pytest.raises(FermError, match="Circular reference"):
        open_script("a.ferm", parent)


def test_open_script_reads_a_real_file(tmp_path: Path) -> None:
    path = tmp_path / "rules.ferm"
    path.write_text("proto tcp;\n")
    script = open_script(str(path), None)
    tk = Tokenizer(script)
    assert tk.next_token() == "proto"
    assert script.parent is None


def test_open_script_missing_file_errors() -> None:
    with pytest.raises(FermError, match="Failed to open"):
        open_script("/no/such/ferm/file.ferm", None)


def test_open_script_pipe_runs_command() -> None:
    # Perl's two-argument open executes a trailing-pipe filename
    # ('cmd|') and reads its stdout -- the documented ferm feature
    # "@include 'program|'" depends on it.
    script = open_script("echo 'chain INPUT ACCEPT;'|", None)
    assert script.handle is not None
    assert script.handle.read() == "chain INPUT ACCEPT;\n"
    assert script.process is not None
    assert script.process.wait() == 0
