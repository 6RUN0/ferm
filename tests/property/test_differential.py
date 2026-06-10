"""Differential fuzzing: the port vs the Perl oracle on pure functions.

Arbitrary inputs through the pure lexing/escaping helpers must behave
identically in the Python port and in the frozen oracle (bug-for-bug,
e.g. a trailing newline slipping past the bare-word ``$`` anchor).
Targets: ferm's ``tokenize_string`` and ``shell_escape``, import-ferm's
save-file lexer, and the backtick-output splitter.

ASCII only, by design: the oracle lexes bytes (no ``use utf8``, so
``\\w`` is ASCII) while the port lexes ``str`` (Unicode ``\\w``); the
divergence on non-ASCII word characters is representational, and real
ferm configs are ASCII.  Codepoints 0 and 1 are reserved by the pipe
protocol (see :mod:`.oracle`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from .oracle import IMPORT_SOURCE, OracleProcess

if TYPE_CHECKING:
    from collections.abc import Iterator

_ASCII_TEXT = st.text(
    alphabet=st.characters(min_codepoint=2, max_codepoint=0x7F),
    max_size=60,
)

# A ferm-flavoured line generator: chunks the lexer actually
# distinguishes, glued with varying separators (including none, to
# exercise adjacency like `name"quoted"`).
_CHUNK = st.one_of(
    st.text(alphabet="ab-+/.:_09", min_size=1, max_size=6),
    st.text(
        alphabet=st.characters(
            min_codepoint=2, max_codepoint=0x7F, exclude_characters='"'
        ),
        max_size=8,
    ).map(lambda body: f'"{body}"'),
    st.sampled_from(sorted("!,=&$%(){};")),
    st.sampled_from(["@def", "@include", "#", "`uname -n`", "$var", "&fn"]),
)
_SEPARATOR = st.sampled_from(["", " ", "\t", "  "])
_FERMISH_LINE = st.lists(st.tuples(_CHUNK, _SEPARATOR), max_size=10).map(
    lambda pairs: "".join(chunk + sep for chunk, sep in pairs)
)

_LINES = _ASCII_TEXT | _FERMISH_LINE

# Backtick output is multi-line: comment stripping is per line, so a
# `#` chunk inside _LINES exercises it on every line independently.
_MULTILINE = st.lists(_LINES, max_size=4).map("\n".join)
_OUTPUTS = _LINES | _MULTILINE


@pytest.fixture(scope="module")
def oracle_tokenize() -> Iterator[OracleProcess]:
    proc = OracleProcess("tokenize")
    yield proc
    proc.close()


@pytest.fixture(
    scope="module",
    params=[("escape_fast", True), ("escape_slow", False)],
    ids=["fast", "slow"],
)
def oracle_escape(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[OracleProcess, bool]]:
    function, fast = request.param
    proc = OracleProcess(function)
    yield proc, fast
    proc.close()


@given(line=_LINES)
def test_tokenize_matches_oracle(
    line: str, oracle_tokenize: OracleProcess
) -> None:
    from pyferm.tokenizer import tokenize_string

    assert tokenize_string(line) == oracle_tokenize.tokenize(line)


@given(line=_LINES)
def test_tokenize_is_idempotent(line: str) -> None:
    # Tokens survive a re-lex: joining them with spaces and tokenizing
    # again yields the same list (no token loses meaning in isolation).
    from pyferm.tokenizer import tokenize_string

    tokens = tokenize_string(line)
    assert tokenize_string(" ".join(tokens)) == tokens


@given(token=_LINES)
def test_shell_escape_matches_oracle(
    token: str, oracle_escape: tuple[OracleProcess, bool]
) -> None:
    from pyferm.backend.iptables import shell_escape

    proc, fast = oracle_escape
    assert shell_escape(token, fast=fast) == proc.query(token)


@pytest.fixture(scope="module")
def oracle_import_tokenize() -> Iterator[OracleProcess]:
    proc = OracleProcess("import_tokenize", source=IMPORT_SOURCE)
    yield proc
    proc.close()


@pytest.fixture(scope="module")
def oracle_backtick_split() -> Iterator[OracleProcess]:
    proc = OracleProcess("backtick_split")
    yield proc
    proc.close()


@given(line=_LINES)
def test_import_tokenize_matches_oracle(
    line: str, oracle_import_tokenize: OracleProcess
) -> None:
    from pyferm.import_ferm import _tokenize

    assert _tokenize(line) == oracle_import_tokenize.tokenize(line)


@given(output=_OUTPUTS)
def test_backtick_split_matches_oracle(
    output: str, oracle_backtick_split: OracleProcess
) -> None:
    from pyferm.functions import _split_backtick_output

    assert _split_backtick_output(output) == oracle_backtick_split.tokenize(
        output
    )
