"""Differential fuzzing: the port vs the Perl oracle on pure functions.

Arbitrary inputs through the pure lexing/escaping helpers must behave
identically in the Python port and in the frozen oracle (bug-for-bug,
e.g. a trailing newline slipping past the bare-word ``$`` anchor).
Targets: ferm's ``tokenize_string`` and ``shell_escape``, import-ferm's
save-file lexer and option-token classifier, the backtick-output
splitter, ``@substr`` (Perl numification + ``substr`` semantics), and
the previous-ruleset reader ``read_previous``.

Full byte range: the latin-1 byte model on every I/O boundary maps
bytes to codepoints bijectively, so port and oracle lex the very same
bytes and must compare byte-for-byte on arbitrary input (the old
representational divergence on non-ASCII word characters is gone).
Codepoints 0 and 1 are reserved by the pipe protocol (see
:mod:`.oracle`).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from .oracle import IMPORT_SOURCE, OracleProcess

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pyferm.domains import DomainInfo

_BYTE_TEXT = st.text(
    alphabet=st.characters(min_codepoint=2, max_codepoint=0xFF),
    max_size=60,
)

# A ferm-flavoured line generator: chunks the lexer actually
# distinguishes, glued with varying separators (including none, to
# exercise adjacency like `name"quoted"`).
_CHUNK = st.one_of(
    st.text(alphabet="ab-+/.:_09", min_size=1, max_size=6),
    st.text(
        alphabet=st.characters(
            min_codepoint=2, max_codepoint=0xFF, exclude_characters='"'
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

_LINES = _BYTE_TEXT | _FERMISH_LINE

# Backtick output is multi-line: comment stripping is per line, so a
# `#` chunk inside _LINES exercises it on every line independently.
_MULTILINE = st.lists(_LINES, max_size=4).map("\n".join)
_OUTPUTS = _LINES | _MULTILINE

# @substr numifies its offset/length strings like Perl: mix real
# numbers (decorated with junk) and arbitrary text.  A leading
# "inf"/"nan" is excluded -- Perl numifies those to IEEE specials whose
# integer cast is platform-defined, and no real config computes an
# offset that way.
_INF_NAN_PREFIX = re.compile(r"\s*[+-]?(?:inf|nan)", re.ASCII | re.IGNORECASE)
_NUMBERISH = (
    st.integers(min_value=-(10**21), max_value=10**21).map(str)
    | st.floats(allow_nan=False, allow_infinity=False).map(repr)
    | st.tuples(
        st.sampled_from(["", " ", "\t ", "+", "-", " -"]),
        st.sampled_from(["12", "3.5", ".5", "2.", "1e3", "1E-2", "9" * 25]),
        st.sampled_from(["", "x", "e", ".", "..", "abc"]),
    ).map("".join)
    | _BYTE_TEXT.filter(lambda text: _INF_NAN_PREFIX.match(text) is None)
)

# Option-ish tokens: `-x`/`--long` hits and near misses, plus explicit
# trailing newlines to probe the oracle's bare-word `$` anchor.
_OPTION_TOKENS = _BYTE_TEXT | st.tuples(
    st.sampled_from(["", "-", "--", "---", "!"]),
    st.text(
        alphabet=st.characters(min_codepoint=2, max_codepoint=0xFF),
        max_size=6,
    ),
    st.sampled_from(["", "\n", "\n\n", " "]),
).map("".join)

# Save-dump lines: `*table` / `:CHAIN POLICY [counters]` shapes plus
# arbitrary noise; read_previous must classify each like the oracle.
# \x1c probes the byte-vs-Unicode \s divergence in the policy field.
_SAVE_LINE = _LINES | st.tuples(
    st.sampled_from(["*", ":", "", " *", "-A "]),
    st.text(alphabet="ab_F0", max_size=4),
    st.sampled_from(["", " ", "\t", "\x1c"]),
    st.sampled_from(["", "-", "ACCEPT", "- [0:0]", "DROP [1:2]"]),
).map("".join)
_SAVE_DUMPS = st.tuples(st.lists(_SAVE_LINE, max_size=6), st.booleans()).map(
    lambda parts: "\n".join(parts[0]) + ("\n" if parts[1] else "")
)


def _read_like_perl(text: str) -> list[str]:
    """Split into lines the way Perl's ``<$fh>`` does (on ``\\n`` only)."""
    return re.findall(r"[^\n]*\n|[^\n]+", text)


def _domain_layout(domain_info: DomainInfo) -> list[str]:
    """Flatten tables/chains into the driver's canonical token list."""
    layout: list[str] = []
    for table in sorted(domain_info.tables):
        table_info = domain_info.tables[table]
        layout.append(f"*{table}")
        if table_info.has_builtin:
            layout.append("+")
        layout.extend(
            sorted(
                chain
                for chain, chain_info in table_info.chains.items()
                if chain_info.builtin
            )
        )
    return layout


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


@pytest.fixture(scope="module")
def oracle_substr() -> Iterator[OracleProcess]:
    proc = OracleProcess("substr3")
    yield proc
    proc.close()


@pytest.fixture(scope="module")
def oracle_option_token() -> Iterator[OracleProcess]:
    proc = OracleProcess("option_token", source=IMPORT_SOURCE)
    yield proc
    proc.close()


@pytest.fixture(scope="module")
def oracle_read_previous() -> Iterator[OracleProcess]:
    proc = OracleProcess("read_previous")
    yield proc
    proc.close()


@given(string=_BYTE_TEXT, offset=_NUMBERISH, length=_NUMBERISH)
def test_substr_matches_oracle(
    string: str, offset: str, length: str, oracle_substr: OracleProcess
) -> None:
    from pyferm.functions import _perl_int, _perl_substr

    assert _perl_substr(
        string, _perl_int(offset), _perl_int(length)
    ) == oracle_substr.query_fields(string, offset, length)


@given(token=_OPTION_TOKENS)
def test_option_token_matches_oracle(
    token: str, oracle_option_token: OracleProcess
) -> None:
    from pyferm.import_ferm import _match_option

    option = _match_option(token)
    expected = oracle_option_token.tokenize(token)
    assert ([] if option is None else [option]) == expected


@given(dump=_SAVE_DUMPS)
def test_read_previous_matches_oracle(
    dump: str, oracle_read_previous: OracleProcess
) -> None:
    from pyferm.domains import DomainInfo, read_previous

    domain_info = DomainInfo()
    save = read_previous(_read_like_perl(dump), domain_info)
    # the dump must be reproduced byte-for-byte (rollback relies on it)
    assert save == dump
    assert _domain_layout(domain_info) == oracle_read_previous.tokenize(dump)
