"""Grammar-based config fuzzing: whole configs, the port vs the oracle.

Hypothesis assembles whole ferm configurations from a small grammar of
the constructs the corpus suite saw in the wild -- domains, tables,
chains, nested match blocks, variables, arrays, a function, ``@if`` --
and optionally applies one random text mutation (delete, insert,
duplicate) so the parser's error paths get exercised too.  Both
implementations compile every config with ``--test --noexec --lines``
in fast and slow mode and must agree bug-for-bug, under the corpus
contract (:mod:`tests.corpus.test_corpus`): same exit verdict, stderr
byte-for-byte, stdout equal after canonicalization.  One stderr
allowance on top of that contract: a bare Perl ``die`` (an upstream
internal crash, e.g. ``proto !tcp dport 0``) prints ``Died at <oracle
path> line N.``, which the port deliberately renders as ``internal
error: ...`` (see :func:`pyferm.errors.internal_error`) -- the two
lines are normalized to a common marker before comparing.

Generated text is side-effect-free by construction: no backticks (ferm
executes them even under ``--noexec``), no ``@include``, ``@hook`` or
``@resolve``; the mutation alphabet cannot introduce them either.
Deliberately *invalid* fragments are part of the grammar (the
``$nodef`` variable, the undefined ``orphan`` jump target, out-of-range
ports): a config that fails is as good a differential probe as one
that compiles, since the two implementations must emit the identical
diagnostic.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.corpus.canon import canonicalize

if TYPE_CHECKING:
    from collections.abc import Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
_ORACLE = ("perl", str(REPO_ROOT / "reference" / "src" / "ferm"))
_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

# Every example costs a full oracle process (~150ms), three orders of
# magnitude above the coprocess-based property tests, so the example
# count is scaled down from the active profile (100 -> 25 by default,
# 2500 -> 250 under ``--hypothesis-profile=thorough``).
_EXAMPLES = max(25, settings().max_examples // 10)


# --- the grammar ------------------------------------------------------

_IFACE = st.sampled_from(["lo", "eth0", "eth1", "ppp0", "eth+"])
_PROTO = st.sampled_from(["tcp", "udp", "icmp", "ipv6-icmp", "esp", "47"])
_OCTET = st.integers(min_value=0, max_value=255)
_V4_HOST = st.tuples(_OCTET, _OCTET, _OCTET, _OCTET).map(
    lambda octets: ".".join(map(str, octets))
)
_V4 = _V4_HOST | st.tuples(_V4_HOST, st.integers(0, 32)).map(
    lambda pair: f"{pair[0]}/{pair[1]}"
)
_V6 = st.sampled_from(["::1", "2001:db8::1", "2001:db8::/32", "fe80::1/64"])
_ADDR = _V4 | _V6

# Out-of-range numbers are deliberate: ferm passes ports through
# unvalidated, so both sides must agree on emitting the nonsense.
_PORT = st.integers(min_value=0, max_value=99999).map(str) | st.sampled_from(
    ["ssh", "http", "domain"]
)
_PORT_RANGE = st.tuples(_PORT, _PORT).map(":".join)
_STATE = st.sampled_from(["NEW", "ESTABLISHED", "RELATED", "INVALID"])


def _array(item: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
    """A ferm value list: ``( a b c )``."""
    return st.lists(item, min_size=1, max_size=3).map(
        lambda items: "(" + " ".join(items) + ")"
    )


def _negated(value: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
    """The value, sometimes with ferm's ``!`` negation prefix."""
    return value | value.map("!".__add__)


# $nodef is never defined: it probes the "no such variable" diagnostic.
_ADDR_VALUE = _negated(
    _ADDR | st.sampled_from(["$addr", "$net", "$nodef"]) | _array(_ADDR)
)
_PORT_VALUE = _negated(
    _PORT | _PORT_RANGE | st.just("$ports") | _array(_PORT | _PORT_RANGE)
)

# "orphan" is never declared as a chain; ferm still emits the jump.
_TARGET = st.sampled_from(
    [
        "ACCEPT",
        "DROP",
        "RETURN",
        "NOP",
        "REJECT",
        "REJECT reject-with icmp-net-unreachable",
        'LOG log-prefix "fuzz: "',
        "jump extra",
        "goto extra",
        "jump orphan",
        "MASQUERADE",
        "DNAT to 198.51.100.7",
        "SNAT to 198.51.100.8",
        "REDIRECT to-ports 8080",
    ]
)

_MATCH = st.one_of(
    st.tuples(st.just("interface "), _IFACE | _array(_IFACE)).map("".join),
    st.tuples(st.just("outerface "), _IFACE).map("".join),
    st.tuples(st.just("proto "), _negated(_PROTO) | _array(_PROTO)).map(
        "".join
    ),
    st.tuples(st.sampled_from(["dport ", "sport "]), _PORT_VALUE).map(
        "".join
    ),
    st.tuples(st.sampled_from(["saddr ", "daddr "]), _ADDR_VALUE).map(
        "".join
    ),
    st.tuples(st.just("mod state state "), _STATE | _array(_STATE)).map(
        "".join
    ),
    st.tuples(st.just("mod limit limit "), st.sampled_from(
        ["3/second", "10/minute", "1/hour"]
    )).map("".join),
    st.just('mod comment comment "fuzzed rule"'),
)

_RULE = (
    st.tuples(st.lists(_MATCH, max_size=3), _TARGET).map(
        lambda pair: " ".join([*pair[0], pair[1]]) + ";"
    )
    | st.sampled_from(["&svc(22);", "&svc($ports);", "&svc((22 8080));"])
)

_CONDITION = st.sampled_from(["0", "1", "$one", "''", "($addr)", "$nodef"])

_STATEMENT = st.recursive(
    _RULE,
    lambda statement: st.one_of(
        st.tuples(_MATCH, st.lists(statement, min_size=1, max_size=3)).map(
            lambda pair: pair[0] + " { " + " ".join(pair[1]) + " }"
        ),
        st.tuples(_CONDITION, statement, statement).map(
            lambda triple: f"@if {triple[0]} {triple[1]} @else {triple[2]}"
        ),
    ),
    max_leaves=6,
)

_BUILTIN_CHAINS: dict[str, tuple[str, ...]] = {
    "filter": ("INPUT", "FORWARD", "OUTPUT"),
    "nat": ("PREROUTING", "POSTROUTING", "OUTPUT"),
    "mangle": ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"),
}


@st.composite
def _table_block(draw: st.DrawFn) -> str:
    """One ``table X { chain ... }`` block with 1-3 chains."""
    table = draw(st.sampled_from(sorted(_BUILTIN_CHAINS)))
    builtin = _BUILTIN_CHAINS[table]
    chains = draw(
        st.lists(
            st.sampled_from([*builtin, "extra", "extra2"]),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    blocks: list[str] = []
    for chain in chains:
        body: list[str] = []
        if chain in builtin and draw(st.booleans()):
            policy = draw(st.sampled_from(["ACCEPT", "DROP"]))
            body.append(f"policy {policy};")
        body.extend(draw(st.lists(_STATEMENT, max_size=4)))
        spec = chain
        if draw(st.booleans()) and len(chains) > 1:
            spec = "(" + " ".join(chains) + ")"
            blocks.append(f"chain {spec} {{ " + " ".join(body) + " }")
            break
        blocks.append(f"chain {spec} {{ " + " ".join(body) + " }")
    return f"table {table} {{ " + " ".join(blocks) + " }"


@st.composite
def _domain_block(draw: st.DrawFn) -> str:
    """A table block, possibly wrapped in a ``domain`` scope."""
    block = draw(_table_block())
    wrapper = draw(
        st.sampled_from(["", "domain ip ", "domain ip6 ", "domain (ip ip6) "])
    )
    if not wrapper:
        return block
    return f"{wrapper}{{ {block} }}"


@st.composite
def _config(draw: st.DrawFn) -> str:
    """A whole configuration: variable/function preamble plus blocks."""
    lines = [
        f"@def $addr = {draw(_ADDR)};",
        f"@def $net = {draw(_ADDR | _array(_ADDR))};",
        f"@def $ports = {draw(_PORT | _array(_PORT | _PORT_RANGE))};",
        f"@def $one = {draw(st.sampled_from(['0', '1', chr(39) * 2]))};",
        "@def &svc($p) = { proto tcp dport $p ACCEPT; }",
    ]
    lines.extend(draw(st.lists(_domain_block(), min_size=1, max_size=2)))
    return "\n".join(lines) + "\n"


# One random text edit on an otherwise grammatical config drives both
# parsers into their error handling; the alphabet stays clear of
# backticks so a mutation can never make the input executable.
_INSERT_ALPHABET = sorted('!&$@(){};,=" #0a')


@st.composite
def _fuzzed_config(draw: st.DrawFn) -> str:
    """A grammatical config, mutated once in half of the examples."""
    text = draw(_config())
    operation = draw(
        st.sampled_from(
            ["keep", "keep", "keep", "delete", "insert", "duplicate"]
        )
    )
    if operation == "keep":
        return text
    position = draw(st.integers(min_value=0, max_value=len(text) - 1))
    if operation == "delete":
        return text[:position] + text[position + 1 :]
    if operation == "insert":
        glyph = draw(st.sampled_from(_INSERT_ALPHABET))
        return text[:position] + glyph + text[position:]
    return text[:position] + text[position] + text[position:]


# --- the differential harness -----------------------------------------

# A bare Perl ``die`` and its sanctioned port rendering (module
# docstring): both reduce to the same marker, the surrounding stderr
# still has to match byte-for-byte.
_PERL_BARE_DIE = re.compile(r"^Died at \S+ line \d+\.$", re.MULTILINE)
_PORT_INTERNAL = re.compile(r"^internal error: .+$", re.MULTILINE)


def _normalize_stderr(text: str) -> str:
    """Reduce both internal-crash renderings to a common marker."""
    text = _PERL_BARE_DIE.sub("<internal crash>", text)
    return _PORT_INTERNAL.sub("<internal crash>", text)


@pytest.fixture(scope="module")
def fuzz_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One temp directory per module; each example overwrites its file."""
    return tmp_path_factory.mktemp("configfuzz")


def _compile_oracle(args: Sequence[str]) -> tuple[bool, str, str]:
    proc = subprocess.run(  # fixed argv, no shell
        [*_ORACLE, *args],
        capture_output=True,
        text=True,
        check=False,
        env=_ENV,
        cwd=REPO_ROOT,
    )
    return proc.returncode == 0, proc.stdout, proc.stderr


def _compile_port(args: Sequence[str]) -> tuple[bool, str, str]:
    # In-process: a subprocess interpreter per example would double the
    # harness cost for no isolation gain (the cli injects all I/O).
    from pyferm.cli import main

    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        try:
            code: int = main(list(args))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code == 0, stdout.getvalue(), stderr.getvalue()


@pytest.mark.timeout(600)
@pytest.mark.parametrize("mode_args", [(), ("--slow",)], ids=["fast", "slow"])
@settings(max_examples=_EXAMPLES, deadline=None)
@given(config=_fuzzed_config())
def test_random_config_matches_oracle(
    config: str, mode_args: tuple[str, ...], fuzz_dir: Path
) -> None:
    path = fuzz_dir / f"input-{'-'.join(mode_args) or 'fast'}.ferm"
    path.write_text(config)
    args = ["--test", "--noexec", "--lines", *mode_args, str(path)]

    oracle = _compile_oracle(args)
    port = _compile_port(args)

    context = f"config:\n{config}"
    assert port[0] == oracle[0], (
        f"exit verdict differs\n{context}\n"
        f"port stderr:\n{port[2]}\noracle stderr:\n{oracle[2]}"
    )
    assert _normalize_stderr(port[2]) == _normalize_stderr(oracle[2]), (
        f"stderr differs\n{context}"
    )
    assert canonicalize(port[1]) == canonicalize(oracle[1]), (
        f"output differs\n{context}"
    )
