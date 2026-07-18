"""
Mutation-killing unit tests for the parser function/def/subchain cluster.

Each test pins one behaviour of ``_call_function``, ``_call_param_function``,
``_parse_def``, ``_parse_set``, ``_parse_preserve`` or ``_parse_subchain`` that
a surviving mutant would flip: the argument-negation flags, the ``$param``
splice guard, the non-param interpolation fallback, the caller-line sentinel,
the cgroup dispatch key, the set/def negation gates, and the ``@preserve`` and
sub-chain guards.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from pyferm.config import Options
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.values import Negated
from tests.unit._parse import parse_source

if TYPE_CHECKING:
    from pyferm.parser import Parser
    from pyferm.rules import RenderedRule


def _parse(source: str, *, options: Options | None = None) -> Parser:
    """Parse *source* through ``Parser.enter`` and return the parser."""
    return parse_source(source, options=options)


def _rule(
    parser: Parser, chain: str, *, table: str = "filter"
) -> RenderedRule:
    """Return the first unfolded rule of one filter chain."""
    return parser.domains[Family.IP].tables[table].chains[chain].rules[0]


def _values(rule: RenderedRule) -> dict[str, object]:
    """Map a rule's option names to their selected values."""
    return {opt.name: opt.value for opt in rule.options}


def test_call_function_restores_caller_line_after_body(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    The trailing line sentinel restores the caller's line after the splice.

    A body error keeps the def line (its own sentinel), but an error in the
    caller's tokens *after* ``&f()`` must report the call site's line -- which
    only the appended ``line_token`` restores.  Dropping it (``None``) or
    building it with a ``None`` line reports the wrong line.
    """
    with pytest.raises(FermError):
        _parse("@def &f() = ACCEPT;\n\n\n\nchain INPUT &f() florble;\n")
    assert "Error in <test> line 5:" in capsys.readouterr().err


def test_call_function_keeps_bareword_matching_param_literal() -> None:
    """
    A bare param-name token after a non-``$`` token stays literal.

    The splice guard requires ``token == "$"``; flipping either ``and`` to
    ``or`` would splice the argument wherever a bareword merely equals a
    parameter name, dropping the preceding keyword.
    """
    parser = _parse(
        "@def &f($p) = mod comment comment p ACCEPT;chain INPUT &f(hi);"
    )
    assert _values(_rule(parser, "INPUT"))["comment"] == "p"


def test_call_function_keeps_non_param_dollar_in_quoted_body() -> None:
    """
    A ``$var`` that is not a parameter survives the quoted-body interpolation.

    The non-parameter fallback re-emits ``f"${match.group(1)}"``; using
    ``group(None)`` or ``group(2)`` raises instead of preserving the name for
    the later scope interpolation.
    """
    parser = _parse(
        "@def $other = zzz;"
        '@def &f($x) = mod comment comment "$x-$other" ACCEPT;'
        "chain INPUT &f(hi);"
    )
    assert _values(_rule(parser, "INPUT"))["comment"] == "hi-zzz"


def test_call_function_accepts_negated_argument() -> None:
    """
    A ``!`` argument is accepted; the call reads params with negation on.

    ``get_function_params`` is threaded ``allow_negation=True``; a falsy flag
    rejects ``&f(! 22)`` up front with "negation is not allowed here" instead
    of binding the argument (used here through a quoted-body interpolation,
    the one context that stringifies a param without splicing it).
    """
    parser = _parse(
        '@def &f($x) = mod comment comment "n$x" ACCEPT;chain INPUT &f(! 22);'
    )
    assert "22" in str(_values(_rule(parser, "INPUT"))["comment"])


def test_cgroup_classid_param_function_dispatches() -> None:
    """
    The ``cgroup`` keyword resolves its ``&cgroup_classid`` argument parser.

    The dispatch table keys the evaluator method by the exact name
    ``"cgroup_classid"``; corrupting that literal makes ``dispatch.get`` miss
    and raise an internal error.
    """
    parser = _parse("chain INPUT mod cgroup cgroup 1048577 ACCEPT;")
    assert _values(_rule(parser, "INPUT"))["cgroup"] == "1048577"


def test_def_value_accepts_negation() -> None:
    """
    A ``@def`` variable value may be negated (``allow_negation=True``).

    A falsy flag rejects ``@def $x = ! ...`` before the binding is created.
    """
    parser = _parse("@def $x = ! 22;chain INPUT proto tcp dport $x DROP;")
    assert _values(_rule(parser, "INPUT"))["dport"] == Negated("22")


def test_set_value_rejects_negation() -> None:
    """
    A ``@set`` element value rejects negation (``allow_negation=False``).

    Flipping the flag to ``True`` would accept ``! 1.2.3.4`` silently.
    """
    with pytest.raises(FermError, match="negation is not allowed here"):
        _parse("@set $s = ! 1.2.3.4;")


def test_preserve_unsupported_domain_without_test_mode() -> None:
    """
    Outside ``--test`` a domain with no captured previous ruleset is rejected.

    The gate reads ``not self.options.test and domain_info.previous is None``;
    nulling ``domain_info``, flipping the ``is None`` test, or nulling the
    message all diverge from the located "not supported on domain" error.
    """
    options = Options(test=False, fast=True)
    with pytest.raises(FermError, match="not supported on domain"):
        _parse("chain INPUT @preserve;", options=options)


def test_preserve_nonempty_chain_is_rejected() -> None:
    """
    ``@preserve`` on a chain that already holds rules is rejected by name.

    The guard message ``"Cannot @preserve chain ... not empty"`` is emitted
    with the offending chain name.
    """
    options = Options(test=True, fast=True)
    with pytest.raises(FermError, match="Cannot @preserve chain INPUT"):
        _parse("chain INPUT { ACCEPT; @preserve; }", options=options)


def test_preserve_regex_records_a_compiled_pattern() -> None:
    """
    A ``/regex/`` preserve name is stored as a compiled pattern.

    ``preserve_regexes`` must hold the compiled object (not ``None``); the
    stored entry has to actually match the intended chain names.
    """
    options = Options(test=True, fast=True)
    parser = _parse('chain "/^ferm_/" @preserve;', options=options)
    table = parser.domains[Family.IP].tables["filter"]
    assert len(table.preserve_regexes) == 1
    pattern = table.preserve_regexes[0]
    assert isinstance(pattern, re.Pattern)
    assert pattern.match("ferm_auto_1") is not None


def test_second_subchain_without_rule_is_rejected() -> None:
    """
    The rule returned after a sub-chain has ``has_rule`` cleared to ``False``.

    Setting it ``True`` would let a following bare ``@subchain`` (with no
    preceding rule) slip past the "No rule specified" guard.
    """
    with pytest.raises(FermError, match="No rule specified before"):
        _parse(
            'chain INPUT { proto tcp @subchain "a" { ACCEPT; } '
            '@subchain "b" { ACCEPT; } }'
        )


def test_nested_subchain_without_rule_in_body_is_rejected() -> None:
    """
    A sub-chain body starts with ``has_rule`` cleared to ``False``.

    Seeding the inner rule ``has_rule=True`` would let a nested ``@subchain``
    as the body's first statement bypass the "No rule specified" guard.
    """
    with pytest.raises(FermError, match="No rule specified before"):
        _parse('chain INPUT proto tcp @subchain { @subchain "x" { ACCEPT; } }')


def test_subchain_parent_rule_records_its_script_position() -> None:
    """
    The parent rule's script position is stamped before it is rendered.

    ``_parse_subchain`` sets ``rule.script`` from the current script position
    just before ``mkrules``; nulling it strips the position that
    ``RenderedRule`` carries for the emitted jump.
    """
    parser = _parse('chain INPUT proto tcp @subchain "a" { ACCEPT; }')
    assert _rule(parser, "INPUT").script is not None


def test_quoted_subchain_name_is_not_interpolated() -> None:
    """
    A quoted sub-chain name is taken verbatim, not re-read through ``getvar``.

    The quoted branch keeps ``$part`` literal; bypassing it (``quoted = None``)
    would interpolate the variable and name the chain after its value instead.
    """
    parser = _parse(
        '@def $part = xyz;chain INPUT proto tcp @subchain "$part" { ACCEPT; }'
    )
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert "$part" in chains
    assert "xyz" not in chains
