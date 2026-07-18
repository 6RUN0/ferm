"""
Unit tests for :mod:`pyferm.functions`.

Exercises the value-evaluation layer: the stack lookups, the recursive
``getvalues`` reader (scalars, arrays, quotes, ``$`` variables, negation),
the ``@`` built-ins, ``collect_tokens``, the protocol helpers and the
keyword-parameter parsers (``ipfilter``/``address_magic``/``cgroup_classid``/
``multiport_params``).
"""

from __future__ import annotations

import io
import re

import pytest

from pyferm.errors import FermError
from pyferm.functions import (
    MAX_CLASSID,
    MAX_VALUE_DEPTH,
    Evaluator,
    _perl_substr,
    _perl_substr_index,
    _split_backtick_output,
    ipfilter,
    realize_protocol,
    realize_protocol_keyword,
)
from pyferm.resolver import (
    ResolverProvider,
    ZonefileResolver,
    set_resolver_provider,
)
from pyferm.scope import Frame, FunctionLike, Rule, Scope
from pyferm.tokenizer import Script, Token, Tokenizer
from pyferm.values import Deferred, Negated, SetRef, Value, realize_deferred


class _FunctionStub:
    """
    A minimal :class:`FunctionLike` double.

    Stands in for a parser ``Function`` in tests that only exercise
    identity/presence (:meth:`Evaluator.lookup_function`, ``@defined(&f)``)
    and never read ``params``/``tokens``/``block``.
    """

    def __init__(self) -> None:
        self.params: list[str] = []
        self.tokens: list[Token] = []
        self.block = False


def _evaluator(
    text: str,
    *,
    variables: dict[str, Value] | None = None,
    functions: dict[str, FunctionLike] | None = None,
    auto: dict[str, Value] | None = None,
    resolver_provider: ResolverProvider | None = None,
) -> Evaluator:
    tokenizer = Tokenizer(Script(filename="t.ferm", handle=io.StringIO(text)))
    scope = Scope()
    scope.push(
        Frame(
            vars=dict(variables or {}),
            functions=dict(functions or {}),
            auto=dict(auto or {}),
        )
    )
    return Evaluator(tokenizer, scope, resolver_provider=resolver_provider)


# -- _run_shell --------------------------------------------------------------


def test_run_shell_returns_backtick_bytes_as_latin1() -> None:
    # backtick output flows into the tokenizer: byte 0xff must survive
    assert _evaluator("")._run_shell(r"printf '\377'") == "\xff"


# -- ipfilter ----------------------------------------------------------------


# ipfilter is a deliberately crude family split: under "ip" it drops a
# ":hex:" run, under "ip6" anything purely numeric IPv4/CIDR; other families
# and non-IP tokens (hostnames, deferred) pass through untouched.
_IPFILTER_CASES = [
    pytest.param(
        "ip", ["1.2.3.4", "2001:db8::1", "::1"], ["1.2.3.4"], id="ip-drops-v6"
    ),
    pytest.param(
        "ip6",
        ["1.2.3.4", "10.0.0.0/8", "2001:db8::1"],
        ["2001:db8::1"],
        id="ip6-drops-v4-and-cidr",
    ),
    pytest.param("eb", ["anything"], ["anything"], id="other-family-passes"),
    # empty input is family-agnostic
    pytest.param("ip", [], [], id="ip-empty"),
    pytest.param("ip6", [], [], id="ip6-empty"),
    # an IPv4-mapped IPv6 address counts as IPv6: dropped from ip, kept by ip6
    pytest.param("ip", ["::ffff:1.2.3.4"], [], id="ip-drops-v4-mapped"),
    pytest.param(
        "ip6", ["::ffff:1.2.3.4"], ["::ffff:1.2.3.4"], id="ip6-keeps-v4-mapped"
    ),
    # an IPv6 CIDR is dropped from the ip pass, kept by ip6
    pytest.param("ip", ["2001:db8::/32"], [], id="ip-drops-v6-cidr"),
    pytest.param(
        "ip6", ["2001:db8::/32"], ["2001:db8::/32"], id="ip6-keeps-v6-cidr"
    ),
    # a hostname is neither shape, so it survives both families (resolved late)
    pytest.param("ip", ["example.com"], ["example.com"], id="ip-keeps-host"),
    pytest.param("ip6", ["example.com"], ["example.com"], id="ip6-keeps-host"),
]


@pytest.mark.parametrize(("domain", "addrs", "expected"), _IPFILTER_CASES)
def test_ipfilter_drops_wrong_family(
    domain: str, addrs: Value, expected: list[Value]
) -> None:
    assert ipfilter(domain, addrs) == expected


# -- protocol helpers --------------------------------------------------------


def test_realize_protocol_promotes_auto_protocol() -> None:
    rule = Rule(auto_protocol="tcp")
    assert realize_protocol(rule) == "tcp"
    assert rule.protocol == "tcp"
    assert rule.auto_protocol is None
    assert [(o.name, o.value) for o in rule.options] == [("protocol", "tcp")]


def test_realize_protocol_keeps_explicit_protocol() -> None:
    rule = Rule(protocol="udp", auto_protocol="tcp")
    assert realize_protocol(rule) == "udp"
    assert rule.auto_protocol == "tcp"  # untouched
    assert rule.options == []


def test_realize_protocol_keyword_promotes_on_match() -> None:
    rule = Rule(auto_protocol="tcp", domain_family="ip")
    realize_protocol_keyword(rule, "syn")  # syn belongs to tcp
    assert rule.protocol == "tcp"
    assert rule.auto_protocol is None
    # the promotion also emits the protocol option (mirrors realize_protocol)
    assert [(o.name, o.value) for o in rule.options] == [("protocol", "tcp")]


def test_realize_protocol_keyword_noop_without_match() -> None:
    rule = Rule(auto_protocol="tcp", domain_family="ip")
    realize_protocol_keyword(rule, "not-a-tcp-keyword")
    assert rule.protocol is None
    assert rule.auto_protocol == "tcp"


# -- variable / function lookups --------------------------------------------


def test_variable_value_line_and_lookup_and_auto() -> None:
    ev = _evaluator("a\n", variables={"x": "1"}, auto={"DOMAIN": "ip"})
    ev.tokenizer.next_token()  # advance to line 1
    assert ev.variable_value("LINE") == "1"
    assert ev.variable_value("x") == "1"
    assert ev.variable_value("DOMAIN") == "ip"
    assert ev.variable_value("missing") is None


def test_string_variable_value_rejects_array() -> None:
    ev = _evaluator("", variables={"arr": ["a", "b"]})
    with pytest.raises(FermError, match="must be a string"):
        ev.string_variable_value("arr")


def test_lookup_function() -> None:
    marker = _FunctionStub()
    ev = _evaluator("", functions={"f": marker})
    assert ev.lookup_function("f") is marker
    assert ev.lookup_function("g") is None


# -- getvalues: scalars, arrays, quotes -------------------------------------


def test_getvalues_scalar() -> None:
    assert _evaluator("word").getvalues() == "word"


def test_getvalues_array_and_single_collapse() -> None:
    assert _evaluator("(a b c)").getvalues() == ["a", "b", "c"]
    assert _evaluator("(solo)").getvalues() == "solo"


def test_getvalues_empty_array_allowed_unless_non_empty() -> None:
    assert _evaluator("()").getvalues() == []
    with pytest.raises(FermError, match="empty array not allowed"):
        _evaluator("()").getvalues(non_empty=True)


def test_getvalues_comma_in_array_errors() -> None:
    with pytest.raises(FermError, match="Comma is not allowed within arrays"):
        _evaluator("(a, b)").getvalues()


def test_getvalues_single_quote_is_literal() -> None:
    assert _evaluator("'a b'").getvalues() == "a b"


def test_getvalues_double_quote_interpolates() -> None:
    ev = _evaluator('"x=$v end"', variables={"v": "1"})
    assert ev.getvalues() == "x=1 end"


def test_getvalues_double_quote_keeps_zero_and_blanks_undefined() -> None:
    ev = _evaluator('"$z/$missing"', variables={"z": "0"})
    assert ev.getvalues() == "0/"


def test_getvalues_dollar_variable() -> None:
    ev = _evaluator("$ v", variables={"v": "hi"})
    assert ev.getvalues() == "hi"


def test_getvalues_dollar_missing_errors() -> None:
    with pytest.raises(FermError, match="no such variable"):
        _evaluator("$ nope").getvalues()


def test_getvalues_negation_requires_flag() -> None:
    with pytest.raises(FermError, match="negation is not allowed"):
        _evaluator("! x").getvalues()
    value = _evaluator("! x").getvalues(allow_negation=True)
    assert value == Negated("x")


def test_getvalues_bare_comma_and_equals_and_paren() -> None:
    with pytest.raises(FermError, match="comma is not allowed"):
        _evaluator(",").getvalues()
    assert _evaluator(",").getvalues(comma_allowed=True) == ","
    with pytest.raises(FermError, match="equals operator"):
        _evaluator("=").getvalues()
    with pytest.raises(FermError, match="Syntax error"):
        _evaluator(")").getvalues()


# -- getvalues: @ built-ins --------------------------------------------------


def test_builtin_eq_ne_not() -> None:
    assert _evaluator("@eq(a, a)").getvalues() == "1"
    assert _evaluator("@eq(a, b)").getvalues() == "0"
    assert _evaluator("@ne(a, b)").getvalues() == "1"
    assert _evaluator("@not(0)").getvalues() == "1"
    assert _evaluator("@not(x)").getvalues() == "0"


def test_builtin_eq_compares_arrays_by_identity() -> None:
    # Perl ``eq`` stringifies array refs to their addresses, so two distinct
    # arrays are never equal regardless of contents (ferm relies on this:
    # ``@eq($a, $b)`` on equal-content arrays is false in the oracle).
    variables: dict[str, Value] = {"a": ["1", "2"], "b": ["1", "2"]}
    assert _evaluator("@eq($a, $b)", variables=variables).getvalues() == "0"
    assert _evaluator("@ne($a, $b)", variables=variables).getvalues() == "1"
    # the same array reached twice is the same ref -> equal
    assert _evaluator("@eq($a, $a)", variables=variables).getvalues() == "1"
    assert _evaluator("@ne($a, $a)", variables=variables).getvalues() == "0"
    # a ref never equals a scalar
    assert _evaluator("@eq($a, x)", variables=variables).getvalues() == "0"


def test_builtin_cat_and_join() -> None:
    assert _evaluator("@cat(a, b, c)").getvalues() == "abc"
    assert _evaluator("@join(-, a, b)").getvalues() == "a-b"
    assert _evaluator("@join(-, (a b c))").getvalues() == "a-b-c"


def test_builtin_substr_and_length() -> None:
    assert _evaluator("@substr(hello, 1, 3)").getvalues() == "ell"
    assert _evaluator("@substr(hello, -2, 2)").getvalues() == "lo"
    assert _evaluator("@length(hello)").getvalues() == "5"


def test_builtin_substr_coerces_non_numeric_like_perl() -> None:
    # Perl numifies the offset/length silently: 'a' -> 0, '1.5' -> 1
    # (truncated toward zero); ferm runs without 'use warnings', so the
    # oracle does not even warn (verified against reference/src/ferm).
    assert _evaluator("@substr(hello, a, 2)").getvalues() == "he"
    assert _evaluator("@substr(hello, 1.5, 2.9)").getvalues() == "el"


# A substr offset/length the way Perl's SvIsUV-aware ``pp_substr`` reads it.
# Grouped by the branch each case pins; the integer UV cases are the
# regression guard for the fuzzer-found bug where general IV numification
# wrapped a [2**63, 2**64) magnitude negative (see _perl_substr_index).
_SUBSTR_INDEX_CASES = [
    # No leading numeric prefix -> 0 (match is None).
    ("non_numeric", "abc", 0),
    ("empty", "", 0),
    ("whitespace_only", "  ", 0),
    ("sign_without_digits", "+", 0),
    ("letter_before_digits", "x12", 0),
    # Integer prefix: read up to the first non-numeric character.
    ("zero", "0", 0),
    ("small_positive", "5", 5),
    ("trailing_garbage", "12abc", 12),
    ("leading_whitespace", "  7", 7),
    ("explicit_plus", "+9", 9),
    ("leading_whitespace_negative", "  -5", -5),
    ("small_negative", "-3", -3),
    # UV-aware integer boundary: a magnitude in [2**63, 2**64) stays a
    # large *positive* value rather than wrapping to a negative IV.
    ("uv_at_2_63", str(2**63), 2**63),
    ("uv_max", str(2**64 - 1), 2**64 - 1),
    # One past UV_MAX (Perl stores it as an NV) saturates to -1.
    ("just_past_uv_max", str(2**64), -1),
    ("far_past_uv_max", str(2**64 + 100), -1),
    # Negative magnitude clamps to IV_MIN (-2**63).
    ("iv_min", str(-(2**63)), -(2**63)),
    ("just_below_iv_min", "-" + str(2**63 + 1), -(2**63)),
    ("far_below_iv_min", "-" + str(2**70), -(2**63)),
    # Float path (a '.' or an exponent): truncate toward zero, not floor.
    ("float_truncates_positive", "1.9", 1),
    ("float_truncates_negative", "-1.9", -1),
    ("float_half", "2.5", 2),
    ("float_leading_dot", ".5", 0),
    ("float_trailing_dot", "1.", 1),
    # Exponent forces the float path even with no '.' in the mantissa.
    ("exponent_positive", "1e3", 1000),
    ("exponent_negative_value", "-1e3", -1000),
    ("exponent_signed_plus", "1e+2", 100),
    ("exponent_signed_minus", "1e-2", 0),
    # Float saturation mirrors the integer path at the UV/IV boundaries.
    ("float_in_uv_window", "1e19", 10**19),
    ("float_at_uv_max_plus_one", "18446744073709551616.0", -1),  # == 2**64
    ("float_just_past_uv_max", "3e19", -1),  # in [2**64, 2**65)
    ("float_past_uv_max", "1e30", -1),
    ("float_below_iv_min", "-1e30", -(2**63)),
]


@pytest.mark.parametrize(
    ("text", "expected"),
    [(text, expected) for _, text, expected in _SUBSTR_INDEX_CASES],
    ids=[name for name, _, _ in _SUBSTR_INDEX_CASES],
)
def test_perl_substr_index_coercion(text: str, expected: int) -> None:
    """``_perl_substr_index`` reads an offset/length exactly like Perl."""
    assert _perl_substr_index(text) == expected


def test_builtin_basename_dirname() -> None:
    assert _evaluator("@basename(/a/b/c.conf)").getvalues() == "c.conf"
    assert _evaluator("@dirname(/a/b/c.conf)").getvalues() == "/a/b/"
    assert _evaluator("@dirname(bare)").getvalues() == ""
    # a root-anchored path: the only slash sits at index 0, so basename drops
    # the leading slash and dirname is exactly "/" (guards the `< 0` split
    # boundary against an off-by-one to `<= 0`).
    assert _evaluator("@basename(/foo)").getvalues() == "foo"
    assert _evaluator("@dirname(/foo)").getvalues() == "/"


def test_builtin_defined_variable_and_function() -> None:
    ev = _evaluator("@defined($ v)", variables={"v": "1"})
    assert ev.getvalues() == "1"
    assert _evaluator("@defined($ v)").getvalues() == ""
    ev2 = _evaluator("@defined(& f)", functions={"f": _FunctionStub()})
    assert ev2.getvalues() == "1"
    # An undefined function is the empty string, mirroring the $-variable arm.
    assert _evaluator("@defined(& missing)").getvalues() == ""


def test_builtin_unknown_errors() -> None:
    with pytest.raises(FermError, match="unknown ferm built-in"):
        _evaluator("@nope()").getvalues()


def test_builtin_resolve_and_ipfilter_are_deferred() -> None:
    value = _evaluator("@resolve(host, 'A')").getvalues()
    assert isinstance(value, Deferred)
    assert value.params == ["host", "A"]
    filt = _evaluator("@ipfilter((1.2.3.4 ::1))").getvalues()
    assert isinstance(filt, Deferred)
    assert filt.params == [["1.2.3.4", "::1"]]


def test_builtin_glob(tmp_path: object) -> None:
    import pathlib

    base = pathlib.Path(str(tmp_path))
    (base / "a.conf").write_text("", encoding="utf-8")
    (base / "b.conf").write_text("", encoding="utf-8")
    (base / "c.txt").write_text("", encoding="utf-8")
    tokenizer = Tokenizer(
        Script(
            filename=str(base / "rules.ferm"),
            handle=io.StringIO("@glob('*.conf')"),
        )
    )
    ev = Evaluator(tokenizer, Scope())
    ev.scope.push(Frame())
    assert ev.getvalues() == [str(base / "a.conf"), str(base / "b.conf")]


def test_builtin_glob_absolute_pattern_is_used_as_is(tmp_path: object) -> None:
    # An already-absolute glob pattern must not be prefixed with the
    # script's own directory -- doubling the prefix would glob a path that
    # does not exist and silently return no matches.
    import pathlib

    base = pathlib.Path(str(tmp_path))
    (base / "a.conf").write_text("", encoding="utf-8")
    tokenizer = Tokenizer(
        Script(
            filename=str(base / "rules.ferm"),
            handle=io.StringIO(f"@glob('{base}/*.conf')"),
        )
    )
    ev = Evaluator(tokenizer, Scope())
    ev.scope.push(Frame())
    assert ev.getvalues() == str(base / "a.conf")


def test_builtin_glob_single_match_collapses_to_scalar(
    tmp_path: object,
) -> None:
    # exactly one match: the len==1 branch returns result[0] (the sole path)
    # as a scalar, not a one-element list.
    import pathlib

    base = pathlib.Path(str(tmp_path))
    (base / "only.conf").write_text("", encoding="utf-8")
    (base / "other.txt").write_text("", encoding="utf-8")
    tokenizer = Tokenizer(
        Script(
            filename=str(base / "rules.ferm"),
            handle=io.StringIO("@glob('*.conf')"),
        )
    )
    ev = Evaluator(tokenizer, Scope())
    ev.scope.push(Frame())
    assert ev.getvalues() == str(base / "only.conf")


# -- getvar / get_function_params / collect_tokens --------------------------


def test_getvar_rejects_array() -> None:
    with pytest.raises(FermError, match="array not allowed"):
        _evaluator("(a b)").getvar()


def test_get_function_params_empty_and_list() -> None:
    assert _evaluator("()").get_function_params() == []
    assert _evaluator("(a, b, c)").get_function_params() == ["a", "b", "c"]


def test_collect_tokens_until_semicolon() -> None:
    ev = _evaluator("a b ; rest")
    tokens = ev.collect_tokens()
    assert [t for t in tokens if isinstance(t, str)] == ["a", "b"]


def test_collect_tokens_include_semicolon_and_braces() -> None:
    ev = _evaluator("a { b ; } ;")
    tokens = ev.collect_tokens(include_semicolon=True)
    assert [t for t in tokens if isinstance(t, str)] == [
        "a",
        "{",
        "b",
        ";",
        "}",
    ]


def test_collect_tokens_unmatched_brace_errors() -> None:
    with pytest.raises(FermError, match="unmatched"):
        _evaluator("a ) ;").collect_tokens()


def test_collect_tokens_mismatched_pair_errors() -> None:
    # a "}" closer whose open bracket was a "(" is a mismatch: the opener is
    # present but the wrong kind, so the `opener != expected` arm must fire
    # (an `and` fusion of the two conditions would let it slip through).
    with pytest.raises(FermError, match="unmatched"):
        _evaluator("a ( } ;").collect_tokens()


# -- backtick shell ----------------------------------------------------------


def test_backtick_runs_command() -> None:
    assert _evaluator("`echo foo bar`").getvalues() == ["foo", "bar"]


def test_backtick_nonzero_exit_errors() -> None:
    with pytest.raises(FermError, match="child exited with status"):
        _evaluator("`exit 3`").getvalues()


def test_backtick_child_stderr_passes_through(
    capfd: pytest.CaptureFixture[str],
) -> None:
    # Perl backticks capture only stdout; the child's stderr reaches the
    # terminal, so a failing script's diagnostics are not swallowed.
    assert _evaluator("`echo ok; echo diag >&2`").getvalues() == "ok"
    assert "diag" in capfd.readouterr().err


def test_backtick_exec_failure_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Perl maps $? == -1 to 'failed to execute: $!' (:1461); only an
    # unspawnable /bin/sh triggers it, so the OSError is injected.
    import subprocess

    def boom(*_args: object, **_kwargs: object) -> object:
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(FermError, match="failed to execute: No such file"):
        _evaluator("`true`").getvalues()


def test_backtick_signal_death_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Perl maps a signal-killed backtick child ($? & 0x7f) to 'child died
    # with signal N' (:1463); subprocess models the same child as a
    # negative returncode.
    import subprocess

    def killed(*_args: object, **_kwargs: object) -> object:
        return subprocess.CompletedProcess("true", -15, stdout="")

    monkeypatch.setattr(subprocess, "run", killed)
    with pytest.raises(FermError, match="child died with signal 15"):
        _evaluator("`true`").getvalues()


# -- address_magic -----------------------------------------------------------


def test_address_magic_plain_and_array() -> None:
    ev = _evaluator("1.2.3.4")
    assert ev.address_magic(Rule(domain="ip")) == ["1.2.3.4"]
    ev2 = _evaluator("(1.2.3.4 5.6.7.8)")
    assert ev2.address_magic(Rule(domain="ip")) == ["1.2.3.4", "5.6.7.8"]


def test_address_magic_negated() -> None:
    ev = _evaluator("! 1.2.3.4")
    result = ev.address_magic(Rule(domain="ip"))
    assert result == Negated(["1.2.3.4"])


def test_address_magic_dualstack_filters() -> None:
    ev = _evaluator("(1.2.3.4 ::1)")
    rule = Rule(domain="ip", domain_both=True)
    assert ev.address_magic(rule) == ["1.2.3.4"]


def test_address_magic_realizes_resolve() -> None:
    zone = ZonefileResolver.from_text("v4.example.com. IN A 192.0.2.1\n")
    set_resolver_provider(lambda: zone)
    try:
        ev = _evaluator("@resolve(v4.example.com)")
        assert ev.address_magic(Rule(domain="ip")) == ["192.0.2.1"]
    finally:
        set_resolver_provider(None)


def test_address_magic_resolves_via_injected_provider() -> None:
    # An evaluator-scoped provider serves @resolve without the process-wide
    # seam: the module global stays untouched, so nothing can leak into
    # later tests even when an assertion fires mid-test.  Snapshot rather
    # than expect None: under xdist an earlier in-process _apply_config run
    # may have left the worker-global provider installed, and this test only
    # claims it does not touch that global, not that it starts clean.
    import pyferm.resolver as resolver_mod

    global_provider = resolver_mod._provider
    zone = ZonefileResolver.from_text("v4.example.com. IN A 192.0.2.1\n")
    ev = _evaluator("@resolve(v4.example.com)", resolver_provider=lambda: zone)
    assert ev.address_magic(Rule(domain="ip")) == ["192.0.2.1"]
    assert resolver_mod._provider is global_provider


# -- cgroup_classid ----------------------------------------------------------


def test_cgroup_classid_hex_pair_and_decimal() -> None:
    assert _evaluator("a:b").cgroup_classid(Rule()) == [str((0xA << 16) + 0xB)]
    assert _evaluator("1234").cgroup_classid(Rule()) == ["1234"]


def test_cgroup_classid_negated_array() -> None:
    result = _evaluator("(1 2)").cgroup_classid(Rule())
    assert result == ["1", "2"]


def test_cgroup_classid_invalid_errors() -> None:
    with pytest.raises(FermError, match="hex:hex or decimal"):
        _evaluator("zzzz:gg").cgroup_classid(Rule())
    with pytest.raises(FermError, match="too large"):
        _evaluator("4294967296").cgroup_classid(Rule())


# -- multiport_params --------------------------------------------------------


def test_multiport_requires_tcp_or_udp() -> None:
    with pytest.raises(FermError, match="you have to specify"):
        _evaluator("80").multiport_params(Rule())


def test_multiport_scalar_joins() -> None:
    ev = _evaluator("80")
    assert ev.multiport_params(Rule(protocol="tcp")) == "80"


def test_multiport_chunks_to_fifteen() -> None:
    ports = " ".join(str(p) for p in range(1, 19))  # 18 single ports
    ev = _evaluator(f"({ports})")
    result = ev.multiport_params(Rule(protocol="tcp"))
    assert result == [
        "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        "16,17,18",
    ]


def test_multiport_range_counts_as_two() -> None:
    # Seven ranges = 14 units, an eighth range would be 16 > 15, so it
    # splits after the seventh.
    ranges = " ".join(f"{p}:{p}" for p in range(1, 9))  # 8 ranges
    ev = _evaluator(f"({ranges})")
    result = ev.multiport_params(Rule(protocol="tcp"))
    assert isinstance(result, list)
    assert result[0] == "1:1,2:2,3:3,4:4,5:5,6:6,7:7"
    assert result[1] == "8:8"


def test_multiport_exactly_fifteen_is_one_scalar_chunk() -> None:
    # 15 ports fill a chunk exactly (no overflow), and a single chunk is
    # returned as a scalar string -- not a one-element list.
    ports = " ".join(str(p) for p in range(1, 16))
    ev = _evaluator(f"({ports})")
    assert (
        ev.multiport_params(Rule(protocol="tcp"))
        == "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
    )


def test_multiport_sixteen_splits_after_fifteen() -> None:
    ports = " ".join(str(p) for p in range(1, 17))
    ev = _evaluator(f"({ports})")
    assert ev.multiport_params(Rule(protocol="tcp")) == [
        "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        "16",
    ]


def test_multiport_range_not_split_across_chunk_boundary() -> None:
    # 14 singles use 14 units, leaving room for 1; a range needs 2, so the
    # whole range moves to the next chunk rather than being split in half.
    items = [str(p) for p in range(1, 15)] + ["100:200"]
    ev = _evaluator("(" + " ".join(items) + ")")
    assert ev.multiport_params(Rule(protocol="tcp")) == [
        "1,2,3,4,5,6,7,8,9,10,11,12,13,14",
        "100:200",
    ]


# -- getvalues depth limit (a sanctioned deviation) ------------------------


def _nested_value(depth: int) -> str:
    """A value whose read needs ``depth`` getvalues frames: nested arrays."""
    return "(" * depth + "x" + ")" * depth


def test_getvalues_at_depth_limit_reads() -> None:
    # the innermost getvalues entry sits at pre-increment depth == paren
    # count, so MAX_VALUE_DEPTH - 1 parens reach the limit and still read
    ev = _evaluator(_nested_value(MAX_VALUE_DEPTH - 1))
    assert ev.getvalues() == "x"
    assert ev._value_depth == 0


def test_getvalues_over_depth_limit_is_ferm_error() -> None:
    ev = _evaluator(_nested_value(MAX_VALUE_DEPTH))
    # a located FermError, never a bare RecursionError traceback
    with pytest.raises(
        FermError, match=r"values nested too deeply \(max 100\)"
    ):
        ev.getvalues()


def test_getvalues_depth_counter_recovers_after_error() -> None:
    ev = _evaluator(_nested_value(MAX_VALUE_DEPTH))
    with pytest.raises(FermError):
        ev.getvalues()
    # the finally chain unwound every frame
    assert ev._value_depth == 0


# -- cgroup_classid: negation, boundaries, hex parsing (mutation-hardening) ---


def test_cgroup_classid_scalar_negation() -> None:
    # A negated scalar classid must round-trip through the Negated branch.
    assert _evaluator("! 5").cgroup_classid(Rule()) == Negated(["5"])


def test_cgroup_classid_zero_is_valid() -> None:
    # 0 is a legal classid: the lower bound is `< 0`, not `<= 0`.
    assert _evaluator("0").cgroup_classid(Rule()) == ["0"]


def test_cgroup_classid_max_value_is_valid() -> None:
    # The upper bound is inclusive: MAX_CLASSID itself is accepted, only
    # MAX_CLASSID + 1 is rejected.
    assert _evaluator(str(MAX_CLASSID)).cgroup_classid(Rule()) == [
        str(MAX_CLASSID)
    ]


def test_cgroup_classid_hex_pair_uses_base_16() -> None:
    # Both halves parse as base 16; digits that also read as base 17 ('10',
    # '20') pin the radix so a base-17 slip is caught.
    assert _evaluator("10:20").cgroup_classid(Rule()) == [
        str((0x10 << 16) + 0x20)
    ]


# -- @-builtins: deferred wiring, empty @join, @substr ref guard -------------


def test_join_without_arguments_is_empty() -> None:
    assert _evaluator("@join()").getvalues() == ""


def test_substr_rejects_reference_argument() -> None:
    # A non-scalar (array) argument to @substr is an error, not silently
    # stringified.
    with pytest.raises(FermError, match="String expected"):
        _evaluator("@substr((a b), 1, 2)").getvalues()


def test_ipfilter_deferred_realizes_with_family() -> None:
    # @ipfilter defers to `ipfilter`; realizing it must apply the family
    # filter (drops the IPv6 address in an ip realization).
    ev = _evaluator("@ipfilter((1.2.3.4 ::1))")
    assert realize_deferred("ip", ev.getvalues()) == ["1.2.3.4"]


def test_cat_deferred_realizes_via_deferred_cat() -> None:
    # A @cat carrying a deferred argument defers to `deferred_cat`; realizing
    # it concatenates the (family-filtered) operands.
    ev = _evaluator("@cat(@ipfilter((1.2.3.4)), x)")
    assert realize_deferred("ip", ev.getvalues()) == ["1.2.3.4x"]


# -- address_magic: SetRef branch (family filtering of a named set) ----------


def test_address_magic_setref_dualstack_filters_elements() -> None:
    # A SetRef value on a dual-stack rule keeps its name but drops
    # wrong-family elements.
    ev = _evaluator("$s", variables={"s": SetRef("myset", ["1.2.3.4", "::1"])})
    assert ev.address_magic(Rule(domain="ip", domain_both=True)) == SetRef(
        "myset", ["1.2.3.4"]
    )


def test_address_magic_setref_single_family_keeps_all() -> None:
    # A SetRef on a single-family rule is returned intact (no ipfilter pass).
    ev = _evaluator("$s", variables={"s": SetRef("myset", ["1.2.3.4", "::1"])})
    assert ev.address_magic(Rule(domain="ip")) == SetRef(
        "myset", ["1.2.3.4", "::1"]
    )


# -- @-builtin arity guards: the exact "Usage: ..." message ------------------


def _exact(message: str) -> str:
    """
    Return a ``pytest.raises`` pattern anchored to the whole error message.

    ``error`` raises ``FermError`` whose ``str`` is exactly the joined
    message (the located context goes to stderr, not the exception), so an
    anchored pattern rejects any wrapped/re-cased variant a mutant produces.
    """
    return r"\A" + re.escape(message) + r"\Z"


# Each @-builtin validates its argument count and reports a fixed "Usage:"
# string (``_params``/``_string_param``); a wrong-arity call must raise it
# verbatim.  Anchoring on the whole message pins the usage text so a mutant
# that blanks, re-cases, or drops it is caught.
_USAGE_ARITY_CASES = [
    pytest.param("@eq(a)", "Usage: @eq(a, b)", id="eq-too-few"),
    pytest.param("@eq(a, b, c)", "Usage: @eq(a, b)", id="eq-too-many"),
    pytest.param("@ne(a)", "Usage: @ne(a, b)", id="ne-too-few"),
    pytest.param("@not(a, b)", "Usage: @not(a)", id="not-too-many"),
    pytest.param(
        "@substr(a, b)",
        "Usage: @substr(string, num, num)",
        id="substr-too-few",
    ),
    pytest.param("@glob(a, b)", "Usage: @glob(string)", id="glob-too-many"),
    pytest.param(
        "@basename(a, b)", "Usage: @basename(path)", id="basename-too-many"
    ),
    pytest.param(
        "@dirname(a, b)", "Usage: @dirname(path)", id="dirname-too-many"
    ),
    pytest.param(
        "@length(a, b)", "Usage: @length(string)", id="length-too-many"
    ),
    pytest.param(
        "@resolve(a, b, c)",
        "Usage: @resolve((hostname ...), [type])",
        id="resolve-too-many",
    ),
    pytest.param(
        "@ipfilter(a, b)",
        "Usage: @ipfilter((ip1 ip2 ...))",
        id="ipfilter-too-many",
    ),
]


@pytest.mark.parametrize(("source", "message"), _USAGE_ARITY_CASES)
def test_builtin_wrong_arity_reports_usage(source: str, message: str) -> None:
    with pytest.raises(FermError, match=_exact(message)):
        _evaluator(source).getvalues()


def test_builtin_unknown_message_is_exact() -> None:
    # The dispatch miss reports a fixed string; anchor it so a mutant that
    # merely wraps the text (a substring match would still pass) is caught.
    with pytest.raises(
        FermError, match=_exact("unknown ferm built-in function")
    ):
        _evaluator("@nope()").getvalues()


def test_builtin_params_forbid_negation_by_default() -> None:
    # Built-ins read their arguments through ``get_function_params()`` with
    # ``allow_negation`` defaulting to False, so a leading "!" is rejected;
    # flipping that default would silently accept ``@not(! 0)``.
    with pytest.raises(FermError, match="negation is not allowed"):
        _evaluator("@not(! 0)").getvalues()


# -- @-builtin string-argument guard (@basename/@dirname/@length) ------------


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("@basename((a b))", id="basename"),
        pytest.param("@dirname((a b))", id="dirname"),
        pytest.param("@length((a b))", id="length"),
    ],
)
def test_string_param_rejects_array_argument(source: str) -> None:
    # A single-string built-in rejects an array (reference) argument instead
    # of stringifying it; the guard reports the shared "String expected".
    with pytest.raises(FermError, match=_exact("String expected")):
        _evaluator(source).getvalues()


# -- @defined argument guards ------------------------------------------------


# @defined has its own hand-rolled reader: the opening "(", the "$"/"&"
# sigil, and the name each have a fixed diagnostic.  Feed a malformed call
# for every arm and pin the message verbatim.
_DEFINED_GUARD_CASES = [
    pytest.param(
        "@defined $ v",
        'function name must be followed by "()"',
        id="missing-paren",
    ),
    pytest.param("@defined($ )", "variable name expected", id="var-name"),
    pytest.param("@defined(& )", "function name expected", id="func-name"),
    pytest.param("@defined(foo)", "'$' or '&' expected", id="sigil-expected"),
]


@pytest.mark.parametrize(("source", "message"), _DEFINED_GUARD_CASES)
def test_builtin_defined_argument_guards(source: str, message: str) -> None:
    with pytest.raises(FermError, match=_exact(message)):
        _evaluator(source).getvalues()


# -- get_function_params argument guards -------------------------------------


_FUNC_PARAMS_GUARD_CASES = [
    pytest.param(
        "@eq a", 'function name must be followed by "()"', id="missing-paren"
    ),
    pytest.param("@eq(a b)", '"," expected', id="comma-expected"),
]


@pytest.mark.parametrize(("source", "message"), _FUNC_PARAMS_GUARD_CASES)
def test_get_function_params_guards(source: str, message: str) -> None:
    with pytest.raises(FermError, match=_exact(message)):
        _evaluator(source).getvalues()


# -- _perl_substr boundary behaviour -----------------------------------------


# Signed offset/length edges around the clamp/undef boundaries of Perl's
# three-argument substr; each row pins one arithmetic/comparison boundary
# that a mutated ``< 0`` / ``> size`` / clamp would move.
_PERL_SUBSTR_BOUNDS_CASES = [
    # offset strictly past the end is undef -> "" (not "past-end" garbage).
    ("offset_past_end", "hello", 6, 2, ""),
    # a negative length measures back from the string end (size + length).
    ("negative_length", "hello", 1, -1, "ell"),
    # a zero length is an empty slice, never the whole tail.
    ("zero_length", "hello", 1, 0, ""),
    # both endpoints before the string collapse to undef -> "".
    ("both_endpoints_before", "hello", -7, -6, ""),
    # a start before the string clamps to 0 (not None, not 1).
    ("start_clamped_to_zero", "hello", -7, 4, "he"),
]


@pytest.mark.parametrize(
    ("string", "offset", "length", "expected"),
    [
        (s, o, length, exp)
        for _, s, o, length, exp in _PERL_SUBSTR_BOUNDS_CASES
    ],
    ids=[name for name, *_ in _PERL_SUBSTR_BOUNDS_CASES],
)
def test_perl_substr_boundaries(
    string: str, offset: int, length: int, expected: str
) -> None:
    assert _perl_substr(string, offset, length) == expected


# -- multiport / classid: guard messages verbatim ---------------------------


def test_multiport_rejects_non_tcp_udp_protocol() -> None:
    # An explicit but wrong protocol (not tcp/udp/udplite) must still be
    # rejected: the guard is not only "no protocol set".
    message = (
        'To use multiport, you have to specify "proto tcp" or '
        '"proto udp" first'
    )
    with pytest.raises(FermError, match=_exact(message)):
        _evaluator("80").multiport_params(Rule(protocol="icmp"))


def test_cgroup_classid_rejects_negative() -> None:
    # A decimal classid below zero is rejected (the value fits the regex but
    # fails the non-negative bound).
    with pytest.raises(
        FermError, match=_exact("classid must be non-negative")
    ):
        _evaluator("-5").cgroup_classid(Rule())


def test_cgroup_classid_guard_messages_are_exact() -> None:
    # Anchor the two remaining classid diagnostics so a wrapped/re-cased
    # variant (which a substring match would accept) is caught.
    with pytest.raises(
        FermError, match=_exact("classid must be hex:hex or decimal")
    ):
        _evaluator("zzzz:gg").cgroup_classid(Rule())
    with pytest.raises(FermError, match=_exact("classid is too large")):
        _evaluator("4294967296").cgroup_classid(Rule())


# -- multiport_params: a chunk reset must clear size back to zero -----------


def test_multiport_thirty_ports_splits_into_two_even_chunks() -> None:
    # 30 single ports split into exactly two 15-port chunks. Resetting the
    # running ``size`` counter to anything but 0 after a chunk boundary
    # would desync the count from the (empty) new chunk and misplace the
    # next split -- e.g. a stray "size = 1" yields 15/14/1 instead of 15/15.
    ports = " ".join(str(p) for p in range(1, 31))
    ev = _evaluator(f"({ports})")
    assert ev.multiport_params(Rule(protocol="tcp")) == [
        "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        "16,17,18,19,20,21,22,23,24,25,26,27,28,29,30",
    ]


# -- multiport_params: negation (scalar and array) ---------------------------


def test_multiport_negated_scalar() -> None:
    # multiport_params reads its value with allow_negation=True: a lone
    # negated port must round-trip as a Negated scalar, not error out.
    ev = _evaluator("! 80")
    assert ev.multiport_params(Rule(protocol="tcp")) == Negated("80")


def test_multiport_negated_array() -> None:
    # multiport_params also passes allow_array_negation=True through to
    # negate_value, so a negated port list is allowed and comma-joined
    # under the Negated tag rather than raising "not possible to negate".
    ev = _evaluator("! (80 443)")
    assert ev.multiport_params(Rule(protocol="tcp")) == Negated("80,443")


# -- _read_array: nested arrays flatten, they do not nest --------------------


def test_getvalues_nested_array_flattens_into_one_list() -> None:
    # A parenthesised array containing a nested array must flatten into a
    # single flat list (the nested array's elements extend the outer
    # wordlist); a mutant that appends the nested list as one element, or
    # extends with None, would either nest it or crash.
    ev = _evaluator("((1.2.3.4 5.6.7.8) 9.9.9.9)")
    assert ev.getvalues() == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]


# -- getvalues: array negation is forbidden unless explicitly allowed -------


def test_address_magic_forbids_negated_array_by_default() -> None:
    # address_magic calls getvalues(allow_negation=True) without opting into
    # allow_array_negation, so its True default must actually be False:
    # negating an address array is rejected here, unlike multiport.
    with pytest.raises(
        FermError, match="it is not possible to negate an array"
    ):
        _evaluator("! (1.2.3.4 5.6.7.8)").address_magic(Rule(domain="ip"))


# -- getvalues: a bare "&" is rejected as a keyword-parameter value ----------


def test_ampersand_token_errors_as_keyword_parameter() -> None:
    # A bare "&" (a function-call sigil with no call site) read as a value
    # must error, not fall through to @-builtin dispatch or be returned as
    # the literal string "&".
    with pytest.raises(
        FermError, match="function calls are not allowed as keyword parameter"
    ):
        _evaluator("&").getvalues()


# -- get_function_params: allow_negation must reach every getvalues call ----


def test_get_function_params_forwards_allow_negation() -> None:
    # The parser passes allow_negation=True when expanding a user &function
    # call so "! arg" is accepted; this must actually reach the per-param
    # getvalues() call, not be dropped in favour of the False default.
    ev = _evaluator("(! x)")
    assert ev.get_function_params(allow_negation=True) == [Negated("x")]


# -- _split_backtick_output: strip "#" comments before splitting ------------


def test_split_backtick_output_strips_comment_and_splits() -> None:
    assert _split_backtick_output("a # comment\nb") == ["a", "b"]
