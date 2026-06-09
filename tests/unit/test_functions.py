"""Unit tests for :mod:`pyferm.functions`.

Exercises the value-evaluation layer: the stack lookups, the recursive
``getvalues`` reader (scalars, arrays, quotes, ``$`` variables, negation),
the ``@`` built-ins, ``collect_tokens``, the protocol helpers and the
keyword-parameter parsers (``ipfilter``/``address_magic``/``cgroup_classid``/
``multiport_params``).
"""

from __future__ import annotations

import io

import pytest

from pyferm.errors import FermError
from pyferm.functions import (
    Evaluator,
    ipfilter,
    realize_protocol,
    realize_protocol_keyword,
)
from pyferm.resolver import ZonefileResolver, set_resolver_provider
from pyferm.scope import Frame, Rule, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.values import Deferred, Negated


def _evaluator(
    text: str,
    *,
    variables: dict[str, object] | None = None,
    functions: dict[str, object] | None = None,
    auto: dict[str, object] | None = None,
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
    return Evaluator(tokenizer, scope)


# -- ipfilter ----------------------------------------------------------------


def test_ipfilter_ip_drops_ipv6() -> None:
    assert ipfilter("ip", ["1.2.3.4", "2001:db8::1", "::1"]) == ["1.2.3.4"]


def test_ipfilter_ip6_drops_ipv4_and_cidr() -> None:
    assert ipfilter("ip6", ["1.2.3.4", "10.0.0.0/8", "2001:db8::1"]) == [
        "2001:db8::1"
    ]


def test_ipfilter_other_domain_passes_through() -> None:
    assert ipfilter("eb", ["anything"]) == ["anything"]


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
    marker = object()
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


def test_builtin_cat_and_join() -> None:
    assert _evaluator("@cat(a, b, c)").getvalues() == "abc"
    assert _evaluator("@join(-, a, b)").getvalues() == "a-b"
    assert _evaluator("@join(-, (a b c))").getvalues() == "a-b-c"


def test_builtin_substr_and_length() -> None:
    assert _evaluator("@substr(hello, 1, 3)").getvalues() == "ell"
    assert _evaluator("@substr(hello, -2, 2)").getvalues() == "lo"
    assert _evaluator("@length(hello)").getvalues() == "5"


def test_builtin_basename_dirname() -> None:
    assert _evaluator("@basename(/a/b/c.conf)").getvalues() == "c.conf"
    assert _evaluator("@dirname(/a/b/c.conf)").getvalues() == "/a/b/"
    assert _evaluator("@dirname(bare)").getvalues() == ""


def test_builtin_defined_variable_and_function() -> None:
    ev = _evaluator("@defined($ v)", variables={"v": "1"})
    assert ev.getvalues() == "1"
    assert _evaluator("@defined($ v)").getvalues() == ""
    ev2 = _evaluator("@defined(& f)", functions={"f": object()})
    assert ev2.getvalues() == "1"


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
    (base / "a.conf").write_text("")
    (base / "b.conf").write_text("")
    (base / "c.txt").write_text("")
    tokenizer = Tokenizer(
        Script(
            filename=str(base / "rules.ferm"),
            handle=io.StringIO("@glob('*.conf')"),
        )
    )
    ev = Evaluator(tokenizer, Scope())
    ev.scope.push(Frame())
    assert ev.getvalues() == [str(base / "a.conf"), str(base / "b.conf")]


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
        "a", "{", "b", ";", "}",
    ]


def test_collect_tokens_unmatched_brace_errors() -> None:
    with pytest.raises(FermError, match="unmatched"):
        _evaluator("a ) ;").collect_tokens()


# -- backtick shell ----------------------------------------------------------


def test_backtick_runs_command() -> None:
    assert _evaluator("`echo foo bar`").getvalues() == ["foo", "bar"]


def test_backtick_nonzero_exit_errors() -> None:
    with pytest.raises(FermError, match="child exited with status"):
        _evaluator("`exit 3`").getvalues()


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
    assert result[0] == "1:1,2:2,3:3,4:4,5:5,6:6,7:7"
    assert result[1] == "8:8"
