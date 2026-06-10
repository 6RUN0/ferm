"""Unit tests for :mod:`pyferm.rules`.

Covers the netfilter predicates ported from ``reference/src/ferm``
(``:1766-1803``) and -- the risk unit called out in the implementation plan
(§4 step 8) -- the render/commit split: the cartesian unfold must produce the
same *set and order* of rules as the oracle while recording values (not
formatted strings), with deferred calls expanded inline and
negation/kind/module carried through untouched.
"""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.modules import ModuleDef
from pyferm.rules import (
    RenderedRule,
    is_netfilter_builtin_chain,
    is_netfilter_core_target,
    is_netfilter_module_target,
    mkrules2,
    netfilter_canonical_protocol,
    netfilter_protocol_module,
)
from pyferm.scope import Rule, append_option
from pyferm.values import Deferred, Multi, Negated, Value

# --- netfilter predicates --------------------------------------------------


@pytest.mark.parametrize("target", ["ACCEPT", "DROP", "RETURN", "QUEUE"])
def test_core_target_accepts_builtins(target: str) -> None:
    assert is_netfilter_core_target(target) is True


def test_core_target_rejects_others() -> None:
    assert is_netfilter_core_target("LOG") is False
    assert is_netfilter_core_target("MYCHAIN") is False


@pytest.mark.parametrize("bad", [None, ""])
def test_core_target_dies_on_empty(bad: str | None) -> None:
    with pytest.raises(FermError):
        is_netfilter_core_target(bad)


def test_module_target_returns_def_or_none() -> None:
    snat = ModuleDef()
    target_defs = {"ip": {"SNAT": snat}}
    assert is_netfilter_module_target(target_defs, "ip", "SNAT") is snat
    # unknown target in a known family
    assert is_netfilter_module_target(target_defs, "ip", "DNAT") is None
    # unknown family
    assert is_netfilter_module_target(target_defs, "ip6", "SNAT") is None


def test_module_target_none_family_is_none() -> None:
    assert is_netfilter_module_target({"ip": {}}, None, "SNAT") is None


def test_module_target_dies_on_empty() -> None:
    with pytest.raises(FermError):
        is_netfilter_module_target({}, "ip", "")


def test_builtin_chain_ignores_table() -> None:
    assert is_netfilter_builtin_chain("filter", "INPUT") is True
    assert is_netfilter_builtin_chain("nat", "PREROUTING") is True
    # the table argument is irrelevant -- only the chain name matters
    assert is_netfilter_builtin_chain("anything", "BROUTING") is True
    assert is_netfilter_builtin_chain("filter", "mychain") is False


@pytest.mark.parametrize(
    ("proto", "expected"),
    [
        ("ipv6-icmp", "icmp"),
        ("icmpv6", "icmp"),
        ("ipv6-mh", "mh"),
        ("tcp", "tcp"),
        ("icmp", "icmp"),
    ],
)
def test_canonical_protocol(proto: str, expected: str) -> None:
    assert netfilter_canonical_protocol(proto) == expected


@pytest.mark.parametrize(
    ("proto", "expected"),
    [(None, None), ("icmpv6", "icmp6"), ("tcp", "tcp"), ("icmp", "icmp")],
)
def test_protocol_module(proto: str | None, expected: str | None) -> None:
    assert netfilter_protocol_module(proto) == expected


# --- render/commit split: structural unfold --------------------------------


def _chosen(rule: RenderedRule) -> dict[str, object]:
    """The selected value per option name, for terse assertions."""
    return {option.name: option.value for option in rule.options}


def test_scalar_only_emits_single_structural_rule() -> None:
    rule = Rule()
    append_option(rule, "protocol", "tcp")
    append_option(rule, "jump", "ACCEPT")

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    assert len(chain_rules) == 1
    (only,) = chain_rules
    # values are recorded verbatim, NOT formatted to "-p tcp"/"-j ACCEPT"
    assert _chosen(only) == {"protocol": "tcp", "jump": "ACCEPT"}


def test_array_options_unfold_in_perl_order() -> None:
    rule = Rule()
    append_option(rule, "sport", ["1", "2"])
    append_option(rule, "dport", ["x", "y"])

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    # outer loop over the first option, inner over the second -> 2x2 product
    assert [_chosen(r) for r in chain_rules] == [
        {"sport": "1", "dport": "x"},
        {"sport": "1", "dport": "y"},
        {"sport": "2", "dport": "x"},
        {"sport": "2", "dport": "y"},
    ]


def test_scalar_value_is_repeated_across_unfolded_rules() -> None:
    rule = Rule()
    append_option(rule, "protocol", "tcp")  # scalar, fixed
    append_option(rule, "dport", ["80", "443"])  # array, unfolds

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    assert [_chosen(r) for r in chain_rules] == [
        {"protocol": "tcp", "dport": "80"},
        {"protocol": "tcp", "dport": "443"},
    ]
    # original option order is preserved in every emitted rule
    assert [o.name for o in chain_rules[0].options] == ["protocol", "dport"]


def test_empty_array_emits_no_rule() -> None:
    rule = Rule()
    append_option(rule, "dport", [])  # realize_deferred yields nothing

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    assert chain_rules == []


def test_deferred_is_realized_inline_during_unfold() -> None:
    # a deferred whose list-context return holds two values
    def two_addrs(_domain: str, *_args: object) -> list[Value]:
        return ["10.0.0.1", "10.0.0.2"]

    deferred = Deferred(function=two_addrs, params=[])
    rule = Rule()
    append_option(rule, "saddr", [deferred])

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    assert [_chosen(r) for r in chain_rules] == [
        {"saddr": "10.0.0.1"},
        {"saddr": "10.0.0.2"},
    ]


def test_non_array_refs_are_treated_as_scalars() -> None:
    # Multi/Negated are refs but not ARRAY -> not unfolded, kept as the value
    rule = Rule()
    append_option(rule, "dport", Multi(["80", "443"]))
    append_option(rule, "protocol", Negated("tcp"))

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    assert len(chain_rules) == 1
    (only,) = chain_rules
    chosen = _chosen(only)
    assert chosen["dport"] == Multi(["80", "443"])
    # negation survives as a tag on the value, never a separate field
    assert chosen["protocol"] == Negated("tcp")


def test_kind_and_module_carry_into_rendered_options() -> None:
    rule = Rule()
    append_option(rule, "protocol", "tcp")  # name -> kind "proto"
    append_option(rule, "match", "state", module="state")  # -> "match_module"
    append_option(rule, "jump", "ACCEPT")  # -> kind "target"

    chain_rules: list[RenderedRule] = []
    mkrules2("ip", chain_rules, rule)

    (only,) = chain_rules
    by_name = {o.name: o for o in only.options}
    assert by_name["protocol"].kind == "proto"
    assert by_name["match"].kind == "match_module"
    assert by_name["match"].module == "state"
    assert by_name["jump"].kind == "target"
    assert by_name["protocol"].module is None
