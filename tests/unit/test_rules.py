"""
Unit tests for :mod:`pyferm.rules`.

Covers the netfilter predicates ported from ``reference/src/ferm``
(``:1766-1803``) and the render/commit split: the cartesian unfold must
produce the same *set and order* of rules as the oracle while recording
values (not formatted strings), with deferred calls expanded inline and
negation/kind/module carried through untouched.
"""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.modules import ModuleDef
from pyferm.rules import (
    RenderedRule,
    append_rule,
    is_netfilter_builtin_chain,
    is_netfilter_core_target,
    is_netfilter_module_target,
    mkrules2,
    netfilter_canonical_protocol,
    netfilter_protocol_module,
)
from pyferm.scope import Option, OptionKind, Rule, append_option
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


def _unfold(rule: Rule, domain: str = "ip") -> list[RenderedRule]:
    """Unfold ``rule`` into RenderedRules via a fresh mkrules2 call."""
    out: list[RenderedRule] = []
    mkrules2(domain, out, rule)
    return out


def test_scalar_only_emits_single_structural_rule() -> None:
    rule = Rule()
    append_option(rule, "protocol", "tcp")
    append_option(rule, "jump", "ACCEPT")

    chain_rules = _unfold(rule)

    assert len(chain_rules) == 1
    (only,) = chain_rules
    # values are recorded verbatim, NOT formatted to "-p tcp"/"-j ACCEPT"
    assert _chosen(only) == {"protocol": "tcp", "jump": "ACCEPT"}


def test_array_options_unfold_in_perl_order() -> None:
    rule = Rule()
    append_option(rule, "sport", ["1", "2"])
    append_option(rule, "dport", ["x", "y"])

    chain_rules = _unfold(rule)

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

    chain_rules = _unfold(rule)

    assert [_chosen(r) for r in chain_rules] == [
        {"protocol": "tcp", "dport": "80"},
        {"protocol": "tcp", "dport": "443"},
    ]
    # original option order is preserved in every emitted rule
    assert [o.name for o in chain_rules[0].options] == ["protocol", "dport"]


def test_empty_array_emits_no_rule() -> None:
    rule = Rule()
    append_option(rule, "dport", [])  # realize_deferred yields nothing

    chain_rules = _unfold(rule)

    assert chain_rules == []


def test_deferred_is_realized_inline_during_unfold() -> None:
    # a deferred whose list-context return holds two values
    def two_addrs(_domain: str, *_args: object) -> list[Value]:
        return ["10.0.0.1", "10.0.0.2"]

    deferred = Deferred(function=two_addrs, params=[])
    rule = Rule()
    append_option(rule, "saddr", [deferred])

    chain_rules = _unfold(rule)

    assert [_chosen(r) for r in chain_rules] == [
        {"saddr": "10.0.0.1"},
        {"saddr": "10.0.0.2"},
    ]


def test_non_array_refs_are_treated_as_scalars() -> None:
    # Multi/Negated are refs but not ARRAY -> not unfolded, kept as the value
    rule = Rule()
    append_option(rule, "dport", Multi(["80", "443"]))
    append_option(rule, "protocol", Negated("tcp"))

    chain_rules = _unfold(rule)

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

    chain_rules = _unfold(rule)

    (only,) = chain_rules
    by_name = {o.name: o for o in only.options}
    assert by_name["protocol"].kind == OptionKind.PROTO
    assert by_name["match"].kind == OptionKind.MATCH_MODULE
    assert by_name["match"].module == "state"
    assert by_name["jump"].kind == OptionKind.TARGET
    assert by_name["protocol"].module is None


# --- append_rule postcondition: no list/Deferred may reach the commit ------


def test_append_rule_rejects_list_chosen() -> None:
    """A list leaked past unfold is a seam bug -> internal_error."""
    rule = Rule()
    opt = Option("dport", [])
    opt.chosen = ["80", "443"]  # list leaked past unfold
    rule.options.append(opt)
    with pytest.raises(FermError, match="internal error"):
        append_rule([], rule)


def test_append_rule_rejects_deferred_chosen() -> None:
    """An unrealized Deferred on chosen is a seam bug -> internal_error."""

    def dummy(_domain: str) -> list[Value]:
        return []  # pragma: no cover

    rule = Rule()
    opt = Option("saddr", [Deferred(function=dummy, params=[])])
    opt.chosen = Deferred(function=dummy, params=[])  # unrealized deferred
    rule.options.append(opt)
    with pytest.raises(FermError, match="internal error"):
        append_rule([], rule)


def test_mkrules2_cardinality_equals_array_product() -> None:
    """Cartesian unfold of two array options yields the exact product count."""
    rule = Rule()
    rule.options.append(Option("sport", ["1", "2", "3"]))
    rule.options.append(Option("dport", ["x", "y"]))
    out = _unfold(rule)
    assert len(out) == 6  # 3 * 2; the invariant must hold, not just the count


def test_mkrules2_empty_array_yields_zero_rules() -> None:
    """An empty array option produces no rules (zero-length product)."""
    rule = Rule()
    rule.options.append(Option("dport", []))
    out = _unfold(rule)
    assert len(out) == 0  # product over a zero-length array


# --- deferred family threading through the unfold (mkrules2/unfold_rule) ----
#
# ``@ipfilter`` is family-sensitive: under ``ip6`` it keeps only the IPv6
# address.  These pin that the family reaches ``realize_deferred`` at every
# unfold call site rather than being dropped to ``None`` (which would leave the
# IPv4 address in and inflate the cartesian product).


def _ipfilter_option(name: str) -> Option:
    from pyferm.functions import ipfilter

    return Option(
        name,
        [Deferred(function=ipfilter, params=[["10.0.0.1", "fe80::1"]])],
    )


def test_mkrules2_threads_family_into_deferred_array() -> None:
    rule = Rule()
    rule.options = [_ipfilter_option("saddr")]
    out = _unfold(rule, domain="ip6")
    # one address survives the ip6 filter -> exactly one rule with fe80::1
    assert len(out) == 1
    assert [o.value for o in out[0].options] == ["fe80::1"]


def test_unfold_rule_threads_family_after_first_array() -> None:
    # A plain array option precedes the deferred one; the recursion under it
    # must still thread the family, so the deferred yields one value (not two).
    rule = Rule()
    rule.options = [Option("dport", ["80", "443"]), _ipfilter_option("saddr")]
    out = _unfold(rule, domain="ip6")
    # 2 dports x 1 surviving addr = 2 rules, all with the ip6 address
    assert len(out) == 2
    saddrs = [o.value for r in out for o in r.options if o.name == "saddr"]
    assert saddrs == ["fe80::1", "fe80::1"]


def test_append_rule_preserves_the_rule_script() -> None:
    # the RenderedRule carries the source position through verbatim; a mutant
    # that hard-codes None would lose the rollback/error anchor.
    from pyferm.scope import SourcePosition

    rule = Rule()
    rule.options = [Option("dport", "22")]
    rule.script = SourcePosition("firewall.ferm", 42)
    out: list[RenderedRule] = []
    append_rule(out, rule)
    assert out[0].script == SourcePosition("firewall.ferm", 42)


def test_mkrules2_cardinality_check_uses_pre_call_baseline() -> None:
    # The postcondition measures ``len - before``: appending a second batch to
    # a chain list that already holds rules must not miscount (a ``+ before``
    # would raise a bogus internal error on the second call).
    def make_rule() -> Rule:
        rule = Rule()
        rule.options = [Option("dport", ["80", "443"])]
        return rule

    out: list[RenderedRule] = []
    mkrules2("ip", out, make_rule())  # before=0 -> 2 rules
    mkrules2("ip", out, make_rule())  # before=2 -> must still validate cleanly
    assert len(out) == 4
