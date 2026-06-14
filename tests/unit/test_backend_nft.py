# tests/unit/test_backend_nft.py
from __future__ import annotations

import pytest

from pyferm.backend.nft import (
    NftBaseChain,
    NftMatch,
    NftRegularChain,
    NftRule,
    NftStatement,
    NftTable,
    NftVerdict,
    render_comment,
    serialize_table,
)
from pyferm.errors import FermError


def test_model_constructors_hold_fields() -> None:
    table = NftTable(family="ip", name="ferm")
    assert (table.family, table.name) == ("ip", "ferm")

    base = NftBaseChain(
        name="INPUT",
        type="filter",
        hook="input",
        priority=0,
        policy="drop",
    )
    assert base.hook == "input"
    assert base.policy == "drop"

    user = NftRegularChain(name="mychain")
    assert user.name == "mychain"

    rule = NftRule(statements=[], comment=None)
    assert rule.statements == []


def test_statement_to_text_dispatches_by_type() -> None:
    assert NftMatch("ip saddr 10.0.0.1").to_text() == "ip saddr 10.0.0.1"
    assert NftVerdict("accept").to_text() == "accept"
    # A statement is an abstract base; subclasses own to_text.
    assert issubclass(NftMatch, NftStatement)
    assert issubclass(NftVerdict, NftStatement)


def test_serialize_table_emits_atomic_transaction() -> None:
    table = NftTable(family="ip", name="ferm")
    chains = [
        NftBaseChain("INPUT", "filter", "input", 0, policy="drop"),
        NftRegularChain("mychain"),
    ]
    rules = {
        "INPUT": [
            NftRule([NftMatch("ct state established,related"),
                     NftVerdict("accept")]),
            NftRule([NftVerdict("jump mychain")]),
        ],
        "mychain": [NftRule([NftVerdict("drop")], comment="hi")],
    }
    out = serialize_table(table, chains, rules, noflush=False)
    assert out == (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add chain ip ferm INPUT "
        "{ type filter hook input priority 0; policy drop; }\n"
        "add chain ip ferm mychain\n"
        "add rule ip ferm INPUT ct state established,related accept\n"
        "add rule ip ferm INPUT jump mychain\n"
        'add rule ip ferm mychain drop comment "hi"\n'
    )


def test_serialize_table_noflush_omits_flush() -> None:
    table = NftTable(family="ip", name="ferm")
    chains = [NftRegularChain("c")]
    out = serialize_table(table, chains, {"c": []}, noflush=True)
    assert "flush table" not in out
    assert out.startswith("add table ip ferm\nadd chain ip ferm c\n")


def test_render_comment_rejects_over_limit() -> None:
    assert render_comment("ok") == 'comment "ok"'
    assert render_comment("two words") == 'comment "two words"'
    with pytest.raises(FermError, match="exceeds nft limit"):
        render_comment("x" * 129)


# ---------------------------------------------------------------------------
# Task 5: nft_family + map_base_chain
# ---------------------------------------------------------------------------
from pyferm.backend.nft import map_base_chain, nft_family  # noqa: E402


def test_nft_family_maps_1to1() -> None:
    assert nft_family("ip") == "ip"
    assert nft_family("ip6") == "ip6"
    assert nft_family("arp") == "arp"
    assert nft_family("eb") == "bridge"


def test_nft_family_unknown_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        nft_family("bogus")


def test_map_base_chain_known_pairs() -> None:
    spec = map_base_chain("ip", "filter", "INPUT")
    assert spec == ("filter", "input", 0)
    assert map_base_chain("ip", "nat", "POSTROUTING") == (
        "nat", "postrouting", 100
    )
    assert map_base_chain("ip", "mangle", "OUTPUT") == (
        "route", "output", -150
    )


def test_map_base_chain_unmappable_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain("eb", "broute", "BROUTING")
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain("arp", "nat", "PREROUTING")


# ---------------------------------------------------------------------------
# Task 6: build_chains + nft_chain_name
# ---------------------------------------------------------------------------
from pyferm.backend.nft import build_chains  # noqa: E402
from pyferm.domains import ChainInfo, TableInfo  # noqa: E402


def test_build_chains_splits_builtin_and_user() -> None:
    table = TableInfo(chains={
        "INPUT": ChainInfo(policy="DROP"),
        "mychain": ChainInfo(),
    })
    chains = build_chains("ip", "filter", table)
    by_name = {c.name: c for c in chains}
    assert isinstance(by_name["INPUT"], NftBaseChain)
    assert by_name["INPUT"].policy == "drop"
    assert by_name["INPUT"].hook == "input"
    assert by_name["INPUT"].type == "filter"
    assert isinstance(by_name["mychain"], NftRegularChain)


def test_build_chains_sorted_for_determinism() -> None:
    table = TableInfo(chains={"zeta": ChainInfo(), "alpha": ChainInfo()})
    names = [c.name for c in build_chains("ip", "filter", table)]
    assert names == ["alpha", "zeta"]


def test_nft_chain_name_disambiguates_non_filter() -> None:
    from pyferm.backend.nft import nft_chain_name

    assert nft_chain_name("filter", "INPUT") == "INPUT"
    assert nft_chain_name("mangle", "INPUT") == "mangle_INPUT"
    # mangle/INPUT becomes a distinct base chain, not a collision with filter.
    table = TableInfo(chains={"INPUT": ChainInfo()})
    chain = build_chains("ip", "mangle", table)[0]
    # mangle/OUTPUT -> route hook (the most error-prone mapping).
    table_out = TableInfo(chains={"OUTPUT": ChainInfo()})
    chain_out = build_chains("ip", "mangle", table_out)[0]
    assert chain_out.type == "route"

    assert chain.name == "mangle_INPUT"
    assert isinstance(chain, NftBaseChain)
    assert (chain.hook, chain.priority) == ("input", -150)


# ---------------------------------------------------------------------------
# Task 7: unwrap_value + first_scalar
# ---------------------------------------------------------------------------
from pyferm.backend.nft import first_scalar, unwrap_value  # noqa: E402
from pyferm.values import Multi, Negated  # noqa: E402


def test_unwrap_value_plain_and_negated() -> None:
    assert unwrap_value("22") == ("22", False)
    assert unwrap_value(Negated("22")) == ("22", True)


def test_unwrap_value_multi_negation_is_error() -> None:
    with pytest.raises(FermError, match="cannot be negated"):
        unwrap_value(Negated(["22", "80"]))


def test_first_scalar_extracts_from_multi() -> None:
    assert first_scalar(Multi(values=["1.2.3.4"])) == "1.2.3.4"
    assert first_scalar("5.6.7.8") == "5.6.7.8"


# ---------------------------------------------------------------------------
# Task 8: translate_match
# ---------------------------------------------------------------------------
from pyferm.backend.nft import translate_match  # noqa: E402
from pyferm.rules import RenderedOption  # noqa: E402


def _opt(name: str, value: object, kind: str = "option", module: object = None) -> RenderedOption:
    return RenderedOption(name=name, value=value, kind=kind, module=module)  # type: ignore[arg-type]


def test_translate_match_addresses_and_ifaces() -> None:
    assert translate_match("ip", _opt("source", "10.0.0.1"), None) \
        == "ip saddr 10.0.0.1"
    assert translate_match("ip6", _opt("destination", "fe80::1"), None) \
        == "ip6 daddr fe80::1"
    assert translate_match("ip", _opt("in-interface", "eth0"), None) \
        == 'iifname "eth0"'
    assert translate_match("ip", _opt("out-interface", "eth1"), None) \
        == 'oifname "eth1"'


def test_translate_match_ports_use_rule_protocol() -> None:
    assert translate_match("ip", _opt("dport", "22"), "tcp") == "tcp dport 22"
    assert translate_match("ip", _opt("sport", "53"), "udp") == "udp sport 53"


def test_translate_match_port_without_protocol_errors() -> None:
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        translate_match("ip", _opt("dport", "22"), None)


def test_translate_match_negation() -> None:
    assert translate_match("ip", _opt("source", Negated("10.0.0.1")), None) \
        == "ip saddr != 10.0.0.1"
    assert translate_match("ip", _opt("dport", Negated("23")), "tcp") \
        == "tcp dport != 23"


def test_translate_match_state_and_limit() -> None:
    assert translate_match(
        "ip", _opt("state", "ESTABLISHED,RELATED", module="state"), None
    ) == "ct state established,related"
    assert translate_match(
        "ip", _opt("limit", "3/second", module="limit"), None
    ) == "limit rate 3/second"


def test_translate_match_uncovered_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        translate_match("ip", _opt("totally-unknown", "x"), None)
