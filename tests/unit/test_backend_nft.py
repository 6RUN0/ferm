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


def test_map_base_chain_known_pairs() -> None:
    spec = map_base_chain("ip", "filter", "INPUT")
    assert spec == ("filter", "input", 0)
    assert map_base_chain("ip", "nat", "POSTROUTING") == ("nat", "postrouting", 100)
    assert map_base_chain("ip", "mangle", "OUTPUT") == ("route", "output", -150)


def test_map_base_chain_unmappable_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain("eb", "broute", "BROUTING")
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain("arp", "nat", "PREROUTING")
