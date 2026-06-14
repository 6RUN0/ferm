# tests/unit/test_backend_nft.py
from __future__ import annotations

from pyferm.backend.nft import (
    NftBaseChain,
    NftRegularChain,
    NftRule,
    NftTable,
)


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


from pyferm.backend.nft import (
    NftMatch,
    NftStatement,
    NftVerdict,
)


def test_statement_to_text_dispatches_by_type() -> None:
    assert NftMatch("ip saddr 10.0.0.1").to_text() == "ip saddr 10.0.0.1"
    assert NftVerdict("accept").to_text() == "accept"
    # A statement is an abstract base; subclasses own to_text.
    assert issubclass(NftMatch, NftStatement)
    assert issubclass(NftVerdict, NftStatement)


from pyferm.backend.nft import serialize_table


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


import pytest

from pyferm.backend.nft import render_comment
from pyferm.errors import FermError


def test_render_comment_rejects_over_limit() -> None:
    assert render_comment("ok") == 'comment "ok"'
    assert render_comment("two words") == 'comment "two words"'
    with pytest.raises(FermError, match="exceeds nft limit"):
        render_comment("x" * 129)
