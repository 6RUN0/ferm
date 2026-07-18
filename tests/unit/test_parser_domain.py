"""
Mutation-killing unit tests for the parser's domain/family cluster.

These pin observable parser state for ``_getvar_family_filtered`` and
``_parse_header`` behaviours that the wider suite exercised only through
emission or golden diffs, so the mutmut survivors in those functions gain a
unit-level assertion.  The ``s``-code target-option path (a named ``@set``
reaching a scalar target option under ``--nft``) is the only route that hands
``_getvar_family_filtered`` a ``SetRef`` to filter, so those tests drive it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.config import Options
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.values import SetRef
from tests.unit._parse import parse_source

if TYPE_CHECKING:
    from pyferm.parser import Parser


def _parse(source: str, *, nft: bool = False) -> Parser:
    """Parse ``source`` through ``Parser.enter`` and return the parser."""
    return parse_source(source, options=Options(test=True, nft=nft))


def _set_mark(parser: Parser, family: Family) -> SetRef:
    """Return the ``set-mark`` SetRef of a family's one PREROUTING rule."""
    domain = parser.domains[family]
    rule = domain.tables["mangle"].chains["PREROUTING"].rules[0]
    (value,) = [o.value for o in rule.options if o.name == "set-mark"]
    assert isinstance(value, SetRef)
    return value


def test_getvar_family_filtered_dual_stack_splits_per_family() -> None:
    """
    A dual-stack ``domain (ip ip6)`` set keeps only its family's addresses.

    ``_getvar_family_filtered`` filters the ``@set`` reaching a scalar target
    option per replayed family (identity ``name`` preserved), so the ip rule
    sees only the v4 member and the ip6 rule only the v6 member.  ``set-mark``
    is merely a convenient ``s``-code carrier for the set here.
    """
    parser = _parse(
        "@set $m = (10.0.0.1 2001:db8::1);\n"
        "domain (ip ip6) table mangle chain PREROUTING {\n"
        "    CONNMARK set-mark $m;\n"
        "}\n",
        nft=True,
    )
    ip_ref = _set_mark(parser, Family.IP)
    ip6_ref = _set_mark(parser, Family.IP6)
    assert ip_ref.name == "m"
    assert ip6_ref.name == "m"
    assert ip_ref.elements == ["10.0.0.1"]
    assert ip6_ref.elements == ["2001:db8::1"]


def test_getvar_family_filtered_single_family_passthrough() -> None:
    """
    Under a single-family domain the set is passed through unfiltered.

    ``domain_both`` is false, so the guard leaves the mixed-family set intact:
    the ip rule keeps the v6 member the dual-stack path would have dropped.
    """
    parser = _parse(
        "@set $m = (10.0.0.1 2001:db8::1);\n"
        "domain ip table mangle chain PREROUTING {\n"
        "    CONNMARK set-mark $m;\n"
        "}\n",
        nft=True,
    )
    ref = _set_mark(parser, Family.IP)
    assert ref.name == "m"
    assert ref.elements == ["10.0.0.1", "2001:db8::1"]


def test_parse_header_rejects_lowercase_builtin_chain() -> None:
    """
    A lowercase built-in chain name is rejected with the exact message.

    The header refuses ``chain input`` (the built-in is ``INPUT``) rather than
    silently creating a distinct lowercase chain.
    """
    with pytest.raises(
        FermError, match="Please write built-in chain names in upper case"
    ):
        _parse("chain input ACCEPT;")


def test_parse_header_priority_enables_domain() -> None:
    """
    A base-chain ``priority`` override enables the domain.

    The priority walk runs with ``enable=True``; an otherwise-empty chain
    block still switches the domain on and records the resolved priority.
    """
    parser = _parse("chain INPUT priority 5 { }", nft=True)
    domain = parser.domains[Family.IP]
    assert domain.enabled is True
    assert domain.tables["filter"].chains["INPUT"].priority == 5


def test_parse_header_chain_array_preserves_enclosing_table() -> None:
    """
    A chain-array header leaves the enclosing table intact for later siblings.

    After ``chain (PREROUTING POSTROUTING)`` replays inside ``table nat``, the
    following ``chain OUTPUT`` must still resolve under ``nat`` rather than
    falling back to the default ``filter`` table.
    """
    parser = _parse(
        "table nat {\n"
        "    chain (PREROUTING POSTROUTING) ACCEPT;\n"
        "    chain OUTPUT ACCEPT;\n"
        "}\n"
    )
    tables = parser.domains[Family.IP].tables
    assert "OUTPUT" in tables["nat"].chains
    assert tables["nat"].chains["OUTPUT"].rules
    assert "filter" not in tables or "OUTPUT" not in tables["filter"].chains


def test_parse_header_policy_preserves_chain_for_following_rule() -> None:
    """
    A ``policy`` header leaves the chain context intact for a following rule.

    ``chain INPUT { policy DROP; proto tcp ACCEPT; }`` records the policy and
    the trailing rule stays attached to ``INPUT``; losing the context would
    strand the rule with no chain.
    """
    parser = _parse("chain INPUT { policy DROP; proto tcp ACCEPT; }")
    tables = parser.domains[Family.IP].tables
    chain = tables["filter"].chains["INPUT"]
    assert chain.policy == "DROP"
    assert len(chain.rules) == 1
