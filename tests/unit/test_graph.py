# tests/unit/test_graph.py
"""Unit + golden tests for the --graph builder and renderers."""

from __future__ import annotations

from pyferm.graph import (
    EdgeKind,
    NodeKind,
    _cluster_id,
    _escape_ident,
    _header_context,
)


def test_edge_and_node_kinds_sort_as_strings() -> None:
    # VERDICT="" must sort first and stay distinct from the four labelled
    # edge kinds; StrEnum lets frozen tuples sort without a custom key.
    assert sorted(EdgeKind) == [
        EdgeKind.VERDICT,
        EdgeKind.GOTO,
        EdgeKind.JUMP,
        EdgeKind.POLICY,
        EdgeKind.SUBCHAIN,
    ]
    assert EdgeKind.VERDICT.value == ""
    assert NodeKind.BUILTIN.value == "builtin"


def test_cluster_id_is_injective() -> None:
    # Across the '__' delimiter: the single-'_' delimiter collided —
    # (a,"5f_") and ("a_","5f") both -> cluster_a_5f_5f. The '__' delimiter
    # separates them (spec §5, F2). Short name on purpose: a longer def
    # line is an unformattable E501.
    assert _cluster_id("a", "5f_") != _cluster_id("a_", "5f")
    assert _cluster_id("ip", "filter") == "ip__filter"
    assert _cluster_id("a.b", "c") == "a_2eb__c"  # '.'=0x2e escaped


def test_escape_ident_orders_backslash_before_quote() -> None:
    # '\' must double BEFORE '"' becomes \" (spec §5, F3), else a\ breaks.
    assert _escape_ident("a\\") == "a\\\\"
    assert _escape_ident('a"b') == 'a\\"b'
    assert _escape_ident("a\x1bb") == "a\\x1bb"  # C0/C1 -> \xNN


def test_header_context_scalar_and_array_and_collapsed() -> None:
    assert _header_context(("domain", "ip6")) == (("ip6",), None, None, None)
    assert _header_context(("domain", "(", "ip", "ip6", ")")) == (
        ("ip", "ip6"),
        None,
        None,
        None,
    )
    # collapsed one-line header: table + chain from one value_span
    assert _header_context(("table", "filter", "chain", "INPUT")) == (
        None,
        ("filter",),
        ("INPUT",),
        None,
    )


def test_header_context_policy_two_forms_and_guards() -> None:
    # folded form: chain declared AND policy target in one header
    assert _header_context(("chain", "INPUT", "policy", "DROP")) == (
        None,
        None,
        ("INPUT",),
        "DROP",
    )
    # standalone in-block form: only the policy target, no chain here (M1)
    assert _header_context(("policy", "DROP")) == (None, None, None, "DROP")
    # mod policy is the match module, not a policy edge (M2)
    assert _header_context(
        ("chain", "INPUT", "mod", "policy", "dir", "in")
    ) == (
        None,
        None,
        ("INPUT",),
        None,
    )
    # non-core policy target is not a policy edge (oracle errors on it)
    assert _header_context(("chain", "INPUT", "policy", "myuserchain")) == (
        None,
        None,
        ("INPUT",),
        None,
    )


def test_header_context_skips_nonliteral_domain_table() -> None:
    # $var lexes as two tokens '$','t'; skip -> no phantom cluster (F4)
    assert _header_context(("domain", "$", "t")) == (None, None, None, None)
    assert _header_context(("table", "$", "t")) == (None, None, None, None)
