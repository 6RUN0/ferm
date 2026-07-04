# tests/unit/test_graph.py
"""Unit + golden tests for the --graph builder and renderers."""

from __future__ import annotations

from pyferm.graph import (
    _KW_HAS_PARAMS,
    ChainGraph,
    Cluster,
    EdgeKind,
    NodeKind,
    _cluster_id,
    _escape_ident,
    _family_targets,
    _fold_family,
    _header_context,
    _jump_edges,
    _scan_verdicts,
    collect_graph,
    render_dot,
)
from pyferm.parser import Parser


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


def test_jump_edges_carry_kind_and_normalize_realgoto() -> None:
    span = ("jump", "a", "goto", "b", "realgoto", "c", "goto", "$v")
    assert list(_jump_edges(span)) == [
        (EdgeKind.JUMP, "a"),
        (EdgeKind.GOTO, "b"),
        (EdgeKind.GOTO, "c"),
    ]  # realgoto -> GOTO; $v skipped


def test_family_fold_and_targets() -> None:
    assert _fold_family("ip6") == "ip"
    assert _fold_family("eb") == "eb"
    ip = _family_targets("ip")
    assert {"ACCEPT", "DROP", "RETURN", "QUEUE"} <= ip  # core
    assert "REJECT" in ip  # module targets
    assert "LOG" in ip
    assert "arpreply" not in ip  # eb-only, not ip
    assert "arpreply" in _family_targets("eb")


def test_kw_has_params_union_includes_target_keys() -> None:
    assert "ctstate" in _KW_HAS_PARAMS["ip"]  # conntrack match
    assert "redirect-target" in _KW_HAS_PARAMS["eb"]  # target-module keyword


def _cluster(graph: ChainGraph, domain: str, table: str) -> Cluster:
    return next(
        c for c in graph.clusters if c.domain == domain and c.table == table
    )


def test_collect_graph_defaults_cluster_and_classifies_nodes() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { jump ssh_guard; jump nowhere; }chain ssh_guard { }"
        )
    )
    c = _cluster(g, "ip", "filter")  # oracle defaults
    nodes = dict(c.nodes)
    assert nodes["INPUT"] == NodeKind.BUILTIN
    assert nodes["ssh_guard"] == NodeKind.USER
    assert nodes["nowhere"] == NodeKind.UNDEFINED
    assert ("INPUT", "ssh_guard", EdgeKind.JUMP) in c.edges
    assert ("INPUT", "nowhere", EdgeKind.JUMP) in c.edges


def test_collect_graph_policy_inblock_and_array() -> None:
    g = collect_graph(
        Parser.parse_to_block("chain (INPUT OUTPUT) { policy DROP; }")
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "DROP", EdgeKind.POLICY) in c.edges
    assert ("OUTPUT", "DROP", EdgeKind.POLICY) in c.edges
    assert dict(c.nodes)["DROP"] == NodeKind.VERDICT


def test_collect_graph_no_cross_table_edges() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "table filter { chain INPUT { jump a; } chain a {} }"
            "table nat { chain PREROUTING { jump b; } chain b {} }"
        )
    )
    filt = _cluster(g, "ip", "filter")
    nat = _cluster(g, "ip", "nat")
    assert all(dst != "b" for _, dst, _ in filt.edges)  # no leak across tables
    assert dict(nat.nodes)["b"] == NodeKind.USER


def test_scan_verdicts_basic_and_suppressions() -> None:
    assert _scan_verdicts(("LOG", ";"), "ip") == ["LOG"]
    assert _scan_verdicts(("ACCEPT", ";"), "ip") == ["ACCEPT"]
    # rule 1: token after a jump keyword is the jump target, not a verdict
    assert _scan_verdicts(("goto", "LOG", ";"), "ip") == []
    # rule 2: option value after a params keyword is skipped (whole group)
    assert (
        _scan_verdicts(
            ("mod", "conntrack", "ctstate", "(", "DNAT", "SNAT", ")"), "ip"
        )
        == []
    )
    # rule 2 (eb): redirect-target ACCEPT -> ACCEPT is the value, suppressed
    assert _scan_verdicts(("redirect-target", "ACCEPT"), "eb") == []
    # rule 3: a quoted candidate is not a bare target token
    assert _scan_verdicts(("log-prefix", '"DROP"'), "ip") == []
    # non-verdict conntrack states never match
    assert _scan_verdicts(("mod", "conntrack", "ctstate", "NEW"), "ip") == []


def test_collect_graph_verdict_leaf_and_nonterminal() -> None:
    g = collect_graph(Parser.parse_to_block("chain INPUT { LOG; DROP; }"))
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "LOG", EdgeKind.VERDICT) in c.edges
    assert ("INPUT", "DROP", EdgeKind.VERDICT) in c.edges
    assert (
        dict(c.nodes)["LOG"] == NodeKind.VERDICT
    )  # nonterminal drawn as leaf


def test_collect_graph_pinned_nonregistry_boundary() -> None:
    # spec §4 pinned boundary: value after a NON-registry key is NOT
    # suppressed, so a value spelled like a target false-fires a leaf.
    g = collect_graph(Parser.parse_to_block("chain INPUT { dport DROP; }"))
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "DROP", EdgeKind.VERDICT) in c.edges  # accepted boundary


def test_render_dot_golden() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { jump ssh_guard; jump block; DROP; policy DROP; }"
            "chain ssh_guard { }"
        )
    )
    assert render_dot(g) == (
        "digraph ferm {\n"
        "  subgraph cluster_ip__filter {\n"
        '    label="ip/filter";\n'
        '    "DROP" [shape=plaintext];\n'
        '    "INPUT" [shape=box];\n'
        '    "block" [style=dashed];\n'
        '    "ssh_guard";\n'
        '    "INPUT" -> "DROP";\n'
        '    "INPUT" -> "DROP" [label="policy"];\n'
        '    "INPUT" -> "block" [label="jump"];\n'
        '    "INPUT" -> "ssh_guard" [label="jump"];\n'
        "  }\n"
        "}\n"
    )
