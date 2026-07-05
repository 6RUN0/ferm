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
    render_d2,
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
    assert _header_context(("domain", "ip6")) == (
        ("ip6",),
        None,
        None,
        None,
        (),
    )
    assert _header_context(("domain", "(", "ip", "ip6", ")")) == (
        ("ip", "ip6"),
        None,
        None,
        None,
        (),
    )
    # collapsed one-line header: table + chain from one value_span
    assert _header_context(("table", "filter", "chain", "INPUT")) == (
        None,
        ("filter",),
        ("INPUT",),
        None,
        (),
    )


def test_header_context_policy_two_forms_and_guards() -> None:
    # folded form: chain declared AND policy target in one header
    assert _header_context(("chain", "INPUT", "policy", "DROP")) == (
        None,
        None,
        ("INPUT",),
        "DROP",
        (),
    )
    # standalone in-block form: only the policy target, no chain here (M1)
    assert _header_context(("policy", "DROP")) == (
        None,
        None,
        None,
        "DROP",
        (),
    )
    # mod policy is the match module, not a policy edge (M2); the run stops
    # at `mod`, so `mod policy dir in` is the inline rule tail.
    assert _header_context(
        ("chain", "INPUT", "mod", "policy", "dir", "in")
    ) == (
        None,
        None,
        ("INPUT",),
        None,
        ("mod", "policy", "dir", "in"),
    )
    # non-core policy target is not a policy edge (oracle errors on it)
    assert _header_context(("chain", "INPUT", "policy", "myuserchain")) == (
        None,
        None,
        ("INPUT",),
        None,
        (),
    )


def test_header_context_skips_nonliteral_domain_table() -> None:
    # $var lexes as the token PAIR '$','t'; both tokens are consumed as one
    # non-literal value (no phantom cluster, F4), so there is no context
    # update and the bare name does not leak into the inline tail.
    assert _header_context(("domain", "$", "t")) == (
        None,
        None,
        None,
        None,
        (),
    )
    assert _header_context(("table", "$", "t")) == (
        None,
        None,
        None,
        None,
        (),
    )


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


def test_render_d2_golden() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { jump ssh_guard; jump block; DROP; policy DROP; }"
            "chain ssh_guard { }"
        )
    )
    assert render_d2(g) == (
        'ip__filter: "ip/filter" {\n'
        '  "DROP": { shape: oval }\n'
        '  "INPUT": { shape: hexagon }\n'
        '  "block": { style.stroke-dash: 3 }\n'
        '  "ssh_guard"\n'
        '  "INPUT" -> "DROP"\n'
        '  "INPUT" -> "DROP": policy\n'
        '  "INPUT" -> "block": jump\n'
        '  "INPUT" -> "ssh_guard": jump\n'
        "}\n"
    )


def test_dual_stack_and_joint_cartesian() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "domain (ip ip6) table (filter nat) chain OUTPUT { jump x; }"
            "chain x {}"
        )
    )
    keys = {(c.domain, c.table) for c in g.clusters}
    assert keys == {
        ("ip", "filter"),
        ("ip", "nat"),
        ("ip6", "filter"),
        ("ip6", "nat"),
    }  # full 2x2


def test_realgoto_renders_as_goto_edge() -> None:
    g = collect_graph(
        Parser.parse_to_block("chain INPUT { realgoto other; } chain other {}")
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "other", EdgeKind.GOTO) in c.edges


def test_edge_dedup_and_jump_plus_verdict() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { jump a; jump a; ACCEPT; jump ACCEPT; } chain a {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    a_edges = [e for e in c.edges if e[:2] == ("INPUT", "a")]
    assert a_edges == [("INPUT", "a", EdgeKind.JUMP)]  # repeat -> one edge
    acc_edges = sorted(e for e in c.edges if e[1] == "ACCEPT")
    assert acc_edges == [
        ("INPUT", "ACCEPT", EdgeKind.VERDICT),
        ("INPUT", "ACCEPT", EdgeKind.JUMP),
    ]  # verdict + jump to same node = two edges


def test_undefined_is_per_cluster() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "table filter { chain INPUT { jump shared; } }"
            "table nat { chain PREROUTING {} chain shared {} }"
        )
    )
    filt = _cluster(g, "ip", "filter")
    assert (
        dict(filt.nodes)["shared"] == NodeKind.UNDEFINED
    )  # declared only in nat


def test_subchain_edge_and_user_node() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            'chain INPUT { proto tcp @subchain "sc" { ACCEPT; } }'
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "sc", EdgeKind.SUBCHAIN) in c.edges
    assert dict(c.nodes)["sc"] == NodeKind.USER


def test_gotosubchain_edge_carries_goto_kind() -> None:
    # The parser gives goto jumptype to subchain keywords starting with
    # "@go", so the @gotosubchain edge must render as GOTO, not SUBCHAIN.
    g = collect_graph(
        Parser.parse_to_block(
            'chain INPUT { proto tcp @gotosubchain "sc" { ACCEPT; } }'
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "sc", EdgeKind.GOTO) in c.edges
    assert dict(c.nodes)["sc"] == NodeKind.USER
    assert '  "INPUT" -> "sc": goto' in render_d2(g).splitlines()
    assert '    "INPUT" -> "sc" [label="goto"];' in render_dot(g).splitlines()


def test_subchain_and_gotosubchain_edges_coexist() -> None:
    # Both keywords side by side must keep their own distinct edge kind.
    g = collect_graph(
        Parser.parse_to_block(
            'chain INPUT { proto tcp @subchain "s1" { ACCEPT; }'
            ' proto udp @gotosubchain "s2" { ACCEPT; } }'
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "s1", EdgeKind.SUBCHAIN) in c.edges
    assert ("INPUT", "s2", EdgeKind.GOTO) in c.edges


def test_quoted_interpolation_chain_header_makes_no_phantom_node() -> None:
    # `chain "$x" { ... }` is a double-quoted interpolation, not a
    # literal chain name -- it must not fabricate a "$x" node/cluster
    # entry (graph.py's own _header_value harvests header names
    # independently of the _treescan.py scanners).
    g = collect_graph(
        Parser.parse_to_block(
            '@def $x = FOO;\nchain "$x" { ACCEPT; }\nchain INPUT { }\n'
        )
    )
    c = _cluster(g, "ip", "filter")
    assert "$x" not in dict(c.nodes)


def test_quoted_interpolation_jump_target_makes_no_phantom_edge() -> None:
    # `jump "$x"` must not create an edge/node for the literal "$x".
    g = collect_graph(
        Parser.parse_to_block('@def $x = FOO;\nchain INPUT { jump "$x"; }\n')
    )
    c = _cluster(g, "ip", "filter")
    assert c.edges == ()
    assert dict(c.nodes).keys() == {"INPUT"}


def test_empty_and_chainless_configs() -> None:
    # zero clusters: render_dot -> "digraph ferm {\n}\n"; render_d2 joins an
    # empty line list ("") and appends the trailing newline -> "\n". A
    # chainless `table nat;` sets context but declares no chain -> also
    # zero clusters (edges live only inside chains).
    assert render_dot(collect_graph(Parser.parse_to_block(""))) == (
        "digraph ferm {\n}\n"
    )
    assert (
        render_d2(collect_graph(Parser.parse_to_block("# just a comment\n")))
        == "\n"
    )
    assert collect_graph(Parser.parse_to_block("table nat;")).clusters == ()


def test_single_domain_ip6_keeps_literal_key() -> None:
    g = collect_graph(
        Parser.parse_to_block("domain ip6 chain INPUT { REJECT; }")
    )
    c = _cluster(g, "ip6", "filter")  # literal ip6 key...
    assert (
        dict(c.nodes)["REJECT"] == NodeKind.VERDICT
    )  # ...but ip6->ip for target


def test_backslash_and_quote_escaping() -> None:
    # _unquote strips the quotes but does NOT process escapes, so the ferm
    # file content `jump "a\b"` names the chain `a\b` (ONE raw backslash);
    # the DOT renderer doubles it (review-verified end-to-end).
    g = collect_graph(Parser.parse_to_block('chain INPUT { jump "a\\b"; }'))
    dot = render_dot(g)
    assert '"a\\\\b"' in dot  # backslash doubled, not breaking the quote


def test_mod_policy_no_policy_edge() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "table filter chain INPUT mod policy dir in { ACCEPT; }"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert all(k != EdgeKind.POLICY for _, _, k in c.edges)  # M2 regression


def test_cycle_within_table_renders_both_edges() -> None:
    # spec section 7: A -> B -> A cycle inside one table; the collector
    # records plain edges (no cycle detection), both must survive.
    g = collect_graph(
        Parser.parse_to_block("chain A { jump B; } chain B { jump A; }")
    )
    c = _cluster(g, "ip", "filter")
    assert ("A", "B", EdgeKind.JUMP) in c.edges
    assert ("B", "A", EdgeKind.JUMP) in c.edges


def test_jump_var_target_is_invisible() -> None:
    # real-parse pin for the eval-free contract: `$v` lexes as TWO tokens
    # ('$', 'v'), the target is non-literal -> no edge, no phantom node.
    g = collect_graph(Parser.parse_to_block("chain INPUT { jump $v; }"))
    c = _cluster(g, "ip", "filter")
    assert c.edges == ()
    assert dict(c.nodes).keys() == {"INPUT"}


def test_subchain_body_attributed_to_subchain_not_outer() -> None:
    # review regression: the body of a rule-prefixed @subchain is a SIBLING
    # BlockNode; its edges belong to the subchain, not the outer chain.
    g = collect_graph(
        Parser.parse_to_block(
            'chain INPUT { proto tcp @subchain "sc" { ACCEPT; jump other; } }'
            "chain other {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "sc", EdgeKind.SUBCHAIN) in c.edges
    assert ("sc", "ACCEPT", EdgeKind.VERDICT) in c.edges
    assert ("sc", "other", EdgeKind.JUMP) in c.edges
    assert ("INPUT", "ACCEPT", EdgeKind.VERDICT) not in c.edges
    assert ("INPUT", "other", EdgeKind.JUMP) not in c.edges


def test_nested_subchain_bodies_are_per_subchain() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            'chain INPUT { proto tcp @subchain "sc" {'
            ' proto udp @subchain "inner" { jump deep; } } } chain deep {}'
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("sc", "inner", EdgeKind.SUBCHAIN) in c.edges
    assert ("inner", "deep", EdgeKind.JUMP) in c.edges
    assert ("INPUT", "deep", EdgeKind.JUMP) not in c.edges


def test_rule_group_block_stays_in_outer_chain() -> None:
    # guard for the lookbehind: a rule-group `proto tcp { ... }` has the
    # SAME RuleNode+BlockNode shape as a rule-prefixed @subchain but its
    # body legitimately belongs to the outer chain.
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { proto tcp { jump grp; } } chain grp {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "grp", EdgeKind.JUMP) in c.edges


def test_scalar_def_rhs_makes_no_edge() -> None:
    # review regression: a scalar @def RHS is a stored value, not a rule --
    # neither its jump nor its verdict tokens may leak as edges.
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { @def $X = jump foo; @def $Y = ACCEPT; jump real; }"
            "chain real {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "real", EdgeKind.JUMP) in c.edges
    assert all(dst != "foo" for _, dst, _ in c.edges)
    assert ("INPUT", "ACCEPT", EdgeKind.VERDICT) not in c.edges


def test_function_def_body_attributed_to_chain() -> None:
    # function @def keeps the lexical attribution the spec pins: the body
    # lives inside the DefNode span and is replayed in the caller's chain.
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT { @def &G() = { jump g; } &G(); } chain g {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "g", EdgeKind.JUMP) in c.edges


def test_header_context_returns_inline_rule_tail() -> None:
    # flat inline rule: the header prefix is the location run, the rest is
    # the rule tail returned for edge emission. `mod policy` stops the run
    # (mod is a rule keyword), so `policy` here is the match module.
    assert _header_context(
        ("chain", "INPUT", "proto", "udp", "dport", "domain", "ACCEPT")
    ) == (
        None,
        None,
        ("INPUT",),
        None,
        ("proto", "udp", "dport", "domain", "ACCEPT"),
    )
    assert _header_context(
        ("chain", "INPUT", "mod", "policy", "dir", "in")
    ) == (
        None,
        None,
        ("INPUT",),
        None,
        ("mod", "policy", "dir", "in"),
    )
    # pure header (no tail) still yields an empty tail
    assert _header_context(("table", "filter", "chain", "INPUT")) == (
        None,
        ("filter",),
        ("INPUT",),
        None,
        (),
    )


def test_flat_inline_dport_domain_no_phantom_cluster() -> None:
    # bug #1: `dport domain` (domain is /etc/services for DNS) must not be
    # misread as a header keyword and fabricate a `domain=)`/`ACCEPT` cluster.
    g = collect_graph(
        Parser.parse_to_block("chain INPUT proto udp dport domain ACCEPT;")
    )
    keys = {(c.domain, c.table) for c in g.clusters}
    assert keys == {("ip", "filter")}  # no phantom cluster
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "ACCEPT", EdgeKind.VERDICT) in c.edges


def test_flat_inline_table_chain_verdict_edge() -> None:
    # bug #2: the fused rule's verdict edge must not be dropped.
    g = collect_graph(
        Parser.parse_to_block(
            "table filter chain INPUT proto tcp dport 22 ACCEPT;"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "ACCEPT", EdgeKind.VERDICT) in c.edges


def test_flat_inline_jump_edge_and_user_node() -> None:
    g = collect_graph(
        Parser.parse_to_block("chain INPUT jump foo; chain foo {}")
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "foo", EdgeKind.JUMP) in c.edges
    assert dict(c.nodes)["foo"] == NodeKind.USER


def test_flat_inline_quoted_jump_target() -> None:
    # token-representation pin: the flat tail keeps its quoting, so the
    # quoted target `"a\b"` names chain `a\b` and the renderer doubles the
    # backslash (mirrors test_backslash_and_quote_escaping for braced form).
    g = collect_graph(Parser.parse_to_block('chain INPUT jump "a\\b";'))
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "a\\b", EdgeKind.JUMP) in c.edges
    assert '"a\\\\b"' in render_dot(g)


def test_flat_inline_array_header_all_clusters() -> None:
    g = collect_graph(
        Parser.parse_to_block(
            "domain (ip ip6) table (filter nat) chain OUTPUT jump x;chain x {}"
        )
    )
    for domain in ("ip", "ip6"):
        for table in ("filter", "nat"):
            c = _cluster(g, domain, table)
            assert ("OUTPUT", "x", EdgeKind.JUMP) in c.edges


def test_flat_inline_no_body_stays_out_of_outer_chain() -> None:
    # a flat rule ends in `;` with no sibling block, so the pending-subchain
    # lookbehind must not fire on it: the following braced chain's body is
    # its own, not re-attributed.
    g = collect_graph(
        Parser.parse_to_block(
            "chain INPUT jump foo; chain foo { jump bar; } chain bar {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("foo", "bar", EdgeKind.JUMP) in c.edges
    assert ("INPUT", "bar", EdgeKind.JUMP) not in c.edges


def test_bare_subchain_without_rule_prefix() -> None:
    # A bare `@subchain "sc" { ... }` (no rule prefix) parses to a
    # SubchainNode, exercising the _scan_span SubchainNode branch that the
    # rule-prefixed form never reaches: only the pre-`{` head (the subchain
    # edge + name) is attributed to the outer chain; the body is elided.
    g = collect_graph(
        Parser.parse_to_block('chain INPUT { @subchain "sc" { ACCEPT; } }')
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "sc", EdgeKind.SUBCHAIN) in c.edges
    assert dict(c.nodes)["sc"] == NodeKind.USER
    assert ("INPUT", "ACCEPT", EdgeKind.VERDICT) not in c.edges  # body elided


def test_scan_verdicts_verdict_after_param_group() -> None:
    # The depth-tracked skip of a `(...)` option value must stop exactly at
    # the matching `)` and still surface a trailing verdict.
    assert _scan_verdicts(("ctstate", "(", "NEW", ")", "ACCEPT"), "ip") == [
        "ACCEPT"
    ]


def test_scan_verdicts_nested_empty_and_unclosed_groups() -> None:
    # Nested groups: the inner ACCEPT is inside the skipped value, the outer
    # `)` closes depth; a value after a balanced nest is a real verdict.
    assert (
        _scan_verdicts(("ctstate", "(", "(", "NEW", ")", "ACCEPT", ")"), "ip")
        == []
    )
    assert _scan_verdicts(
        ("ctstate", "(", "(", "NEW", ")", ")", "ACCEPT"), "ip"
    ) == ["ACCEPT"]
    # empty group, then a verdict
    assert _scan_verdicts(("ctstate", "(", ")", "ACCEPT"), "ip") == ["ACCEPT"]
    # unclosed group must not IndexError, and swallows the rest
    assert _scan_verdicts(("ctstate", "(", "NEW", "ACCEPT"), "ip") == []


def test_scan_verdicts_jump_target_and_scalar_value_skips() -> None:
    # jump target skipped, trailing verdict kept (rule 1 advances by two)
    assert _scan_verdicts(("jump", "foo", "ACCEPT"), "ip") == ["ACCEPT"]
    # i>0 guard: a verdict at index 0 has no previous token to misread
    assert _scan_verdicts(("ACCEPT", "ctstate"), "ip") == ["ACCEPT"]
    # scalar option value after a params keyword is skipped by exactly one
    assert _scan_verdicts(("saddr", "1.2.3.4", "ACCEPT"), "ip") == ["ACCEPT"]


def test_family_targets_family_absent_from_target_defs() -> None:
    # arp has no key in TARGET_DEFS; the default must be an empty mapping,
    # not None (frozenset(None) would raise).
    assert "ACCEPT" in _family_targets("arp")
    g = collect_graph(
        Parser.parse_to_block("domain arp chain INPUT { ACCEPT; }")
    )
    c = _cluster(g, "arp", "filter")
    assert ("INPUT", "ACCEPT", EdgeKind.VERDICT) in c.edges


def test_walk_bare_block_is_not_a_subchain_body() -> None:
    # pending_subchain starts as None; a leading bare `{ ... }` block must be
    # walked in the outer chain, not mistaken for a subchain body.
    g = collect_graph(
        Parser.parse_to_block("chain INPUT { { jump foo; } } chain foo {}")
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "foo", EdgeKind.JUMP) in c.edges


def test_walk_subchain_body_keeps_inherited_table() -> None:
    # a rule-prefixed subchain body in a non-filter table must recurse with
    # the inherited table, not fall back to filter.
    g = collect_graph(
        Parser.parse_to_block(
            "table nat { chain PREROUTING {"
            ' proto tcp @subchain "sc" { jump foo; } } chain foo {} }'
        )
    )
    nat = _cluster(g, "ip", "nat")
    assert ("sc", "foo", EdgeKind.JUMP) in nat.edges
    filt = [c for c in g.clusters if c.table == "filter"]
    assert not any(("sc", "foo", EdgeKind.JUMP) in c.edges for c in filt)


def test_walk_statement_after_rule_subchain_is_kept() -> None:
    # the subchain-body branch must `continue`, not `break`: a statement
    # after the rule-prefixed subchain block still belongs to the chain.
    g = collect_graph(
        Parser.parse_to_block(
            'chain INPUT { proto tcp @subchain "sc" { ACCEPT; } jump after; }'
            "chain after {}"
        )
    )
    c = _cluster(g, "ip", "filter")
    assert ("INPUT", "after", EdgeKind.JUMP) in c.edges


def test_walk_policy_in_non_filter_table() -> None:
    # a policy edge in a nat chain must land in the nat cluster: the
    # effective-table fallback is `t or (filter,)`, so a set `t` wins.
    g = collect_graph(
        Parser.parse_to_block("table nat chain POSTROUTING { policy ACCEPT; }")
    )
    nat = _cluster(g, "ip", "nat")
    assert ("POSTROUTING", "ACCEPT", EdgeKind.POLICY) in nat.edges


def test_walk_chainless_flat_rule_makes_no_cluster() -> None:
    # a flat inline rule with no chain context emits nothing (`tail and c`);
    # it must not fabricate an empty cluster.
    g = collect_graph(Parser.parse_to_block("table filter proto tcp ACCEPT;"))
    assert g.clusters == ()


def test_header_context_truncated_spans_do_not_index_error() -> None:
    # degenerate/truncated header spans must return cleanly, never IndexError
    # past the token list end (bound guards on every toks[i] access).
    assert _header_context(("policy",)) == (None, None, None, None, ())
    assert _header_context(("chain",)) == (None, None, None, None, ())
    assert _header_context(("domain", "(", "ip")) == (
        ("ip",),
        None,
        None,
        None,
        (),
    )
    assert list(_jump_edges(("jump",))) == []


def test_header_context_array_var_member_is_dropped() -> None:
    # a `$var` member inside a `(...)` array value lexes as the token pair
    # '$','t' and must be consumed WHOLE: the bare name neither becomes a
    # phantom domain nor leaks into the tail.
    assert _header_context(("domain", "(", "$", "t", ")")) == (
        None,
        None,
        None,
        None,
        (),
    )


def test_header_context_var_value_does_not_desync_the_run() -> None:
    # `domain $d chain INPUT`: consuming only the `$` sigil left the bare
    # `d` to stop the location run, so the chain was never harvested and
    # `d` leaked into the inline tail. The pair is consumed whole now.
    assert _header_context(("domain", "$", "d", "chain", "INPUT")) == (
        None,
        None,
        ("INPUT",),
        None,
        (),
    )


def test_header_context_open_brace_is_not_a_chain_name() -> None:
    # `chain {` (no name) must leave new_chains None; the `{` boundary token
    # is not captured as a chain name.
    _, _, chains, _, _ = _header_context(("chain", "{"))
    assert chains is None


def test_header_context_policy_then_header_keyword() -> None:
    # after `policy TARGET` the scan advances by exactly two and resumes, so
    # a following `chain FOO` redeclares the chain and empties the tail.
    assert _header_context(
        ("chain", "INPUT", "policy", "DROP", "chain", "FOO")
    ) == (None, None, ("FOO",), "DROP", ())


def test_corpus_stuart_has_no_garbage_clusters() -> None:
    # regression for the `dport (domain)` line: no cluster may have a domain
    # or table that is not a real family/table name.
    from pathlib import Path

    src = Path("tests/corpus/configs/stuart-ha-server.ferm").read_text(
        encoding="utf-8"
    )
    g = collect_graph(Parser.parse_to_block(src))
    valid_domains = {"ip", "ip6", "arp", "eb"}
    for c in g.clusters:
        assert c.domain in valid_domains, f"garbage domain {c.domain!r}"
        assert ")" not in c.table, f"garbage table {c.table!r}"
        assert c.table != "ACCEPT", f"garbage table {c.table!r}"
