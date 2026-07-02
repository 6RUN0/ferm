"""Unit tests for the eval-free analyzers behind ``ferm --lint``.

Every analyzer consumes Parser.parse_to_block (both @if branches, never
the walk tree). The CLI wrapper contract (output format, exit codes,
flag validation) is pinned separately in tests/unit/test_lint.py.
"""

from __future__ import annotations

import pytest

from pyferm.analysis import (
    Finding,
    Severity,
    _ChainCollector,
    _declared_chains,
    _is_quoted,
    _walk_all,
    find_deprecated_keywords,
    find_duplicate_definitions,
    find_jump_cycles,
    find_undefined_chain_jumps,
    find_unreachable_chains,
    find_unused_defs,
    run_analysis,
)
from pyferm.parser import MAX_BLOCK_DEPTH, Parser
from pyferm.tree import Block, BlockNode


def _tree(config: str) -> Block:
    return Parser.parse_to_block(config)


def test_unused_def_detected() -> None:
    assert "$x" in find_unused_defs(_tree("@def $x = 1;\n"))


def test_used_def_not_flagged() -> None:
    cfg = "@def $x = 1;\ntable filter chain INPUT { saddr $x ACCEPT; }\n"
    assert "$x" not in find_unused_defs(_tree(cfg))


def test_def_used_only_in_untaken_if_branch_counts_as_used() -> None:
    # THE key proof: post-eval would wrongly flag it (branch not taken); the
    # structural AST sees BOTH branches -> NOT unused.
    cfg = (
        "@def $x = 1;\n"
        "@if 0 { table filter chain INPUT { saddr $x ACCEPT; } }\n"
    )
    assert "$x" not in find_unused_defs(_tree(cfg))


def test_def_used_only_inside_match_block_counts_as_used() -> None:
    # The match block now nests as a BlockNode; the $x mention inside it must
    # still be seen (guards the parse_to_block match-block nesting fix).
    cfg = (
        "@def $x = 1;\n"
        "table filter chain INPUT { saddr 1.2.3.4 { daddr $x ACCEPT; } }\n"
    )
    assert "$x" not in find_unused_defs(_tree(cfg))


def test_interpolation_in_double_quotes_counts_as_use() -> None:
    # "$x" inside one double-quoted token is interpolated by ferm (the
    # oracle regex is \$(\w+)), so it IS a use -- the former pinned
    # false positive is closed by design in this slice.
    cfg = (
        "@def $x = 1;\n"
        'table filter chain OUTPUT { mod comment comment "$x" ACCEPT; }\n'
    )
    assert find_unused_defs(_tree(cfg)) == []


def test_single_quoted_var_is_not_a_use() -> None:
    # ferm never interpolates single quotes: '$x' stays literal, so the
    # def remains unused (proves the quote KIND is checked, not just
    # quotedness).
    cfg = (
        "@def $x = 1;\n"
        "table filter chain OUTPUT { mod comment comment '$x' ACCEPT; }\n"
    )
    assert find_unused_defs(_tree(cfg)) == ["$x"]


def test_curly_dollar_form_is_not_a_use() -> None:
    # ferm has no ${name} interpolation (the oracle passes "${x}"
    # through verbatim), so it must NOT count as a use.
    cfg = (
        "@def $x = 1;\n"
        'table filter chain OUTPUT { mod comment comment "${x}" ACCEPT; }\n'
    )
    assert find_unused_defs(_tree(cfg)) == ["$x"]


def test_dangling_jump_detected() -> None:
    cfg = "table filter chain INPUT { jump MISSING; }\n"
    assert "MISSING" in find_undefined_chain_jumps(_tree(cfg))


def test_jump_to_declared_user_chain_not_flagged() -> None:
    # THE false-positive guard: chains are declared by `chain FOO {}`, NOT only
    # by @subchain. Jumping into a user chain is a basic ferm idiom.
    cfg = (
        "table filter {\n"
        "  chain FOO { ACCEPT; }\n"
        "  chain INPUT { jump FOO; }\n"
        "}\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_jump_to_one_line_declared_chain_not_flagged() -> None:
    # DOMINANT real-world style: `table filter chain FOO {}` collapses to ONE
    # HeaderNode(keyword='table', value_span=(...,'chain','FOO')). The harvest
    # must scan value_span for an embedded `chain <NAME>`, not just a leading
    # keyword=='chain' -- else a jump to a one-line chain false-flags.
    cfg = (
        "table filter chain INPUT { jump FOO; }\n"
        "table filter chain FOO { ACCEPT; }\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_jump_to_policy_declared_chain_not_flagged() -> None:
    # A chain named by a one-line `... chain INPUT policy DROP;` header (no
    # block) is still a declaration site.
    cfg = (
        "table filter chain INPUT policy DROP;\n"
        "table filter chain OUT { jump INPUT; }\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_jump_into_chain_declared_in_untaken_if_branch() -> None:
    # The chain is declared only inside an untaken @if branch; the structural
    # tree sees both branches, so the jump is NOT flagged.
    cfg = (
        "@if 0 { table filter chain FOO { ACCEPT; } }\n"
        "table filter chain INPUT { jump FOO; }\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_var_jump_target_is_known_limitation() -> None:
    # `jump $t` -- target is a $var; contract narrowed to literal names, so it
    # is NOT reported as undefined (pinned limitation).
    cfg = "@def $t = FOO;\ntable filter chain INPUT { jump $t; }\n"
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_jump_to_chain_named_like_a_keyword_not_flagged() -> None:
    # A user chain may be named after a header keyword (table/domain/policy/
    # priority/chain) -- the oracle accepts such names. `chain` takes exactly
    # ONE name (or a parenthesised array), so the keyword must be harvested as
    # the chain name, not treated as a name-run terminator (else a valid jump
    # false-flags as undefined).
    for name in ("table", "domain", "policy", "priority", "chain"):
        cfg = (
            "table filter {\n"
            f"  chain {name} {{ ACCEPT; }}\n"
            f"  chain INPUT {{ jump {name}; }}\n"
            "}\n"
        )
        assert find_undefined_chain_jumps(_tree(cfg)) == [], name


def test_uncalled_function_reported_with_sigil() -> None:
    # `@def &myfunc(...)` with no call site: the function ITSELF is the
    # unused definition. The exact-list assert simultaneously pins that
    # its $-parameters are locals and stay unreported.
    cfg = '@def &myfunc($p1, $p2) = LOG log-prefix "$p1:$p2";\n'
    assert find_unused_defs(_tree(cfg)) == ["&myfunc"]


def test_uncalled_function_first_param_not_misregistered() -> None:
    # The first parameter must not be mis-registered as the declared
    # name: the finding is &f, never $a.
    cfg = "@def &f($a, $b) = saddr $b ACCEPT;\n"
    assert find_unused_defs(_tree(cfg)) == ["&f"]


def test_subchain_declaration_harvested_not_flagged_as_undefined() -> None:
    # A mid-rule `proto tcp @subchain "SC" { ... }` places "@subchain" inside
    # the RuleNode span (the structural parser stops the span at the "{" match
    # block, so "@subchain" is in the span not leading it). _declared_chains
    # must recognise the _SUBCHAIN_KW branch and yield "SC" as a declared chain
    # so the subsequent `jump SC` is NOT flagged as undefined.
    cfg = (
        "table filter chain INPUT {\n"
        '  proto tcp @subchain "SC" { dport 22 ACCEPT; }\n'
        "  jump SC;\n"
        "}\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_dangling_goto_detected() -> None:
    # `goto` is the second target keyword in _jump_targets; only `jump` is
    # tested by the existing suite. A goto to a non-existent chain IS flagged.
    cfg = "table filter chain INPUT { goto MISSING; }\n"
    assert "MISSING" in find_undefined_chain_jumps(_tree(cfg))


def test_goto_to_declared_chain_not_flagged() -> None:
    # A goto to a declared chain must not produce a false positive.
    # The second goto (MISSING) makes the test non-vacuous: if goto were
    # ignored entirely the result would be [] instead of ["MISSING"], failing
    # the assertion and proving goto targets ARE collected.
    cfg = (
        "table filter {\n"
        "  chain FOO { ACCEPT; }\n"
        "  chain INPUT { goto FOO; goto MISSING; }\n"
        "}\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == ["MISSING"]


def test_jump_to_chain_in_array_declaration_not_flagged() -> None:
    # `chain (FOO BAR) { ... }` declares both FOO and BAR via the array-form
    # branch in _declared_chains. A jump to FOO (or BAR) must NOT be flagged.
    cfg = (
        "table filter {\n"
        "  chain (FOO BAR) { ACCEPT; }\n"
        "  chain INPUT { jump FOO; }\n"
        "}\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == []


def test_jump_to_name_absent_from_array_declaration_is_flagged() -> None:
    # Only names IN the array are declared; a jump to a name outside it IS
    # an undefined chain jump.
    cfg = (
        "table filter {\n"
        "  chain (FOO BAR) { ACCEPT; }\n"
        "  chain INPUT { jump MISSING; }\n"
        "}\n"
    )
    assert "MISSING" in find_undefined_chain_jumps(_tree(cfg))


def test_def_used_only_in_set_not_flagged_as_unused() -> None:
    # $x appears ONLY inside `@set $s = ($x)` -- visit_SetNode must harvest
    # the $x mention from the span so it is NOT reported as an unused @def.
    cfg = "@def $x = 22;\n@set $s = ($x);\n"
    assert "$x" not in find_unused_defs(_tree(cfg))


def test_def_used_only_in_if_condition_not_flagged_as_unused() -> None:
    # $x appears ONLY in the @if condition span, not in the branch body.
    # visit_IfNode must harvest cond_span so $x is NOT reported as unused.
    cfg = "@def $x = 1;\n@if $x { ACCEPT; }\n"
    assert "$x" not in find_unused_defs(_tree(cfg))


def test_multiple_unused_defs_sorted_exactly() -> None:
    # Two unused defs given in reverse-alphabetical source order must come back
    # in sorted order, pinning the sort contract that `in`-only asserts leave
    # unpinned.
    cfg = "@def $beta = 2;\n@def $alpha = 1;\n"
    assert find_unused_defs(_tree(cfg)) == ["$alpha", "$beta"]


def test_multiple_dangling_jumps_sorted_and_deduped() -> None:
    # FOO is jumped to twice; result must contain it exactly ONCE (set dedup)
    # and the full list must be sorted, pinning both contracts.
    cfg = (
        "table filter chain INPUT {\n"
        "  jump FOO;\n"
        "  jump BAR;\n"
        "  jump FOO;\n"
        "}\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == ["BAR", "FOO"]


def test_deeply_nested_input_does_not_crash_analyzers() -> None:
    # parse_to_block must not RecursionError on pathological nesting the
    # product rejects; it caps depth like Parser.enter (error-tolerant).
    depth = 600  # past Python's default recursion headroom (~500 frames)
    cfg = (
        "table filter "
        + "chain X { " * depth
        + "ACCEPT; "
        + "} " * depth
        + "\n"
    )
    tree = Parser.parse_to_block(cfg)  # must not raise
    find_unused_defs(tree)  # must not raise
    find_undefined_chain_jumps(tree)  # must not raise


def test_severity_order_is_error_warning_info() -> None:
    # The IntEnum order IS the output and gating order.
    assert Severity.ERROR < Severity.WARNING < Severity.INFO


def test_run_analysis_wraps_legacy_analyzers_in_findings() -> None:
    cfg = "@def $foo = 1;\ntable filter chain INPUT { jump MISSING; }\n"
    assert run_analysis(_tree(cfg)) == [
        Finding(
            Severity.WARNING,
            "unused-definition",
            "unused definition: $foo",
        ),
        Finding(
            Severity.WARNING,
            "undefined-jump",
            "jump to undefined chain: MISSING",
        ),
    ]


def test_run_analysis_keeps_unused_block_before_undefined_block() -> None:
    # Registration order dominates message text within one severity tier:
    # "unused definition: $z" > "jump to undefined chain: A" as strings,
    # yet the unused block still prints first (never interleaved).
    cfg = "@def $z = 1;\ntable filter chain INPUT { jump A; }\n"
    messages = [f.message for f in run_analysis(_tree(cfg))]
    assert messages == [
        "unused definition: $z",
        "jump to undefined chain: A",
    ]


def test_run_analysis_clean_config_is_empty() -> None:
    cfg = "@def $x = 1;\ntable filter chain INPUT { saddr $x ACCEPT; }\n"
    assert run_analysis(_tree(cfg)) == []


def test_called_function_not_flagged() -> None:
    cfg = (
        "@def &f($a) = saddr $a ACCEPT;\n"
        "table filter chain INPUT { &f(1.2.3.4); }\n"
    )
    assert find_unused_defs(_tree(cfg)) == []


def test_function_called_only_from_unused_function_counts_as_used() -> None:
    # No transitive liveness (documented safe-direction limitation):
    # &g is unused, but its body calls &f, so &f counts as used.
    cfg = "@def &f($a) = saddr $a ACCEPT;\n@def &g($a) = &f($a);\n"
    assert find_unused_defs(_tree(cfg)) == ["&g"]


def test_function_def_does_not_count_as_its_own_use() -> None:
    # The definition head ('&', 'f') must be excluded from mentions --
    # otherwise every function would mark itself used.
    cfg = "@def &f($a) = saddr $a ACCEPT;\n"
    assert find_unused_defs(_tree(cfg)) == ["&f"]


def test_unused_vars_and_functions_sort_together() -> None:
    # "$" (0x24) sorts before "&" (0x26): vars first, then functions.
    cfg = "@def $b = 1;\n@def &a($x) = saddr $x ACCEPT;\n"
    assert find_unused_defs(_tree(cfg)) == ["$b", "&a"]


def test_realgoto_to_missing_chain_is_flagged() -> None:
    # realgoto is a deprecated alias of goto and a real jump edge; the
    # structural tree keeps it verbatim (the remap is eval-path-only).
    cfg = "table filter chain INPUT { realgoto MISSING; }\n"
    assert "MISSING" in find_undefined_chain_jumps(_tree(cfg))


def test_realgoto_to_declared_chain_not_flagged() -> None:
    # The second realgoto keeps the test non-vacuous (as in the goto
    # twin above).
    cfg = (
        "table filter {\n"
        "  chain FOO { ACCEPT; }\n"
        "  chain INPUT { realgoto FOO; realgoto MISSING; }\n"
        "}\n"
    )
    assert find_undefined_chain_jumps(_tree(cfg)) == ["MISSING"]


def test_jump_inside_function_def_body_is_flagged_when_undefined() -> None:
    # A function body is a flat span on its DefNode; the chain harvest
    # must scan it, so a jump to a missing chain inside a body IS found.
    cfg = "@def &f() = jump MISSING;\n"
    assert "MISSING" in find_undefined_chain_jumps(_tree(cfg))


def test_subchain_names_populate_collector_registry() -> None:
    # The new subchains field has no public consumer until the
    # unreachable-chain analyzer lands (a later task); pin its
    # population directly so this commit ships no untested lines.
    cfg = (
        "table filter chain INPUT {\n"
        '  proto tcp @subchain "SC" { ACCEPT; }\n'
        "}\n"
    )
    collector = _ChainCollector()
    _walk_all(_tree(cfg), collector)
    assert collector.subchains == {"SC"}


def test_realgoto_reported_as_deprecated_with_hint() -> None:
    cfg = "table filter chain INPUT { realgoto FOO; }\n"
    assert find_deprecated_keywords(_tree(cfg)) == [
        Finding(
            Severity.INFO,
            "deprecated-keyword",
            "deprecated keyword: realgoto (use goto)",
        )
    ]


def test_goto_is_not_deprecated() -> None:
    cfg = "table filter chain INPUT { goto FOO; }\n"
    assert find_deprecated_keywords(_tree(cfg)) == []


def test_repeated_realgoto_reported_once() -> None:
    cfg = (
        "table filter chain INPUT { realgoto A; }\n"
        "table filter chain OUTPUT { realgoto B; }\n"
    )
    assert len(find_deprecated_keywords(_tree(cfg))) == 1


def test_chain_named_realgoto_is_pinned_false_positive() -> None:
    # The scan is token-membership, not keyword-position dispatch: a
    # chain literally NAMED realgoto false-fires via its jump-target
    # token -- a documented false positive of this analyzer.
    cfg = (
        "table filter {\n"
        "  chain realgoto { ACCEPT; }\n"
        "  chain INPUT { jump realgoto; }\n"
        "}\n"
    )
    assert len(find_deprecated_keywords(_tree(cfg))) == 1


def _unreachable(cfg: str) -> list[str]:
    return [f.message for f in find_unreachable_chains(_tree(cfg))]


def test_never_jumped_user_chain_is_unreachable() -> None:
    # INPUT is a built-in entry point -> excluded; FOO is flagged. The
    # exact list pins both directions at once.
    cfg = (
        "table filter {\n"
        "  chain INPUT { ACCEPT; }\n"
        "  chain FOO { ACCEPT; }\n"
        "}\n"
    )
    assert _unreachable(cfg) == ["unreachable chain: FOO"]


def test_jumped_chain_is_reachable() -> None:
    cfg = (
        "table filter {\n"
        "  chain FOO { ACCEPT; }\n"
        "  chain INPUT { jump FOO; }\n"
        "}\n"
    )
    assert _unreachable(cfg) == []


def test_realgoto_counts_as_reaching() -> None:
    # BAR keeps the test non-vacuous: only the realgoto'd chain clears.
    cfg = (
        "table filter {\n"
        "  chain FOO { ACCEPT; }\n"
        "  chain BAR { ACCEPT; }\n"
        "  chain INPUT { realgoto FOO; }\n"
        "}\n"
    )
    assert _unreachable(cfg) == ["unreachable chain: BAR"]


def test_brouting_is_builtin_but_sibling_user_chain_is_flagged() -> None:
    # BROUTING is the ebtables broute entry chain -- the sixth allowlist
    # name; a hand-written five-name list would false-flag it.
    cfg = (
        "domain eb table broute {\n"
        "  chain BROUTING { ACCEPT; }\n"
        "  chain XX { ACCEPT; }\n"
        "}\n"
    )
    assert _unreachable(cfg) == ["unreachable chain: XX"]


def test_named_subchain_is_implicitly_reached() -> None:
    # @subchain "SC" carries its own implicit jump: no literal jump
    # token exists, yet SC must not be flagged (ferm's own antiddos
    # example uses exactly this shape).
    cfg = (
        "table filter chain INPUT {\n"
        '  proto tcp @subchain "SC" { ACCEPT; }\n'
        "}\n"
    )
    assert _unreachable(cfg) == []


def test_chain_reached_only_from_function_body_not_flagged() -> None:
    cfg = "@def &f() = jump FOO;\ntable filter chain FOO { ACCEPT; }\n"
    assert _unreachable(cfg) == []


def test_chain_reached_only_via_var_jump_is_pinned_false_positive() -> None:
    # `jump $t` targets are invisible (literal-name contract), so FOO
    # IS flagged -- a documented false positive of this analyzer.
    cfg = (
        "@def $t = FOO;\n"
        "table filter {\n"
        "  chain FOO { ACCEPT; }\n"
        "  chain INPUT { jump $t; }\n"
        "}\n"
    )
    assert _unreachable(cfg) == ["unreachable chain: FOO"]


def _cycles(cfg: str) -> list[str]:
    return [f.message for f in find_jump_cycles(_tree(cfg))]


def test_self_loop_reported() -> None:
    cfg = "table filter chain FOO { jump FOO; }\n"
    assert _cycles(cfg) == ["jump cycle: FOO -> FOO"]


def test_two_cycle_reported_once_with_canonical_start() -> None:
    # Declared B-first so discovery order differs from the canonical
    # rotation; the single finding must still start at A.
    cfg = "table filter {\n  chain B { jump A; }\n  chain A { jump B; }\n}\n"
    assert _cycles(cfg) == ["jump cycle: A -> B -> A"]


def test_three_cycle_reported_once() -> None:
    cfg = (
        "table filter {\n"
        "  chain A { jump B; }\n"
        "  chain B { jump C; }\n"
        "  chain C { jump A; }\n"
        "}\n"
    )
    assert _cycles(cfg) == ["jump cycle: A -> B -> C -> A"]


def test_dag_diamond_is_clean() -> None:
    # A->B, A->C, B->D, C->D: revisiting D via two paths is NOT a cycle.
    cfg = (
        "table filter {\n"
        "  chain A { jump B; jump C; }\n"
        "  chain B { jump D; }\n"
        "  chain C { jump D; }\n"
        "  chain D { ACCEPT; }\n"
        "}\n"
    )
    assert _cycles(cfg) == []


def test_goto_and_realgoto_edges_participate() -> None:
    cfg = (
        "table filter {\n  chain A { goto B; }\n  chain B { realgoto A; }\n}\n"
    )
    assert _cycles(cfg) == ["jump cycle: A -> B -> A"]


def test_long_linear_chain_does_not_recurse() -> None:
    # The DFS axis is the NUMBER of chains, which MAX_BLOCK_DEPTH does
    # not bound; the iterative search must survive a path far past the
    # interpreter's recursion limit.
    n = 3000
    body = "\n".join(
        f"  chain C{i:04d} {{ jump C{i + 1:04d}; }}" for i in range(n)
    )
    cfg = f"table filter {{\n{body}\n  chain C{n:04d} {{ ACCEPT; }}\n}}\n"
    assert find_jump_cycles(_tree(cfg)) == []


def test_cross_branch_if_cycle_is_pinned_false_positive() -> None:
    # Both @if branches feed ONE graph: A->B (then) plus B->A (else) is
    # reported although no single generated ruleset contains both --
    # the documented phantom-cycle class.
    cfg = (
        "@if $c {\n"
        "  table filter chain A { jump B; }\n"
        "} @else {\n"
        "  table filter chain B { jump A; }\n"
        "}\n"
    )
    assert _cycles(cfg) == ["jump cycle: A -> B -> A"]


def test_cross_table_cycle_is_pinned_false_positive() -> None:
    # The chain namespace flattens (domain, table): filter's A->B plus
    # nat's B->A is reported as one cycle -- same documented class.
    cfg = (
        "table filter { chain A { jump B; } chain B { ACCEPT; } }\n"
        "table nat { chain B { jump A; } chain A { ACCEPT; } }\n"
    )
    assert _cycles(cfg) == ["jump cycle: A -> B -> A"]


def test_cycle_via_function_call_is_pinned_false_negative() -> None:
    # A real runtime loop routed through a function CALL is invisible:
    # a top-level @def body has no chain context (empty edge sources)
    # and a call site (&f()) is not a jump token. The error tier
    # under-reports here -- the one safe-direction gap of this analyzer.
    cfg = "@def &f() = jump A;\ntable filter chain A { &f(); }\n"
    assert _cycles(cfg) == []


def test_uncalled_nested_def_contributes_phantom_edge() -> None:
    # The dual of the gap above: a @def nested in a chain block is
    # attributed to that chain even when the function is NEVER called,
    # so its body's jump manufactures a phantom edge -- the third
    # documented over-reporting class (with cross-@if and cross-table).
    cfg = "table filter chain B { @def &f() = jump B; ACCEPT; }\n"
    assert _cycles(cfg) == ["jump cycle: B -> B"]


def _duplicates(cfg: str) -> list[str]:
    return [f.message for f in find_duplicate_definitions(_tree(cfg))]


def test_same_scope_duplicate_def_reported() -> None:
    # ferm semantics (oracle-verified): a same-frame re-@def silently
    # last-wins -- legal but pointless, hence a style warning.
    cfg = "@def $x = 1;\n@def $x = 2;\n"
    assert _duplicates(cfg) == ["duplicate definition: $x"]


def test_nested_redefinition_is_shadowing_not_duplicate() -> None:
    # Every '{' pushes a fresh oracle stack frame; the inner value does
    # not survive the '}' -- genuine shadowing, never reported.
    cfg = (
        "@def $x = 1;\n"
        "table filter chain INPUT { @def $x = 2; saddr $x ACCEPT; }\n"
    )
    assert _duplicates(cfg) == []


def test_braced_if_redefinition_is_shadowing() -> None:
    # A braced @if branch is a real Block (frame) too.
    cfg = "@def $x = 1;\n@if $c { @def $x = 2; }\n"
    assert _duplicates(cfg) == []


def test_braceless_if_guarded_redef_is_pinned_blind_spot() -> None:
    # The structural parser swallows a braceless guarded statement into
    # the IfNode condition span (then_body stays empty), so this @def
    # is invisible to the analyzer -- a documented blind spot.
    cfg = "@def $x = 1;\n@if $c @def $x = 2;\n"
    assert _duplicates(cfg) == []


def test_single_definition_is_clean() -> None:
    assert _duplicates("@def $x = 1;\n") == []


def test_triple_definition_reported_once() -> None:
    cfg = "@def $x = 1;\n@def $x = 2;\n@def $x = 3;\n"
    assert _duplicates(cfg) == ["duplicate definition: $x"]


def test_duplicate_function_def_reported_with_sigil() -> None:
    cfg = "@def &f($a) = saddr $a ACCEPT;\n@def &f($a) = daddr $a ACCEPT;\n"
    assert _duplicates(cfg) == ["duplicate definition: &f"]


def test_cycle_through_non_last_edge_of_a_branching_chain() -> None:
    # A has TWO outgoing jumps; the cycle runs through B, the edge that
    # sorts FIRST, so the adjacency fold must keep every edge per
    # source, not just the last one appended.
    cfg = (
        "table filter {\n"
        "  chain A { jump B; jump C; }\n"
        "  chain B { jump A; }\n"
        "  chain C { ACCEPT; }\n"
        "}\n"
    )
    assert _cycles(cfg) == ["jump cycle: A -> B -> A"]


def test_duplicate_var_def_with_function_call_rhs() -> None:
    # The '&' in the RHS call must not re-classify the $-var def as a
    # function def: the declared name is decided LEFT of '=' only.
    cfg = (
        "@def &f($a) = saddr $a ACCEPT;\n"
        "@def $x = 1;\n"
        "@def $x = &f(2);\n"
        "table filter chain INPUT { &f(3); saddr $x ACCEPT; }\n"
    )
    assert _duplicates(cfg) == ["duplicate definition: $x"]


def test_var_def_rhs_mentions_count_every_ref() -> None:
    # $a and $b are BOTH mentioned by $x's RHS; only $x itself is
    # unused (a mention registry that drops all but the first RHS ref
    # would false-flag $b).
    cfg = "@def $a = 1;\n@def $b = 2;\n@def $x = $a $b;\n"
    assert find_unused_defs(_tree(cfg)) == ["$x"]


@pytest.mark.parametrize(
    ("tok", "expected"),
    [
        ('""', True),  # empty pair is exactly the minimum length
        ("''", True),
        ("'A'", True),
        ('"A"', True),
        ('"', False),  # a lone quote is not a pair
        ("'", False),
        ("A", False),
        ("", False),
        ("'A\"", False),  # mismatched pair
    ],
)
def test_is_quoted_boundaries(tok: str, expected: bool) -> None:
    assert _is_quoted(tok) is expected


@pytest.mark.parametrize(
    ("span", "expected"),
    [
        (["chain", "FOO", "{"], ["FOO"]),
        # dominant one-line header form: chain sits mid-span.
        (["table", "filter", "chain", "FOO", "{"], ["FOO"]),
        (["chain", "(", "A", "B", ")", "{"], ["A", "B"]),
        # $vars are literal-only, skipped in both forms.
        (["chain", "(", "$v", "B", ")", "{"], ["B"]),
        (["chain", "$v", "{"], []),
        (["chain", "'Q'", "{"], ["Q"]),
        (["chain", '"Q"', "policy", "DROP", ";"], ["Q"]),
        # bare 'chain' with no name: boundary tokens are not names.
        (["chain", ";"], []),
        (["chain", "{"], []),
        (["chain"], []),
        # unterminated array at span end must not scan past the end.
        (["chain", "(", "A", "B"], ["A", "B"]),
        # a second declaration after a closed array is still seen.
        (["chain", "(", "A", ")", "chain", "B", "{"], ["A", "B"]),
        # an EMBEDDED declaration is found at ANY offset, odd included.
        (["x", "chain", "FOO", "{"], ["FOO"]),
        # @subchain declares only when the name is quoted.
        (["@subchain", "'S'", "{"], ["S"]),
        (["@subchain", "S", "{"], []),
        (["@subchain"], []),
        # an unquoted @subchain must not stop the scan for later ones.
        (["@subchain", "$v", "@subchain", "'S'", "{"], ["S"]),
    ],
)
def test_declared_chains_token_scan(
    span: list[str], expected: list[str]
) -> None:
    assert list(_declared_chains(span)) == expected


def _nested_if(depth: int, payload: str) -> str:
    return "@if $c { " * depth + payload + "} " * depth


def test_duplicate_scan_ignores_nesting_past_the_parser_cap() -> None:
    # End-to-end contract on hostile nesting: the STRUCTURAL PARSER
    # stops descending at its own MAX_BLOCK_DEPTH cap, so content one
    # level past it is silently invisible to the analyzers (advisory
    # lint stays total instead of raising).
    payload = "@def $x = 1; @def $x = 2; "
    seen = _nested_if(MAX_BLOCK_DEPTH - 1, payload)
    ignored = _nested_if(MAX_BLOCK_DEPTH, payload)
    assert _duplicates(seen) == ["duplicate definition: $x"]
    assert _duplicates(ignored) == []


def test_unused_def_scan_ignores_nesting_past_the_parser_cap() -> None:
    # Same end-to-end boundary for the NodeVisitor walk.
    seen = _nested_if(MAX_BLOCK_DEPTH - 1, "@def $x = 1; ")
    ignored = _nested_if(MAX_BLOCK_DEPTH, "@def $x = 1; ")
    assert find_unused_defs(_tree(seen)) == ["$x"]
    assert find_unused_defs(_tree(ignored)) == []


def test_jump_cycle_scan_ignores_nesting_past_the_parser_cap() -> None:
    # Same end-to-end boundary for the edge collector; the enclosing
    # chain block itself consumes one nesting level, hence MAX-2/MAX-1.
    def cfg(depth: int) -> str:
        inner = _nested_if(depth, "jump FOO; ")
        return "table filter chain FOO { " + inner + "}"

    assert _cycles(cfg(MAX_BLOCK_DEPTH - 2)) == ["jump cycle: FOO -> FOO"]
    assert _cycles(cfg(MAX_BLOCK_DEPTH - 1)) == []


def _bury(block: Block, depth: int) -> Block:
    # Wrap a parsed Block under ``depth`` synthetic BlockNode levels --
    # deeper than parse_to_block can ever build, so the analyzers' OWN
    # depth guard (their second line of defense behind the parser cap)
    # is what decides visibility.
    pos = block.source_pos
    for _ in range(depth):
        block = Block(pos, statements=(BlockNode(pos, body=block),))
    return block


def test_duplicate_guard_trips_exactly_past_max_block_depth() -> None:
    # A block AT depth MAX_BLOCK_DEPTH is still scanned; one PAST it is
    # ignored.
    inner = _tree("@def $x = 1; @def $x = 2; ")
    at_cap = find_duplicate_definitions(_bury(inner, MAX_BLOCK_DEPTH))
    past_cap = find_duplicate_definitions(_bury(inner, MAX_BLOCK_DEPTH + 1))
    assert [f.message for f in at_cap] == ["duplicate definition: $x"]
    assert past_cap == []


def test_walk_guard_trips_exactly_past_max_block_depth() -> None:
    inner = _tree("@def $x = 1; ")
    assert find_unused_defs(_bury(inner, MAX_BLOCK_DEPTH)) == ["$x"]
    assert find_unused_defs(_bury(inner, MAX_BLOCK_DEPTH + 1)) == []


def test_edge_guard_trips_exactly_past_max_block_depth() -> None:
    # The chain BODY sits one level below the buried root, hence MAX-1.
    inner = _tree("table filter chain FOO { jump FOO; }")
    at_cap = find_jump_cycles(_bury(inner, MAX_BLOCK_DEPTH - 1))
    past_cap = find_jump_cycles(_bury(inner, MAX_BLOCK_DEPTH))
    assert [f.message for f in at_cap] == ["jump cycle: FOO -> FOO"]
    assert past_cap == []
