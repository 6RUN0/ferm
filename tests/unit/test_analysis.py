"""The two internal AST proofs over the eval-free parse_to_block tree.

These exercise the tree's name- and graph-analysis capabilities (the layer-6
acceptance criterion): they are NOT a linter -- no CLI, no severity, no user
output -- only proofs that the structural tree is fit for analysis. Both
consume Parser.parse_to_block (both @if branches), not the walk tree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyferm.analysis import (
    find_undefined_chain_jumps,
    find_unused_defs,
)
from pyferm.parser import Parser

if TYPE_CHECKING:
    from pyferm.tree import Block


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


def test_interpolation_is_known_limitation() -> None:
    # $x only inside "prefix $x" (one double-quoted token) -> false unused,
    # pinned as a known limitation (syntactic-references contract).
    cfg = (
        "@def $x = 1;\n"
        'table filter chain OUTPUT { mod comment comment "$x" ACCEPT; }\n'
    )
    assert "$x" in find_unused_defs(_tree(cfg))  # documents the blind spot


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


def test_function_parameter_not_flagged_as_unused_def() -> None:
    # `@def &f($p1, $p2) = ...` -- $p1/$p2 are function parameters (locals),
    # NOT @def variable declarations. They must not be reported as unused defs
    # (this exact shape ships in reference/test/misc/stringex.ferm).
    cfg = '@def &myfunc($p1, $p2) = LOG log-prefix "$p1:$p2";\n'
    assert find_unused_defs(_tree(cfg)) == []


def test_function_first_param_with_used_second_not_flagged() -> None:
    # The first parameter must not be mis-registered as the declared name.
    cfg = "@def &f($a, $b) = saddr $b ACCEPT;\n"
    assert find_unused_defs(_tree(cfg)) == []


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
