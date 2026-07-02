"""The two internal AST proofs over the eval-free parse_to_block tree.

These exercise the tree's name- and graph-analysis capabilities (the layer-6
acceptance criterion): they are NOT a linter -- no CLI, no severity, no user
output -- only proofs that the structural tree is fit for analysis. Both
consume Parser.parse_to_block (both @if branches), not the walk tree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyferm.analysis import (
    Finding,
    Severity,
    _ChainCollector,
    _walk_all,
    find_deprecated_keywords,
    find_undefined_chain_jumps,
    find_unused_defs,
    run_analysis,
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
