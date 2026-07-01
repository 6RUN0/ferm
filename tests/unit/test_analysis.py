"""The two internal AST proofs over the eval-free parse_to_block tree.

These exercise the tree's name- and graph-analysis capabilities (the layer-6
acceptance criterion): they are NOT a linter -- no CLI, no severity, no user
output -- only proofs that the structural tree is fit for analysis. Both
consume Parser.parse_to_block (both @if branches), not the walk tree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyferm.analysis import find_unused_defs
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
