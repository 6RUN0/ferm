"""The shared token-scan primitives, and analysis.py's re-export of them."""

from __future__ import annotations

import pyferm._treescan as treescan
from pyferm import analysis


def test_analysis_reexports_are_the_treescan_objects() -> None:
    # Re-export identity: analysis must bind the SAME objects, so callers
    # and mutant-kill tests that import pyferm.analysis._jump_targets keep
    # hitting the canonical definition.
    for name in (
        "_str_tokens",
        "_is_quoted",
        "_unquote",
        "_index_of",
        "_iter_var_refs",
        "_iter_func_refs",
        "_jump_targets",
        "_subchain_names",
        "_declared_chains",
        "_child_blocks",
        "_JUMP_KW",
        "_SUBCHAIN_KW",
        "_CHAIN_VALUE_BOUNDARY",
    ):
        assert getattr(analysis, name) is getattr(treescan, name), name


def test_jump_targets_still_works_through_treescan() -> None:
    assert list(treescan._jump_targets(("jump", "foo", ";"))) == ["foo"]
    assert list(treescan._jump_targets(("goto", "$x"))) == []  # $var skipped


def test_quoted_interpolation_skipped_across_all_harvesters() -> None:
    # A bare $var is skipped as the token pair ("$", name); a quoted
    # '"$x"'/'"@arr"' evades that skip (it starts with '"', not '$') unless
    # each harvester also checks the unquoted body. Cover all five sites.
    assert list(treescan._jump_targets(("jump", '"$x"'))) == []
    assert list(treescan._jump_targets(("jump", '"@arr"'))) == []
    assert list(treescan._chain_decls(["chain", '"$x"', "{"])) == []
    assert list(
        treescan._chain_decls(["chain", "(", '"$x"', "A", ")", "{"])
    ) == ["A"]
    assert list(treescan._chain_decls(["@subchain", '"$x"', "{"])) == []
    assert list(treescan._subchain_decls(["@subchain", '"$x"', "{"])) == []
    assert list(treescan._subchain_pairs(["@gotosubchain", '"$x"', "{"])) == []
    # legit literal quoted names must keep being harvested
    assert list(treescan._chain_decls(["chain", '"FOO"', "{"])) == ["FOO"]
    assert list(treescan._jump_targets(("jump", '"FOO"'))) == ["FOO"]
    assert list(treescan._subchain_decls(["@subchain", '"FOO"', "{"])) == [
        "FOO"
    ]
