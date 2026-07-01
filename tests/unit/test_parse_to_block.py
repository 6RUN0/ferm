"""Structural coverage for the eval-free Parser.parse_to_block.

parse_to_block builds a retained tree over BOTH @if branches without
evaluating conditions, substituting variables, loading modules or resolving
@include. It is off the golden/parity path -- these tests pin the structure
the analyzers consume.
"""

from __future__ import annotations

from pyferm.parser import Parser
from pyferm.tree import Block, IfNode


def _block(config: str) -> Block:
    return Parser.parse_to_block(config)


def test_if_captures_both_branch_bodies() -> None:
    root = _block("@if 1 { A; } @else { B; }\n")
    ifs = [n for n in root.statements if isinstance(n, IfNode)]
    assert len(ifs) == 1
    node = ifs[0]
    # BOTH branches are structured Blocks -- the key capability the walk lacks.
    assert isinstance(node.then_body, Block)
    assert isinstance(node.else_body, Block)


def test_untaken_branch_is_structured_without_eval() -> None:
    # @if 0 does NOT evaluate to skip structuring -- parse_to_block sees the
    # body.
    root = _block("@if 0 { table filter chain INPUT { saddr $x ACCEPT; } }\n")
    ifs = [n for n in root.statements if isinstance(n, IfNode)]
    assert len(ifs) == 1
    then_body = ifs[0].then_body
    assert isinstance(then_body, Block)
    # non-empty: the untaken body is present
    assert then_body.statements
