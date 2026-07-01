"""Structural coverage for the eval-free Parser.parse_to_block.

parse_to_block builds a retained tree over BOTH @if branches without
evaluating conditions, substituting variables, loading modules or resolving
@include. It is off the golden/parity path -- these tests pin the structure
the analyzers consume.
"""

from __future__ import annotations

from pyferm.parser import Parser
from pyferm.tree import Block, BlockNode, DefNode, HeaderNode, IfNode, RuleNode


def _block(config: str) -> Block:
    return Parser.parse_to_block(config)


def test_match_block_nests_as_structured_block() -> None:
    # `saddr $x { ... }` must nest the block body as a BlockNode the analyzers
    # descend into -- NOT be lumped into one RuleNode span (the arity-blind
    # capture used to do that, hiding inner decls/jumps/$vars).
    root = _block("saddr $x { table filter chain FOO { jump BAR; } }\n")
    kinds = [type(n).__name__ for n in root.statements]
    assert kinds == ["RuleNode", "BlockNode"]
    rule, block = root.statements
    assert isinstance(rule, RuleNode)
    assert rule.span == ("saddr", "$", "x")  # $x still visible for unused-defs
    assert isinstance(block, BlockNode)
    assert isinstance(block.body, Block)
    header = block.body.statements[0]
    assert isinstance(header, HeaderNode)  # chain FOO now a HeaderNode
    assert isinstance(header.body, Block)
    inner_rule = header.body.statements[0]
    assert isinstance(inner_rule, RuleNode)
    assert inner_rule.span == ("jump", "BAR", ";")  # inner jump visible


def test_directive_block_body_is_not_split() -> None:
    # A @def with a { } body keeps the whole body in its span (stop_at_brace is
    # off for directives), so it is one DefNode, not a Def + a stray block.
    root = _block("@def &svc($p) = { proto tcp dport $p ACCEPT; }\n")
    assert [type(n).__name__ for n in root.statements] == ["DefNode"]
    defn = root.statements[0]
    assert isinstance(defn, DefNode)
    assert defn.span[-1] == "}"  # body retained through the closing brace


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
