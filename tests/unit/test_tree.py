"""Structural AST node taxonomy and the SourcePosition forward seam."""

from __future__ import annotations

import dataclasses

import pytest

from pyferm.scope import SourcePosition
from pyferm.tree import Block, DefNode, IfNode, RuleNode


def test_source_position_has_optional_column_defaulting_none() -> None:
    pos = SourcePosition("f.ferm", 3)
    assert pos.column is None
    pos2 = SourcePosition("f.ferm", 3, column=None)
    assert pos2.column is None


def test_block_holds_ordered_statements() -> None:
    pos = SourcePosition("f", 1)
    rule = RuleNode(source_pos=pos, span=("proto", "tcp", "ACCEPT", ";"))
    block = Block(source_pos=pos, statements=(rule,))
    assert block.statements == (rule,)


def test_ifnode_walk_shape_cond_span_only() -> None:
    # The WALK-built IfNode carries only the condition span; branch bodies stay
    # None on the walk path (branches are handled live via collect_tokens after
    # the condition is evaluated). Structured branch bodies are populated ONLY
    # by parse_to_block (analyzer pass).
    pos = SourcePosition("f", 1)
    node = IfNode(source_pos=pos, cond_span=("$", "x"))
    assert node.cond_span == ("$", "x")  # $x is two raw tokens
    assert node.then_body is None
    assert node.else_body is None


def test_nodes_are_frozen() -> None:
    node = DefNode(
        source_pos=SourcePosition("f", 1), span=("$", "x", "=", "1", ";")
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        node.span = ()  # type: ignore[misc]
