"""Structural AST node taxonomy and the SourcePosition forward seam."""

from __future__ import annotations

from pyferm.scope import SourcePosition


def test_source_position_has_optional_column_defaulting_none() -> None:
    pos = SourcePosition("f.ferm", 3)
    assert pos.column is None
    pos2 = SourcePosition("f.ferm", 3, column=None)
    assert pos2.column is None
