"""
Mutation-killing unit tests for :mod:`pyferm.walker`.

Each test pins one real behavioural gap left by a surviving mutant on the
single AST evaluation path (the ``visit_<NodeType>`` dispatch). Companion to
``tests/unit/test_walker_slicing.py`` and ``tests/unit/test_parser.py``; the
walker is driven by parsing real ferm source through :func:`parse_source`.
"""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from tests.unit._parse import parse_source


def test_negation_error_names_routed_header_keyword() -> None:
    """
    A leftover ``!`` on a route_resolved header keyword names that keyword.

    ``! table`` resolves to the ``table`` header and is routed through
    ``route_resolved`` to a typed HeaderNode -- the leaf ``handle`` (which
    re-stamps ``shown_keyword``) is never reached, and ``table`` is not
    deprecated so ``_visit_stmt_node`` does not remap it either. Line 181 of
    ``visit_RuleNode`` (``self.shown_keyword = keyword``) is therefore the
    only site that stamps the keyword, so the trailing negation diagnostic
    must name ``table`` rather than ``None``.
    """
    with pytest.raises(FermError, match="Doesn't support negation: table"):
        parse_source("table filter chain INPUT { ! table nat ACCEPT; }")
