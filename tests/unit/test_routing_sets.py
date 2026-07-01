"""Routing-set alignment guard for the walk dispatcher.

`_dispatch_leading` consumes a `_STMT_KEYWORDS` token BEFORE
`_visit_stmt_node` confirms it can dispatch it. That is safe only while
`_STMT_KEYWORDS` is exactly the set `_visit_stmt_node` routes -- otherwise a
consumed token would be silently lost and a headless rule captured.
`_visit_stmt_node` routes every `_STMT_NODES` key (directives + subchains)
plus every `_HEADER_KEYWORDS` member, so this equality is the invariant that
keeps the consume-before-confirm correct. A future edit adding a keyword to
one side only trips this test.
"""

from __future__ import annotations

from pyferm.parser import (
    _HEADER_KEYWORDS,
    _STMT_KEYWORDS,
    _STMT_NODES,
    _SUBCHAIN_KEYWORDS,
)


def test_stmt_keywords_exactly_the_dispatched_set() -> None:
    dispatched = frozenset(_STMT_NODES) | _HEADER_KEYWORDS
    assert dispatched == _STMT_KEYWORDS


def test_subchain_keywords_are_dispatched_stmt_nodes() -> None:
    # _visit_stmt_node routes _SUBCHAIN_KEYWORDS via a dedicated branch, so
    # they must also be _STMT_NODES keys (SubchainNode) and _STMT_KEYWORDS.
    assert _SUBCHAIN_KEYWORDS.issubset(frozenset(_STMT_NODES))
    assert _SUBCHAIN_KEYWORDS.issubset(_STMT_KEYWORDS)
