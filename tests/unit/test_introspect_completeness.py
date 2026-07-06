"""
Completeness gate: curated BUILTINS vs the parser's dispatch tables.

Every fixed keyword the parser or evaluator dispatches now lives in a
table -- ``STMT_TABLE``, the staged leaf tables on :class:`Parser`,
``Evaluator.BUILTIN_FUNCTIONS`` -- or in ``CORE_TARGETS``, so the gate
is a plain set equality; the AST scan this file used to run (and its
manual ignore/known lists) died with the if-chains it scanned.
``@if``/``@else`` stay literal branches with unique constructors and
are named explicitly; the punctuation control tokens (``;`` ``}`` ``$``
``&``) are dispatch, not documented keywords, so the union simply
leaves ``_LEAF_CONTROL``/``_LEAF_SIGILS`` out.
"""

from __future__ import annotations

from pyferm.functions import Evaluator
from pyferm.introspect import BUILTINS, BuiltinCategory
from pyferm.parser import _LEAF_MODULE_LOAD, STMT_TABLE, Parser, StmtKind
from pyferm.rules import CORE_TARGETS


def test_builtins_cover_exactly_the_dispatch_tables() -> None:
    documented = (
        frozenset(STMT_TABLE)
        | frozenset(_LEAF_MODULE_LOAD)
        | Parser._LEAF_ACTIONS.keys()
        # @if -> IfNode in _dispatch_leading; @else -- a _LEAF_CONTROL
        # key, but (unlike ";"/"}") a documented builtin, hence named
        # explicitly.
        | {"@if", "@else"}
        | frozenset(CORE_TARGETS)
        | Evaluator.BUILTIN_FUNCTIONS.keys()
    )
    assert documented == BUILTINS.keys()


def test_builtin_categories_match_the_dispatch_tables() -> None:
    # Keyed STRICTLY on StmtSpec.kind, never on is_location: the LOCATION
    # category covers all five HEADER keys (policy/priority included),
    # while is_location is true only for domain/table/chain and feeds
    # _LOCATION_KEYWORDS alone.
    expected: dict[str, BuiltinCategory] = {}
    for key, spec in STMT_TABLE.items():
        expected[key] = (
            BuiltinCategory.LOCATION
            if spec.kind is StmtKind.HEADER
            else BuiltinCategory.STRUCTURE
        )
    for key in ("@if", "@else"):
        expected[key] = BuiltinCategory.STRUCTURE
    for key in _LEAF_MODULE_LOAD | Parser._LEAF_ACTIONS.keys():
        expected[key] = BuiltinCategory.RULE
    for key in CORE_TARGETS:
        expected[key] = BuiltinCategory.TARGET
    for key in Evaluator.BUILTIN_FUNCTIONS:
        expected[key] = BuiltinCategory.FUNCTION
    mismatched = {
        key: (BUILTINS[key].category, category)
        for key, category in expected.items()
        if BUILTINS[key].category is not category
    }
    assert not mismatched, f"BUILTINS category drift: {mismatched}"
