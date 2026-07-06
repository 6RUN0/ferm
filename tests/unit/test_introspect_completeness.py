"""
Completeness gate: curated BUILTINS vs the parser's dispatch tables.

Every fixed keyword the parser or evaluator dispatches now lives in a
table -- ``STMT_TABLE``, the staged leaf tables on :class:`Parser`,
``Evaluator.BUILTIN_FUNCTIONS`` -- or in ``CORE_TARGETS``, so the gate
is a plain set equality.  ``@if``/``@else`` stay literal branches with
unique constructors and are named explicitly; the punctuation control
tokens (``;`` ``}`` ``$`` ``&``) are dispatch, not documented keywords,
so the union simply leaves ``_LEAF_CONTROL``/``_LEAF_SIGILS`` out.

Two side gates guard what the equality cannot see: the AST scan
(``test_no_keyword_dispatch_outside_the_tables``) catches a keyword
dispatched via a hand-written string compare instead of a table, and
the scan-layer pin (``test_scan_layer_keyword_sets_track_the_parser``)
holds the eval-free ``_treescan``/``graph`` keyword mirrors to the
parser tables they deliberately do not import.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pyferm.functions
import pyferm.parser
from pyferm._treescan import _JUMP_KW, _SUBCHAIN_KW
from pyferm.functions import Evaluator
from pyferm.graph import _KIND_BY_JUMP_KEYWORD, _KIND_BY_SUBCHAIN_KEYWORD
from pyferm.introspect import BUILTINS, BuiltinCategory
from pyferm.parser import (
    _LEAF_MODULE_LOAD,
    _SUBCHAIN_KEYWORDS,
    DEPRECATED_KEYWORDS,
    STMT_TABLE,
    Parser,
    StmtKind,
)
from pyferm.rules import CORE_TARGETS

if TYPE_CHECKING:
    from collections.abc import Iterator


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


def test_scan_layer_keyword_sets_track_the_parser() -> None:
    """The eval-free scan layer's keyword mirrors follow the tables.

    ``_treescan`` keeps its own literal subchain/jump sets (and graph.py
    its EdgeKind maps) so the minimal scan core stays parser-free.  The
    price is drift: a spelling added to ``STMT_TABLE`` or an alias added
    to ``DEPRECATED_KEYWORDS`` would parse fine yet be invisible to
    ``--lint``/``--graph``.  Pin the mirrors here instead of importing.
    """
    assert _SUBCHAIN_KW == _SUBCHAIN_KEYWORDS
    assert _KIND_BY_SUBCHAIN_KEYWORD.keys() == _SUBCHAIN_KEYWORDS

    jump_handler = Parser._LEAF_ACTIONS["jump"]
    jump_core = {
        key
        for key, handler in Parser._LEAF_ACTIONS.items()
        if handler is jump_handler
    }
    # The scan layer sees raw tokens, so it must also know every
    # deprecated alias the eval path would remap to a jump keyword.
    jump_aliases = {
        alias
        for alias, replacement in DEPRECATED_KEYWORDS.items()
        if replacement in jump_core
    }
    assert frozenset(_JUMP_KW) == jump_core | jump_aliases
    assert _KIND_BY_JUMP_KEYWORD.keys() == jump_core | jump_aliases
    for alias, replacement in DEPRECATED_KEYWORDS.items():
        if replacement in _KIND_BY_JUMP_KEYWORD:
            assert (
                _KIND_BY_JUMP_KEYWORD[alias]
                is _KIND_BY_JUMP_KEYWORD[replacement]
            ), f"alias {alias!r} maps to a different edge kind"


#: Dispatch variables whose string comparisons the out-of-table scan
#: harvests.  Same shape and limitation as test_visitor_completeness:
#: compares through other variable names or regexes are invisible.
_SCAN_NAMES: Final = frozenset({"keyword", "token", "lead", "tok"})

#: Scan hits that are dispatch punctuation, not documented keywords.
_SCAN_IGNORED: Final = frozenset(
    {";", "}", "{", "$", "&", "!", "(", ")", "=", ","}
)

#: mutmut mutant bodies (x_<name>__mutmut_<N>); pruning them keeps the
#: harvest equal to the unmutated source when the suite runs from
#: <repo>/mutants/.
_MUTANT_DEF_RE: Final = re.compile(r"__mutmut_\d+$")


def _module_constants(tree: ast.Module) -> dict[str, set[str]]:
    """Module-level NAME = frozenset({...}) string members."""
    consts: dict[str, set[str]] = {}
    for node in tree.body:
        target = None
        value = (
            node.value
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            else None
        )
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if not (isinstance(target, ast.Name) and value is not None):
            continue
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
            and isinstance(value.args[0], (ast.Set, ast.Tuple, ast.List))
        ):
            members = {
                elt.value
                for elt in value.args[0].elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
            if members:
                consts[target.id] = members
    return consts


def _walk_skipping_mutants(tree: ast.Module) -> Iterator[ast.AST]:
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and _MUTANT_DEF_RE.search(node.name):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _collect_keywords(source_path: Path) -> set[str]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    consts = _module_constants(tree)
    words: set[str] = set()
    for node in _walk_skipping_mutants(tree):
        if not isinstance(node, ast.Compare):
            continue
        left = node.left
        if not (isinstance(left, ast.Name) and left.id in _SCAN_NAMES):
            continue
        for comp in node.comparators:
            if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                words.add(comp.value)
            elif isinstance(comp, (ast.Tuple, ast.Set, ast.List)):
                words.update(
                    elt.value
                    for elt in comp.elts
                    if isinstance(elt, ast.Constant)
                    and isinstance(elt.value, str)
                )
            elif isinstance(comp, ast.Name) and comp.id in consts:
                words.update(consts[comp.id])
    return words


def test_no_keyword_dispatch_outside_the_tables() -> None:
    """No fixed keyword is dispatched via an ad-hoc string compare.

    The equality gate above only sees the tables, so a hand-written
    ``if tok == "newkw"`` branch handling a keyword absent from both
    the tables and BUILTINS would pass it silently.  AST-scan the two
    dispatch sources for string compares against the dispatch variables
    and require every hit to be a documented builtin, a deprecated
    alias, or listed punctuation.
    """
    words: set[str] = set()
    for module in (pyferm.parser, pyferm.functions):
        assert module.__file__ is not None, f"{module} has no source file"
        words |= _collect_keywords(Path(module.__file__))
    unknown = (
        words - BUILTINS.keys() - set(DEPRECATED_KEYWORDS) - _SCAN_IGNORED
    )
    assert not unknown, (
        "keyword dispatched outside the tables (add a table entry or a "
        f"documented ignore): {sorted(unknown)}"
    )
