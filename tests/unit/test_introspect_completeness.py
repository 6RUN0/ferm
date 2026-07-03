"""
Completeness gate: curated BUILTINS vs the parser's keyword dispatch.

parser.py/functions.py dispatch built-in keywords via string compares
(if-chains), so nothing enforces that pyferm.introspect.BUILTINS keeps
up.  This gate AST-scans both sources for string literals compared
against the dispatch variables and fails when a word appears that
BUILTINS does not know (or vice versa).  Same shape and limitations as
test_visitor_completeness.py: compares through variables or regexes are
invisible and live in the documented manual/ignore lists.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pyferm.functions
import pyferm.parser
from pyferm.introspect import BUILTINS
from pyferm.parser import DEPRECATED_KEYWORDS

#: Dispatch variables whose string comparisons the scan harvests.
_SCAN_NAMES: Final = frozenset({"keyword", "token", "lead", "tok"})

#: Collected-but-not-a-keyword tokens (assert 1), each with a reason.
_INTROSPECT_IGNORED: Final = frozenset(
    {
        ";",  # statement terminator, not a keyword
        "}",  # block close, not a keyword
        "{",  # block open, not a keyword
        "$",  # variable sigil
        "&",  # function sigil
        "!",  # negation token
        "(",  # tuple/array open
        ")",  # tuple/array close
        "=",  # @def assignment
        ",",  # list separator
    }
)

#: BUILTINS keys the scan cannot find (assert 2), each with a reason.
_INTROSPECT_MANUAL: Final = frozenset(
    {
        "mod",  # regex dispatch mod(?:ule)? -- parser.py:1402
        "module",  # same regex
        "ACCEPT",  # core target, lives in rules.py (not scanned)
        "DROP",  # core target
        "RETURN",  # core target
        "QUEUE",  # core target
    }
)


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


def _collect_keywords(source_path: Path) -> set[str]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    consts = _module_constants(tree)
    words: set[str] = set()
    for node in ast.walk(tree):
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


def _scanned_words() -> set[str]:
    words: set[str] = set()
    for module in (pyferm.parser, pyferm.functions):
        assert module.__file__ is not None, f"{module} has no source file"
        words |= _collect_keywords(Path(module.__file__))
    words |= set(DEPRECATED_KEYWORDS)
    return words


def test_every_scanned_keyword_is_describable() -> None:
    unknown = (
        _scanned_words()
        - set(BUILTINS)
        - set(DEPRECATED_KEYWORDS)
        - _INTROSPECT_IGNORED
    )
    assert not unknown, (
        "parser dispatches keywords unknown to introspect.BUILTINS "
        f"(add entries or documented ignores): {sorted(unknown)}"
    )


def test_every_builtin_is_scan_found_or_manual() -> None:
    missing = set(BUILTINS) - _scanned_words() - _INTROSPECT_MANUAL
    assert not missing, (
        "BUILTINS entries the scan cannot find (typo or dead entry?): "
        f"{sorted(missing)}"
    )
